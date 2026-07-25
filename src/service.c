#define _GNU_SOURCE
#include "service.h"

#include <linux/capability.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct Service {
        gchar *name;
        gchar *path;
        gchar *exec;
        gchar *user;
        NssUser *identity;
        gint ref_count;
        uid_t uid;
        gid_t gid;
        guint64 serial;
        gboolean starting;
};

struct ServiceManager {
        GDBusConnection *controller;
        gchar *address;
        gchar *bus_type;
        GHashTable *services;
        GHashTable *environment;
};

typedef struct {
        ServiceManager *manager;
        Service *service;
        gchar *user;
        uid_t uid;
        gid_t gid;
        gid_t *groups;
        gint n_groups;
} Activation;

static gboolean controller_call(ServiceManager *manager, const gchar *path, const gchar *interface,
                                const gchar *method, GVariant *arguments, GError **error)
{
        GVariant *reply = g_dbus_connection_call_sync(manager->controller, NULL, path, interface, method, arguments,
                                                      NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
        if (!reply)
                return FALSE;
        g_variant_unref(reply);
        return TRUE;
}

static void report_error(const gchar *what, GError *error)
{
        g_printerr("%s: %s\n", what, error ? error->message : "unknown error");
        g_clear_error(&error);
}

Service *service_reference(Service *service)
{
        g_atomic_int_inc(&service->ref_count);
        return service;
}

static void service_unref(Service *service)
{
        if (!service || !g_atomic_int_dec_and_test(&service->ref_count))
                return;
        g_free(service->name);
        g_free(service->path);
        g_free(service->exec);
        g_free(service->user);
        nss_user_unref(service->identity);
        g_free(service);
}

ServiceManager *service_manager_new(void)
{
        ServiceManager *manager = g_new0(ServiceManager, 1);
        manager->services = service_table_new();
        manager->environment = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        return manager;
}

void service_manager_free(ServiceManager *manager)
{
        if (!manager)
                return;
        g_clear_object(&manager->controller);
        g_hash_table_unref(manager->services);
        g_hash_table_unref(manager->environment);
        g_free(manager->address);
        g_free(manager->bus_type);
        g_free(manager);
}

void service_manager_set_connection(ServiceManager *manager, GDBusConnection *controller, const gchar *address,
                                    const gchar *bus_type)
{
        g_set_object(&manager->controller, controller);
        g_free(manager->address);
        g_free(manager->bus_type);
        manager->address = g_strdup(address);
        manager->bus_type = g_strdup(bus_type);
}

GHashTable *service_manager_table(ServiceManager *manager)
{
        return manager->services;
}

void service_manager_take_table(ServiceManager *manager, GHashTable *services)
{
        g_hash_table_unref(manager->services);
        manager->services = services;
}

static gchar *service_object_path(const gchar *name, const gchar *exec, const gchar *user)
{
        GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
        const guchar separator = 0;
        gchar *path;

        g_checksum_update(checksum, (const guchar *)name, -1);
        g_checksum_update(checksum, &separator, 1);
        g_checksum_update(checksum, (const guchar *)exec, -1);
        g_checksum_update(checksum, &separator, 1);
        if (user)
                g_checksum_update(checksum, (const guchar *)user, -1);
        path = g_strdup_printf("/org/bus1/DBus/Name/%s", g_checksum_get_string(checksum));
        g_checksum_free(checksum);
        return path;
}

gboolean service_register(ServiceManager *manager, Service *service, GError **error)
{
        g_debug("Registering activatable D-Bus name %s from %s", service->name, service->path);
        return controller_call(manager, "/org/bus1/DBus/Broker", "org.bus1.DBus.Broker", "AddName",
                               g_variant_new("(osu)", service->path, service->name, (guint)service->uid), error);
}

gboolean service_release(ServiceManager *manager, Service *service, GError **error)
{
        return controller_call(manager, service->path, "org.bus1.DBus.Name", "Release", NULL, error);
}

static void reset_service(ServiceManager *manager, Service *service, const gchar *reason)
{
        GError *error = NULL;
        controller_call(manager, service->path, "org.bus1.DBus.Name", "Reset",
                        g_variant_new("(ts)", service->serial, reason), &error);
        g_clear_error(&error);
        service->starting = FALSE;
}

static void activation_free(Activation *activation)
{
        if (!activation)
                return;
        service_unref(activation->service);
        g_free(activation->user);
        g_free(activation->groups);
        g_free(activation);
}

static void activation_child_setup(gpointer data)
{
        Activation *activation = data;
        if (!activation->user || (geteuid() == activation->uid && getegid() == activation->gid))
                return;
        if (geteuid() != 0 || syscall(SYS_setgroups, activation->n_groups, activation->groups) < 0 ||
            syscall(SYS_setresgid, activation->gid, activation->gid, activation->gid) < 0 ||
            syscall(SYS_setresuid, activation->uid, activation->uid, activation->uid) < 0)
                _exit(127);
}

static void activation_done(GPid pid, gint status, gpointer data)
{
        Activation *activation = data;
        if (!WIFEXITED(status) || WEXITSTATUS(status))
                reset_service(activation->manager, activation->service, "org.bus1.DBus.Name.Error.UnitFailure");
        else
                activation->service->starting = FALSE;
        g_spawn_close_pid(pid);
        activation_free(activation);
}

static gchar **activation_environment(ServiceManager *manager)
{
        gchar **environment = g_get_environ();
        GHashTableIter iterator;
        gpointer key, value;
        g_hash_table_iter_init(&iterator, manager->environment);
        while (g_hash_table_iter_next(&iterator, &key, &value))
                environment = g_environ_setenv(environment, key, value, TRUE);
        return environment;
}

static void activate(ServiceManager *manager, Service *service, guint64 serial)
{
        GError *error = NULL;
        gchar **arguments = NULL;
        gchar **environment;
        const NssUser *identity = service->identity;
        Activation *activation;
        GPid pid;

        if (service->starting)
                return;
        service->starting = TRUE;
        service->serial = serial;
        if (!g_shell_parse_argv(service->exec, NULL, &arguments, &error)) {
                report_error("Invalid service Exec", error);
                reset_service(manager, service, "org.bus1.DBus.Name.Error.InvalidUnit");
                return;
        }
        environment = activation_environment(manager);
        environment = g_environ_setenv(environment, "DBUS_STARTER_ADDRESS", manager->address, TRUE);
        environment = g_environ_setenv(environment, "DBUS_STARTER_BUS_TYPE", manager->bus_type, TRUE);
        activation = g_new0(Activation, 1);
        activation->manager = manager;
        activation->service = service_reference(service);
        if (identity) {
                gsize n_groups = 0;
                const gid_t *groups = nss_user_groups(identity, &n_groups);
                activation->user = g_strdup(nss_user_name(identity));
                activation->uid = nss_user_uid(identity);
                activation->gid = nss_user_gid(identity);
                environment = g_environ_setenv(environment, "HOME", nss_user_home(identity), TRUE);
                environment = g_environ_setenv(environment, "USER", nss_user_name(identity), TRUE);
                environment = g_environ_setenv(environment, "LOGNAME", nss_user_name(identity), TRUE);
                environment = g_environ_setenv(environment, "SHELL", nss_user_shell(identity), TRUE);
                if (geteuid() != activation->uid || getegid() != activation->gid) {
                        if (geteuid() != 0 || n_groups > G_MAXINT) {
                                g_set_error(&error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                                            "Cannot prepare credentials for service user %s",
                                            nss_user_name(identity));
                                report_error("Service activation failed", error);
                                reset_service(manager, service, "org.bus1.DBus.Name.Error.StartupFailure");
                                activation_free(activation);
                                g_strfreev(arguments);
                                g_strfreev(environment);
                                return;
                        }
                        activation->n_groups = n_groups;
                        activation->groups = g_memdup2(groups, sizeof(*groups) * n_groups);
                }
        }
        if (!g_spawn_async(NULL, arguments, environment,
                           G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH_FROM_ENVP, activation_child_setup,
                           activation, &pid, &error)) {
                report_error("Service activation failed", error);
                reset_service(manager, service, "org.bus1.DBus.Name.Error.StartupFailure");
                activation_free(activation);
        } else {
                g_child_watch_add(pid, activation_done, activation);
        }
        g_strfreev(arguments);
        g_strfreev(environment);
}

void service_manager_signal(GDBusConnection *connection, const gchar *sender, const gchar *path,
                            const gchar *interface, const gchar *signal, GVariant *parameters, gpointer data)
{
        ServiceManager *manager = data;
        (void)connection;
        (void)sender;
        if (g_str_equal(interface, "org.bus1.DBus.Name") && g_str_equal(signal, "Activate")) {
                Service *service = g_hash_table_lookup(manager->services, path);
                if (service) {
                        guint64 serial;
                        g_variant_get(parameters, "(t)", &serial);
                        g_debug("Activating D-Bus service %s", service->name);
                        activate(manager, service, serial);
                }
        } else if (g_str_equal(interface, "org.bus1.DBus.Broker") &&
                   g_str_equal(signal, "SetActivationEnvironment")) {
                GVariant *dictionary;
                GVariantIter iterator;
                gchar *key, *value;
                g_variant_get(parameters, "(@a{ss})", &dictionary);
                g_variant_iter_init(&iterator, dictionary);
                while (g_variant_iter_next(&iterator, "{ss}", &key, &value)) {
                        if (*key && !strchr(key, '='))
                                g_hash_table_replace(manager->environment, key, value);
                        else {
                                g_warning("Ignoring invalid D-Bus activation environment variable");
                                g_free(key);
                                g_free(value);
                        }
                }
                g_variant_unref(dictionary);
        }
}

GHashTable *service_table_new(void)
{
        return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)service_unref);
}

gboolean service_table_scan(GPtrArray *service_dirs, NssCache *nss, gboolean user_scope, GHashTable *services,
                            GError **error)
{
        GHashTable *names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

        for (guint i = 0; i < service_dirs->len; ++i) {
                GError *directory_error = NULL;
                GDir *directory = g_dir_open(g_ptr_array_index(service_dirs, i), 0, &directory_error);
                const gchar *filename;
                if (!directory) {
                        if (g_error_matches(directory_error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
                                g_clear_error(&directory_error);
                                continue;
                        }
                        if (g_error_matches(directory_error, G_FILE_ERROR, G_FILE_ERROR_ACCES) ||
                            g_error_matches(directory_error, G_FILE_ERROR, G_FILE_ERROR_PERM)) {
                                g_warning("Cannot access D-Bus service directory %s: %s",
                                          (gchar *)g_ptr_array_index(service_dirs, i),
                                          directory_error->message);
                                g_clear_error(&directory_error);
                                continue;
                        }
                        g_propagate_prefixed_error(error, directory_error, "Cannot scan D-Bus services in %s: ",
                                                   (gchar *)g_ptr_array_index(service_dirs, i));
                        g_hash_table_unref(names);
                        return FALSE;
                }
                while ((filename = g_dir_read_name(directory))) {
                        gchar *file, *name = NULL, *exec = NULL, *user = NULL, *systemd_service = NULL;
                        gchar **arguments = NULL;
                        GKeyFile *key_file;
                        GError *service_error = NULL;
                        const NssUser *identity = NULL;
                        Service *service;

                        if (!g_str_has_suffix(filename, ".service"))
                                continue;
                        file = g_build_filename(g_ptr_array_index(service_dirs, i), filename, NULL);
                        key_file = g_key_file_new();
                        if (!g_key_file_load_from_file(key_file, file, G_KEY_FILE_NONE, &service_error)) {
                                g_warning("Ignoring unreadable D-Bus service file %s: %s", file,
                                          service_error->message);
                                g_clear_error(&service_error);
                                goto next;
                        }
                        name = g_key_file_get_string(key_file, "D-BUS Service", "Name", NULL);
                        exec = g_key_file_get_string(key_file, "D-BUS Service", "Exec", NULL);
                        user = g_key_file_get_string(key_file, "D-BUS Service", "User", NULL);
                        systemd_service =
                                g_key_file_get_string(key_file, "D-BUS Service", "SystemdService", NULL);
                        if (!name || !exec) {
                                if (name && !exec && systemd_service)
                                        g_message("Ignoring systemd-only D-Bus service %s", file);
                                else
                                        g_warning("Ignoring D-Bus service file %s: missing %s", file,
                                                  name ? "Exec" : "Name");
                                goto next;
                        }
                        if (user)
                                identity = nss_cache_lookup_user(nss, user, &service_error);
                        if (!g_dbus_is_name(name) || name[0] == ':' ||
                            !g_shell_parse_argv(exec, NULL, &arguments, NULL) || !arguments[0] || !*arguments[0]) {
                                g_warning("Ignoring invalid D-Bus service file %s", file);
                                g_clear_error(&service_error);
                                goto next;
                        }
                        if (user && !identity) {
                                if (g_error_matches(service_error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND)) {
                                        g_warning("Ignoring D-Bus service file %s: %s", file,
                                                  service_error->message);
                                        g_clear_error(&service_error);
                                        goto next;
                                }
                                g_propagate_prefixed_error(error, service_error, "%s: ", file);
                                g_strfreev(arguments);
                                g_free(systemd_service);
                                g_free(user);
                                g_free(name);
                                g_free(exec);
                                g_key_file_unref(key_file);
                                g_free(file);
                                g_dir_close(directory);
                                g_hash_table_unref(names);
                                return FALSE;
                        }
                        if (strlen(filename) != strlen(name) + strlen(".service") ||
                            !g_str_has_prefix(filename, name)) {
                                if (!user_scope) {
                                        g_warning("Ignoring system D-Bus service file %s: filename does not match "
                                                  "Name=%s",
                                                  file, name);
                                        goto next;
                                }
                                g_warning("User D-Bus service file %s is not named after %s", file, name);
                        }
                        if (g_hash_table_contains(names, name)) {
                                g_warning("Ignoring duplicate D-Bus service name %s in %s", name, file);
                                goto next;
                        }
                        service = g_new0(Service, 1);
                        service->ref_count = 1;
                        service->name = g_steal_pointer(&name);
                        service->exec = g_steal_pointer(&exec);
                        service->user = g_steal_pointer(&user);
                        service->identity = nss_user_ref(identity);
                        service->uid = identity ? nss_user_uid(identity) : getuid();
                        service->gid = identity ? nss_user_gid(identity) : getgid();
                        service->path = service_object_path(service->name, service->exec, service->user);
                        g_hash_table_add(names, g_strdup(service->name));
                        g_hash_table_insert(services, g_strdup(service->path), service);
next:
                        g_strfreev(arguments);
                        g_free(systemd_service);
                        g_free(user);
                        g_free(name);
                        g_free(exec);
                        g_key_file_unref(key_file);
                        g_free(file);
                }
                g_dir_close(directory);
        }
        g_hash_table_unref(names);
        return TRUE;
}

gboolean service_table_register_all(ServiceManager *manager, GHashTable *services, GError **error)
{
        GHashTableIter iterator;
        gpointer value;
        g_hash_table_iter_init(&iterator, services);
        while (g_hash_table_iter_next(&iterator, NULL, &value))
                if (!service_register(manager, value, error))
                        return FALSE;
        return TRUE;
}

gboolean service_equal(Service *left, Service *right)
{
        gsize left_n = 0, right_n = 0;
        const gid_t *left_groups = left->identity ? nss_user_groups(left->identity, &left_n) : NULL;
        const gid_t *right_groups = right->identity ? nss_user_groups(right->identity, &right_n) : NULL;
        return g_strcmp0(left->name, right->name) == 0 && g_strcmp0(left->exec, right->exec) == 0 &&
               g_strcmp0(left->user, right->user) == 0 && left->uid == right->uid && left->gid == right->gid &&
               left_n == right_n && (left_n == 0 || memcmp(left_groups, right_groups, left_n * sizeof(gid_t)) == 0);
}
