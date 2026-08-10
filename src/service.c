#define _GNU_SOURCE
#include "service.h"
#include "process.h"
#include "service-file.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

struct Service {
        char *name;
        char *path;
        char *exec;
        char *user;
        PtrVec arguments;
        NssUser *identity;
        atomic_uint ref_count;
        uid_t uid;
        gid_t gid;
        uint64_t serial;
        bool starting;
};

typedef struct Activation {
        ServiceManager *manager;
        Service *service;
        char *user;
        uid_t uid;
        gid_t gid;
        gid_t *groups;
        size_t n_groups;
} Activation;

struct ServiceManager {
        Controller *controller;
        char *address;
        char *bus_type;
        ServiceTable *services;
        StrMap environment;
        U32Map activations;
};

Service *service_reference(Service *service)
{
        atomic_fetch_add_explicit(&service->ref_count, 1, memory_order_relaxed);
        return service;
}

static void service_unref(void *data)
{
        Service *service = data;
        if (!service || atomic_fetch_sub_explicit(&service->ref_count, 1, memory_order_acq_rel) != 1)
                return;
        free(service->name);
        free(service->path);
        free(service->exec);
        free(service->user);
        ptr_vec_clear(&service->arguments);
        nss_user_unref(service->identity);
        free(service);
}

static void activation_free(void *data)
{
        Activation *activation = data;
        if (!activation)
                return;
        service_unref(activation->service);
        free(activation->user);
        free(activation->groups);
        free(activation);
}

ServiceTable *service_table_new(void)
{
        return str_map_new(service_unref);
}

void service_table_free(ServiceTable *services)
{
        str_map_free(services);
}

ServiceManager *service_manager_new(void)
{
        ServiceManager *manager = calloc(1, sizeof(*manager));
        if (!manager)
                return NULL;
        manager->services = service_table_new();
        str_map_init(&manager->environment, free);
        u32_map_init(&manager->activations, activation_free);
        if (!manager->services) {
                service_manager_free(manager);
                return NULL;
        }
        return manager;
}

void service_manager_free(ServiceManager *manager)
{
        if (!manager)
                return;
        service_table_free(manager->services);
        str_map_clear(&manager->environment);
        u32_map_clear(&manager->activations);
        free(manager->address);
        free(manager->bus_type);
        free(manager);
}

void service_manager_set_controller(ServiceManager *manager, Controller *controller, const char *address,
                                    const char *bus_type)
{
        manager->controller = controller;
        free(manager->address);
        free(manager->bus_type);
        manager->address = str_dup(address);
        manager->bus_type = str_dup(bus_type);
}

ServiceTable *service_manager_table(ServiceManager *manager)
{
        return manager->services;
}

void service_manager_take_table(ServiceManager *manager, ServiceTable *services)
{
        service_table_free(manager->services);
        manager->services = services;
}

static char *service_object_path(const char *name)
{
        static const char hex[] = "0123456789abcdef";
        const char prefix[] = "/org/bus1/DBus/Name/_";
        size_t prefix_length = sizeof(prefix) - 1, length = strlen(name);
        char *path;
        if (length > (SIZE_MAX - prefix_length - 1) / 2)
                return NULL;
        path = malloc(prefix_length + length * 2 + 1);
        if (!path)
                return NULL;
        memcpy(path, prefix, prefix_length);
        for (size_t i = 0; i < length; ++i) {
                unsigned char byte = (unsigned char)name[i];
                path[prefix_length + i * 2] = hex[byte >> 4];
                path[prefix_length + i * 2 + 1] = hex[byte & 15];
        }
        path[prefix_length + length * 2] = 0;
        return path;
}

bool service_register(ServiceManager *manager, Service *service, Error **error)
{
        return controller_add_name(manager->controller, service->path, service->name, service->uid, error);
}

bool service_release(ServiceManager *manager, Service *service, Error **error)
{
        return controller_release(manager->controller, service->path, error);
}

static void reset_service(ServiceManager *manager, Service *service, const char *reason)
{
        Error *error = NULL;
        if (manager->controller &&
            !controller_reset(manager->controller, service->path, service->serial, reason, &error)) {
                fprintf(stderr, "Cannot reset D-Bus service %s: %s\n", service->name,
                        error ? error->message : "unknown error");
                error_free(error);
        }
        service->starting = false;
}

static bool activation_child_setup(void *data, int *error_number)
{
        Activation *activation = data;
        if (!activation->user || (geteuid() == activation->uid && getegid() == activation->gid))
                return true;
        if (geteuid() != 0 || syscall(SYS_setgroups, activation->n_groups, activation->groups) < 0 ||
            syscall(SYS_setresgid, activation->gid, activation->gid, activation->gid) < 0 ||
            syscall(SYS_setresuid, activation->uid, activation->uid, activation->uid) < 0) {
                *error_number = errno ? errno : EPERM;
                return false;
        }
        return true;
}

static bool environment_set(StrMap *environment, const char *key, const char *value)
{
        char *copy = str_dup(value);
        if (!copy || !str_map_set(environment, key, copy)) {
                free(copy);
                return false;
        }
        return true;
}

static bool environment_current(StrMap *environment)
{
        str_map_init(environment, free);
        for (char **item = environ; item && *item; ++item) {
                char *equal = strchr(*item, '=');
                char *key;
                if (!equal)
                        continue;
                key = strndup(*item, (size_t)(equal - *item));
                if (!key || !environment_set(environment, key, equal + 1)) {
                        free(key);
                        str_map_clear(environment);
                        return false;
                }
                free(key);
        }
        return true;
}

static char **environment_export(const StrMap *environment)
{
        char **values = calloc(environment->len + 1, sizeof(*values));
        if (!values)
                return NULL;
        for (size_t i = 0; i < environment->len; ++i) {
                values[i] = str_printf("%s=%s", environment->entries[i].key, (char *)environment->entries[i].value);
                if (!values[i]) {
                        for (size_t j = 0; j < i; ++j)
                                free(values[j]);
                        free(values);
                        return NULL;
                }
        }
        return values;
}

static void string_vector_free(char **values)
{
        if (!values)
                return;
        for (size_t i = 0; values[i]; ++i)
                free(values[i]);
        free(values);
}

static void activate(ServiceManager *manager, Service *service, uint64_t serial)
{
        Error *error = NULL;
        StrMap environment;
        char **environment_vector = NULL, **arguments = NULL;
        const NssUser *identity = service->identity;
        Activation *activation = NULL;
        ProcessSpec spec;
        pid_t pid;

        if (service->starting)
                return;
        service->starting = true;
        service->serial = serial;
        if (!environment_current(&environment))
                goto memory;
        for (size_t i = 0; i < manager->environment.len; ++i)
                if (!environment_set(&environment, manager->environment.entries[i].key,
                                     manager->environment.entries[i].value))
                        goto memory_environment;
        if (!environment_set(&environment, "DBUS_STARTER_ADDRESS", manager->address) ||
            !environment_set(&environment, "DBUS_STARTER_BUS_TYPE", manager->bus_type))
                goto memory_environment;
        activation = calloc(1, sizeof(*activation));
        if (!activation)
                goto memory_environment;
        activation->manager = manager;
        activation->service = service_reference(service);
        if (identity) {
                const gid_t *groups = nss_user_groups(identity, &activation->n_groups);
                activation->user = str_dup(nss_user_name(identity));
                activation->uid = nss_user_uid(identity);
                activation->gid = nss_user_gid(identity);
                if (!activation->user || !environment_set(&environment, "HOME", nss_user_home(identity)) ||
                    !environment_set(&environment, "USER", nss_user_name(identity)) ||
                    !environment_set(&environment, "LOGNAME", nss_user_name(identity)) ||
                    !environment_set(&environment, "SHELL", nss_user_shell(identity)))
                        goto memory_environment;
                if (geteuid() != activation->uid || getegid() != activation->gid) {
                        if (geteuid() != 0 || activation->n_groups > INT_MAX) {
                                error_set(&error, EPERM, "Cannot prepare credentials for service user %s",
                                          nss_user_name(identity));
                                goto failure;
                        }
                        activation->groups = malloc(sizeof(*groups) * activation->n_groups);
                        if (!activation->groups)
                                goto memory_environment;
                        memcpy(activation->groups, groups, sizeof(*groups) * activation->n_groups);
                }
        }
        arguments = calloc(service->arguments.len + 1, sizeof(*arguments));
        if (!arguments)
                goto memory_environment;
        for (size_t i = 0; i < service->arguments.len; ++i)
                arguments[i] = service->arguments.items[i];
        environment_vector = environment_export(&environment);
        if (!environment_vector)
                goto memory_environment;
        spec = (ProcessSpec){
                .argv = arguments,
                .environment = environment_vector,
                .search_path = true,
                .child_setup = activation_child_setup,
                .child_setup_data = activation,
        };
        if (!process_spawn(&spec, &pid, &error))
                goto failure;
        if (!u32_map_set(&manager->activations, (uint32_t)pid, activation)) {
                kill(pid, SIGTERM);
                while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
                        ;
                error_set(&error, ENOMEM, "Cannot track activated service");
                goto failure;
        }
        activation = NULL;
        free(arguments);
        string_vector_free(environment_vector);
        str_map_clear(&environment);
        return;
memory_environment:
        error_set(&error, ENOMEM, "Cannot allocate activation state");
failure:
        fprintf(stderr, "Service activation failed for %s: %s\n", service->name,
                error ? error->message : "unknown error");
        error_free(error);
        reset_service(manager, service, "org.bus1.DBus.Name.Error.StartupFailure");
        activation_free(activation);
        free(arguments);
        string_vector_free(environment_vector);
        str_map_clear(&environment);
        return;
memory:
        fprintf(stderr, "Service activation failed for %s: out of memory\n", service->name);
        reset_service(manager, service, "org.bus1.DBus.Name.Error.StartupFailure");
}

bool service_manager_reap(ServiceManager *manager, pid_t pid, int status)
{
        Activation *activation = u32_map_remove(&manager->activations, (uint32_t)pid);
        if (!activation)
                return false;
        if (!WIFEXITED(status) || WEXITSTATUS(status))
                reset_service(manager, activation->service, "org.bus1.DBus.Name.Error.UnitFailure");
        else
                activation->service->starting = false;
        activation_free(activation);
        return true;
}

bool service_manager_handle_packet(ServiceManager *manager, DBusPacket *packet, Error **error)
{
        if (packet->header.type != DBUS_MESSAGE_SIGNAL)
                return true;
        if (str_equal(packet->header.interface, "org.bus1.DBus.Name") && str_equal(packet->header.member, "Activate")) {
                uint64_t serial;
                Service *service = packet->header.path ? str_map_get(manager->services, packet->header.path) : NULL;
                if (!str_equal(packet->header.signature, "t") || !dbus_reader_u64(&packet->body, &serial) ||
                    packet->body.offset != packet->body.length)
                        return error_set(error, EPROTO, "Malformed D-Bus activation signal");
                if (service)
                        activate(manager, service, serial);
        } else if (str_equal(packet->header.interface, "org.bus1.DBus.Broker") &&
                   str_equal(packet->header.member, "SetActivationEnvironment")) {
                DBusReader dictionary;
                if (!str_equal(packet->header.signature, "a{ss}") || !dbus_reader_array(&packet->body, 8, &dictionary))
                        return error_set(error, EPROTO, "Malformed activation environment signal");
                while (dictionary.offset < dictionary.length) {
                        const char *key, *value;
                        size_t key_length, value_length;
                        if (!dbus_reader_align(&dictionary, 8) || !dbus_reader_string(&dictionary, &key, &key_length) ||
                            !dbus_reader_string(&dictionary, &value, &value_length))
                                return error_set(error, EPROTO, "Malformed activation environment entry");
                        if (key_length && !memchr(key, '=', key_length) &&
                            !environment_set(&manager->environment, key, value))
                                return error_set(error, ENOMEM, "Cannot store activation environment");
                }
        }
        return true;
}

bool service_table_scan(PtrVec *service_dirs, NssCache *nss, bool user_scope, ServiceTable *services, Error **error)
{
        StrMap names;
        str_map_init(&names, NULL);
        for (size_t i = 0; i < service_dirs->len; ++i) {
                const char *directory_path = service_dirs->items[i];
                DIR *directory = opendir(directory_path);
                struct dirent *entry;
                if (!directory) {
                        if (errno == ENOENT)
                                continue;
                        if (errno == EACCES || errno == EPERM) {
                                fprintf(stderr, "Cannot access D-Bus service directory %s: %s\n", directory_path,
                                        strerror(errno));
                                continue;
                        }
                        str_map_clear(&names);
                        return error_set_errno(error, errno, "Cannot scan D-Bus services in %s", directory_path);
                }
                int read_error = 0;
                for (;;) {
                        char *path;
                        ServiceFile parsed = {0};
                        Error *local_error = NULL;
                        const NssUser *identity = NULL;
                        Service *service;
                        errno = 0;
                        entry = readdir(directory);
                        if (!entry) {
                                read_error = errno;
                                break;
                        }
                        if (!str_has_suffix(entry->d_name, ".service"))
                                continue;
                        path = path_join(directory_path, entry->d_name);
                        if (!path || !service_file_load(path, &parsed, &local_error)) {
                                fprintf(stderr, "Ignoring unreadable D-Bus service file %s: %s\n",
                                        path ? path : entry->d_name,
                                        local_error ? local_error->message : "out of memory");
                                error_free(local_error);
                                free(path);
                                continue;
                        }
                        if (!parsed.name || !parsed.exec) {
                                if (parsed.name && parsed.systemd_service)
                                        fprintf(stderr, "Ignoring systemd-only D-Bus service %s\n", path);
                                else
                                        fprintf(stderr, "Ignoring D-Bus service file %s: missing %s\n", path,
                                                parsed.name ? "Exec" : "Name");
                                goto next;
                        }
                        if (!dbus_name_is_valid(parsed.name)) {
                                fprintf(stderr, "Ignoring invalid D-Bus service file %s\n", path);
                                goto next;
                        }
                        if (parsed.user) {
                                identity = nss_cache_lookup_user(nss, parsed.user, &local_error);
                                if (!identity) {
                                        if (local_error && local_error->code == NSS_ERROR_NOT_FOUND) {
                                                fprintf(stderr, "Ignoring D-Bus service file %s: %s\n", path,
                                                        local_error->message);
                                                error_free(local_error);
                                                goto next;
                                        }
                                        error_prefix(&local_error, "%s: ", path);
                                        if (error)
                                                *error = local_error;
                                        else
                                                error_free(local_error);
                                        service_file_clear(&parsed);
                                        free(path);
                                        closedir(directory);
                                        str_map_clear(&names);
                                        return false;
                                }
                        }
                        if (strlen(entry->d_name) != strlen(parsed.name) + strlen(".service") ||
                            !str_has_prefix(entry->d_name, parsed.name)) {
                                if (!user_scope) {
                                        fprintf(stderr,
                                                "Ignoring system D-Bus service file %s: filename does not match "
                                                "Name=%s\n",
                                                path, parsed.name);
                                        goto next;
                                }
                                fprintf(stderr, "User D-Bus service file %s is not named after %s\n", path,
                                        parsed.name);
                        }
                        if (str_map_contains(&names, parsed.name)) {
                                fprintf(stderr, "Ignoring duplicate D-Bus service name %s in %s\n", parsed.name, path);
                                goto next;
                        }
                        service = calloc(1, sizeof(*service));
                        if (!service) {
                                service_file_clear(&parsed);
                                free(path);
                                closedir(directory);
                                str_map_clear(&names);
                                return error_set(error, ENOMEM, "Cannot allocate D-Bus service");
                        }
                        atomic_init(&service->ref_count, 1);
                        service->name = parsed.name;
                        parsed.name = NULL;
                        service->exec = parsed.exec;
                        parsed.exec = NULL;
                        service->user = parsed.user;
                        parsed.user = NULL;
                        service->arguments = parsed.arguments;
                        parsed.arguments = (PtrVec){0};
                        service->identity = nss_user_ref(identity);
                        service->uid = identity ? nss_user_uid(identity) : getuid();
                        service->gid = identity ? nss_user_gid(identity) : getgid();
                        service->path = service_object_path(service->name);
                        if (!service->path || !str_map_set(&names, service->name, NULL) ||
                            !str_map_set(services, service->path, service)) {
                                service_unref(service);
                                service_file_clear(&parsed);
                                free(path);
                                closedir(directory);
                                str_map_clear(&names);
                                return error_set(error, ENOMEM, "Cannot store D-Bus service");
                        }
                next:
                        service_file_clear(&parsed);
                        free(path);
                }
                if (read_error) {
                        closedir(directory);
                        str_map_clear(&names);
                        return error_set_errno(error, read_error, "Cannot scan D-Bus services in %s", directory_path);
                }
                closedir(directory);
        }
        str_map_clear(&names);
        return true;
}

bool service_table_register_all(ServiceManager *manager, ServiceTable *services, Error **error)
{
        for (size_t i = 0; i < services->len; ++i)
                if (!service_register(manager, services->entries[i].value, error))
                        return false;
        return true;
}

bool service_equal(Service *left, Service *right)
{
        size_t left_n = 0, right_n = 0;
        const gid_t *left_groups = left->identity ? nss_user_groups(left->identity, &left_n) : NULL;
        const gid_t *right_groups = right->identity ? nss_user_groups(right->identity, &right_n) : NULL;
        return str_equal(left->name, right->name) && str_equal(left->exec, right->exec) &&
               str_equal(left->user, right->user) && left->uid == right->uid && left->gid == right->gid &&
               left_n == right_n && (!left_n || memcmp(left_groups, right_groups, left_n * sizeof(gid_t)) == 0);
}
