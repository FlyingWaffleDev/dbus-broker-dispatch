#define _GNU_SOURCE
#include "config-policy.h"
#include "config.h"
#include "file-watch.h"
#include "service.h"
#include <errno.h>
#include <expat.h>
#include <fcntl.h>
#include <getopt.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <gio/gunixsocketaddress.h>
#include <glib-unix.h>
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_ELOGIND
#include <elogind/sd-login.h>
#endif

typedef struct {
        gboolean user, audit, daemonize;
        int startup_fd;
        gchar *config, *address, *broker, *socket_path, *pid_file;
        guint system_uid_max;
        guint64 max_bytes, max_fds, max_matches;
        uid_t broker_uid;
        gid_t broker_gid;
        gboolean drop_broker_privileges;
        GPid broker_pid;
        GSocket *listener;
        GDBusConnection *controller;
        GMainLoop *loop;
        gboolean broker_failed;
        guint broker_watch_source;
        ServiceManager *service_manager;
        GPtrArray *service_dirs;
        GArray *static_uids, *dynamic_uids;
        LauncherConfig *config_state;
        FileWatch *file_watch;
#ifdef HAVE_ELOGIND
        sd_login_monitor *console_monitor;
        guint console_source;
        guint console_retry_source;
#endif
} Launcher;

typedef struct {
        int fd;
        uid_t uid;
        gid_t gid;
        gboolean drop_privileges;
        gboolean retain_audit;
} BrokerChild;

static void die_error(const gchar *what, GError *e)
{
        g_printerr("%s: %s\n", what, e ? e->message : "unknown error");
        g_clear_error(&e);
}

static gint compare_uids(gconstpointer left, gconstpointer right)
{
        return (*(const guint *)left > *(const guint *)right) - (*(const guint *)left < *(const guint *)right);
}

static GArray *effective_console_uids(Launcher *l)
{
        GArray *uids = g_array_new(FALSE, FALSE, sizeof(guint));
        if (l->static_uids)
                g_array_append_vals(uids, l->static_uids->data, l->static_uids->len);
        if (l->dynamic_uids)
                g_array_append_vals(uids, l->dynamic_uids->data, l->dynamic_uids->len);
        g_array_sort(uids, compare_uids);
        for (guint index = 1; index < uids->len;) {
                if (g_array_index(uids, guint, index) == g_array_index(uids, guint, index - 1))
                        g_array_remove_index(uids, index);
                else
                        ++index;
        }
        return uids;
}

static void load_static_console_users(Launcher *l)
{
        gchar **names;
        l->static_uids = g_array_new(FALSE, FALSE, sizeof(guint));
        if (!SYSTEM_CONSOLE_USERS[0])
                return;
        names = g_strsplit(SYSTEM_CONSOLE_USERS, ",", -1);
        for (guint index = 0; names[index]; ++index) {
                struct passwd *entry = getpwnam(names[index]);
                if (!entry)
                        g_warning("Ignoring unknown system-console user '%s'", names[index]);
                else {
                        guint uid = entry->pw_uid;
                        g_array_append_val(l->static_uids, uid);
                }
        }
        g_strfreev(names);
}

#ifdef HAVE_ELOGIND
/* elogind is deliberately limited to policy classification; it is never used
 * to manage units or sessions.  Failed queries keep the previous UID set. */
static gboolean refresh_console_users(Launcher *l)
{
        uid_t *uids = NULL;
        GArray *candidate;
        int n = sd_get_uids(&uids);
        if (n < 0) {
                g_warning("elogind local-session query failed: %s", g_strerror(-n));
                return FALSE;
        }
        candidate = g_array_new(FALSE, FALSE, sizeof(guint));
        for (int i = 0; i < n; ++i) {
                char **sessions = NULL;
                int ns = sd_uid_get_sessions(uids[i], 1, &sessions);
                if (ns < 0) {
                        g_warning("elogind session query for UID %u failed: %s", (guint)uids[i], g_strerror(-ns));
                        g_array_unref(candidate);
                        free(uids);
                        return FALSE;
                }
                for (int j = 0; ns > 0 && j < ns; ++j) {
                        char *seat = NULL;
                        int remote = sd_session_is_remote(sessions[j]);
                        int seat_result = remote == 0 ? sd_session_get_seat(sessions[j], &seat) : 0;
                        if (remote < 0 || (seat_result < 0 && seat_result != -ENODATA)) {
                                int failure = remote < 0 ? remote : seat_result;
                                g_warning("elogind query for session %s failed: %s", sessions[j], g_strerror(-failure));
                                free(seat);
                                for (int k = 0; k < ns; ++k)
                                        free(sessions[k]);
                                free(sessions);
                                g_array_unref(candidate);
                                free(uids);
                                return FALSE;
                        }
                        if (remote == 0 && seat_result >= 0 && seat && *seat) {
                                guint uid = uids[i];
                                g_array_append_val(candidate, uid);
                                free(seat);
                                break;
                        }
                        free(seat);
                }
                if (sessions) {
                        for (int j = 0; ns > 0 && j < ns; ++j)
                                free(sessions[j]);
                        free(sessions);
                }
        }
        free(uids);
        g_array_sort(candidate, compare_uids);
        for (guint index = 1; index < candidate->len;) {
                if (g_array_index(candidate, guint, index) == g_array_index(candidate, guint, index - 1))
                        g_array_remove_index(candidate, index);
                else
                        ++index;
        }
        if (l->dynamic_uids)
                g_array_unref(l->dynamic_uids);
        l->dynamic_uids = candidate;
        return TRUE;
}
#else
static gboolean refresh_console_users(Launcher *l)
{
        (void)l;
        return TRUE;
}
#endif

static gboolean call(Launcher *l, const gchar *path, const gchar *iface, const gchar *method, GVariant *args,
                     GError **error)
{
        GVariant *reply = g_dbus_connection_call_sync(l->controller, NULL, path, iface, method, args, NULL,
                                                      G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
        if (!reply)
                return FALSE;
        g_variant_unref(reply);
        return TRUE;
}
static GVariant *make_policy(Launcher *l, LauncherConfig *config)
{
        GArray *uids = effective_console_uids(l);
        GVariant *policy = launcher_config_export_policy(config, l->user, l->system_uid_max, uids);
        g_array_unref(uids);
        return policy;
}

static gboolean read_optional_file(const gchar *path, gchar **contents, GError **error)
{
        GError *local_error = NULL;

        if (g_file_get_contents(path, contents, NULL, &local_error))
                return TRUE;
        if (g_error_matches(local_error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
                g_clear_error(&local_error);
                *contents = NULL;
                return TRUE;
        }
        g_propagate_prefixed_error(error, local_error, "%s: ", path);
        return FALSE;
}

static gboolean configure_apparmor(LauncherConfig *config, GError **error)
{
        gchar *enabled_contents = NULL;
        gchar *mask = NULL;
        guint mode = launcher_config_apparmor_mode(config);
        gboolean enabled;
        gboolean supported;

        if (mode == 0)
                return TRUE;
        if (!read_optional_file("/sys/module/apparmor/parameters/enabled", &enabled_contents, error) ||
            !read_optional_file("/sys/kernel/security/apparmor/features/dbus/mask", &mask, error)) {
                g_free(enabled_contents);
                g_free(mask);
                return FALSE;
        }
        enabled = enabled_contents && enabled_contents[0] == 'Y';
        supported = mask && strstr(mask, "acquire") && strstr(mask, "send") && strstr(mask, "receive");
        g_free(enabled_contents);
        g_free(mask);
        if (enabled && supported) {
                launcher_config_set_apparmor_mode(config, 1);
                return TRUE;
        }
        if (mode == 2) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                            "D-Bus configuration requires AppArmor, but kernel D-Bus mediation is unavailable");
                return FALSE;
        }
        if (enabled && !supported)
                g_warning("Disabling D-Bus AppArmor policy because kernel D-Bus mediation is unavailable");
        launcher_config_set_apparmor_mode(config, 0);
        return TRUE;
}

static gboolean configure_broker_user(Launcher *l, GError **error)
{
        const gchar *user = launcher_config_user(l->config_state);
        const NssUser *entry;

        if (!user || !*user)
                return TRUE;
        entry = nss_cache_lookup_user(launcher_config_nss_cache(l->config_state), user, error);
        if (!entry) {
                g_prefix_error(error, "Invalid D-Bus broker user: ");
                return FALSE;
        }
        if (geteuid() != 0 && (geteuid() != nss_user_uid(entry) || getegid() != nss_user_gid(entry))) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                            "Only root can start dbus-broker as configured user %s", user);
                return FALSE;
        }
        l->broker_uid = nss_user_uid(entry);
        l->broker_gid = nss_user_gid(entry);
        l->drop_broker_privileges = geteuid() != l->broker_uid || getegid() != l->broker_gid;
        return TRUE;
}

#ifdef HAVE_ELOGIND
static gboolean uid_arrays_equal(const GArray *left, const GArray *right)
{
        if (left == right)
                return TRUE;
        if (!left || !right || left->len != right->len)
                return FALSE;
        return left->len == 0 || memcmp(left->data, right->data, left->len * sizeof(guint)) == 0;
}

static gboolean update_console_policy(Launcher *l)
{
        GArray *previous = l->dynamic_uids ? g_array_ref(l->dynamic_uids) : NULL;
        GError *error = NULL;

        if (!refresh_console_users(l)) {
                if (previous)
                        g_array_unref(previous);
                return FALSE;
        }
        if (uid_arrays_equal(previous, l->dynamic_uids)) {
                if (previous)
                        g_array_unref(previous);
                return TRUE;
        }
        if (!call(l, "/org/bus1/DBus/Listener/0", "org.bus1.DBus.Listener", "SetPolicy",
                  g_variant_new("(v)", make_policy(l, l->config_state)), &error)) {
                g_warning("Cannot update console-sensitive D-Bus policy: %s", error->message);
                g_clear_error(&error);
                g_array_unref(l->dynamic_uids);
                l->dynamic_uids = previous;
                return FALSE;
        }
        if (previous)
                g_array_unref(previous);
        return TRUE;
}

static gboolean setup_console_monitor(Launcher *l);

static gboolean retry_console_monitor(gpointer data)
{
        Launcher *l = data;

        if (setup_console_monitor(l)) {
                l->console_retry_source = 0;
                return G_SOURCE_REMOVE;
        }
        return G_SOURCE_CONTINUE;
}

static gboolean console_monitor_event(gint fd, GIOCondition condition, gpointer data)
{
        Launcher *l = data;
        (void)fd;

        if (condition & (G_IO_ERR | G_IO_HUP)) {
                l->console_source = 0;
                l->console_monitor = sd_login_monitor_unref(l->console_monitor);
                if (!l->console_retry_source)
                        l->console_retry_source = g_timeout_add_seconds(30, retry_console_monitor, l);
                return G_SOURCE_REMOVE;
        }
        sd_login_monitor_flush(l->console_monitor);
        update_console_policy(l);
        return G_SOURCE_CONTINUE;
}

static gboolean setup_console_monitor(Launcher *l)
{
        int fd;
        int result;

        if (l->user || !launcher_config_uses_console_policy(l->config_state) || l->console_monitor)
                return TRUE;
        result = sd_login_monitor_new("session", &l->console_monitor);
        if (result < 0) {
                g_warning("Cannot monitor elogind sessions: %s", g_strerror(-result));
                return FALSE;
        }
        fd = sd_login_monitor_get_fd(l->console_monitor);
        if (fd < 0) {
                g_warning("Cannot get elogind monitor descriptor: %s", g_strerror(-fd));
                l->console_monitor = sd_login_monitor_unref(l->console_monitor);
                return FALSE;
        }
        l->console_source = g_unix_fd_add(fd, G_IO_IN | G_IO_ERR | G_IO_HUP, console_monitor_event, l);
        update_console_policy(l);
        return TRUE;
}

static void destroy_console_monitor(Launcher *l)
{
        if (l->console_source) {
                g_source_remove(l->console_source);
                l->console_source = 0;
        }
        if (l->console_retry_source) {
                g_source_remove(l->console_retry_source);
                l->console_retry_source = 0;
        }
        l->console_monitor = sd_login_monitor_unref(l->console_monitor);
        if (l->dynamic_uids) {
                g_array_unref(l->dynamic_uids);
                l->dynamic_uids = NULL;
        }
}

static void configure_console_monitor(Launcher *l)
{
        if (!l->user && launcher_config_uses_console_policy(l->config_state)) {
                if (!setup_console_monitor(l) && !l->console_retry_source)
                        l->console_retry_source = g_timeout_add_seconds(30, retry_console_monitor, l);
                return;
        }
        destroy_console_monitor(l);
}
#else
static void configure_console_monitor(Launcher *l)
{
        (void)l;
}
static void destroy_console_monitor(Launcher *l)
{
        (void)l;
}
#endif
static gboolean reload_config(Launcher *l, GError **error);

static GPtrArray *watch_paths_for_config(LauncherConfig *config)
{
        GPtrArray *paths = g_ptr_array_new_with_free_func(g_free);
        GPtrArray *config_paths = launcher_config_watch_paths(config);
        GPtrArray *service_dirs = launcher_config_service_dirs(config);

        for (guint index = 0; index < config_paths->len; ++index)
                g_ptr_array_add(paths, g_strdup(g_ptr_array_index(config_paths, index)));
        for (guint index = 0; index < service_dirs->len; ++index) {
                const gchar *directory = g_ptr_array_index(service_dirs, index);
                /* Missing directories must remain watched via their nearest
                 * existing ancestor. Existing but inaccessible service
                 * directories are optional and were already skipped by the
                 * scanner, so do not turn them into a startup failure here. */
                if (g_file_test(directory, G_FILE_TEST_EXISTS) &&
                    access(directory, R_OK | X_OK) < 0 &&
                    (errno == EACCES || errno == EPERM))
                        continue;
                g_ptr_array_add(paths, g_canonicalize_filename(directory, NULL));
        }
        return paths;
}

static void automatic_reload(gpointer data)
{
        Launcher *launcher = data;
        GError *error = NULL;
        if (!reload_config(launcher, &error)) {
                g_warning("Automatic D-Bus configuration reload failed: %s", error->message);
                g_clear_error(&error);
        } else {
                g_message("Automatically reloaded D-Bus configuration and services");
        }
}

static void controller_method(GDBusConnection *connection, const gchar *sender, const gchar *path,
                              const gchar *interface, const gchar *method, GVariant *parameters,
                              GDBusMethodInvocation *invocation, gpointer data)
{
        Launcher *l = data;
        GError *e = NULL;
        (void)connection;
        (void)sender;
        (void)path;
        (void)interface;
        (void)parameters;
        if (!g_str_equal(method, "ReloadConfig")) {
                g_dbus_method_invocation_return_error(invocation, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                                                      "Unsupported controller method");
                return;
        }
        if (!reload_config(l, &e)) {
                g_dbus_method_invocation_return_dbus_error(invocation, "org.bus1.DBus.Controller.Error.InvalidConfig",
                                                           e->message);
                g_clear_error(&e);
        } else
                g_dbus_method_invocation_return_value(invocation, NULL);
}
static const GDBusInterfaceVTable controller_vtable = {.method_call = controller_method};
static gboolean reload_config(Launcher *l, GError **error)
{
        LauncherConfig *candidate = launcher_config_new();
        GHashTable *candidate_services = service_table_new();
        GHashTable *current_services = service_manager_table(l->service_manager);
        FileWatch *candidate_watch = file_watch_new(automatic_reload, l);
        GPtrArray *candidate_paths = NULL;
        GPtrArray *unchanged = g_ptr_array_new_with_free_func(g_free);
        GPtrArray *released = g_ptr_array_new();
        GPtrArray *added = g_ptr_array_new();
        GHashTableIter iter;
        gpointer key;
        gpointer value;
        const gchar *address;
        GVariant *policy;
        gboolean success = FALSE;

        if (!launcher_config_load(candidate, l->config, error) || !configure_apparmor(candidate, error) ||
            !service_table_scan(launcher_config_service_dirs(candidate), launcher_config_nss_cache(candidate),
                                l->user, candidate_services, error)) {
                launcher_config_free(candidate);
                g_hash_table_unref(candidate_services);
                g_ptr_array_unref(unchanged);
                g_ptr_array_unref(released);
                g_ptr_array_unref(added);
                file_watch_free(candidate_watch);
                return FALSE;
        }
        candidate_paths = watch_paths_for_config(candidate);
        if (!file_watch_set_paths(candidate_watch, candidate_paths, error)) {
                launcher_config_free(candidate);
                g_hash_table_unref(candidate_services);
                g_ptr_array_unref(unchanged);
                g_ptr_array_unref(released);
                g_ptr_array_unref(added);
                g_ptr_array_unref(candidate_paths);
                file_watch_free(candidate_watch);
                return FALSE;
        }
        g_clear_pointer(&candidate_paths, g_ptr_array_unref);
        address = launcher_config_address(candidate);
        if (g_strcmp0(address, launcher_config_address(l->config_state)) != 0) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                            "Reload cannot change the bus listener address");
                launcher_config_free(candidate);
                g_hash_table_unref(candidate_services);
                g_ptr_array_unref(unchanged);
                g_ptr_array_unref(released);
                g_ptr_array_unref(added);
                file_watch_free(candidate_watch);
                return FALSE;
        }
        if (launcher_config_max_bytes(candidate) != l->max_bytes || launcher_config_max_fds(candidate) != l->max_fds ||
            launcher_config_max_matches(candidate) != l->max_matches) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                            "Reload cannot change dbus-broker resource limits");
                launcher_config_free(candidate);
                g_hash_table_unref(candidate_services);
                g_ptr_array_unref(unchanged);
                g_ptr_array_unref(released);
                g_ptr_array_unref(added);
                file_watch_free(candidate_watch);
                return FALSE;
        }
        if (g_strcmp0(launcher_config_user(candidate), launcher_config_user(l->config_state)) != 0) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                            "Reload cannot change the configured dbus-broker user");
                launcher_config_free(candidate);
                g_hash_table_unref(candidate_services);
                g_ptr_array_unref(unchanged);
                g_ptr_array_unref(released);
                g_ptr_array_unref(added);
                file_watch_free(candidate_watch);
                return FALSE;
        }

        /* Preserve runtime activation state for unchanged services. */
        g_hash_table_iter_init(&iter, candidate_services);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                Service *previous = g_hash_table_lookup(current_services, key);
                if (previous && service_equal(previous, value))
                        g_ptr_array_add(unchanged, g_strdup(key));
        }
        for (guint index = 0; index < unchanged->len; ++index) {
                const gchar *unchanged_key = g_ptr_array_index(unchanged, index);
                Service *previous = g_hash_table_lookup(current_services, unchanged_key);
                g_hash_table_replace(candidate_services, g_strdup(unchanged_key), service_reference(previous));
        }

        g_hash_table_iter_init(&iter, current_services);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                Service *replacement = g_hash_table_lookup(candidate_services, key);
                if ((!replacement || !service_equal(value, replacement)) &&
                    !service_release(l->service_manager, value, error))
                        goto rollback;
                if (!replacement || !service_equal(value, replacement))
                        g_ptr_array_add(released, value);
        }
        g_hash_table_iter_init(&iter, candidate_services);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                Service *previous = g_hash_table_lookup(current_services, key);
                if ((!previous || !service_equal(previous, value)) &&
                    !service_register(l->service_manager, value, error))
                        goto rollback;
                if (!previous || !service_equal(previous, value))
                        g_ptr_array_add(added, value);
        }
        policy = make_policy(l, candidate);
        if (!call(l, "/org/bus1/DBus/Listener/0", "org.bus1.DBus.Listener", "SetPolicy", g_variant_new("(v)", policy),
                  error))
                goto rollback;

        launcher_config_free(l->config_state);
        l->config_state = candidate;
        l->service_dirs = launcher_config_service_dirs(candidate);
        service_manager_take_table(l->service_manager, candidate_services);
        service_manager_set_connection(l->service_manager, l->controller, l->address,
                                       launcher_config_bus_type(candidate)
                                               ? launcher_config_bus_type(candidate)
                                               : (l->user ? "session" : "system"));
        file_watch_free(l->file_watch);
        l->file_watch = candidate_watch;
        candidate_watch = NULL;
        configure_console_monitor(l);
        success = TRUE;
        goto out;

rollback:
        for (guint index = added->len; index > 0; --index) {
                GError *rollback_error = NULL;
                if (!service_release(l->service_manager, g_ptr_array_index(added, index - 1), &rollback_error)) {
                        g_warning("Reload rollback could not release a newly added service: %s",
                                  rollback_error->message);
                        g_clear_error(&rollback_error);
                }
        }
        for (guint index = 0; index < released->len; ++index) {
                GError *rollback_error = NULL;
                if (!service_register(l->service_manager, g_ptr_array_index(released, index), &rollback_error)) {
                        g_warning("Reload rollback could not restore a released service: %s", rollback_error->message);
                        g_clear_error(&rollback_error);
                }
        }
        launcher_config_free(candidate);
        g_hash_table_unref(candidate_services);

out:
        file_watch_free(candidate_watch);
        g_ptr_array_unref(unchanged);
        g_ptr_array_unref(released);
        g_ptr_array_unref(added);
        return success;
}
static gboolean on_hup(gpointer data)
{
        Launcher *l = data;
        GError *e = NULL;
        if (!reload_config(l, &e)) {
                die_error("Reload failed", e);
                return G_SOURCE_CONTINUE;
        }
        g_message("Reloaded D-Bus configuration policy");
        return G_SOURCE_CONTINUE;
}
static gboolean quit_loop(gpointer data)
{
        g_main_loop_quit(data);
        return G_SOURCE_CONTINUE;
}
static void broker_exit(GPid pid, gint status, gpointer data)
{
        Launcher *l = data;

        if (WIFEXITED(status))
                g_warning("dbus-broker exited with status %d", WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
                g_warning("dbus-broker was terminated by signal %d", WTERMSIG(status));
        else
                g_warning("dbus-broker exited unexpectedly");
        l->broker_failed = TRUE;
        l->broker_pid = 0;
        l->broker_watch_source = 0;
        g_spawn_close_pid(pid);
        g_main_loop_quit(l->loop);
}
static gboolean bind_listener(Launcher *l, GError **error)
{
        GSocketAddress *a;
        struct stat st;
        struct stat parent_stat;
        int probe;
        struct sockaddr_un sockaddr = {0};
        gchar *parent = g_path_get_dirname(l->socket_path);

        if (lstat(parent, &parent_stat) < 0 || !S_ISDIR(parent_stat.st_mode) ||
            (l->user && parent_stat.st_uid != geteuid()) || (parent_stat.st_mode & 0022)) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                            "D-Bus socket parent must be a non-writable trusted directory: %s", parent);
                g_free(parent);
                return FALSE;
        }
        g_free(parent);

        if (lstat(l->socket_path, &st) == 0) {
                if (!S_ISSOCK(st.st_mode) || st.st_uid != geteuid()) {
                        g_set_error(error, G_IO_ERROR, G_IO_ERROR_EXISTS,
                                    "Refusing to replace non-socket or foreign-owned path %s", l->socket_path);
                        return FALSE;
                }
                if (strlen(l->socket_path) >= sizeof(sockaddr.sun_path)) {
                        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FILENAME_TOO_LONG, "Socket path is too long: %s",
                                    l->socket_path);
                        return FALSE;
                }
                probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                if (probe < 0) {
                        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno), "socket: %s", g_strerror(errno));
                        return FALSE;
                }
                sockaddr.sun_family = AF_UNIX;
                g_strlcpy(sockaddr.sun_path, l->socket_path, sizeof(sockaddr.sun_path));
                if (connect(probe, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == 0) {
                        close(probe);
                        g_set_error(error, G_IO_ERROR, G_IO_ERROR_ADDRESS_IN_USE,
                                    "A D-Bus listener is already active at %s", l->socket_path);
                        return FALSE;
                }
                if (errno != ECONNREFUSED && errno != ENOENT) {
                        int saved_errno = errno;
                        close(probe);
                        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(saved_errno),
                                    "Cannot verify stale socket %s: %s", l->socket_path, g_strerror(saved_errno));
                        return FALSE;
                }
                close(probe);
                if (unlink(l->socket_path) < 0 && errno != ENOENT) {
                        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno), "unlink %s: %s", l->socket_path,
                                    g_strerror(errno));
                        return FALSE;
                }
        } else if (errno != ENOENT) {
                g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno), "lstat %s: %s", l->socket_path,
                            g_strerror(errno));
                return FALSE;
        }

        l->listener = g_socket_new(G_SOCKET_FAMILY_UNIX, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT, error);
        if (!l->listener)
                return FALSE;
        a = g_unix_socket_address_new(l->socket_path);
        if (!g_socket_bind(l->listener, a, FALSE, error) || !g_socket_listen(l->listener, error)) {
                g_object_unref(a);
                return FALSE;
        }
        g_object_unref(a);
        if (!l->user && chmod(l->socket_path, 0666) < 0) {
                g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno), "chmod %s: %s", l->socket_path,
                            g_strerror(errno));
                return FALSE;
        }
        return TRUE;
}
static void child_setup(gpointer data)
{
        BrokerChild *child = data;
        gboolean keep_audit = FALSE;
        pid_t parent = getppid();

        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                _exit(127);
        if ((child->fd != 3 && dup2(child->fd, 3) < 0) || (child->fd == 3 && fcntl(3, F_SETFD, 0) < 0))
                _exit(127);
        if (getppid() != parent)
                _exit(127);
        if (child->drop_privileges) {
                struct __user_cap_header_struct header = {
                        .version = _LINUX_CAPABILITY_VERSION_3,
                        .pid = 0,
                };
                struct __user_cap_data_struct capabilities[_LINUX_CAPABILITY_U32S_3] = {0};
                guint capability_index = CAP_AUDIT_WRITE / 32;
                guint capability_mask = 1U << (CAP_AUDIT_WRITE % 32);

                if (child->retain_audit) {
                        if (syscall(SYS_capget, &header, capabilities) < 0)
                                _exit(127);
                        keep_audit = (capabilities[capability_index].permitted & capability_mask) != 0;
                }
                if ((keep_audit && prctl(PR_SET_KEEPCAPS, 1) < 0) || syscall(SYS_setgroups, 0, NULL) < 0 ||
                    syscall(SYS_setresgid, child->gid, child->gid, child->gid) < 0 ||
                    syscall(SYS_setresuid, child->uid, child->uid, child->uid) < 0)
                        _exit(127);
                if (keep_audit) {
                        for (guint index = 0; index < G_N_ELEMENTS(capabilities); ++index)
                                capabilities[index] = (struct __user_cap_data_struct){0};
                        capabilities[capability_index].effective = capability_mask;
                        capabilities[capability_index].permitted = capability_mask;
                        capabilities[capability_index].inheritable = capability_mask;
                        if (syscall(SYS_capset, &header, capabilities) < 0 ||
                            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_AUDIT_WRITE, 0, 0) < 0)
                                _exit(127);
                }
        }
}
static gchar *read_machine_id(GError **error)
{
        gchar *id = NULL;
        gsize len = 0;
        if (!g_file_get_contents("/etc/machine-id", &id, &len, error))
                return NULL;
        g_strstrip(id);
        if (strlen(id) != 32) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                            "/etc/machine-id must contain a 32-character machine ID");
                g_free(id);
                return NULL;
        }
        for (gchar *p = id; *p; ++p)
                if (!g_ascii_isxdigit(*p)) {
                        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "/etc/machine-id is not hexadecimal");
                        g_free(id);
                        return NULL;
                }
        return id;
}
static gboolean write_pid_file(const gchar *path, GError **error)
{
        gchar *contents;
        gsize length;
        gsize written = 0;
        int fd;
        struct stat st;

        if (!path)
                return TRUE;
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
        if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid()) {
                int saved_errno = fd < 0 ? errno : EINVAL;
                if (fd >= 0)
                        close(fd);
                g_set_error(error, G_IO_ERROR, g_io_error_from_errno(saved_errno),
                            "Cannot securely write PID file %s: %s", path, g_strerror(saved_errno));
                return FALSE;
        }
        contents = g_strdup_printf("%ld\n", (long)getpid());
        length = strlen(contents);
        while (written < length) {
                ssize_t result = write(fd, contents + written, length - written);
                if (result > 0) {
                        written += result;
                        continue;
                }
                if (result < 0 && errno == EINTR)
                        continue;
                if (result == 0)
                        errno = EIO;
                break;
        }
        if (written != length || close(fd) < 0) {
                int saved_errno = errno;
                if (written != length)
                        close(fd);
                g_free(contents);
                g_set_error(error, G_IO_ERROR, g_io_error_from_errno(saved_errno), "write %s: %s", path,
                            g_strerror(saved_errno));
                return FALSE;
        }
        g_free(contents);
        return TRUE;
}

static gboolean daemonize(Launcher *l, GError **error)
{
        char status;
        pid_t pid;
        ssize_t result;
        int null_fd;
        int startup_pipe[2];

        if (!l->daemonize)
                return write_pid_file(l->pid_file, error);
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, startup_pipe) < 0) {
                g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno), "startup socketpair: %s",
                            g_strerror(errno));
                return FALSE;
        }
        pid = fork();
        if (pid < 0) {
                int saved_errno = errno;
                close(startup_pipe[0]);
                close(startup_pipe[1]);
                g_set_error(error, G_IO_ERROR, g_io_error_from_errno(saved_errno), "fork: %s", g_strerror(saved_errno));
                return FALSE;
        }
        if (pid > 0) {
                close(startup_pipe[1]);
                do
                        result = read(startup_pipe[0], &status, 1);
                while (result < 0 && errno == EINTR);
                close(startup_pipe[0]);
                _exit(result == 1 && status == 'R' ? 0 : 1);
        }
        close(startup_pipe[0]);
        l->startup_fd = startup_pipe[1];
        if (setsid() < 0 || chdir("/") < 0 || (null_fd = open("/dev/null", O_RDWR | O_CLOEXEC)) < 0 ||
            dup2(null_fd, STDIN_FILENO) < 0 || dup2(null_fd, STDOUT_FILENO) < 0 || dup2(null_fd, STDERR_FILENO) < 0) {
                int saved_errno = errno;
                status = 'F';
                do
                        result = send(l->startup_fd, &status, 1, MSG_NOSIGNAL);
                while (result < 0 && errno == EINTR);
                close(l->startup_fd);
                l->startup_fd = -1;
                g_set_error(error, G_IO_ERROR, g_io_error_from_errno(saved_errno), "daemon setup: %s",
                            g_strerror(saved_errno));
                return FALSE;
        }
        if (null_fd > STDERR_FILENO)
                close(null_fd);
        if (!write_pid_file(l->pid_file, error)) {
                status = 'F';
                do
                        result = send(l->startup_fd, &status, 1, MSG_NOSIGNAL);
                while (result < 0 && errno == EINTR);
                close(l->startup_fd);
                l->startup_fd = -1;
                return FALSE;
        }
        return TRUE;
}

static void notify_startup(Launcher *l, gboolean ready)
{
        char status = ready ? 'R' : 'F';

        if (l->startup_fd < 0)
                return;
        while (send(l->startup_fd, &status, 1, MSG_NOSIGNAL) < 0 && errno == EINTR)
                ;
        close(l->startup_fd);
        l->startup_fd = -1;
}
static gboolean start_broker(Launcher *l, GError **error)
{
        int pair[2];
        GSocket *s;
        GSocketConnection *sc;
        gchar *arg, *machine_arg, *max_bytes_arg, *max_fds_arg, *max_matches_arg, *machine_id;
        gchar *argv[8];
        BrokerChild child = {
                .uid = l->broker_uid,
                .gid = l->broker_gid,
                .drop_privileges = l->drop_broker_privileges,
                .retain_audit = l->audit,
        };
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) {
                g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno), "socketpair: %s", g_strerror(errno));
                return FALSE;
        }
        child.fd = pair[1];
        machine_id = read_machine_id(error);
        if (!machine_id) {
                close(pair[0]);
                close(pair[1]);
                return FALSE;
        }
        arg = g_strdup("--controller=3");
        machine_arg = g_strdup_printf("--machine-id=%s", machine_id);
        max_bytes_arg = g_strdup_printf("--max-bytes=%" G_GUINT64_FORMAT, l->max_bytes);
        max_fds_arg = g_strdup_printf("--max-fds=%" G_GUINT64_FORMAT, l->max_fds);
        max_matches_arg = g_strdup_printf("--max-matches=%" G_GUINT64_FORMAT, l->max_matches);
        argv[0] = l->broker;
        argv[1] = arg;
        argv[2] = machine_arg;
        argv[3] = max_bytes_arg;
        argv[4] = max_fds_arg;
        argv[5] = max_matches_arg;
        argv[6] = l->audit ? "--audit" : NULL;
        argv[7] = NULL;
        g_message("Starting dbus-broker with machine ID %.8s...", machine_id);
        if (!g_spawn_async(NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, child_setup, &child, &l->broker_pid, error)) {
                close(pair[0]);
                close(pair[1]);
                g_free(arg);
                g_free(machine_arg);
                g_free(max_bytes_arg);
                g_free(max_fds_arg);
                g_free(max_matches_arg);
                g_free(machine_id);
                return FALSE;
        }
        close(pair[1]);
        g_free(arg);
        g_free(machine_arg);
        g_free(max_bytes_arg);
        g_free(max_fds_arg);
        g_free(max_matches_arg);
        g_free(machine_id);
        s = g_socket_new_from_fd(pair[0], error);
        if (!s)
                return FALSE;
        sc = G_SOCKET_CONNECTION(g_socket_connection_factory_create_connection(s));
        g_object_unref(s);
        /* dbus-broker is the server on its controller socket (see controller_init()).
         * The controller must therefore initiate D-Bus SASL authentication as client. */
        l->controller = g_dbus_connection_new_sync(G_IO_STREAM(sc), NULL, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
                                                   NULL, NULL, error);
        g_object_unref(sc);
        return l->controller != NULL;
}
static gboolean add_listener(Launcher *l, GError **error)
{
        GUnixFDList *fds = g_unix_fd_list_new();
        gint idx = g_unix_fd_list_append(fds, g_socket_get_fd(l->listener), error);
        GVariant *reply;
        if (idx < 0) {
                g_object_unref(fds);
                return FALSE;
        }
        reply = g_dbus_connection_call_with_unix_fd_list_sync(
                l->controller, NULL, "/org/bus1/DBus/Broker", "org.bus1.DBus.Broker", "AddListener",
                g_variant_new("(ohv)", "/org/bus1/DBus/Listener/0", idx, make_policy(l, l->config_state)), NULL,
                G_DBUS_CALL_FLAGS_NONE, -1, fds, NULL, NULL, error);
        g_object_unref(fds);
        if (!reply)
                return FALSE;
        g_variant_unref(reply);
        return TRUE;
}
static void usage(void)
{
        g_print("Usage: dbus-broker-dispatch --scope=system|user [--config-file=PATH] [--address=ADDRESS] "
                "[--broker=PATH] [--pid-file=PATH] [--system-uid-max=N] [--audit] [--foreground]\n");
}

static gchar *socket_path_from_address(const gchar *address, GError **error)
{
        const gchar *encoded;
        gchar *path;

        if (!g_str_has_prefix(address, "unix:path=")) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                            "Only filesystem-backed unix:path= D-Bus addresses are supported");
                return NULL;
        }
        encoded = address + strlen("unix:path=");
        if (!*encoded || strpbrk(encoded, ",;")) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Invalid D-Bus listener address: %s",
                            address);
                return NULL;
        }
        path = g_uri_unescape_string(encoded, NULL);
        if (!path || !g_path_is_absolute(path)) {
                g_free(path);
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                            "The unix:path= listener must contain an absolute, valid escaped path");
                return NULL;
        }
        return path;
}

int main(int argc, char **argv)
{
        Launcher l = {.startup_fd = -1};
        GError *e = NULL;
        GMainLoop *loop;
        gint c;
        guint64 max = 999;
        const gchar *runtime;
        const gchar *configured_address;
        GDBusNodeInfo *info;
        guint reg;
        guint hup_source, term_source, int_source;
        gboolean scope_set = FALSE;
        gboolean broker_explicit = FALSE;
        l.system_uid_max = 999;
        l.daemonize = TRUE;
        static const struct option opts[] = {{"scope", 1, 0, 's'},
                                             {"config-file", 1, 0, 'c'},
                                             {"address", 1, 0, 'a'},
                                             {"broker", 1, 0, 'b'},
                                             {"pid-file", 1, 0, 'p'},
                                             {"system-uid-max", 1, 0, 'm'},
                                             {"audit", 0, 0, 'A'},
                                             {"foreground", 0, 0, 'f'},
                                             {"help", 0, 0, 'h'},
                                             {"version", 0, 0, 'V'},
                                             {0}};
        while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1)
                switch (c) {
                case 's':
                        scope_set = TRUE;
                        if (!strcmp(optarg, "user"))
                                l.user = TRUE;
                        else if (strcmp(optarg, "system") != 0) {
                                usage();
                                return 2;
                        }
                        break;
                case 'c':
                        l.config = g_strdup(optarg);
                        break;
                case 'a':
                        l.address = g_strdup(optarg);
                        break;
                case 'b':
                        l.broker = g_strdup(optarg);
                        broker_explicit = TRUE;
                        break;
                case 'p':
                        l.pid_file = g_strdup(optarg);
                        break;
                case 'm':
                        if (!g_ascii_string_to_unsigned(optarg, 10, 0, G_MAXUINT, &max, &e)) {
                                die_error("--system-uid-max", e);
                                return 2;
                        }
                        l.system_uid_max = max;
                        break;
                case 'A':
                        l.audit = TRUE;
                        break;
                case 'f':
                        l.daemonize = FALSE;
                        break;
                case 'V':
                        g_print("dbus-broker-dispatch %s\n", PROJECT_VERSION);
                        return 0;
                default:
                        usage();
                        return c == 'h' ? 0 : 2;
                }
        if (optind != argc) {
                usage();
                return 2;
        }
        if (!scope_set) {
                g_printerr("--scope=system or --scope=user is required\n");
                return 2;
        }
        l.service_manager = service_manager_new();
        if (!l.broker)
                l.broker = g_strdup(DEFAULT_BROKER);
        if (!g_file_test(l.broker, G_FILE_TEST_IS_EXECUTABLE)) {
                if (broker_explicit) {
                        g_printerr("Configured dbus-broker is not executable: %s\n", l.broker);
                        return 1;
                }
                g_free(l.broker);
                l.broker = g_find_program_in_path("dbus-broker");
        }
        if (!l.broker) {
                g_printerr("dbus-broker not found; use --broker=PATH\n");
                return 1;
        }
        if (l.user) {
                struct stat runtime_stat;
                runtime = g_get_user_runtime_dir();
                if (!runtime || lstat(runtime, &runtime_stat) < 0 || !S_ISDIR(runtime_stat.st_mode) ||
                    runtime_stat.st_uid != geteuid() || (runtime_stat.st_mode & 0077)) {
                        g_printerr("XDG_RUNTIME_DIR is required for --scope=user\n");
                        return 1;
                }
                l.socket_path = g_build_filename(runtime, "bus", NULL);
        } else
                l.socket_path = g_strdup("/run/dbus/system_bus_socket");
        if (!l.config)
                l.config = g_strdup(l.user ? "/usr/share/dbus-1/session.conf" : "/usr/share/dbus-1/system.conf");
        l.config_state = launcher_config_new();
        if (!launcher_config_load(l.config_state, l.config, &e)) {
                die_error("Invalid D-Bus configuration", e);
                return 1;
        }
        if (!configure_apparmor(l.config_state, &e)) {
                die_error("Cannot configure AppArmor policy", e);
                return 1;
        }
        if (!configure_broker_user(&l, &e)) {
                die_error("Cannot configure dbus-broker user", e);
                return 1;
        }
        l.max_bytes = launcher_config_max_bytes(l.config_state);
        l.max_fds = launcher_config_max_fds(l.config_state);
        l.max_matches = launcher_config_max_matches(l.config_state);
        l.service_dirs = launcher_config_service_dirs(l.config_state);
        configured_address = launcher_config_address(l.config_state);
        if (!l.address && configured_address)
                l.address = g_strdup(configured_address);
        if (!l.address) {
                gchar *escaped_path = g_dbus_address_escape_value(l.socket_path);
                l.address = g_strdup_printf("unix:path=%s", escaped_path);
                g_free(escaped_path);
        }
        g_free(l.socket_path);
        l.socket_path = socket_path_from_address(l.address, &e);
        if (!l.socket_path) {
                die_error("Invalid D-Bus address", e);
                return 1;
        }
        if (!l.user) {
                load_static_console_users(&l);
                if (launcher_config_uses_console_policy(l.config_state))
                        refresh_console_users(&l);
        }
        if (!service_table_scan(l.service_dirs, launcher_config_nss_cache(l.config_state), l.user,
                                service_manager_table(l.service_manager), &e)) {
                die_error("Cannot start dispatcher", e);
                return 1;
        }
        if (!daemonize(&l, &e)) {
                die_error("Cannot start dispatcher", e);
                return 1;
        }
        l.file_watch = file_watch_new(automatic_reload, &l);
        GPtrArray *initial_watch_paths = watch_paths_for_config(l.config_state);
        if (!file_watch_set_paths(l.file_watch, initial_watch_paths, &e)) {
                g_ptr_array_unref(initial_watch_paths);
                notify_startup(&l, FALSE);
                die_error("Cannot monitor D-Bus configuration", e);
                if (l.pid_file)
                        unlink(l.pid_file);
                return 1;
        }
        g_ptr_array_unref(initial_watch_paths);
        loop = g_main_loop_new(NULL, FALSE);
        l.loop = loop;
        hup_source = g_unix_signal_add(SIGHUP, on_hup, &l);
        term_source = g_unix_signal_add(SIGTERM, quit_loop, loop);
        int_source = g_unix_signal_add(SIGINT, quit_loop, loop);
        if (!bind_listener(&l, &e) || !start_broker(&l, &e)) {
                notify_startup(&l, FALSE);
                die_error("Cannot start dispatcher", e);
                if (l.controller)
                        g_object_unref(l.controller);
                if (l.listener) {
                        g_object_unref(l.listener);
                        unlink(l.socket_path);
                }
                if (l.pid_file)
                        unlink(l.pid_file);
                g_source_remove(hup_source);
                g_source_remove(term_source);
                g_source_remove(int_source);
                g_main_loop_unref(loop);
                return 1;
        }
        service_manager_set_connection(l.service_manager, l.controller, l.address,
                                       launcher_config_bus_type(l.config_state)
                                               ? launcher_config_bus_type(l.config_state)
                                               : (l.user ? "session" : "system"));
        /* Keep the listening socket private until policy and every activation
         * name are installed.  Otherwise a fast client can connect through the
         * broker and observe a partially initialized bus. */
        if (!service_table_register_all(l.service_manager, service_manager_table(l.service_manager), &e) ||
            !add_listener(&l, &e)) {
                notify_startup(&l, FALSE);
                die_error("Cannot start dispatcher", e);
                if (l.controller)
                        g_object_unref(l.controller);
                if (l.listener) {
                        g_object_unref(l.listener);
                        unlink(l.socket_path);
                }
                if (l.pid_file)
                        unlink(l.pid_file);
                g_source_remove(hup_source);
                g_source_remove(term_source);
                g_source_remove(int_source);
                g_main_loop_unref(loop);
                return 1;
        }
        info = g_dbus_node_info_new_for_xml(
                "<node><interface name='org.bus1.DBus.Controller'><method name='ReloadConfig'/></interface></node>",
                &e);
        if (!info) {
                notify_startup(&l, FALSE);
                die_error("Controller API", e);
                g_object_unref(l.controller);
                g_object_unref(l.listener);
                unlink(l.socket_path);
                if (l.pid_file)
                        unlink(l.pid_file);
                g_source_remove(hup_source);
                g_source_remove(term_source);
                g_source_remove(int_source);
                g_main_loop_unref(loop);
                return 1;
        }
        reg = g_dbus_connection_register_object(l.controller, "/org/bus1/DBus/Controller", info->interfaces[0],
                                                &controller_vtable, &l, NULL, &e);
        if (!reg) {
                notify_startup(&l, FALSE);
                die_error("Controller API", e);
                g_dbus_node_info_unref(info);
                g_object_unref(l.controller);
                g_object_unref(l.listener);
                unlink(l.socket_path);
                if (l.pid_file)
                        unlink(l.pid_file);
                g_source_remove(hup_source);
                g_source_remove(term_source);
                g_source_remove(int_source);
                g_main_loop_unref(loop);
                return 1;
        }
        g_dbus_connection_signal_subscribe(l.controller, NULL, NULL, NULL, NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
                                           service_manager_signal, l.service_manager, NULL);
        configure_console_monitor(&l);
        l.broker_watch_source = g_child_watch_add(l.broker_pid, broker_exit, &l);
        notify_startup(&l, TRUE);
        g_main_loop_run(loop);
        g_dbus_connection_unregister_object(l.controller, reg);
        g_source_remove(hup_source);
        g_source_remove(term_source);
        g_source_remove(int_source);
        g_main_loop_unref(loop);
        g_dbus_node_info_unref(info);
        destroy_console_monitor(&l);
        file_watch_free(l.file_watch);
        if (l.broker_watch_source) {
                g_source_remove(l.broker_watch_source);
                l.broker_watch_source = 0;
        }
        /* Drop the service manager's controller reference before synchronously
         * closing the connection; GDBus otherwise keeps its worker alive while
         * the manager and connection retain each other through subscriptions. */
        service_manager_set_connection(l.service_manager, NULL, l.address,
                                       launcher_config_bus_type(l.config_state)
                                               ? launcher_config_bus_type(l.config_state)
                                               : (l.user ? "session" : "system"));
        g_dbus_connection_close_sync(l.controller, NULL, NULL);
        if (l.broker_pid) {
                int broker_status;
                if (kill(l.broker_pid, SIGTERM) < 0 && errno != ESRCH)
                        g_warning("Cannot terminate dbus-broker: %s", g_strerror(errno));
                while (waitpid(l.broker_pid, &broker_status, 0) < 0 && errno == EINTR)
                        ;
                g_spawn_close_pid(l.broker_pid);
        }
        g_object_unref(l.controller);
        g_object_unref(l.listener);
        unlink(l.socket_path);
        if (l.pid_file)
                unlink(l.pid_file);
        if (l.static_uids)
                g_array_unref(l.static_uids);
        if (l.dynamic_uids)
                g_array_unref(l.dynamic_uids);
        service_manager_free(l.service_manager);
        launcher_config_free(l.config_state);
        g_free(l.config);
        g_free(l.address);
        g_free(l.broker);
        g_free(l.socket_path);
        g_free(l.pid_file);
        return l.broker_failed ? 1 : 0;
}
