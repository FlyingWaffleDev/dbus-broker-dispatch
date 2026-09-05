#define _GNU_SOURCE
#include "address.h"
#include "config-policy.h"
#include "config.h"
#include "controller.h"
#include "event.h"
#include "log.h"
#include "process.h"
#include "service.h"
#include "util.h"
#include "watch.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
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

typedef struct Launcher Launcher;

typedef struct BrokerChild {
        int fd;
        uid_t uid;
        gid_t gid;
        bool drop_privileges;
        bool retain_audit;
} BrokerChild;

struct Launcher {
        bool user, audit, daemonize, broker_failed;
        /* Only paths this process actually created may be removed on exit. A
         * failed start must never delete a running dispatcher's socket. */
        bool listener_bound, pid_file_written;
        int startup_fd, listener_fd, signal_fd;
        char *config, *address, *broker, *socket_path, *pid_file;
        uint32_t system_uid_max;
        uint64_t max_bytes, max_fds, max_matches;
        uid_t broker_uid;
        gid_t broker_gid;
        bool drop_broker_privileges;
        pid_t broker_pid;
        EventLoop loop;
        /* Reload requests are recorded here and executed from the main loop.
         * Running them inside packet dispatch re-entered reload_config through
         * the blocking controller calls it makes. */
        bool reload_pending, reloading;
        U32Vec reload_serials;
        EventSource signal_source, controller_source, watch_source, watch_timer_source;
        Controller controller;
        ServiceManager *service_manager;
        PtrVec *service_dirs;
        U32Vec static_uids, dynamic_uids;
        LauncherConfig *config_state;
        Watch *watch;
#ifdef HAVE_ELOGIND
        sd_login_monitor *console_monitor;
        EventSource console_source;
#endif
};

static void print_error(const char *what, Error *error)
{
        log_error("%s: %s", what, error ? error->message : "unknown error");
        error_free(error);
}

static bool read_optional_file(const char *path, char **contents, Error **error)
{
        if (read_file(path, contents, NULL, error))
                return true;
        if (error && *error && (*error)->code == ENOENT) {
                error_clear(error);
                *contents = NULL;
                return true;
        }
        return false;
}

static bool configure_apparmor(LauncherConfig *config, Error **error)
{
        char *enabled_contents = NULL, *mask = NULL;
        uint32_t mode = launcher_config_apparmor_mode(config);
        bool enabled, supported;
        if (!mode)
                return true;
        if (!read_optional_file("/sys/module/apparmor/parameters/enabled", &enabled_contents, error) ||
            !read_optional_file("/sys/kernel/security/apparmor/features/dbus/mask", &mask, error)) {
                free(enabled_contents);
                free(mask);
                return false;
        }
        enabled = enabled_contents && enabled_contents[0] == 'Y';
        supported = mask && strstr(mask, "acquire") && strstr(mask, "send") && strstr(mask, "receive");
        free(enabled_contents);
        free(mask);
        if (enabled && supported) {
                launcher_config_set_apparmor_mode(config, 1);
                return true;
        }
        if (mode == 2)
                return error_set(error, ENOTSUP,
                                 "D-Bus configuration requires AppArmor, but kernel D-Bus mediation is unavailable");
        if (enabled && !supported)
                log_warning("Disabling D-Bus AppArmor policy because kernel D-Bus mediation is unavailable");
        launcher_config_set_apparmor_mode(config, 0);
        return true;
}

static bool configure_broker_user(Launcher *launcher, Error **error)
{
        const char *name = launcher_config_user(launcher->config_state);
        const NssUser *user;
        if (!name || !*name)
                return true;
        user = nss_cache_lookup_user(launcher_config_nss_cache(launcher->config_state), name, error);
        if (!user) {
                error_prefix(error, "Invalid D-Bus broker user: ");
                return false;
        }
        if (geteuid() != 0 && (geteuid() != nss_user_uid(user) || getegid() != nss_user_gid(user)))
                return error_set(error, EPERM, "Only root can start dbus-broker as configured user %s", name);
        launcher->broker_uid = nss_user_uid(user);
        launcher->broker_gid = nss_user_gid(user);
        launcher->drop_broker_privileges = geteuid() != launcher->broker_uid || getegid() != launcher->broker_gid;
        return true;
}

static U32Vec effective_console_uids(Launcher *launcher)
{
        U32Vec result = {0};
        for (size_t i = 0; i < launcher->static_uids.len; ++i)
                u32_vec_push(&result, launcher->static_uids.items[i]);
        for (size_t i = 0; i < launcher->dynamic_uids.len; ++i)
                u32_vec_push(&result, launcher->dynamic_uids.items[i]);
        u32_vec_sort_unique(&result);
        return result;
}

static void load_static_console_users(Launcher *launcher)
{
        char *copy = str_dup(SYSTEM_CONSOLE_USERS), *cursor = copy, *name;
        while (copy && (name = strsep(&cursor, ","))) {
                struct passwd *entry = getpwnam(name);
                if (!entry)
                        log_warning("Ignoring unknown system-console user '%s'", name);
                else
                        u32_vec_push(&launcher->static_uids, (uint32_t)entry->pw_uid);
        }
        free(copy);
        u32_vec_sort_unique(&launcher->static_uids);
}

static bool make_policy(Launcher *launcher, LauncherConfig *config, DBusWriter *policy, Error **error)
{
        U32Vec uids = effective_console_uids(launcher);
        bool result = launcher_config_export_policy_wire(config, launcher->user, launcher->system_uid_max, uids.items,
                                                         uids.len, policy, error);
        u32_vec_clear(&uids);
        return result;
}

#ifdef HAVE_ELOGIND
static bool refresh_console_users(Launcher *launcher)
{
        uid_t *uids = NULL;
        U32Vec candidate = {0};
        int count = sd_get_uids(&uids);
        if (count < 0) {
                log_error("elogind local-session query failed: %s", strerror(-count));
                return false;
        }
        for (int i = 0; i < count; ++i) {
                char **sessions = NULL;
                int n_sessions = sd_uid_get_sessions(uids[i], 1, &sessions);
                if (n_sessions < 0) {
                        log_error("elogind session query for UID %u failed: %s", (unsigned)uids[i],
                                  strerror(-n_sessions));
                        free(uids);
                        u32_vec_clear(&candidate);
                        return false;
                }
                for (int j = 0; j < n_sessions; ++j) {
                        char *seat = NULL;
                        int remote = sd_session_is_remote(sessions[j]);
                        int seat_result = remote == 0 ? sd_session_get_seat(sessions[j], &seat) : 0;
                        if (remote == 0 && seat_result >= 0 && seat && *seat) {
                                u32_vec_push(&candidate, (uint32_t)uids[i]);
                                free(seat);
                                break;
                        }
                        free(seat);
                }
                for (int j = 0; j < n_sessions; ++j)
                        free(sessions[j]);
                free(sessions);
        }
        free(uids);
        u32_vec_sort_unique(&candidate);
        u32_vec_clear(&launcher->dynamic_uids);
        launcher->dynamic_uids = candidate;
        return true;
}

static bool console_event(EventSource *source, uint32_t events, void *data, Error **error)
{
        Launcher *launcher = data;
        DBusWriter policy = {0};
        Error *local_error = NULL;
        (void)source;
        (void)events;
        sd_login_monitor_flush(launcher->console_monitor);
        if (refresh_console_users(launcher) && make_policy(launcher, launcher->config_state, &policy, &local_error) &&
            controller_set_policy(&launcher->controller, "/org/bus1/DBus/Listener/0",
                                  launcher_config_policy_signature(), &policy, &local_error)) {
                dbus_writer_clear(&policy);
                return true;
        }
        dbus_writer_clear(&policy);
        if (local_error)
                print_error("Cannot update console-sensitive D-Bus policy", local_error);
        (void)error;
        return true;
}

static bool configure_console_monitor(Launcher *launcher, Error **error)
{
        int result, fd;
        if (launcher->user || !launcher_config_uses_console_policy(launcher->config_state))
                return true;
        result = sd_login_monitor_new("session", &launcher->console_monitor);
        if (result < 0)
                return error_set_errno(error, -result, "Cannot create elogind session monitor");
        fd = sd_login_monitor_get_fd(launcher->console_monitor);
        if (fd < 0)
                return error_set_errno(error, -fd, "Cannot access elogind session monitor");
        return event_source_add(&launcher->loop, &launcher->console_source, fd, EPOLLIN, console_event, launcher,
                                error);
}
#else
static bool refresh_console_users(Launcher *launcher)
{
        (void)launcher;
        return true;
}
static bool configure_console_monitor(Launcher *launcher, Error **error)
{
        (void)launcher;
        (void)error;
        return true;
}
#endif

static PtrVec *watch_paths_for_config(LauncherConfig *config)
{
        PtrVec *paths = ptr_vec_new(free);
        PtrVec *config_paths = launcher_config_watch_paths(config);
        PtrVec *service_dirs = launcher_config_service_dirs(config);
        if (!paths)
                return NULL;
        for (size_t i = 0; i < config_paths->len; ++i) {
                char *path = str_dup(config_paths->items[i]);
                if (!path || !ptr_vec_push(paths, path)) {
                        free(path);
                        ptr_vec_free(paths);
                        return NULL;
                }
        }
        for (size_t i = 0; i < service_dirs->len; ++i) {
                const char *directory = service_dirs->items[i];
                if (access(directory, F_OK) == 0 && access(directory, R_OK | X_OK) < 0 &&
                    (errno == EACCES || errno == EPERM))
                        continue;
                char *path = path_canonicalize(directory, NULL);
                if (!path || !ptr_vec_push(paths, path)) {
                        free(path);
                        ptr_vec_free(paths);
                        return NULL;
                }
        }
        return paths;
}

static bool install_watch_sources(Launcher *launcher, Error **error);
static bool reload_config(Launcher *launcher, Error **error);

/* Called from the watch timer, SIGHUP, and the controller's ReloadConfig. All
 * of those run inside packet dispatch, so they only record the request. */
static void request_reload(Launcher *launcher)
{
        launcher->reload_pending = true;
}

static void automatic_reload(void *data)
{
        request_reload(data);
}

static bool set_policy(Launcher *launcher, LauncherConfig *config, Error **error)
{
        DBusWriter policy = {0};
        bool result = make_policy(launcher, config, &policy, error) &&
                      controller_set_policy(&launcher->controller, "/org/bus1/DBus/Listener/0",
                                            launcher_config_policy_signature(), &policy, error);
        dbus_writer_clear(&policy);
        return result;
}

static bool reload_config(Launcher *launcher, Error **error)
{
        LauncherConfig *candidate;
        ServiceTable *candidate_services;
        ServiceTable *current;
        Watch *candidate_watch = NULL;
        PtrVec *paths = NULL;
        PtrVec released, added;
        bool success = false;
        ptr_vec_init(&released, NULL);
        ptr_vec_init(&added, NULL);
        /* Defence in depth: every caller defers to the main loop, so this can
         * only fire if a new reload trigger forgets to. */
        if (launcher->reloading)
                return error_set(error, EBUSY, "A D-Bus configuration reload is already in progress");
        launcher->reloading = true;
        candidate = launcher_config_new();
        candidate_services = service_table_new();
        current = service_manager_table(launcher->service_manager);
        if (!candidate || !candidate_services)
                goto memory;
        if (!launcher_config_load(candidate, launcher->config, error) || !configure_apparmor(candidate, error) ||
            !service_table_scan(launcher_config_service_dirs(candidate), launcher_config_nss_cache(candidate),
                                launcher->user, candidate_services, error))
                goto out;
        if (!str_equal(launcher_config_address(candidate), launcher_config_address(launcher->config_state)) ||
            launcher_config_max_bytes(candidate) != launcher->max_bytes ||
            launcher_config_max_fds(candidate) != launcher->max_fds ||
            launcher_config_max_matches(candidate) != launcher->max_matches ||
            !str_equal(launcher_config_user(candidate), launcher_config_user(launcher->config_state))) {
                error_set(error, ENOTSUP, "Reload cannot change listener, resource limits, or broker user");
                goto out;
        }
        paths = watch_paths_for_config(candidate);
        candidate_watch = watch_new(automatic_reload, launcher, error);
        if (!paths || !candidate_watch || !watch_set_paths(candidate_watch, paths, error))
                goto out;
        for (size_t i = 0; i < candidate_services->len; ++i) {
                Service *previous = str_map_get(current, candidate_services->entries[i].key);
                if (previous && service_equal(previous, candidate_services->entries[i].value)) {
                        Service *ref = service_reference(previous);
                        if (!str_map_set(candidate_services, candidate_services->entries[i].key, ref)) {
                                service_unref(ref);
                                error_set(error, ENOMEM, "Out of memory reusing service reference");
                                goto out;
                        }
                }
        }
        for (size_t i = 0; i < current->len; ++i) {
                Service *replacement = str_map_get(candidate_services, current->entries[i].key);
                if (!replacement || !service_equal(current->entries[i].value, replacement)) {
                        if (!service_release(launcher->service_manager, current->entries[i].value, error))
                                goto rollback;
                        if (!ptr_vec_push(&released, current->entries[i].value)) {
                                error_set(error, ENOMEM, "Out of memory tracking released service");
                                goto rollback;
                        }
                }
        }
        for (size_t i = 0; i < candidate_services->len; ++i) {
                Service *previous = str_map_get(current, candidate_services->entries[i].key);
                if (!previous || !service_equal(previous, candidate_services->entries[i].value)) {
                        if (!service_register(launcher->service_manager, candidate_services->entries[i].value, error))
                                goto rollback;
                        if (!ptr_vec_push(&added, candidate_services->entries[i].value)) {
                                error_set(error, ENOMEM, "Out of memory tracking added service");
                                goto rollback;
                        }
                }
        }
        if (!set_policy(launcher, candidate, error))
                goto rollback;
        launcher_config_free(launcher->config_state);
        launcher->config_state = candidate;
        candidate = NULL;
        launcher->service_dirs = launcher_config_service_dirs(launcher->config_state);
        service_manager_take_table(launcher->service_manager, candidate_services);
        candidate_services = NULL;
        service_manager_set_controller(launcher->service_manager, &launcher->controller, launcher->address,
                                       launcher_config_bus_type(launcher->config_state)
                                               ? launcher_config_bus_type(launcher->config_state)
                                               : (launcher->user ? "session" : "system"));
        event_source_remove(&launcher->watch_source);
        event_source_remove(&launcher->watch_timer_source);
        watch_free(launcher->watch);
        launcher->watch = candidate_watch;
        candidate_watch = NULL;
        /* The new generation is already live at this point, so a watch failure
         * cannot be reported as a failed reload; it would leave callers
         * believing the old configuration was kept. */
        success = true;
        if (!install_watch_sources(launcher, error)) {
                print_error("Reloaded configuration is active but file watching stopped", error ? *error : NULL);
                if (error)
                        *error = NULL;
        }
        goto out;
rollback:
        for (size_t i = added.len; i > 0; --i) {
                Error *ignored = NULL;
                service_release(launcher->service_manager, added.items[i - 1], &ignored);
                error_free(ignored);
        }
        for (size_t i = 0; i < released.len; ++i) {
                Error *ignored = NULL;
                service_register(launcher->service_manager, released.items[i], &ignored);
                error_free(ignored);
        }
        {
                Error *ignored = NULL;
                set_policy(launcher, launcher->config_state, &ignored);
                error_free(ignored);
        }
        goto out;
memory:
        error_set(error, ENOMEM, "Cannot allocate reload state");
out:
        launcher_config_free(candidate);
        service_table_free(candidate_services);
        watch_free(candidate_watch);
        ptr_vec_free(paths);
        ptr_vec_clear(&released);
        ptr_vec_clear(&added);
        launcher->reloading = false;
        return success;
}

static bool controller_packet(Controller *controller, DBusPacket *packet, void *data, Error **error)
{
        Launcher *launcher = data;
        if (!service_manager_handle_packet(launcher->service_manager, packet, error))
                return false;
        if (packet->header.type == DBUS_MESSAGE_METHOD_CALL &&
            str_equal(packet->header.path, "/org/bus1/DBus/Controller") &&
            str_equal(packet->header.interface, "org.bus1.DBus.Controller") &&
            str_equal(packet->header.member, "ReloadConfig")) {
                (void)controller;
                /* Queue the caller's serial; the main loop replies once the
                 * coalesced reload has run. */
                if (!u32_vec_push(&launcher->reload_serials, packet->header.serial))
                        return error_set(error, ENOMEM, "Cannot queue D-Bus reload request");
                request_reload(launcher);
        }
        return true;
}

/* Runs one reload for however many requests accumulated during dispatch, then
 * answers every queued ReloadConfig caller. */
static void run_pending_reload(Launcher *launcher)
{
        Error *reload_error = NULL;
        size_t answered;
        bool reloaded;

        if (!launcher->reload_pending)
                return;
        launcher->reload_pending = false;
        /* Only requests made before this reload started are satisfied by it.
         * Anything queued while it runs sets reload_pending again and is
         * answered by the next pass. */
        answered = launcher->reload_serials.len;
        reloaded = reload_config(launcher, &reload_error);
        if (reloaded)
                log_info("Reloaded D-Bus configuration and services");
        else
                log_error("D-Bus configuration reload failed: %s",
                          reload_error ? reload_error->message : "unknown error");
        for (size_t i = 0; i < answered; ++i) {
                Error *reply_error = NULL;
                uint32_t serial = launcher->reload_serials.items[i];
                bool sent =
                        reloaded
                                ? controller_reply(&launcher->controller, serial, &reply_error)
                                : controller_reply_error(
                                          &launcher->controller, serial, "org.bus1.DBus.Controller.Error.InvalidConfig",
                                          reload_error ? reload_error->message : "Invalid configuration", &reply_error);
                if (!sent)
                        print_error("Cannot answer D-Bus reload request", reply_error);
        }
        /* memmove() rejects a null pointer even for a zero count. */
        if (answered && launcher->reload_serials.len > answered)
                memmove(launcher->reload_serials.items, launcher->reload_serials.items + answered,
                        (launcher->reload_serials.len - answered) * sizeof(*launcher->reload_serials.items));
        launcher->reload_serials.len -= answered;
        error_free(reload_error);
}

static bool bind_listener(Launcher *launcher, Error **error)
{
        struct stat st, parent_stat;
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        char *parent = path_dirname(launcher->socket_path);
        int probe;
        if (!parent)
                return error_set(error, ENOMEM, "Cannot allocate socket parent path");
        if (lstat(parent, &parent_stat) < 0 || !S_ISDIR(parent_stat.st_mode) ||
            (launcher->user && parent_stat.st_uid != geteuid()) || (parent_stat.st_mode & 0022)) {
                error_set(error, EPERM, "D-Bus socket parent must be a non-writable trusted directory: %s", parent);
                free(parent);
                return false;
        }
        free(parent);
        if (strlen(launcher->socket_path) >= sizeof(address.sun_path))
                return error_set(error, ENAMETOOLONG, "Socket path is too long: %s", launcher->socket_path);
        strcpy(address.sun_path, launcher->socket_path);
        if (lstat(launcher->socket_path, &st) == 0) {
                if (!S_ISSOCK(st.st_mode) || st.st_uid != geteuid())
                        return error_set(error, EEXIST, "Refusing to replace non-socket or foreign-owned path %s",
                                         launcher->socket_path);
                probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                if (probe < 0)
                        return error_set_errno(error, errno, "Cannot create stale-socket probe");
                if (connect(probe, (struct sockaddr *)&address, sizeof(address)) == 0) {
                        close(probe);
                        return error_set(error, EADDRINUSE, "A D-Bus listener is already active at %s",
                                         launcher->socket_path);
                }
                int saved = errno;
                close(probe);
                if (saved != ECONNREFUSED && saved != ENOENT)
                        return error_set_errno(error, saved, "Cannot verify stale socket %s", launcher->socket_path);
                if (unlink(launcher->socket_path) < 0 && errno != ENOENT)
                        return error_set_errno(error, errno, "Cannot unlink %s", launcher->socket_path);
        } else if (errno != ENOENT) {
                return error_set_errno(error, errno, "Cannot inspect %s", launcher->socket_path);
        }
        launcher->listener_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (launcher->listener_fd < 0 ||
            bind(launcher->listener_fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
            listen(launcher->listener_fd, SOMAXCONN) < 0)
                return error_set_errno(error, errno, "Cannot bind D-Bus listener %s", launcher->socket_path);
        launcher->listener_bound = true;
        if (!launcher->user && chmod(launcher->socket_path, 0666) < 0)
                return error_set_errno(error, errno, "Cannot chmod %s", launcher->socket_path);
        return true;
}

static bool broker_child_setup(void *data, int *error_number)
{
        BrokerChild *child = data;
        bool keep_audit = false;
        pid_t parent = getppid();
        sigset_t empty;
        /* The dispatcher blocks its event-loop signals and the mask survives
         * execve. Leaving it set would, among other things, make the
         * PR_SET_PDEATHSIG below undeliverable. */
        sigemptyset(&empty);
        if (sigprocmask(SIG_SETMASK, &empty, NULL) < 0)
                goto fail;
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || (child->fd != 3 && dup2(child->fd, 3) < 0) ||
            (child->fd == 3 && fcntl(3, F_SETFD, 0) < 0) || getppid() != parent)
                goto fail;
        if (child->fd != 3)
                close(child->fd);
        if (child->drop_privileges) {
                struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};
                struct __user_cap_data_struct capabilities[_LINUX_CAPABILITY_U32S_3] = {0};
                unsigned index = CAP_AUDIT_WRITE / 32, mask = 1U << (CAP_AUDIT_WRITE % 32);
                if (child->retain_audit) {
                        if (syscall(SYS_capget, &header, capabilities) < 0)
                                goto fail;
                        keep_audit = (capabilities[index].permitted & mask) != 0;
                }
                if ((keep_audit && prctl(PR_SET_KEEPCAPS, 1) < 0) || syscall(SYS_setgroups, 0, NULL) < 0 ||
                    syscall(SYS_setresgid, child->gid, child->gid, child->gid) < 0 ||
                    syscall(SYS_setresuid, child->uid, child->uid, child->uid) < 0)
                        goto fail;
                if (keep_audit) {
                        memset(capabilities, 0, sizeof(capabilities));
                        capabilities[index].effective = capabilities[index].permitted =
                                capabilities[index].inheritable = mask;
                        if (syscall(SYS_capset, &header, capabilities) < 0 ||
                            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_AUDIT_WRITE, 0, 0) < 0)
                                goto fail;
                }
        }
        return true;
fail:
        *error_number = errno ? errno : EPERM;
        return false;
}

static char *read_machine_id(Error **error)
{
        char *id = NULL;
        size_t length;
        if (!read_file("/etc/machine-id", &id, &length, error))
                return NULL;
        while (length && isspace((unsigned char)id[length - 1]))
                id[--length] = 0;
        if (length != 32) {
                free(id);
                error_set(error, EINVAL, "/etc/machine-id must contain a 32-character machine ID");
                return NULL;
        }
        for (size_t i = 0; i < length; ++i)
                if (!isxdigit((unsigned char)id[i])) {
                        free(id);
                        error_set(error, EINVAL, "/etc/machine-id is not hexadecimal");
                        return NULL;
                }
        return id;
}

static bool start_broker(Launcher *launcher, Error **error)
{
        int pair[2];
        char *machine = NULL, *machine_arg = NULL, *bytes = NULL, *fds = NULL, *matches = NULL;
        char *arguments[8];
        BrokerChild child;
        ProcessSpec spec;
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0)
                return error_set_errno(error, errno, "Cannot create controller socketpair");
        /* Only our end becomes non-blocking; the broker inherits pair[1] as-is.
         * Without this the transport's poll timeouts can never fire and any
         * stalled controller exchange would hang the dispatcher forever. */
        if (fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL, 0) | O_NONBLOCK) < 0) {
                int saved = errno;
                close(pair[0]);
                close(pair[1]);
                return error_set_errno(error, saved, "Cannot configure controller socket");
        }
        machine = read_machine_id(error);
        if (!machine)
                goto fail;
        machine_arg = str_printf("--machine-id=%s", machine);
        bytes = str_printf("--max-bytes=%" PRIu64, launcher->max_bytes);
        fds = str_printf("--max-fds=%" PRIu64, launcher->max_fds);
        matches = str_printf("--max-matches=%" PRIu64, launcher->max_matches);
        if (!machine_arg || !bytes || !fds || !matches) {
                error_set(error, ENOMEM, "Cannot allocate broker arguments");
                goto fail;
        }
        arguments[0] = launcher->broker;
        arguments[1] = "--controller=3";
        arguments[2] = machine_arg;
        arguments[3] = bytes;
        arguments[4] = fds;
        arguments[5] = matches;
        arguments[6] = launcher->audit ? "--audit" : NULL;
        arguments[7] = NULL;
        child = (BrokerChild){.fd = pair[1],
                              .uid = launcher->broker_uid,
                              .gid = launcher->broker_gid,
                              .drop_privileges = launcher->drop_broker_privileges,
                              .retain_audit = launcher->audit};
        spec = (ProcessSpec){.argv = arguments, .child_setup = broker_child_setup, .child_setup_data = &child};
        if (!process_spawn(&spec, &launcher->broker_pid, error))
                goto fail;
        close(pair[1]);
        controller_init(&launcher->controller, pair[0], controller_packet, launcher);
        if (!controller_authenticate(&launcher->controller, geteuid(), error)) {
                kill(launcher->broker_pid, SIGTERM);
                while (waitpid(launcher->broker_pid, NULL, 0) < 0 && errno == EINTR)
                        ;
                launcher->broker_pid = 0;
                controller_clear(&launcher->controller);
                goto fail_controller;
        }
        free(machine);
        free(machine_arg);
        free(bytes);
        free(fds);
        free(matches);
        return true;
fail:
        close(pair[0]);
        close(pair[1]);
fail_controller:
        free(machine);
        free(machine_arg);
        free(bytes);
        free(fds);
        free(matches);
        return false;
}

static bool add_listener(Launcher *launcher, Error **error)
{
        DBusWriter policy = {0};
        bool result = make_policy(launcher, launcher->config_state, &policy, error) &&
                      controller_add_listener(&launcher->controller, "/org/bus1/DBus/Listener/0", launcher->listener_fd,
                                              launcher_config_policy_signature(), &policy, error);
        dbus_writer_clear(&policy);
        return result;
}

static bool write_pid_file(Launcher *launcher, Error **error)
{
        const char *path = launcher->pid_file;
        char contents[64];
        int fd, length;
        struct stat st;
        if (!path)
                return true;
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
        if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid()) {
                int saved = fd < 0 ? errno : EINVAL;
                if (fd >= 0)
                        close(fd);
                return error_set_errno(error, saved, "Cannot securely write PID file %s", path);
        }
        length = snprintf(contents, sizeof(contents), "%ld\n", (long)getpid());
        size_t offset = 0;
        while (offset < (size_t)length) {
                ssize_t n = write(fd, contents + offset, (size_t)length - offset);
                if (n > 0)
                        offset += (size_t)n;
                else if (n < 0 && errno == EINTR)
                        continue;
                else {
                        int saved = n < 0 ? errno : EIO;
                        close(fd);
                        return error_set_errno(error, saved, "Cannot write %s", path);
                }
        }
        if (close(fd) < 0)
                return error_set_errno(error, errno, "Cannot close %s", path);
        launcher->pid_file_written = true;
        return true;
}

static bool daemonize_launcher(Launcher *launcher, Error **error)
{
        int pair[2], null_fd;
        pid_t child;
        char status;
        ssize_t n;
        if (!launcher->daemonize)
                return true;
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0)
                return error_set_errno(error, errno, "Cannot create startup socketpair");
        child = fork();
        if (child < 0) {
                int saved = errno;
                close(pair[0]);
                close(pair[1]);
                return error_set_errno(error, saved, "Cannot daemonize");
        }
        if (child > 0) {
                close(pair[1]);
                do
                        n = read(pair[0], &status, 1);
                while (n < 0 && errno == EINTR);
                close(pair[0]);
                _exit(n == 1 && status == 'R' ? 0 : 1);
        }
        close(pair[0]);
        launcher->startup_fd = pair[1];
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (setsid() < 0 || chdir("/") < 0 || null_fd < 0 || dup2(null_fd, 0) < 0 || dup2(null_fd, 1) < 0 ||
            dup2(null_fd, 2) < 0)
                return error_set_errno(error, errno, "Cannot configure daemon process");
        if (null_fd > 2)
                close(null_fd);
        /* stderr is /dev/null from here on, so diagnostics must go to syslog. */
        log_use_syslog("dbus-broker-dispatch");
        return true;
}

static void notify_startup(Launcher *launcher, bool ready)
{
        char status = ready ? 'R' : 'F';
        if (launcher->startup_fd < 0)
                return;
        while (send(launcher->startup_fd, &status, 1, MSG_NOSIGNAL) < 0 && errno == EINTR)
                ;
        close(launcher->startup_fd);
        launcher->startup_fd = -1;
}

static bool controller_event(EventSource *source, uint32_t events, void *data, Error **error)
{
        (void)source;
        if (events & (EPOLLERR | EPOLLHUP))
                return error_set(error, ECONNRESET, "D-Bus controller disconnected");
        return controller_dispatch(&((Launcher *)data)->controller, error);
}

/* File watching is an optimisation, not a correctness requirement: losing it
 * must never terminate a running bus. Failures are logged and a reload is
 * requested so the current state is at least re-read once. */
static bool watch_event(EventSource *source, uint32_t events, void *data, Error **error)
{
        Launcher *launcher = data;
        Error *watch_error = NULL;
        (void)source;
        (void)events;
        (void)error;
        if (!watch_dispatch_inotify(launcher->watch, &watch_error)) {
                print_error("D-Bus configuration watch failed; continuing without it", watch_error);
                request_reload(launcher);
        }
        return true;
}

static bool watch_timer_event(EventSource *source, uint32_t events, void *data, Error **error)
{
        Launcher *launcher = data;
        Error *watch_error = NULL;
        (void)source;
        (void)events;
        (void)error;
        if (!watch_dispatch_timer(launcher->watch, &watch_error))
                print_error("D-Bus configuration watch timer failed", watch_error);
        return true;
}

static bool install_watch_sources(Launcher *launcher, Error **error)
{
        return event_source_add(&launcher->loop, &launcher->watch_source, watch_inotify_fd(launcher->watch), EPOLLIN,
                                watch_event, launcher, error) &&
               event_source_add(&launcher->loop, &launcher->watch_timer_source, watch_timer_fd(launcher->watch),
                                EPOLLIN, watch_timer_event, launcher, error);
}

static bool signal_event(EventSource *source, uint32_t events, void *data, Error **error)
{
        Launcher *launcher = data;
        struct signalfd_siginfo info;
        (void)source;
        (void)events;
        for (;;) {
                ssize_t n = read(launcher->signal_fd, &info, sizeof(info));
                if (n == (ssize_t)sizeof(info)) {
                        if (info.ssi_signo == SIGTERM || info.ssi_signo == SIGINT)
                                event_loop_quit(&launcher->loop);
                        else if (info.ssi_signo == SIGHUP) {
                                request_reload(launcher);
                        } else if (info.ssi_signo == SIGCHLD) {
                                for (;;) {
                                        int status;
                                        pid_t pid = waitpid(-1, &status, WNOHANG);
                                        if (pid <= 0)
                                                break;
                                        if (pid == launcher->broker_pid) {
                                                if (WIFSIGNALED(status))
                                                        log_error("dbus-broker was killed by signal %d",
                                                                  WTERMSIG(status));
                                                else if (WIFEXITED(status) && WEXITSTATUS(status))
                                                        log_error("dbus-broker exited with status %d",
                                                                  WEXITSTATUS(status));
                                                else
                                                        log_error("dbus-broker exited unexpectedly");
                                                launcher->broker_pid = 0;
                                                launcher->broker_failed = true;
                                                event_loop_quit(&launcher->loop);
                                        } else {
                                                service_manager_reap(launcher->service_manager, pid, status);
                                        }
                                }
                        }
                        continue;
                }
                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                        return true;
                return error_set_errno(error, n < 0 ? errno : EIO, "Cannot read signal events");
        }
}

static char *find_program(const char *name)
{
        const char *path = getenv("PATH");
        char *copy = str_dup(path ? path : "/usr/local/bin:/usr/bin:/bin"), *cursor = copy, *directory;
        while (copy && (directory = strsep(&cursor, ":"))) {
                char *candidate = path_join(*directory ? directory : ".", name);
                if (candidate && access(candidate, X_OK) == 0) {
                        free(copy);
                        return candidate;
                }
                free(candidate);
        }
        free(copy);
        return NULL;
}

static void usage(void)
{
        puts("Usage: dbus-broker-dispatch --scope=system|user [OPTIONS]\n"
             "\n"
             "Run dbus-broker without systemd.\n"
             "\n"
             "Options:\n"
             "  --scope=system|user   Bus scope. This option is required.\n"
             "  --config-file=PATH    D-Bus XML configuration file.\n"
             "  --address=ADDRESS     Public address. Only unix:path= is accepted.\n"
             "  --broker=PATH         dbus-broker executable.\n"
             "  --pid-file=PATH       Write the dispatcher PID to PATH.\n"
             "  --system-uid-max=N    Highest UID treated as a system user.\n"
             "  --audit               Pass audit capability to dbus-broker.\n"
             "  --foreground          Stay in the foreground.\n"
             "  --help                Show this help text.\n"
             "  --version             Show the version.");
}

static void launcher_clear(Launcher *launcher)
{
#ifdef HAVE_ELOGIND
        event_source_remove(&launcher->console_source);
        if (launcher->console_monitor)
                sd_login_monitor_unref(launcher->console_monitor);
#endif
        event_source_remove(&launcher->controller_source);
        event_source_remove(&launcher->signal_source);
        event_source_remove(&launcher->watch_source);
        event_source_remove(&launcher->watch_timer_source);
        watch_free(launcher->watch);
        controller_clear(&launcher->controller);
        if (launcher->signal_fd >= 0)
                close(launcher->signal_fd);
        if (launcher->listener_fd >= 0)
                close(launcher->listener_fd);
        if (launcher->broker_pid) {
                kill(launcher->broker_pid, SIGTERM);
                while (waitpid(launcher->broker_pid, NULL, 0) < 0 && errno == EINTR)
                        ;
        }
        if (launcher->listener_bound && launcher->socket_path)
                unlink(launcher->socket_path);
        if (launcher->pid_file_written && launcher->pid_file)
                unlink(launcher->pid_file);
        service_manager_free(launcher->service_manager);
        launcher_config_free(launcher->config_state);
        u32_vec_clear(&launcher->static_uids);
        u32_vec_clear(&launcher->dynamic_uids);
        u32_vec_clear(&launcher->reload_serials);
        event_loop_clear(&launcher->loop);
        free(launcher->config);
        free(launcher->address);
        free(launcher->broker);
        free(launcher->socket_path);
        free(launcher->pid_file);
}

int main(int argc, char **argv)
{
        Launcher launcher = {.startup_fd = -1,
                             .listener_fd = -1,
                             .signal_fd = -1,
                             .controller.transport.fd = -1,
                             .loop.epoll_fd = -1};
        Error *error = NULL;
        bool scope_set = false, broker_explicit = false;
        uint64_t parsed;
        int option;
        const char *runtime, *configured_address;
        static const struct option options[] = {
                {"scope", required_argument, NULL, 's'},
                {"config-file", required_argument, NULL, 'c'},
                {"address", required_argument, NULL, 'a'},
                {"broker", required_argument, NULL, 'b'},
                {"pid-file", required_argument, NULL, 'p'},
                {"system-uid-max", required_argument, NULL, 'm'},
                {"audit", no_argument, NULL, 'A'},
                {"foreground", no_argument, NULL, 'f'},
                {"help", no_argument, NULL, 'h'},
                {"version", no_argument, NULL, 'V'},
                {NULL, 0, NULL, 0},
        };
        launcher.system_uid_max = 999;
        launcher.daemonize = true;
        while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
                switch (option) {
                case 's':
                        scope_set = true;
                        if (!strcmp(optarg, "user"))
                                launcher.user = true;
                        else if (strcmp(optarg, "system")) {
                                usage();
                                return 2;
                        }
                        break;
                case 'c':
                        launcher.config = str_dup(optarg);
                        break;
                case 'a':
                        launcher.address = str_dup(optarg);
                        break;
                case 'b':
                        launcher.broker = str_dup(optarg);
                        broker_explicit = true;
                        break;
                case 'p':
                        launcher.pid_file = str_dup(optarg);
                        break;
                case 'm':
                        if (!parse_u64(optarg, UINT32_MAX, &parsed)) {
                                fputs("Invalid --system-uid-max\n", stderr);
                                return 2;
                        }
                        launcher.system_uid_max = (uint32_t)parsed;
                        break;
                case 'A':
                        launcher.audit = true;
                        break;
                case 'f':
                        launcher.daemonize = false;
                        break;
                case 'V':
                        printf("dbus-broker-dispatch %s\n", PROJECT_VERSION);
                        return 0;
                default:
                        usage();
                        return option == 'h' ? 0 : 2;
                }
        }
        if (!scope_set || optind != argc) {
                usage();
                return 2;
        }
        launcher.service_manager = service_manager_new();
        if (!launcher.service_manager) {
                fputs("Cannot allocate dispatcher state\n", stderr);
                goto fail;
        }
        launcher.broker = launcher.broker ? launcher.broker : str_dup(DEFAULT_BROKER);
        if (!launcher.broker || access(launcher.broker, X_OK) < 0) {
                if (broker_explicit) {
                        fprintf(stderr, "Configured dbus-broker is not executable: %s\n", launcher.broker);
                        goto fail;
                }
                free(launcher.broker);
                launcher.broker = find_program("dbus-broker");
        }
        if (!launcher.broker) {
                fputs("dbus-broker not found; use --broker=PATH\n", stderr);
                goto fail;
        }
        if (launcher.user) {
                struct stat st;
                runtime = getenv("XDG_RUNTIME_DIR");
                if (!runtime || lstat(runtime, &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
                    (st.st_mode & 0077)) {
                        fputs("XDG_RUNTIME_DIR is required for --scope=user\n", stderr);
                        goto fail;
                }
                launcher.socket_path = path_join(runtime, "bus");
        } else
                launcher.socket_path = str_dup("/run/dbus/system_bus_socket");
        launcher.config = launcher.config ? launcher.config
                                          : str_dup(launcher.user ? "/usr/share/dbus-1/session.conf"
                                                                  : "/usr/share/dbus-1/system.conf");
        launcher.config_state = launcher_config_new();
        if (!launcher.config_state || !launcher_config_load(launcher.config_state, launcher.config, &error) ||
            !configure_apparmor(launcher.config_state, &error) || !configure_broker_user(&launcher, &error)) {
                print_error("Invalid D-Bus configuration", error);
                goto fail;
        }
        launcher.max_bytes = launcher_config_max_bytes(launcher.config_state);
        launcher.max_fds = launcher_config_max_fds(launcher.config_state);
        launcher.max_matches = launcher_config_max_matches(launcher.config_state);
        launcher.service_dirs = launcher_config_service_dirs(launcher.config_state);
        configured_address = launcher_config_address(launcher.config_state);
        if (!launcher.address && configured_address)
                launcher.address = str_dup(configured_address);
        if (!launcher.address) {
                char *escaped = percent_escape(launcher.socket_path);
                launcher.address = escaped ? str_printf("unix:path=%s", escaped) : NULL;
                free(escaped);
                if (!launcher.address) {
                        fputs("Cannot build the D-Bus listener address\n", stderr);
                        goto fail;
                }
        }
        free(launcher.socket_path);
        launcher.socket_path = socket_path_from_address(launcher.address, &error);
        if (!launcher.socket_path) {
                print_error("Invalid D-Bus address", error);
                goto fail;
        }
        if (!launcher.user) {
                load_static_console_users(&launcher);
                if (launcher_config_uses_console_policy(launcher.config_state))
                        refresh_console_users(&launcher);
        }
        if (!service_table_scan(launcher.service_dirs, launcher_config_nss_cache(launcher.config_state), launcher.user,
                                service_manager_table(launcher.service_manager), &error) ||
            !daemonize_launcher(&launcher, &error) || !event_loop_init(&launcher.loop, &error)) {
                notify_startup(&launcher, false);
                print_error("Cannot start dispatcher", error);
                goto fail;
        }
        PtrVec *paths = watch_paths_for_config(launcher.config_state);
        launcher.watch = watch_new(automatic_reload, &launcher, &error);
        int signals[] = {SIGHUP, SIGTERM, SIGINT, SIGCHLD};
        launcher.signal_fd = event_signal_fd(signals, 4, NULL, &error);
        if (!paths || !launcher.watch || !watch_set_paths(launcher.watch, paths, &error) || launcher.signal_fd < 0 ||
            !install_watch_sources(&launcher, &error) ||
            !event_source_add(&launcher.loop, &launcher.signal_source, launcher.signal_fd, EPOLLIN, signal_event,
                              &launcher, &error) ||
            !bind_listener(&launcher, &error) || !start_broker(&launcher, &error)) {
                ptr_vec_free(paths);
                notify_startup(&launcher, false);
                print_error("Cannot start dispatcher", error);
                goto fail;
        }
        ptr_vec_free(paths);
        service_manager_set_controller(launcher.service_manager, &launcher.controller, launcher.address,
                                       launcher_config_bus_type(launcher.config_state)
                                               ? launcher_config_bus_type(launcher.config_state)
                                               : (launcher.user ? "session" : "system"));
        if (!service_table_register_all(launcher.service_manager, service_manager_table(launcher.service_manager),
                                        &error) ||
            !add_listener(&launcher, &error) || !configure_console_monitor(&launcher, &error) ||
            !event_source_add(&launcher.loop, &launcher.controller_source, controller_fd(&launcher.controller), EPOLLIN,
                              controller_event, &launcher, &error) ||
            !write_pid_file(&launcher, &error)) {
                notify_startup(&launcher, false);
                print_error("Cannot initialize dispatcher", error);
                goto fail;
        }
        notify_startup(&launcher, true);
        /* Not event_loop_run(): reloads must happen between dispatches, never
         * inside one. */
        launcher.loop.running = true;
        while (launcher.loop.running) {
                /* Controller calls made by reloads or other callbacks can
                 * leave complete packets buffered without a readable fd. */
                if (!controller_dispatch(&launcher.controller, &error)) {
                        print_error("Dispatcher controller failed", error);
                        launcher.broker_failed = true;
                        break;
                }
                service_manager_dispatch_timeouts(launcher.service_manager);
                int manager_timeout = service_manager_timeout_ms(launcher.service_manager);
                int timeout = launcher.reload_pending || launcher.controller.dispatch_pending ? 0 : manager_timeout;
                if (!event_loop_dispatch(&launcher.loop, timeout, &error)) {
                        print_error("Dispatcher event loop failed", error);
                        launcher.broker_failed = true;
                        break;
                }
                service_manager_dispatch_timeouts(launcher.service_manager);
                run_pending_reload(&launcher);
        }
        bool failed = launcher.broker_failed;
        launcher_clear(&launcher);
        return failed ? 1 : 0;
fail:
        launcher_clear(&launcher);
        return 1;
}
