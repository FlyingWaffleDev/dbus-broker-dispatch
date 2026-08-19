#define _GNU_SOURCE
#include "config-policy.h"
#include "config.h"
#include "controller.h"
#include "event.h"
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
        int startup_fd, listener_fd, signal_fd;
        char *config, *address, *broker, *socket_path, *pid_file;
        uint32_t system_uid_max;
        uint64_t max_bytes, max_fds, max_matches;
        uid_t broker_uid;
        gid_t broker_gid;
        bool drop_broker_privileges;
        pid_t broker_pid;
        EventLoop loop;
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
        fprintf(stderr, "%s: %s\n", what, error ? error->message : "unknown error");
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
                fputs("Disabling D-Bus AppArmor policy because kernel D-Bus mediation is unavailable\n", stderr);
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
                        fprintf(stderr, "Ignoring unknown system-console user '%s'\n", name);
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
                fprintf(stderr, "elogind local-session query failed: %s\n", strerror(-count));
                return false;
        }
        for (int i = 0; i < count; ++i) {
                char **sessions = NULL;
                int n_sessions = sd_uid_get_sessions(uids[i], 1, &sessions);
                if (n_sessions < 0) {
                        fprintf(stderr, "elogind session query for UID %u failed: %s\n", (unsigned)uids[i],
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

static void automatic_reload(void *data)
{
        Launcher *launcher = data;
        Error *error = NULL;
        if (!reload_config(launcher, &error))
                print_error("Automatic D-Bus configuration reload failed", error);
        else
                fputs("Automatically reloaded D-Bus configuration and services\n", stderr);
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
        LauncherConfig *candidate = launcher_config_new();
        ServiceTable *candidate_services = service_table_new();
        ServiceTable *current = service_manager_table(launcher->service_manager);
        Watch *candidate_watch = NULL;
        PtrVec *paths = NULL;
        PtrVec released, added;
        bool success = false;
        ptr_vec_init(&released, NULL);
        ptr_vec_init(&added, NULL);
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
                if (previous && service_equal(previous, candidate_services->entries[i].value))
                        str_map_set(candidate_services, candidate_services->entries[i].key,
                                    service_reference(previous));
        }
        for (size_t i = 0; i < current->len; ++i) {
                Service *replacement = str_map_get(candidate_services, current->entries[i].key);
                if ((!replacement || !service_equal(current->entries[i].value, replacement)) &&
                    !service_release(launcher->service_manager, current->entries[i].value, error))
                        goto rollback;
                if (!replacement || !service_equal(current->entries[i].value, replacement))
                        ptr_vec_push(&released, current->entries[i].value);
        }
        for (size_t i = 0; i < candidate_services->len; ++i) {
                Service *previous = str_map_get(current, candidate_services->entries[i].key);
                if ((!previous || !service_equal(previous, candidate_services->entries[i].value)) &&
                    !service_register(launcher->service_manager, candidate_services->entries[i].value, error))
                        goto rollback;
                if (!previous || !service_equal(previous, candidate_services->entries[i].value))
                        ptr_vec_push(&added, candidate_services->entries[i].value);
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
        if (!install_watch_sources(launcher, error))
                goto out;
        success = true;
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
                Error *reload_error = NULL;
                if (!reload_config(launcher, &reload_error)) {
                        bool result = controller_reply_error(
                                controller, packet->header.serial, "org.bus1.DBus.Controller.Error.InvalidConfig",
                                reload_error ? reload_error->message : "Invalid configuration", error);
                        error_free(reload_error);
                        return result;
                }
                return controller_reply(controller, packet->header.serial, error);
        }
        return true;
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
        if (!launcher->user && chmod(launcher->socket_path, 0666) < 0)
                return error_set_errno(error, errno, "Cannot chmod %s", launcher->socket_path);
        return true;
}

static bool broker_child_setup(void *data, int *error_number)
{
        BrokerChild *child = data;
        bool keep_audit = false;
        pid_t parent = getppid();
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

static bool write_pid_file(const char *path, Error **error)
{
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
        return true;
}

static bool daemonize_launcher(Launcher *launcher, Error **error)
{
        int pair[2], null_fd;
        pid_t child;
        char status;
        ssize_t n;
        if (!launcher->daemonize)
                return write_pid_file(launcher->pid_file, error);
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
        return write_pid_file(launcher->pid_file, error);
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

static bool watch_event(EventSource *source, uint32_t events, void *data, Error **error)
{
        (void)source;
        (void)events;
        return watch_dispatch_inotify(((Launcher *)data)->watch, error);
}

static bool watch_timer_event(EventSource *source, uint32_t events, void *data, Error **error)
{
        (void)source;
        (void)events;
        return watch_dispatch_timer(((Launcher *)data)->watch, error);
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
                                Error *reload_error = NULL;
                                if (!reload_config(launcher, &reload_error))
                                        print_error("Reload failed", reload_error);
                        } else if (info.ssi_signo == SIGCHLD) {
                                for (;;) {
                                        int status;
                                        pid_t pid = waitpid(-1, &status, WNOHANG);
                                        if (pid <= 0)
                                                break;
                                        if (pid == launcher->broker_pid) {
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

static char *percent_escape(const char *value)
{
        static const char hex[] = "0123456789ABCDEF";
        StrBuf out = {0};
        for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
                if (isalnum(*p) || strchr("_-./", *p))
                        str_buf_append_n(&out, (const char *)p, 1);
                else {
                        char escaped[] = {'%', hex[*p >> 4], hex[*p & 15]};
                        str_buf_append_n(&out, escaped, sizeof(escaped));
                }
        }
        return str_buf_steal(&out);
}

static int hex_value(char value)
{
        if (value >= '0' && value <= '9')
                return value - '0';
        if (value >= 'a' && value <= 'f')
                return value - 'a' + 10;
        if (value >= 'A' && value <= 'F')
                return value - 'A' + 10;
        return -1;
}

static char *socket_path_from_address(const char *address, Error **error)
{
        const char *encoded;
        StrBuf path = {0};
        if (!str_has_prefix(address, "unix:path=")) {
                error_set(error, ENOTSUP, "Only filesystem-backed unix:path= D-Bus addresses are supported");
                return NULL;
        }
        encoded = address + strlen("unix:path=");
        if (!*encoded || strpbrk(encoded, ",;")) {
                error_set(error, EINVAL, "Invalid D-Bus listener address: %s", address);
                return NULL;
        }
        for (const char *p = encoded; *p; ++p) {
                char byte = *p;
                if (*p == '%') {
                        int high = hex_value(p[1]), low = hex_value(p[2]);
                        if (high < 0 || low < 0)
                                goto invalid;
                        byte = (char)((high << 4) | low);
                        p += 2;
                        if (!byte)
                                goto invalid;
                }
                if (!str_buf_append_n(&path, &byte, 1))
                        goto invalid;
        }
        if (!path.data || !path_is_absolute(path.data))
                goto invalid;
        return str_buf_steal(&path);
invalid:
        str_buf_clear(&path);
        error_set(error, EINVAL, "The unix:path= listener must contain an absolute, valid escaped path");
        return NULL;
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
        if (launcher->socket_path)
                unlink(launcher->socket_path);
        if (launcher->pid_file)
                unlink(launcher->pid_file);
        service_manager_free(launcher->service_manager);
        launcher_config_free(launcher->config_state);
        u32_vec_clear(&launcher->static_uids);
        u32_vec_clear(&launcher->dynamic_uids);
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
        launcher.broker = launcher.broker ? launcher.broker : str_dup(DEFAULT_BROKER);
        if (!launcher.broker || access(launcher.broker, X_OK) < 0) {
                if (broker_explicit) {
                        fprintf(stderr, "Configured dbus-broker is not executable: %s\n", launcher.broker);
                        return 1;
                }
                free(launcher.broker);
                launcher.broker = find_program("dbus-broker");
        }
        if (!launcher.broker) {
                fputs("dbus-broker not found; use --broker=PATH\n", stderr);
                return 1;
        }
        if (launcher.user) {
                struct stat st;
                runtime = getenv("XDG_RUNTIME_DIR");
                if (!runtime || lstat(runtime, &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
                    (st.st_mode & 0077)) {
                        fputs("XDG_RUNTIME_DIR is required for --scope=user\n", stderr);
                        return 1;
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
                return 1;
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
                launcher.address = str_printf("unix:path=%s", escaped);
                free(escaped);
        }
        free(launcher.socket_path);
        launcher.socket_path = socket_path_from_address(launcher.address, &error);
        if (!launcher.socket_path) {
                print_error("Invalid D-Bus address", error);
                return 1;
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
                return 1;
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
                launcher_clear(&launcher);
                return 1;
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
                              controller_event, &launcher, &error)) {
                notify_startup(&launcher, false);
                print_error("Cannot initialize dispatcher", error);
                launcher_clear(&launcher);
                return 1;
        }
        notify_startup(&launcher, true);
        if (!event_loop_run(&launcher.loop, &error)) {
                print_error("Dispatcher event loop failed", error);
                launcher.broker_failed = true;
        }
        bool failed = launcher.broker_failed;
        launcher_clear(&launcher);
        return failed ? 1 : 0;
}
