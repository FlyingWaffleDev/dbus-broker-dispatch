#define _GNU_SOURCE
#include "pam-dbus-broker-dispatch.h"
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define STATE_NAME ".dbus-broker-dispatch.pam"
#define PID_NAME "dbus-broker-dispatch.pid"
#define PAM_DATA_KEY "dbus-broker-dispatch/session"
/* A login waiting on another login's bus start must outlast that start. */
#define STARTUP_TIMEOUT_MS 25000
#define LOCK_TIMEOUT_MS 30000

#ifdef SYS_setgroups32
#define SYSCALL_SETGROUPS SYS_setgroups32
#else
#define SYSCALL_SETGROUPS SYS_setgroups
#endif
#ifdef SYS_setresgid32
#define SYSCALL_SETRESGID SYS_setresgid32
#else
#define SYSCALL_SETRESGID SYS_setresgid
#endif
#ifdef SYS_setresuid32
#define SYSCALL_SETRESUID SYS_setresuid32
#else
#define SYSCALL_SETRESUID SYS_setresuid
#endif

typedef struct {
        char *runtime;
        uid_t uid;
        gid_t gid;
        pid_t pid;
        unsigned long long start_time;
} SessionData;

typedef struct {
        pid_t pid;
        unsigned long long start_time;
        unsigned count;
} State;

typedef struct {
        const char *dispatcher;
        const char *config;
        bool debug;
} Options;

static uint64_t now_monotonic_ms(void)
{
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void free_session_data(pam_handle_t *pamh, void *data, int error_status)
{
        SessionData *session = data;
        (void)pamh;
        (void)error_status;
        if (session) {
                free(session->runtime);
                free(session);
        }
}

static bool join_path(char *out, size_t size, const char *directory, const char *name)
{
        int length = snprintf(out, size, "%s/%s", directory, name);
        return length >= 0 && (size_t)length < size;
}

static bool safe_runtime_dir(const char *path, uid_t uid, int *directory_fd)
{
        struct stat st;
        int fd;

        if (!path || path[0] != '/' || strlen(path) >= PATH_MAX)
                return false;
        fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
                return false;
        if (fstat(fd, &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != uid || (st.st_mode & 0777) != 0700) {
                close(fd);
                return false;
        }
        *directory_fd = fd;
        return true;
}

static int open_user_file(int directory_fd, const char *name, uid_t uid, gid_t gid, bool create)
{
        struct stat st;
        int fd;

        if (create) {
                fd = openat(directory_fd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
                if (fd >= 0) {
                        if (fchown(fd, uid, gid) < 0 || fchmod(fd, 0600) < 0) {
                                int saved_errno = errno;
                                close(fd);
                                unlinkat(directory_fd, name, 0);
                                errno = saved_errno;
                                return -1;
                        }
                } else if (errno == EEXIST) {
                        fd = openat(directory_fd, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
                }
        } else {
                fd = openat(directory_fd, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        }
        if (fd < 0)
                return -1;
        if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != uid ||
            (st.st_mode & 0777) != 0600) {
                close(fd);
                errno = EINVAL;
                return -1;
        }
        return fd;
}

static bool socket_is_live(int directory_fd, uid_t uid)
{
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        struct stat st;
        int path_fd, fd;
        bool live = false;

        path_fd = openat(directory_fd, "bus", O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (path_fd < 0)
                return false;
        if (fstat(path_fd, &st) < 0 || !S_ISSOCK(st.st_mode) || st.st_uid != uid) {
                close(path_fd);
                return false;
        }
        if (snprintf(address.sun_path, sizeof(address.sun_path), "/proc/self/fd/%d", path_fd) >=
            (int)sizeof(address.sun_path)) {
                close(path_fd);
                return false;
        }
        /* Non-blocking, so a listener that never accepts cannot hang the
         * login. A full backlog still means something is listening. */
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd >= 0) {
                live = connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0 || errno == EAGAIN;
                close(fd);
        }
        close(path_fd);
        return live;
}

/* Waits for the per-user startup lock, but not forever: a stuck holder must
 * not block every later login of that user. */
static bool lock_runtime_dir(int directory_fd)
{
        uint64_t deadline = now_monotonic_ms() + LOCK_TIMEOUT_MS;
        while (flock(directory_fd, LOCK_EX | LOCK_NB) < 0) {
                if (errno != EWOULDBLOCK && errno != EINTR)
                        return false;
                uint64_t now = now_monotonic_ms();
                if (now >= deadline) {
                        errno = ETIMEDOUT;
                        return false;
                }
                int slice = deadline - now > 50 ? 50 : (int)(deadline - now);
                poll(NULL, 0, slice);
        }
        return true;
}

static bool process_start_time(pid_t pid, uid_t uid, unsigned long long *start_time)
{
        char path[64], buffer[4096], *right, *field, *save = NULL;
        struct stat st;
        ssize_t length;
        int fd;

        if (pid <= 1 || snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) >= (int)sizeof(path))
                return false;
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
                return false;
        if (fstat(fd, &st) < 0 || st.st_uid != uid) {
                close(fd);
                return false;
        }
        length = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);
        if (length <= 0)
                return false;
        buffer[length] = '\0';
        right = strrchr(buffer, ')');
        if (!right || right[1] != ' ')
                return false;
        field = strtok_r(right + 2, " ", &save);
        /* The text after comm starts at field 3; starttime is field 22. */
        for (unsigned number = 3; field && number < 22; ++number)
                field = strtok_r(NULL, " ", &save);
        if (!field)
                return false;
        errno = 0;
        char *end = NULL;
        unsigned long long parsed = strtoull(field, &end, 10);
        if (errno || end == field || (*end && *end != '\n'))
                return false;
        *start_time = parsed;
        return true;
}

static bool read_pid_file(int directory_fd, uid_t uid, pid_t *pid)
{
        char buffer[64], *end = NULL;
        struct stat st;
        ssize_t length;
        long parsed;
        int fd = openat(directory_fd, PID_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);

        if (fd < 0)
                return false;
        if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != uid || st.st_nlink != 1) {
                close(fd);
                return false;
        }
        length = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);
        if (length <= 0)
                return false;
        buffer[length] = '\0';
        errno = 0;
        parsed = strtol(buffer, &end, 10);
        if (errno || end == buffer || (*end && *end != '\n') || parsed <= 1 || parsed > INT_MAX)
                return false;
        *pid = (pid_t)parsed;
        return true;
}

static bool read_state(int directory_fd, uid_t uid, State *state)
{
        char buffer[128], *cursor, *end;
        ssize_t length;
        long parsed_pid;
        unsigned long parsed_count;
        int fd = open_user_file(directory_fd, STATE_NAME, uid, (gid_t)-1, false);

        if (fd < 0)
                return false;
        length = pread(fd, buffer, sizeof(buffer) - 1, 0);
        close(fd);
        if (length <= 0)
                return false;
        buffer[length] = '\0';
        cursor = buffer;
        errno = 0;
        parsed_pid = strtol(cursor, &end, 10);
        if (errno || end == cursor || *end != ' ' || parsed_pid <= 1 || parsed_pid > INT_MAX)
                return false;
        cursor = end + 1;
        errno = 0;
        state->start_time = strtoull(cursor, &end, 10);
        if (errno || end == cursor || *end != ' ' || state->start_time == 0)
                return false;
        cursor = end + 1;
        errno = 0;
        parsed_count = strtoul(cursor, &end, 10);
        while (*end == '\n' || *end == '\r')
                ++end;
        if (errno || end == cursor || *end || parsed_count == 0 || parsed_count > UINT_MAX)
                return false;
        state->pid = (pid_t)parsed_pid;
        state->count = (unsigned)parsed_count;
        return true;
}

static bool write_state(int directory_fd, uid_t uid, gid_t gid, const State *state)
{
        char buffer[128];
        int length, fd = open_user_file(directory_fd, STATE_NAME, uid, gid, true);
        bool success = false;

        if (fd < 0)
                return false;
        length = snprintf(buffer, sizeof(buffer), "%ld %llu %u\n", (long)state->pid, state->start_time, state->count);
        if (length > 0 && (size_t)length < sizeof(buffer) && ftruncate(fd, 0) == 0 &&
            pwrite(fd, buffer, (size_t)length, 0) == length && fsync(fd) == 0)
                success = true;
        close(fd);
        return success;
}

static char *escape_address_path(const char *path)
{
        static const char hex[] = "0123456789ABCDEF";
        size_t length = strlen(path);
        char *escaped = malloc(length * 3 + 1), *out = escaped;

        if (!escaped)
                return NULL;
        for (const unsigned char *p = (const unsigned char *)path; *p; ++p) {
                if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_' ||
                    *p == '-' || *p == '/' || *p == '.' || *p == '\\') {
                        *out++ = (char)*p;
                } else {
                        *out++ = '%';
                        *out++ = hex[*p >> 4];
                        *out++ = hex[*p & 15];
                }
        }
        *out = '\0';
        return escaped;
}

static bool absolute_executable(const char *path)
{
        struct stat st;
        return path && path[0] == '/' && stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0 &&
               (geteuid() != 0 || (st.st_uid == 0 && !(st.st_mode & 0022)));
}

static bool parse_options(int argc, const char **argv, Options *options)
{
        *options = (Options){.dispatcher = DEFAULT_DISPATCHER};
        for (int i = 0; i < argc; ++i) {
                if (!strncmp(argv[i], "dispatcher=", 11))
                        options->dispatcher = argv[i] + 11;
                else if (!strncmp(argv[i], "config-file=", 12))
                        options->config = argv[i] + 12;
                else if (!strcmp(argv[i], "debug"))
                        options->debug = true;
                else
                        return false;
        }
        return absolute_executable(options->dispatcher) && (!options->config || options->config[0] == '/');
}

static bool lookup_user(const char *name, struct passwd *entry, char **storage)
{
        long suggested = sysconf(_SC_GETPW_R_SIZE_MAX);
        size_t size = suggested > 0 && suggested < 1024 * 1024 ? (size_t)suggested : 16384;
        struct passwd *result = NULL;

        *storage = NULL;
        for (;;) {
                char *resized = realloc(*storage, size);
                int r;
                if (!resized) {
                        free(*storage);
                        *storage = NULL;
                        return false;
                }
                *storage = resized;
                r = getpwnam_r(name, entry, *storage, size, &result);
                if (r == ERANGE && size < (size_t)16 * 1024 * 1024) {
                        size *= 2;
                        continue;
                }
                if (r != 0 || !result) {
                        free(*storage);
                        *storage = NULL;
                        return false;
                }
                return true;
        }
}

static bool supplementary_groups(const char *user, gid_t primary, gid_t **groups, int *count)
{
        int needed = 16;
        gid_t *list = NULL;

        for (;;) {
                gid_t *resized = realloc(list, (size_t)needed * sizeof(*list));
                if (!resized) {
                        free(list);
                        return false;
                }
                list = resized;
                int available = needed;
                if (getgrouplist(user, primary, list, &available) >= 0) {
                        *groups = list;
                        *count = available;
                        return true;
                }
                if (available <= needed || available > 65536) {
                        free(list);
                        return false;
                }
                needed = available;
        }
}

static char **build_environment(pam_handle_t *pamh, const struct passwd *entry, const char *runtime)
{
        char **source = pam_getenvlist(pamh);
        size_t count = 0, capacity = 16;
        char **environment = calloc(capacity, sizeof(*environment));
        const char *blocked[] = {
                "HOME=", "USER=", "LOGNAME=", "SHELL=", "PATH=", "XDG_RUNTIME_DIR=", "DBUS_SESSION_BUS_ADDRESS="};

        if (!environment) {
                if (source) {
                        for (size_t i = 0; source[i]; ++i)
                                free(source[i]);
                        free(source);
                }
                return NULL;
        }
        if (source) {
                for (size_t i = 0; source[i]; ++i) {
                        bool include = strncmp(source[i], "LD_", 3) != 0;
                        for (size_t j = 0; include && j < sizeof(blocked) / sizeof(blocked[0]); ++j)
                                if (!strncmp(source[i], blocked[j], strlen(blocked[j])))
                                        include = false;
                        if (include) {
                                if (count + 8 >= capacity) {
                                        capacity *= 2;
                                        char **resized = realloc(environment, capacity * sizeof(*environment));
                                        if (!resized)
                                                goto fail;
                                        environment = resized;
                                }
                                char *copy = strdup(source[i]);
                                if (!copy)
                                        goto fail;
                                environment[count++] = copy;
                        }
                }
        }
#define ADD_ENV(format, value)                                                                                         \
        do {                                                                                                           \
                char *item = NULL;                                                                                     \
                if (asprintf(&item, format, value) < 0)                                                                \
                        goto fail;                                                                                     \
                environment[count++] = item;                                                                           \
        } while (0)
        ADD_ENV("HOME=%s", entry->pw_dir && *entry->pw_dir ? entry->pw_dir : "/");
        ADD_ENV("USER=%s", entry->pw_name);
        ADD_ENV("LOGNAME=%s", entry->pw_name);
        ADD_ENV("SHELL=%s", entry->pw_shell && *entry->pw_shell ? entry->pw_shell : "/bin/sh");
        ADD_ENV("XDG_RUNTIME_DIR=%s", runtime);
        {
                char *path_item = strdup("PATH=/usr/local/bin:/usr/bin:/bin");
                if (!path_item)
                        goto fail;
                environment[count++] = path_item;
        }
        environment[count] = NULL;
#undef ADD_ENV
        if (source) {
                for (size_t i = 0; source[i]; ++i)
                        free(source[i]);
                free(source);
        }
        return environment;
fail:
        if (source) {
                for (size_t i = 0; source[i]; ++i)
                        free(source[i]);
                free(source);
        }
        for (size_t i = 0; i < count; ++i)
                free(environment[i]);
        free(environment);
        return NULL;
}

static void free_environment(char **environment)
{
        if (!environment)
                return;
        for (size_t i = 0; environment[i]; ++i)
                free(environment[i]);
        free(environment);
}

static void child_exec(const Options *options, const struct passwd *entry, const char *pid_path, gid_t *groups,
                       int group_count, char **environment, int ready_fd)
{
        char *arguments[10];
        size_t n = 0;
        sigset_t empty;
        struct sigaction action = {.sa_handler = SIG_DFL};
        int null_fd;

        arguments[n++] = (char *)options->dispatcher;
        arguments[n++] = "--scope=user";
        arguments[n++] = "--fork";
        arguments[n++] = "--ready-fd=3";
        arguments[n++] = "--pid-file";
        arguments[n++] = (char *)pid_path;
        if (options->config) {
                arguments[n++] = "--config-file";
                arguments[n++] = (char *)options->config;
        }
        arguments[n] = NULL;

        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        sigemptyset(&action.sa_mask);
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGCHLD, &action, NULL);
        sigaction(SIGPIPE, &action, NULL);
        if (geteuid() == 0 && (syscall(SYSCALL_SETGROUPS, group_count, groups) < 0 ||
                               syscall(SYSCALL_SETRESGID, entry->pw_gid, entry->pw_gid, entry->pw_gid) < 0 ||
                               syscall(SYSCALL_SETRESUID, entry->pw_uid, entry->pw_uid, entry->pw_uid) < 0))
                _exit(126);
        /* Move ready_fd onto 3 before detaching stdin/stdout/stderr, in case a
         * PAM host had any of 0..2 closed and socketpair() handed them out. */
        if (ready_fd == 3 ? fcntl(3, F_SETFD, 0) < 0 : dup2(ready_fd, 3) < 0)
                _exit(126);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null_fd < 0)
                _exit(126);
        for (int target = 0; target < 3; ++target) {
                if (null_fd == target ? fcntl(target, F_SETFD, 0) < 0 : dup2(null_fd, target) < 0)
                        _exit(126);
        }
        if (null_fd > 3)
                close(null_fd);
        bool close_fallback = true;
#ifdef SYS_close_range
        if (syscall(SYS_close_range, 4U, UINT_MAX, 0U) == 0)
                close_fallback = false;
        else if (errno != ENOSYS)
                _exit(126);
#endif
        if (close_fallback) {
                long limit = sysconf(_SC_OPEN_MAX);
                if (limit < 0 || limit > 1048576)
                        limit = 65536;
                for (int fd = 4; fd < limit; ++fd)
                        close(fd);
        }
        execve(options->dispatcher, arguments, environment);
        _exit(127);
}

static bool start_dispatcher(pam_handle_t *pamh, const Options *options, const struct passwd *entry,
                             const char *runtime, const char *pid_path)
{
        gid_t *groups = NULL;
        int group_count = 0, pair[2], result = 0;
        char **environment, status = 0;
        pid_t child;
        uint64_t deadline;

        if (geteuid() == 0 && !supplementary_groups(entry->pw_name, entry->pw_gid, &groups, &group_count))
                return false;
        environment = build_environment(pamh, entry, runtime);
        if (!environment || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) {
                free(groups);
                free_environment(environment);
                return false;
        }
        child = fork();
        if (child == 0)
                child_exec(options, entry, pid_path, groups, group_count, environment, pair[1]);
        free(groups);
        free_environment(environment);
        close(pair[1]);
        if (child < 0) {
                close(pair[0]);
                return false;
        }
        /* The dispatcher reports readiness itself. Its exit status is not
         * reliable here: the host application may reap children on its own
         * or ignore SIGCHLD. */
        struct pollfd ready = {.fd = pair[0], .events = POLLIN};
        deadline = now_monotonic_ms() + STARTUP_TIMEOUT_MS;
        for (;;) {
                uint64_t now = now_monotonic_ms();
                int remaining = now >= deadline ? 0 : (int)(deadline - now);
                result = poll(&ready, 1, remaining);
                if (result < 0 && errno == EINTR)
                        continue;
                break;
        }
        bool success = result > 0 && recv(pair[0], &status, 1, MSG_DONTWAIT) == 1 && status == 'R';
        close(pair[0]);
        /* A dispatcher stuck before daemonizing is still this child. */
        if (!success && waitpid(child, NULL, WNOHANG) == 0)
                kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
                ;
        return success;
}

static bool state_matches_bus(int directory_fd, uid_t uid, State *state)
{
        pid_t pid;
        unsigned long long start_time;
        return read_state(directory_fd, uid, state) && read_pid_file(directory_fd, uid, &pid) && pid == state->pid &&
               process_start_time(pid, uid, &start_time) && start_time == state->start_time;
}

static void stop_owned_process(const State *state, uid_t uid)
{
        unsigned long long start_time;
        int pid_fd = -1;

#ifdef SYS_pidfd_open
        pid_fd = (int)syscall(SYS_pidfd_open, state->pid, 0U);
#endif
        if (!process_start_time(state->pid, uid, &start_time) || start_time != state->start_time) {
                if (pid_fd >= 0)
                        close(pid_fd);
                return;
        }
#if defined(SYS_pidfd_send_signal)
        if (pid_fd >= 0)
                (void)syscall(SYS_pidfd_send_signal, pid_fd, SIGTERM, NULL, 0U);
        else
#endif
                (void)kill(state->pid, SIGTERM);
        if (pid_fd >= 0) {
                struct pollfd poll_fd = {.fd = pid_fd, .events = POLLIN};
                uint64_t deadline = now_monotonic_ms() + 5000;
                for (;;) {
                        uint64_t now = now_monotonic_ms();
                        int remaining = now >= deadline ? 0 : (int)(deadline - now);
                        if (poll(&poll_fd, 1, remaining) < 0 && errno == EINTR)
                                continue;
                        break;
                }
                close(pid_fd);
        }
}

static int hex_digit(char c)
{
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

static bool address_matches_socket(const char *address, const char *socket_path)
{
        if (!address || strncmp(address, "unix:path=", 10) != 0)
                return false;
        const char *p = address + 10;
        const char *s = socket_path;
        while (*p && *p != ',' && *p != ';') {
                char c;
                if (*p == '%') {
                        if (!p[1] || !p[2])
                                return false;
                        int h1 = hex_digit(p[1]), h2 = hex_digit(p[2]);
                        if (h1 < 0 || h2 < 0)
                                return false;
                        c = (char)((h1 << 4) | h2);
                        p += 3;
                } else {
                        c = *p++;
                }
                if (!c || !*s || *s++ != c)
                        return false;
        }
        return *s == '\0';
}

static int publish_address(pam_handle_t *pamh, const char *runtime)
{
        char path[PATH_MAX];
        char *escaped, *assignment;
        int result;

        if (!join_path(path, sizeof(path), runtime, "bus"))
                return PAM_BUF_ERR;
        escaped = escape_address_path(path);
        if (!escaped || asprintf(&assignment, "DBUS_SESSION_BUS_ADDRESS=unix:path=%s", escaped) < 0) {
                free(escaped);
                return PAM_BUF_ERR;
        }
        result = pam_putenv(pamh, assignment);
        free(assignment);
        free(escaped);
        return result;
}

int dbus_dispatch_open_session(pam_handle_t *pamh, int argc, const char **argv)
{
        const char *user = NULL, *runtime, *existing;
        struct passwd entry;
        char *passwd_storage = NULL;
        char pid_path[PATH_MAX], socket_path[PATH_MAX];
        Options options;
        SessionData *session = NULL;
        State state;
        int directory_fd = -1, result = PAM_SESSION_ERR;
        bool counted = false;

        if (pam_get_data(pamh, PAM_DATA_KEY, (const void **)&session) == PAM_SUCCESS && session != NULL)
                return PAM_SUCCESS;

        if (!parse_options(argc, argv, &options)) {
                pam_syslog(pamh, LOG_ERR, "invalid option or dispatcher path");
                return PAM_SERVICE_ERR;
        }
        if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || !lookup_user(user, &entry, &passwd_storage)) {
                pam_syslog(pamh, LOG_ERR, "cannot resolve PAM user");
                return PAM_USER_UNKNOWN;
        }
        runtime = pam_getenv(pamh, "XDG_RUNTIME_DIR");
        if (!runtime || !*runtime) {
                free(passwd_storage);
                return PAM_IGNORE;
        }
        if (!join_path(socket_path, sizeof(socket_path), runtime, "bus")) {
                free(passwd_storage);
                return PAM_BUF_ERR;
        }
        existing = pam_getenv(pamh, "DBUS_SESSION_BUS_ADDRESS");
        if (existing && *existing) {
                if (!address_matches_socket(existing, socket_path)) {
                        free(passwd_storage);
                        return PAM_SUCCESS;
                }
        }
        if (!safe_runtime_dir(runtime, entry.pw_uid, &directory_fd) ||
            !join_path(pid_path, sizeof(pid_path), runtime, PID_NAME)) {
                pam_syslog(pamh, LOG_ERR, "unsafe XDG_RUNTIME_DIR for user %s", user);
                goto out;
        }
        if (!lock_runtime_dir(directory_fd)) {
                pam_syslog(pamh, LOG_ERR, "cannot lock user bus startup: %s", strerror(errno));
                goto out;
        }

        if (socket_is_live(directory_fd, entry.pw_uid)) {
                if (state_matches_bus(directory_fd, entry.pw_uid, &state)) {
                        if (state.count == UINT_MAX ||
                            !write_state(directory_fd, entry.pw_uid, entry.pw_gid,
                                         &(State){state.pid, state.start_time, state.count + 1}))
                                goto out;
                        counted = true;
                }
        } else {
                unlinkat(directory_fd, STATE_NAME, 0);
                if (!start_dispatcher(pamh, &options, &entry, runtime, pid_path) ||
                    !socket_is_live(directory_fd, entry.pw_uid)) {
                        pam_syslog(pamh, LOG_ERR, "dbus-broker-dispatch failed to start for user %s", user);
                        goto out;
                }
                pid_t pid;
                unsigned long long start_time;
                if (!read_pid_file(directory_fd, entry.pw_uid, &pid) ||
                    !process_start_time(pid, entry.pw_uid, &start_time)) {
                        pam_syslog(pamh, LOG_ERR, "cannot record user bus ownership for user %s", user);
                        goto out;
                }
                if (!write_state(directory_fd, entry.pw_uid, entry.pw_gid, &(State){pid, start_time, 1})) {
                        pam_syslog(pamh, LOG_ERR, "cannot record user bus ownership for user %s", user);
                        stop_owned_process(&(State){pid, start_time, 1}, entry.pw_uid);
                        goto out;
                }
                state = (State){pid, start_time, 1};
                counted = true;
        }
        result = publish_address(pamh, runtime);
        if (result != PAM_SUCCESS)
                goto out;
        if (counted) {
                session = calloc(1, sizeof(*session));
                if (session)
                        session->runtime = strdup(runtime);
                if (!session || !session->runtime) {
                        result = PAM_BUF_ERR;
                        goto out;
                }
                session->uid = entry.pw_uid;
                session->gid = entry.pw_gid;
                session->pid = state.pid;
                session->start_time = state.start_time;
                result = pam_set_data(pamh, PAM_DATA_KEY, session, free_session_data);
                if (result != PAM_SUCCESS)
                        goto out;
                session = NULL;
        }
        if (options.debug)
                pam_syslog(pamh, LOG_DEBUG, "user bus ready at %s/bus", runtime);
out:
        if (result != PAM_SUCCESS && counted && state_matches_bus(directory_fd, entry.pw_uid, &state)) {
                if (state.count > 1) {
                        --state.count;
                        (void)write_state(directory_fd, entry.pw_uid, entry.pw_gid, &state);
                } else {
                        unlinkat(directory_fd, STATE_NAME, 0);
                        stop_owned_process(&state, entry.pw_uid);
                }
        }
        free_session_data(pamh, session, result);
        if (directory_fd >= 0)
                flock(directory_fd, LOCK_UN);
        if (directory_fd >= 0)
                close(directory_fd);
        free(passwd_storage);
        return result;
}

int dbus_dispatch_close_session(pam_handle_t *pamh)
{
        const SessionData *session = NULL;
        State state;
        int directory_fd = -1;

        if (pam_get_data(pamh, PAM_DATA_KEY, (const void **)&session) != PAM_SUCCESS || !session)
                return PAM_SUCCESS;
        if (!safe_runtime_dir(session->runtime, session->uid, &directory_fd))
                return PAM_SUCCESS;
        if (!lock_runtime_dir(directory_fd))
                goto out;
        if (!state_matches_bus(directory_fd, session->uid, &state)) {
                unlinkat(directory_fd, STATE_NAME, 0);
                goto out;
        }
        /* A session opened before a bus restart owns no reference to the
         * replacement bus, even though the runtime directory is the same. */
        if (state.pid != session->pid || state.start_time != session->start_time)
                goto out;
        if (state.count > 1) {
                --state.count;
                (void)write_state(directory_fd, session->uid, session->gid, &state);
        } else {
                unlinkat(directory_fd, STATE_NAME, 0);
                stop_owned_process(&state, session->uid);
        }
out:
        flock(directory_fd, LOCK_UN);
        close(directory_fd);
        (void)pam_set_data(pamh, PAM_DATA_KEY, NULL, NULL);
        return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        (void)flags;
        return dbus_dispatch_open_session(pamh, argc, argv);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        (void)flags;
        (void)argc;
        (void)argv;
        return dbus_dispatch_close_session(pamh);
}
