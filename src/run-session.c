#define _GNU_SOURCE
#include "address.h"
#include "process.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t command_pid;

static void forward_signal(int signal_number)
{
        if (command_pid > 0)
                kill(command_pid, signal_number);
}

static char *join_path(const char *directory, const char *name)
{
        size_t a = strlen(directory), b = strlen(name);
        bool slash = a > 0 && directory[a - 1] != '/';
        char *path;

        if (a > SIZE_MAX - b - (slash ? 2 : 1))
                return NULL;
        path = malloc(a + b + (slash ? 2 : 1));
        if (!path)
                return NULL;
        memcpy(path, directory, a);
        if (slash)
                path[a++] = '/';
        memcpy(path + a, name, b + 1);
        return path;
}

static char *find_program(const char *name)
{
        const char *path;
        const char *part;

        if (strchr(name, '/'))
                return access(name, X_OK) == 0 ? strdup(name) : NULL;
        path = getenv("PATH");
        if (!path)
                path = "/usr/local/bin:/usr/bin:/bin";
        for (part = path;;) {
                const char *end = strchr(part, ':');
                size_t length = end ? (size_t)(end - part) : strlen(part);
                const char *directory = length ? part : ".";
                size_t directory_length = length ? length : 1;
                char *candidate;

                if (directory_length <= SIZE_MAX - strlen(name) - 2) {
                        candidate = malloc(directory_length + strlen(name) + 2);
                        if (!candidate)
                                return NULL;
                        memcpy(candidate, directory, directory_length);
                        candidate[directory_length] = '/';
                        strcpy(candidate + directory_length + 1, name);
                        if (access(candidate, X_OK) == 0)
                                return candidate;
                        free(candidate);
                }
                if (!end)
                        return NULL;
                part = end + 1;
        }
}

typedef struct {
        pid_t parent;
        int ready_fd;
} LauncherChild;

static bool launcher_child_setup(void *data, int *error_number)
{
        LauncherChild *child = data;

        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() != child->parent ||
            fcntl(child->ready_fd, F_SETFD, 0) < 0) {
                *error_number = errno ? errno : ESRCH;
                return false;
        }
        return true;
}

static bool start_bus(const char *launcher, const char *address, pid_t *pid, Error **error)
{
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0)
                return error_set_errno(error, errno, "Cannot create bus startup socket");
        /* --ready-fd reserves stdin/stdout/stderr, including when inherited
         * standard descriptors were closed. */
        if (pair[1] < 3) {
                int moved = fcntl(pair[1], F_DUPFD_CLOEXEC, 3);
                if (moved < 0) {
                        int saved = errno;
                        close(pair[0]);
                        close(pair[1]);
                        return error_set_errno(error, saved, "Cannot move bus startup socket");
                }
                close(pair[1]);
                pair[1] = moved;
        }
        char ready_arg[32];
        snprintf(ready_arg, sizeof(ready_arg), "--ready-fd=%d", pair[1]);
        char *const arguments[] = {
                (char *)launcher, "--scope=user", "--foreground", "--address", (char *)address, ready_arg, NULL};
        LauncherChild child = {.parent = getpid(), .ready_fd = pair[1]};
        ProcessSpec spec = {
                .argv = arguments,
                .child_setup = launcher_child_setup,
                .child_setup_data = &child,
        };
        bool success = process_spawn(&spec, pid, error);
        close(pair[1]);
        if (success) {
                struct pollfd ready = {.fd = pair[0], .events = POLLIN};
                int result;
                char status = 0;
                do
                        result = poll(&ready, 1, 5000);
                while (result < 0 && errno == EINTR);
                if (result < 0)
                        success = error_set_errno(error, errno, "Cannot wait for user bus startup");
                else if (!result)
                        success = error_set(error, ETIMEDOUT, "Timed out waiting for user bus startup");
                else if (recv(pair[0], &status, 1, MSG_DONTWAIT) != 1 || status != 'R')
                        success = error_set(error, EIO, "User bus dispatcher failed before it was ready");
        }
        close(pair[0]);
        return success;
}

static void stop_bus(pid_t bus)
{
        int status;

        if (kill(bus, SIGTERM) < 0 && errno != ESRCH)
                fprintf(stderr, "Cannot stop user bus: %s\n", strerror(errno));
        while (waitpid(bus, &status, 0) < 0 && errno == EINTR)
                ;
}

int main(int argc, char **argv)
{
        const char *runtime;
        char *launcher = NULL, *address = NULL, *socket_path = NULL;
        char *directory = NULL, *escaped = NULL;
        Error *error = NULL;
        pid_t bus = 0, child;
        struct sigaction action = {.sa_handler = forward_signal};
        sigset_t blocked_signals, previous_mask;
        struct stat st;
        int status, exit_status = 1;
        bool directory_created = false;

        if (argc < 2) {
                fputs("Usage: dbus-broker-run-session -- COMMAND [ARGS...]\n", stderr);
                return 2;
        }
        if (strcmp(argv[1], "--") == 0)
                ++argv, --argc;
        if (argc < 2) {
                fputs("A command is required.\n", stderr);
                return 2;
        }
        runtime = getenv("XDG_RUNTIME_DIR");
        if (!runtime || !*runtime) {
                fputs("XDG_RUNTIME_DIR is required for a user D-Bus bus.\n", stderr);
                return 1;
        }
        if (!path_is_absolute(runtime) || lstat(runtime, &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
            (st.st_mode & 0077)) {
                fputs("XDG_RUNTIME_DIR must be an absolute, private, user-owned directory.\n", stderr);
                return 1;
        }
        directory = join_path(runtime, "dbus-run-session-XXXXXX");
        if (!directory || !mkdtemp(directory)) {
                fprintf(stderr, "Cannot create temporary bus directory: %s\n", strerror(errno));
                goto out;
        }
        directory_created = true;
        socket_path = join_path(directory, "bus");
        escaped = socket_path ? percent_escape(socket_path) : NULL;
        address = escaped ? str_printf("unix:path=%s", escaped) : NULL;
        if (!address || setenv("DBUS_SESSION_BUS_ADDRESS", address, 1) < 0) {
                fprintf(stderr, "Cannot set session bus address: %s\n", strerror(errno));
                goto out;
        }

        launcher = find_program("dbus-broker-dispatch");
        if (!launcher)
                launcher = strdup("dbus-broker-dispatch");
        if (!launcher)
                goto out;
        if (!start_bus(launcher, address, &bus, &error)) {
                fprintf(stderr, "Cannot start user bus: %s\n", error ? error->message : "out of memory");
                goto out;
        }
        sigemptyset(&blocked_signals);
        sigaddset(&blocked_signals, SIGINT);
        sigaddset(&blocked_signals, SIGTERM);
        sigaddset(&blocked_signals, SIGHUP);
        sigaddset(&blocked_signals, SIGQUIT);
        sigprocmask(SIG_BLOCK, &blocked_signals, &previous_mask);
        child = fork();
        if (child < 0) {
                sigprocmask(SIG_SETMASK, &previous_mask, NULL);
                fprintf(stderr, "Cannot start command: %s\n", strerror(errno));
                goto out;
        }
        if (child == 0) {
                sigprocmask(SIG_SETMASK, &previous_mask, NULL);
                execvp(argv[1], argv + 1);
                _exit(127);
        }
        command_pid = child;
        sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigprocmask(SIG_SETMASK, &previous_mask, NULL);
        while (waitpid(child, &status, 0) < 0) {
                if (errno != EINTR) {
                        status = 127 << 8;
                        break;
                }
        }
        command_pid = 0;
        exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
out:
        if (bus > 0)
                stop_bus(bus);
        if (directory_created) {
                if (socket_path)
                        unlink(socket_path);
                if (rmdir(directory) < 0)
                        fprintf(stderr, "Cannot remove temporary bus directory %s: %s\n", directory, strerror(errno));
        }
        error_free(error);
        free(escaped);
        free(directory);
        free(address);
        free(socket_path);
        free(launcher);
        return exit_status;
}
