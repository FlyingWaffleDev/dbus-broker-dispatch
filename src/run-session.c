#define _GNU_SOURCE
#include "process.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
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

static bool launcher_child_setup(void *data, int *error_number)
{
        pid_t parent = getppid();

        (void)data;
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() != parent) {
                *error_number = errno ? errno : ESRCH;
                return false;
        }
        return true;
}

static bool start_bus(const char *launcher, pid_t *pid, Error **error)
{
        char *const arguments[] = {(char *)launcher, "--scope=user", "--foreground", NULL};
        ProcessSpec spec = {
                .argv = arguments,
                .child_setup = launcher_child_setup,
        };
        return process_spawn(&spec, pid, error);
}

static bool wait_for_bus(const char *socket_path, pid_t bus, bool *reaped, char **message)
{
        struct timespec delay = {.tv_nsec = 10 * 1000 * 1000};
        struct stat st;
        int status;

        for (unsigned int attempt = 0; attempt < 500; ++attempt) {
                pid_t result = waitpid(bus, &status, WNOHANG);
                if (result == bus) {
                        *reaped = true;
                        *message = strdup("user bus dispatcher exited before its listener was ready");
                        return false;
                }
                if (result < 0 && errno != EINTR) {
                        if (asprintf(message, "waitpid: %s", strerror(errno)) < 0)
                                *message = NULL;
                        return false;
                }
                if (lstat(socket_path, &st) == 0 && S_ISSOCK(st.st_mode))
                        return true;
                while (nanosleep(&delay, &delay) < 0 && errno == EINTR)
                        ;
                delay = (struct timespec){.tv_nsec = 10 * 1000 * 1000};
        }
        *message = strdup("timed out waiting for the user bus listener");
        return false;
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
        char *launcher, *address, *socket_path, *message = NULL;
        Error *error = NULL;
        pid_t bus, child;
        struct sigaction action = {.sa_handler = forward_signal};
        sigset_t blocked_signals, previous_mask;
        struct stat st;
        int status;
        bool bus_reaped = false;

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
        socket_path = join_path(runtime, "bus");
        if (!socket_path) {
                fputs("Cannot allocate user bus path.\n", stderr);
                return 1;
        }
        if (lstat(socket_path, &st) == 0) {
                fprintf(stderr, "A user bus path already exists at %s.\n", socket_path);
                free(socket_path);
                return 1;
        }
        if (errno != ENOENT) {
                fprintf(stderr, "Cannot inspect %s: %s\n", socket_path, strerror(errno));
                free(socket_path);
                return 1;
        }

        launcher = find_program("dbus-broker-dispatch");
        if (!launcher)
                launcher = strdup("dbus-broker-dispatch");
        if (!launcher) {
                free(socket_path);
                return 1;
        }
        if (!start_bus(launcher, &bus, &error)) {
                fprintf(stderr, "Cannot start user bus: %s\n", error ? error->message : "out of memory");
                error_free(error);
                free(socket_path);
                free(launcher);
                return 1;
        }
        if (!wait_for_bus(socket_path, bus, &bus_reaped, &message)) {
                fprintf(stderr, "Cannot start user bus: %s\n", message ? message : "out of memory");
                free(message);
                if (!bus_reaped)
                        stop_bus(bus);
                free(socket_path);
                free(launcher);
                return 1;
        }

        if (asprintf(&address, "unix:path=%s", socket_path) < 0)
                address = NULL;
        if (!address || setenv("DBUS_SESSION_BUS_ADDRESS", address, 1) < 0) {
                fprintf(stderr, "Cannot set session bus address: %s\n", strerror(errno));
                stop_bus(bus);
                free(address);
                free(socket_path);
                free(launcher);
                return 1;
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
                stop_bus(bus);
                free(address);
                free(socket_path);
                free(launcher);
                return 1;
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
        stop_bus(bus);
        free(address);
        free(socket_path);
        free(launcher);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
