#define _GNU_SOURCE
#include <errno.h>
#include <glib.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t command_pid;

static void forward_signal(int signal_number)
{
        if (command_pid > 0)
                kill(command_pid, signal_number);
}

static void launcher_child_setup(gpointer data)
{
        pid_t parent = getppid();

        (void)data;
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() != parent)
                _exit(127);
}

static gboolean wait_for_bus(const gchar *socket_path, GPid bus, gboolean *reaped, GError **error)
{
        struct stat st;
        int status;

        for (guint attempt = 0; attempt < 500; ++attempt) {
                pid_t result = waitpid(bus, &status, WNOHANG);
                if (result == bus) {
                        *reaped = TRUE;
                        g_set_error(error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                                    "user bus dispatcher exited before its listener was ready");
                        return FALSE;
                }
                if (result < 0 && errno != EINTR) {
                        g_set_error(error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED, "waitpid: %s", g_strerror(errno));
                        return FALSE;
                }
                if (lstat(socket_path, &st) == 0 && S_ISSOCK(st.st_mode))
                        return TRUE;
                g_usleep((gulong)10 * 1000);
        }
        g_set_error(error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED, "timed out waiting for the user bus listener");
        return FALSE;
}

static void stop_bus(GPid bus)
{
        int status;

        if (kill(bus, SIGTERM) < 0 && errno != ESRCH)
                g_warning("Cannot stop user bus: %s", g_strerror(errno));
        while (waitpid(bus, &status, 0) < 0 && errno == EINTR)
                ;
        g_spawn_close_pid(bus);
}

int main(int argc, char **argv)
{
        const char *runtime;
        gchar *launcher, *address, *socket_path;
        GPid bus;
        GError *error = NULL;
        struct sigaction action = {.sa_handler = forward_signal};
        sigset_t blocked_signals, previous_mask;
        struct stat st;
        pid_t child;
        int status;
        gboolean bus_reaped = FALSE;

        if (argc < 2) {
                g_printerr("Usage: dbus-broker-run-session -- COMMAND [ARGS...]\n");
                return 2;
        }
        if (g_strcmp0(argv[1], "--") == 0)
                ++argv, --argc;
        if (argc < 2) {
                g_printerr("A command is required.\n");
                return 2;
        }
        runtime = g_get_user_runtime_dir();
        if (!runtime || !*runtime) {
                g_printerr("XDG_RUNTIME_DIR is required for a user D-Bus bus.\n");
                return 1;
        }
        socket_path = g_build_filename(runtime, "bus", NULL);
        if (lstat(socket_path, &st) == 0) {
                g_printerr("A user bus path already exists at %s.\n", socket_path);
                g_free(socket_path);
                return 1;
        }
        if (errno != ENOENT) {
                g_printerr("Cannot inspect %s: %s\n", socket_path, g_strerror(errno));
                g_free(socket_path);
                return 1;
        }

        launcher = g_find_program_in_path("dbus-broker-dispatch");
        if (!launcher)
                launcher = g_strdup("dbus-broker-dispatch");
        if (!g_spawn_async(NULL, (gchar *[]){launcher, "--scope=user", "--foreground", NULL}, NULL,
                           G_SPAWN_DO_NOT_REAP_CHILD, launcher_child_setup, NULL, &bus, &error)) {
                g_printerr("Cannot start user bus: %s\n", error->message);
                g_clear_error(&error);
                g_free(socket_path);
                g_free(launcher);
                return 1;
        }
        if (!wait_for_bus(socket_path, bus, &bus_reaped, &error)) {
                g_printerr("Cannot start user bus: %s\n", error->message);
                g_clear_error(&error);
                if (!bus_reaped)
                        stop_bus(bus);
                else
                        g_spawn_close_pid(bus);
                g_free(socket_path);
                g_free(launcher);
                return 1;
        }

        address = g_strdup_printf("unix:path=%s", socket_path);
        g_setenv("DBUS_SESSION_BUS_ADDRESS", address, TRUE);
        sigemptyset(&blocked_signals);
        sigaddset(&blocked_signals, SIGINT);
        sigaddset(&blocked_signals, SIGTERM);
        sigaddset(&blocked_signals, SIGHUP);
        sigaddset(&blocked_signals, SIGQUIT);
        sigprocmask(SIG_BLOCK, &blocked_signals, &previous_mask);
        child = fork();
        if (child < 0) {
                sigprocmask(SIG_SETMASK, &previous_mask, NULL);
                g_printerr("Cannot start command: %s\n", g_strerror(errno));
                stop_bus(bus);
                g_free(address);
                g_free(socket_path);
                g_free(launcher);
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
        g_free(address);
        g_free(socket_path);
        g_free(launcher);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
