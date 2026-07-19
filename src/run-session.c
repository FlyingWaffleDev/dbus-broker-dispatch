#define _GNU_SOURCE
#include <glib.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
        const char *runtime;
        gchar *launcher, *address;
        GPid bus;
        GError *error = NULL;
        int status;

        if (argc < 2) {
                g_printerr("Usage: %s -- COMMAND [ARGS...]\n", argv[0]);
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
        launcher = g_find_program_in_path("dbus-broker-openrc-launch");
        if (!launcher) launcher = g_strdup("dbus-broker-openrc-launch");
        if (!g_spawn_async(NULL, (gchar *[]) { launcher, "--scope=user", "--foreground", NULL },
                           NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &bus, &error)) {
                g_printerr("Cannot start user bus: %s\n", error->message);
                g_clear_error(&error); g_free(launcher); return 1;
        }
        address = g_strdup_printf("unix:path=%s/bus", runtime);
        g_setenv("DBUS_SESSION_BUS_ADDRESS", address, TRUE);
        if (fork() == 0) { execvp(argv[1], argv + 1); _exit(127); }
        if (wait(&status) < 0) status = 127 << 8;
        kill(bus, SIGTERM);
        g_spawn_close_pid(bus);
        g_free(address); g_free(launcher);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
