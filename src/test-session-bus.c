#define _GNU_SOURCE
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void test_session_bus(gconstpointer data) {
        const gchar *launcher = data;
        gchar *runtime = NULL, *address = NULL, **environment = NULL;
        GPid pid = 0;
        GDBusConnection *connection = NULL;
        GVariant *reply = NULL;
        GError *error = NULL;
        int status;

        runtime = g_dir_make_tmp("openrc-broker-session-test-XXXXXX", &error);
        g_assert_no_error(error);
        g_assert_cmpint(chmod(runtime, 0700), ==, 0);
        environment = g_get_environ();
        environment = g_environ_setenv(environment, "XDG_RUNTIME_DIR", runtime, TRUE);
        g_assert_true(g_spawn_async(NULL,
                                    (gchar *[]){ (gchar *)launcher, "--scope=user", "--foreground", NULL },
                                    environment, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &error));
        g_assert_no_error(error);
        g_strfreev(environment);

        address = g_strdup_printf("unix:path=%s/bus", runtime);
        for (guint attempt = 0; attempt < 100; ++attempt) {
                connection = g_dbus_connection_new_for_address_sync(address,
                                                                      G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
                                                                      G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
                                                                      NULL, NULL, &error);
                if (connection)
                        break;
                g_clear_error(&error);
                g_usleep(10 * 1000);
        }
        g_assert_nonnull(connection);
        reply = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus", "/",
                                             "org.freedesktop.DBus", "ListNames", NULL,
                                             G_VARIANT_TYPE("(as)"), G_DBUS_CALL_FLAGS_NONE,
                                             -1, NULL, &error);
        g_assert_no_error(error);
        g_assert_nonnull(reply);

        g_variant_unref(reply);
        g_object_unref(connection);
        kill(pid, SIGTERM);
        g_assert_cmpint(waitpid(pid, &status, 0), ==, pid);
        g_spawn_close_pid(pid);
        g_free(address);
        g_assert_cmpint(g_rmdir(runtime), ==, 0);
        g_free(runtime);
}

int main(int argc, char **argv) {
        g_test_init(&argc, &argv, NULL);
        g_assert_cmpint(argc, ==, 2);
        g_test_add_data_func("/session-bus/connect-and-list", argv[1], test_session_bus);
        return g_test_run();
}
