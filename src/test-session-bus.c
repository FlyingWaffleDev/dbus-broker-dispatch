#define _GNU_SOURCE
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void test_session_bus(gconstpointer data) {
        const gchar *launcher = data;
        gchar *runtime = NULL, *data_home = NULL, *service_dir = NULL, *service_file = NULL, *config_file = NULL;
        gchar *marker = NULL, *command_file = NULL, *quoted_marker = NULL, *command = NULL, *service_contents = NULL;
        gchar *config_contents = NULL, *address = NULL, *contents = NULL, **environment = NULL;
        GPid pid = 0;
        GDBusConnection *connection = NULL;
        GVariant *reply = NULL;
        GError *error = NULL;
        int status;

        runtime = g_dir_make_tmp("openrc-broker-session-test-XXXXXX", &error);
        g_assert_no_error(error);
        g_assert_cmpint(chmod(runtime, 0700), ==, 0);
        data_home = g_build_filename(runtime, "data", NULL);
        service_dir = g_build_filename(data_home, "dbus-1", "services", NULL);
        service_file = g_build_filename(service_dir, "org.example.SessionTest.service", NULL);
        marker = g_build_filename(runtime, "activation-display", NULL);
        command_file = g_build_filename(runtime, "activation-command", NULL);
        g_assert_cmpint(g_mkdir_with_parents(service_dir, 0700), ==, 0);
        quoted_marker = g_shell_quote(marker);
        command = g_strdup_printf("#!/bin/sh\nprintf %%s \"$DISPLAY\" > %s\n", quoted_marker);
        g_assert_true(g_file_set_contents(command_file, command, -1, &error));
        g_assert_no_error(error);
        g_assert_cmpint(chmod(command_file, 0700), ==, 0);
        /* Exercise the D-Bus service-file User= path.  The test runner's own
         * account keeps this portable for unprivileged test runs. */
        service_contents = g_strdup_printf("[D-BUS Service]\nName=org.example.SessionTest\nExec=%s\nUser=%s\n",
                                           command_file, g_get_user_name());
        g_assert_true(g_file_set_contents(service_file, service_contents, -1, &error));
        g_assert_no_error(error);
        g_free(service_contents);
        config_file = g_build_filename(runtime, "session.conf", NULL);
        config_contents = g_strdup_printf("<busconfig>"
                                          "<listen>unix:path=%s/bus</listen>"
                                          "<servicedir>%s</servicedir>"
                                          "<policy context='default'>"
                                          "<allow user='*'/><deny own='*'/>"
                                          "<allow send_destination='org.freedesktop.DBus'/>"
                                          "<allow receive_type='method_call'/><allow receive_type='method_return'/>"
                                          "<allow receive_type='error'/><allow receive_type='signal'/>"
                                          "</policy>"
                                          "<policy user='%s'><allow own='org.example.PolicyTest'/></policy>"
                                          "</busconfig>", runtime, service_dir, g_get_user_name());
        g_assert_true(g_file_set_contents(config_file, config_contents, -1, &error));
        g_assert_no_error(error);
        environment = g_get_environ();
        environment = g_environ_setenv(environment, "XDG_RUNTIME_DIR", runtime, TRUE);
        environment = g_environ_setenv(environment, "XDG_DATA_HOME", data_home, TRUE);
        g_assert_true(g_spawn_async(NULL,
                                    (gchar *[]){ (gchar *)launcher, "--scope=user", "--foreground", "--config-file", config_file, NULL },
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
        reply = NULL;

        reply = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                             "org.freedesktop.DBus", "RequestName",
                                             g_variant_new("(su)", "org.example.PolicyTest", 0),
                                             G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE,
                                             -1, NULL, &error);
        g_assert_no_error(error);
        g_assert_nonnull(reply);
        g_variant_unref(reply);
        reply = NULL;

        {
                GVariantBuilder builder;
                g_variant_builder_init(&builder, G_VARIANT_TYPE("a{ss}"));
                g_variant_builder_add(&builder, "{ss}", "DISPLAY", ":test-display");
                reply = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                                     "org.freedesktop.DBus", "UpdateActivationEnvironment",
                                                     g_variant_new("(@a{ss})", g_variant_builder_end(&builder)),
                                                     NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
                g_assert_no_error(error);
                g_assert_nonnull(reply);
                g_variant_unref(reply);
        }
        g_dbus_connection_call(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "StartServiceByName", g_variant_new("(su)", "org.example.SessionTest", 0),
                               NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
        for (guint attempt = 0; attempt < 100 && !g_file_test(marker, G_FILE_TEST_EXISTS); ++attempt)
                g_usleep(10 * 1000);
        g_assert_true(g_file_get_contents(marker, &contents, NULL, &error));
        g_assert_no_error(error);
        g_assert_cmpstr(contents, ==, ":test-display");

        g_object_unref(connection);
        kill(pid, SIGTERM);
        g_assert_cmpint(waitpid(pid, &status, 0), ==, pid);
        g_spawn_close_pid(pid);
        g_free(address);
        g_free(contents);
        g_assert_cmpint(g_remove(config_file), ==, 0);
        g_assert_cmpint(g_remove(marker), ==, 0);
        g_assert_cmpint(g_remove(command_file), ==, 0);
        g_assert_cmpint(g_remove(service_file), ==, 0);
        g_assert_cmpint(g_rmdir(service_dir), ==, 0);
        g_free(service_dir);
        service_dir = g_build_filename(data_home, "dbus-1", NULL);
        g_assert_cmpint(g_rmdir(service_dir), ==, 0);
        g_assert_cmpint(g_rmdir(data_home), ==, 0);
        g_assert_cmpint(g_rmdir(runtime), ==, 0);
        g_free(command);
        g_free(config_contents);
        g_free(config_file);
        g_free(quoted_marker);
        g_free(marker);
        g_free(command_file);
        g_free(service_file);
        g_free(service_dir);
        g_free(data_home);
        g_free(runtime);
}

int main(int argc, char **argv) {
        g_test_init(&argc, &argv, NULL);
        g_assert_cmpint(argc, ==, 2);
        g_test_add_data_func("/session-bus/connect-and-list", argv[1], test_session_bus);
        return g_test_run();
}
