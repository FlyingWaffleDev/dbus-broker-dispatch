#define _GNU_SOURCE
#include <errno.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void launcher_child_setup(gpointer data)
{
        pid_t parent = getppid();

        (void)data;
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() != parent)
                _exit(127);
}

static void test_session_bus(gconstpointer data)
{
        const gchar *launcher = data;
        gchar *runtime = NULL, *service_dir = NULL, *service_file = NULL, *config_file = NULL;
        gchar *marker = NULL, *reload_marker = NULL, *command_file = NULL, *reload_command_file = NULL;
        gchar *quoted_marker = NULL, *quoted_reload_marker = NULL, *command = NULL, *reload_command = NULL;
        gchar *service_contents = NULL;
        gchar *config_contents = NULL, *config_replacement = NULL, *replacement_path = NULL;
        gchar *address = NULL, *contents = NULL, **environment = NULL;
        GPid pid = 0;
        GDBusConnection *connection = NULL;
        GVariant *reply = NULL;
        GError *error = NULL;
        int status;

        runtime = g_dir_make_tmp("broker-dispatch-session-test-XXXXXX", &error);
        g_assert_no_error(error);
        g_assert_cmpint(chmod(runtime, 0700), ==, 0);
        service_dir = g_build_filename(runtime, "dbus-1", "services", NULL);
        service_file = g_build_filename(service_dir, "org.example.SessionTest.service", NULL);
        marker = g_build_filename(runtime, "activation-display", NULL);
        reload_marker = g_build_filename(runtime, "automatic-reload", NULL);
        command_file = g_build_filename(runtime, "activation-command", NULL);
        reload_command_file = g_build_filename(runtime, "reload-command", NULL);
        g_assert_cmpint(g_mkdir_with_parents(service_dir, 0700), ==, 0);
        quoted_marker = g_shell_quote(marker);
        command = g_strdup_printf("#!/bin/sh\nprintf %%s \"$DISPLAY\" > %s\nsleep 0.2\nexit 1\n", quoted_marker);
        g_assert_true(g_file_set_contents(command_file, command, -1, &error));
        g_assert_no_error(error);
        g_assert_cmpint(chmod(command_file, 0700), ==, 0);
        quoted_reload_marker = g_shell_quote(reload_marker);
        reload_command = g_strdup_printf("#!/bin/sh\nprintf reloaded > %s\nexit 1\n", quoted_reload_marker);
        g_assert_true(g_file_set_contents(reload_command_file, reload_command, -1, &error));
        g_assert_no_error(error);
        g_assert_cmpint(chmod(reload_command_file, 0700), ==, 0);
        /* User= is normally absent on session services; the launcher must
         * register activation against its own UID rather than root. */
        service_contents = g_strdup_printf("[D-BUS Service]\nName=org.example.SessionTest\nExec=%s\n", command_file);
        g_assert_true(g_file_set_contents(service_file, service_contents, -1, &error));
        g_assert_no_error(error);
        g_clear_pointer(&service_contents, g_free);
        config_file = g_build_filename(runtime, "session.conf", NULL);
        config_contents = g_strdup_printf("<busconfig>"
                                          "<listen>unix:path=%s/bus</listen>"
                                          "<type>session</type>"
                                          "<standard_session_servicedirs/>"
                                          "<policy context='default'>"
                                          "<allow user='*'/><deny own='*'/>"
                                          "<allow send_destination='org.freedesktop.DBus'/>"
                                          "<allow receive_type='method_call'/><allow receive_type='method_return'/>"
                                          "<allow receive_type='error'/><allow receive_type='signal'/>"
                                          "</policy>"
                                          "<policy user='%s'><allow own='org.example.PolicyTest'/></policy>"
                                          "</busconfig>",
                                          runtime, g_get_user_name());
        g_assert_true(g_file_set_contents(config_file, config_contents, -1, &error));
        g_assert_no_error(error);
        environment = g_get_environ();
        environment = g_environ_setenv(environment, "XDG_RUNTIME_DIR", runtime, TRUE);
        g_assert_true(g_spawn_async(
                NULL,
                (gchar *[]){(gchar *)launcher, "--scope=user", "--foreground", "--config-file", config_file, NULL},
                environment, G_SPAWN_DO_NOT_REAP_CHILD, launcher_child_setup, NULL, &pid, &error));
        g_assert_no_error(error);
        g_strfreev(environment);

        address = g_strdup_printf("unix:path=%s/bus", runtime);
        for (guint attempt = 0; attempt < 500; ++attempt) {
                connection = g_dbus_connection_new_for_address_sync(
                        address,
                        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
                        NULL, NULL, &error);
                if (connection)
                        break;
                g_clear_error(&error);
                g_usleep(10 * 1000);
        }
        g_assert_nonnull(connection);
        reply = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus", "/", "org.freedesktop.DBus",
                                            "ListNames", NULL, G_VARIANT_TYPE("(as)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL,
                                            &error);
        g_assert_no_error(error);
        g_assert_nonnull(reply);
        g_variant_unref(reply);
        reply = NULL;

        reply = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                            "org.freedesktop.DBus", "RequestName",
                                            g_variant_new("(su)", "org.example.PolicyTest", 0), G_VARIANT_TYPE("(u)"),
                                            G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
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
                                                    g_variant_new("(@a{ss})", g_variant_builder_end(&builder)), NULL,
                                                    G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
                g_assert_no_error(error);
                g_assert_nonnull(reply);
                g_variant_unref(reply);
        }
        g_dbus_connection_call(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                               "org.freedesktop.DBus", "StartServiceByName",
                               g_variant_new("(su)", "org.example.SessionTest", 0), NULL,
                               G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
        g_assert_true(g_dbus_connection_flush_sync(connection, NULL, &error));
        g_assert_no_error(error);
        for (guint attempt = 0; attempt < 500 && !g_file_test(marker, G_FILE_TEST_EXISTS); ++attempt)
                g_usleep(10 * 1000);
        g_assert_true(g_file_get_contents(marker, &contents, NULL, &error));
        g_assert_no_error(error);
        g_assert_cmpstr(contents, ==, ":test-display");

        /* A service-directory change must trigger a debounced automatic reload.
         * The replacement also exercises immutable per-generation service
         * credentials while the previous activation is being reaped. */
        g_free(service_contents);
        service_contents = g_strdup_printf("[D-BUS Service]\nName=org.example.SessionTest\nExec=%s\n",
                                           reload_command_file);
        g_assert_true(g_file_set_contents(service_file, service_contents, -1, &error));
        g_assert_no_error(error);
        g_usleep(750 * 1000);
        g_dbus_connection_call(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                               "org.freedesktop.DBus", "StartServiceByName",
                               g_variant_new("(su)", "org.example.SessionTest", 0), NULL,
                               G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
        g_assert_true(g_dbus_connection_flush_sync(connection, NULL, &error));
        g_assert_no_error(error);
        for (guint attempt = 0; attempt < 500 && !g_file_test(reload_marker, G_FILE_TEST_EXISTS); ++attempt)
                g_usleep(10 * 1000);
        g_assert_true(g_file_test(reload_marker, G_FILE_TEST_EXISTS));

        /* Configuration watches must survive the atomic replacement pattern
         * used by package managers and editors. */
        config_replacement = g_strdup_printf("<busconfig>"
                                             "<listen>unix:path=%s/bus</listen><type>session</type>"
                                             "<standard_session_servicedirs/>"
                                             "<policy context='default'><allow user='*'/><deny own='*'/>"
                                             "<allow send_destination='org.freedesktop.DBus'/>"
                                             "<allow receive_sender='*'/></policy>"
                                             "<policy user='%s'><allow own='org.example.PolicyTest'/>"
                                             "<allow own='org.example.AutomaticPolicy'/></policy></busconfig>",
                                             runtime, g_get_user_name());
        replacement_path = g_build_filename(runtime, "session.conf.new", NULL);
        g_assert_true(g_file_set_contents(replacement_path, config_replacement, -1, &error));
        g_assert_no_error(error);
        g_assert_cmpint(g_rename(replacement_path, config_file), ==, 0);
        g_usleep(750 * 1000);
        reply = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                            "org.freedesktop.DBus", "RequestName",
                                            g_variant_new("(su)", "org.example.AutomaticPolicy", 0),
                                            G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
        g_assert_no_error(error);
        g_assert_nonnull(reply);
        g_variant_unref(reply);
        reply = NULL;

        g_object_unref(connection);
        kill(pid, SIGTERM);
        g_assert_cmpint(waitpid(pid, &status, 0), ==, pid);
        g_spawn_close_pid(pid);
        g_free(address);
        g_free(contents);
        g_assert_cmpint(g_remove(config_file), ==, 0);
        g_assert_cmpint(g_remove(marker), ==, 0);
        g_assert_cmpint(g_remove(reload_marker), ==, 0);
        g_assert_cmpint(g_remove(command_file), ==, 0);
        g_assert_cmpint(g_remove(reload_command_file), ==, 0);
        g_assert_cmpint(g_remove(service_file), ==, 0);
        g_assert_cmpint(g_rmdir(service_dir), ==, 0);
        g_free(service_dir);
        service_dir = g_build_filename(runtime, "dbus-1", NULL);
        g_assert_cmpint(g_rmdir(service_dir), ==, 0);
        g_assert_cmpint(g_rmdir(runtime), ==, 0);
        g_free(command);
        g_free(reload_command);
        g_free(service_contents);
        g_free(config_contents);
        g_free(config_replacement);
        g_free(replacement_path);
        g_free(config_file);
        g_free(quoted_marker);
        g_free(quoted_reload_marker);
        g_free(marker);
        g_free(reload_marker);
        g_free(command_file);
        g_free(reload_command_file);
        g_free(service_file);
        g_free(service_dir);
        g_free(runtime);
}

static void test_daemon_startup(gconstpointer data)
{
        const gchar *dispatcher = data;
        gchar *runtime, *config_file, *pid_file, *socket_path, *config_contents, *pid_contents = NULL;
        gchar **environment;
        gchar *end = NULL;
        GError *error = NULL;
        struct stat socket_stat;
        gint64 parsed_pid;
        int status;

        runtime = g_dir_make_tmp("broker-dispatch-daemon-test-XXXXXX", &error);
        g_assert_no_error(error);
        g_assert_cmpint(chmod(runtime, 0700), ==, 0);
        config_file = g_build_filename(runtime, "session.conf", NULL);
        pid_file = g_build_filename(runtime, "dispatch.pid", NULL);
        socket_path = g_build_filename(runtime, "bus", NULL);
        config_contents = g_strdup_printf("<busconfig>"
                                          "<listen>unix:path=%s</listen>"
                                          "<policy context='default'>"
                                          "<allow user='*'/><allow own='*'/><allow send_destination='*'/>"
                                          "<allow receive_sender='*'/>"
                                          "</policy>"
                                          "</busconfig>",
                                          socket_path);
        g_assert_true(g_file_set_contents(config_file, config_contents, -1, &error));
        g_assert_no_error(error);
        environment = g_get_environ();
        environment = g_environ_setenv(environment, "XDG_RUNTIME_DIR", runtime, TRUE);
        g_assert_true(g_spawn_sync(NULL,
                                   (gchar *[]){(gchar *)dispatcher, "--scope=user", "--config-file", config_file,
                                               "--pid-file", pid_file, NULL},
                                   environment, G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL,
                                   NULL, NULL, &status, &error));
        g_assert_no_error(error);
        g_assert_true(WIFEXITED(status));
        g_assert_cmpint(WEXITSTATUS(status), ==, 0);
        g_assert_cmpint(lstat(socket_path, &socket_stat), ==, 0);
        g_assert_true(S_ISSOCK(socket_stat.st_mode));
        g_assert_true(g_file_get_contents(pid_file, &pid_contents, NULL, &error));
        g_assert_no_error(error);
        errno = 0;
        parsed_pid = g_ascii_strtoll(pid_contents, &end, 10);
        g_assert_cmpint(errno, ==, 0);
        g_assert_true(end != pid_contents && (*end == '\n' || *end == '\0'));
        g_assert_cmpint(parsed_pid, >, 1);
        g_assert_cmpint(kill((pid_t)parsed_pid, SIGTERM), ==, 0);
        for (guint attempt = 0; attempt < 500 && (g_file_test(socket_path, G_FILE_TEST_EXISTS) ||
                                                  g_file_test(pid_file, G_FILE_TEST_EXISTS));
             ++attempt)
                g_usleep(10 * 1000);
        g_assert_false(g_file_test(socket_path, G_FILE_TEST_EXISTS));
        g_assert_false(g_file_test(pid_file, G_FILE_TEST_EXISTS));

        /* A daemonized start must propagate post-fork initialization errors
         * to its caller instead of reporting a false successful start. */
        g_assert_true(g_file_set_contents(socket_path, "occupied", -1, &error));
        g_assert_no_error(error);
        g_assert_true(g_spawn_sync(NULL,
                                   (gchar *[]){(gchar *)dispatcher, "--scope=user", "--config-file", config_file,
                                               "--pid-file", pid_file, NULL},
                                   environment, G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL,
                                   NULL, NULL, &status, &error));
        g_assert_no_error(error);
        g_assert_true(WIFEXITED(status));
        g_assert_cmpint(WEXITSTATUS(status), ==, 1);
        g_assert_false(g_file_test(pid_file, G_FILE_TEST_EXISTS));
        g_assert_cmpint(g_remove(socket_path), ==, 0);

        g_strfreev(environment);
        g_free(pid_contents);
        g_assert_cmpint(g_remove(config_file), ==, 0);
        g_assert_cmpint(g_rmdir(runtime), ==, 0);
        g_free(config_contents);
        g_free(socket_path);
        g_free(pid_file);
        g_free(config_file);
        g_free(runtime);
}

int main(int argc, char **argv)
{
        g_test_init(&argc, &argv, NULL);
        g_assert_cmpint(argc, ==, 2);
        g_test_add_data_func("/session-bus/connect-and-list", argv[1], test_session_bus);
        g_test_add_data_func("/session-bus/daemon-startup", argv[1], test_daemon_startup);
        return g_test_run();
}
