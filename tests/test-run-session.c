#include <glib.h>
#include <glib/gstdio.h>
#include <sys/wait.h>

static gchar **test_environment(const gchar *runtime, const gchar *launcher, const gchar *marker)
{
        gchar **environment = g_get_environ();
        gchar *launcher_dir = g_path_get_dirname(launcher);
        gchar *path = g_strdup_printf("%s:%s", launcher_dir, g_getenv("PATH"));

        environment = g_environ_setenv(environment, "XDG_RUNTIME_DIR", runtime, TRUE);
        environment = g_environ_setenv(environment, "PATH", path, TRUE);
        if (marker)
                environment = g_environ_setenv(environment, "MARKER", marker, TRUE);
        g_free(path);
        g_free(launcher_dir);
        return environment;
}

static void test_command_status(gconstpointer data)
{
        const gchar *const *programs = data;
        gchar *runtime, *marker, *socket_path, *expected, *contents = NULL;
        gchar **environment;
        GError *error = NULL;
        int status;

        runtime = g_dir_make_tmp("broker-run-session-XXXXXX", &error);
        g_assert_no_error(error);
        marker = g_build_filename(runtime, "address", NULL);
        socket_path = g_build_filename(runtime, "bus", NULL);
        environment = test_environment(runtime, programs[1], marker);
        g_assert_true(g_spawn_sync(NULL,
                                   (gchar *[]){(gchar *)programs[0], "--", "/bin/sh", "-c",
                                               "printf %s \"$DBUS_SESSION_BUS_ADDRESS\" > \"$MARKER\"; exit 42", NULL},
                                   environment, 0, NULL, NULL, NULL, NULL, &status, &error));
        g_assert_no_error(error);
        g_assert_true(WIFEXITED(status));
        g_assert_cmpint(WEXITSTATUS(status), ==, 42);
        g_assert_true(g_file_get_contents(marker, &contents, NULL, &error));
        g_assert_no_error(error);
        expected = g_strdup_printf("unix:path=%s", socket_path);
        g_assert_cmpstr(contents, ==, expected);
        g_assert_false(g_file_test(socket_path, G_FILE_TEST_EXISTS));

        g_strfreev(environment);
        g_free(expected);
        g_free(contents);
        g_assert_cmpint(g_remove(marker), ==, 0);
        g_assert_cmpint(g_rmdir(runtime), ==, 0);
        g_free(socket_path);
        g_free(marker);
        g_free(runtime);
}

static void test_existing_path(gconstpointer data)
{
        const gchar *const *programs = data;
        gchar *runtime, *socket_path, *contents = NULL;
        gchar **environment;
        GError *error = NULL;
        int status;

        runtime = g_dir_make_tmp("broker-run-session-XXXXXX", &error);
        g_assert_no_error(error);
        socket_path = g_build_filename(runtime, "bus", NULL);
        g_assert_true(g_file_set_contents(socket_path, "keep", -1, &error));
        g_assert_no_error(error);
        environment = test_environment(runtime, programs[1], NULL);
        g_assert_true(g_spawn_sync(NULL, (gchar *[]){(gchar *)programs[0], "--", "/bin/true", NULL}, environment,
                                   G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL, NULL, NULL,
                                   &status, &error));
        g_assert_no_error(error);
        g_assert_true(WIFEXITED(status));
        g_assert_cmpint(WEXITSTATUS(status), ==, 1);
        g_assert_true(g_file_get_contents(socket_path, &contents, NULL, &error));
        g_assert_no_error(error);
        g_assert_cmpstr(contents, ==, "keep");

        g_strfreev(environment);
        g_free(contents);
        g_assert_cmpint(g_remove(socket_path), ==, 0);
        g_assert_cmpint(g_rmdir(runtime), ==, 0);
        g_free(socket_path);
        g_free(runtime);
}

int main(int argc, char **argv)
{
        static const gchar *programs[2];

        g_test_init(&argc, &argv, NULL);
        g_assert_cmpint(argc, ==, 3);
        programs[0] = argv[1];
        programs[1] = argv[2];
        g_test_add_data_func("/run-session/command-status", programs, test_command_status);
        g_test_add_data_func("/run-session/existing-path", programs, test_existing_path);
        return g_test_run();
}
