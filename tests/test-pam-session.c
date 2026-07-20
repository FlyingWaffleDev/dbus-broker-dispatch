#define _GNU_SOURCE
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

static int conversation(int count, const struct pam_message **messages, struct pam_response **responses, void *data)
{
        (void)count;
        (void)messages;
        (void)responses;
        (void)data;
        return PAM_CONV_ERR;
}

static pam_handle_t *new_handle(const gchar *runtime, const gchar *configuration_directory)
{
        const struct pam_conv conv = {.conv = conversation};
        struct passwd *entry = getpwuid(getuid());
        pam_handle_t *pamh = NULL;
        gchar *assignment;

        g_assert_nonnull(entry);
        g_assert_cmpint(pam_start_confdir("dispatch-test", entry->pw_name, &conv, configuration_directory, &pamh),
                        ==, PAM_SUCCESS);
        assignment = g_strdup_printf("XDG_RUNTIME_DIR=%s", runtime);
        g_assert_cmpint(pam_putenv(pamh, assignment), ==, PAM_SUCCESS);
        g_free(assignment);
        return pamh;
}

static gchar *read_pid(const gchar *path)
{
        gchar *contents = NULL;
        GError *error = NULL;
        g_assert_true(g_file_get_contents(path, &contents, NULL, &error));
        g_assert_no_error(error);
        return contents;
}

static void wait_until_absent(const gchar *path)
{
        for (guint attempt = 0; attempt < 500 && g_file_test(path, G_FILE_TEST_EXISTS); ++attempt)
                g_usleep(10 * 1000);
        g_assert_false(g_file_test(path, G_FILE_TEST_EXISTS));
}

static void test_shared_session_bus(gconstpointer data)
{
        gchar **programs = (gchar **)data;
        const gchar *module = programs[0], *dispatcher = programs[1];
        gchar *runtime, *pam_config, *config, *pid_path, *socket_path, *state_path, *contents;
        gchar *expected_address, *escaped_socket;
        gchar *first_pid, *second_pid;
        const gchar *arguments[2];
        pam_handle_t *first, *second;
        GError *error = NULL;

        runtime = g_dir_make_tmp("broker,dispatch-pam-test-XXXXXX", &error);
        g_assert_no_error(error);
        g_assert_cmpint(chmod(runtime, 0700), ==, 0);
        config = g_build_filename(runtime, "session.conf", NULL);
        pam_config = g_build_filename(runtime, "dispatch-test", NULL);
        pid_path = g_build_filename(runtime, "dbus-broker-dispatch.pid", NULL);
        socket_path = g_build_filename(runtime, "bus", NULL);
        state_path = g_build_filename(runtime, ".dbus-broker-dispatch.pam", NULL);
        escaped_socket = g_dbus_address_escape_value(socket_path);
        contents = g_strdup_printf("<busconfig><listen>unix:path=%s</listen>"
                                   "<policy context='default'><allow user='*'/><allow own='*'/>"
                                   "<allow send_destination='*'/><allow receive_sender='*'/></policy></busconfig>",
                                   escaped_socket);
        g_assert_true(g_file_set_contents(config, contents, -1, &error));
        g_assert_no_error(error);
        arguments[0] = g_strdup_printf("dispatcher=%s", dispatcher);
        arguments[1] = g_strdup_printf("config-file=%s", config);
        gchar *pam_contents = g_strdup_printf("session required %s %s %s\n", module, arguments[0], arguments[1]);
        g_assert_true(g_file_set_contents(pam_config, pam_contents, -1, &error));
        g_assert_no_error(error);

        first = new_handle(runtime, runtime);
        g_assert_cmpint(pam_open_session(first, 0), ==, PAM_SUCCESS);
        expected_address = g_strdup_printf("unix:path=%s", escaped_socket);
        g_assert_cmpstr(pam_getenv(first, "DBUS_SESSION_BUS_ADDRESS"), ==, expected_address);
        g_assert_true(g_file_test(socket_path, G_FILE_TEST_EXISTS));
        first_pid = read_pid(pid_path);

        second = new_handle(runtime, runtime);
        g_assert_cmpint(pam_open_session(second, 0), ==, PAM_SUCCESS);
        second_pid = read_pid(pid_path);
        g_assert_cmpstr(first_pid, ==, second_pid);

        g_assert_cmpint(pam_close_session(first, 0), ==, PAM_SUCCESS);
        g_assert_true(g_file_test(socket_path, G_FILE_TEST_EXISTS));
        g_assert_cmpint(pam_end(first, PAM_SUCCESS), ==, PAM_SUCCESS);
        g_assert_cmpint(pam_close_session(second, 0), ==, PAM_SUCCESS);
        g_assert_cmpint(pam_end(second, PAM_SUCCESS), ==, PAM_SUCCESS);
        wait_until_absent(socket_path);
        wait_until_absent(pid_path);

        g_assert_cmpint(g_remove(config), ==, 0);
        g_assert_cmpint(g_remove(pam_config), ==, 0);
        if (g_file_test(state_path, G_FILE_TEST_EXISTS))
                g_assert_cmpint(g_remove(state_path), ==, 0);
        g_assert_cmpint(g_rmdir(runtime), ==, 0);
        g_free((gpointer)arguments[0]);
        g_free((gpointer)arguments[1]);
        g_free(expected_address);
        g_free(escaped_socket);
        g_free(first_pid);
        g_free(second_pid);
        g_free(contents);
        g_free(pam_contents);
        g_free(state_path);
        g_free(socket_path);
        g_free(pid_path);
        g_free(config);
        g_free(pam_config);
        g_free(runtime);
}

static void test_rejects_unsafe_runtime(gconstpointer data)
{
        gchar **programs = (gchar **)data;
        const gchar *module = programs[0], *dispatcher = programs[1];
        gchar *runtime, *pam_config, *pam_contents;
        pam_handle_t *pamh;
        GError *error = NULL;

        runtime = g_dir_make_tmp("broker-dispatch-pam-unsafe-XXXXXX", &error);
        g_assert_no_error(error);
        g_assert_cmpint(chmod(runtime, 0755), ==, 0);
        pam_config = g_build_filename(runtime, "dispatch-test", NULL);
        pam_contents = g_strdup_printf("session required %s dispatcher=%s\n", module, dispatcher);
        g_assert_true(g_file_set_contents(pam_config, pam_contents, -1, &error));
        g_assert_no_error(error);
        pamh = new_handle(runtime, runtime);
        g_assert_cmpint(pam_open_session(pamh, 0), ==, PAM_SESSION_ERR);
        g_assert_cmpint(pam_end(pamh, PAM_SUCCESS), ==, PAM_SUCCESS);
        g_assert_cmpint(g_remove(pam_config), ==, 0);
        g_assert_cmpint(g_rmdir(runtime), ==, 0);
        g_free(pam_contents);
        g_free(pam_config);
        g_free(runtime);
}

int main(int argc, char **argv)
{
        g_test_init(&argc, &argv, NULL);
        g_assert_cmpint(argc, ==, 3);
        g_test_add_data_func("/pam-session/shared-bus", &argv[1], test_shared_session_bus);
        g_test_add_data_func("/pam-session/unsafe-runtime", &argv[1], test_rejects_unsafe_runtime);
        return g_test_run();
}
