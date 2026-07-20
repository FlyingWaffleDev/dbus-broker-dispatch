#include "config-policy.h"

#include <glib.h>
#include <glib/gstdio.h>

static void test_system_config(void)
{
        LauncherConfig *config;
        GError *error = NULL;
        GVariant *policy;

        if (!g_file_test("/usr/share/dbus-1/system.conf", G_FILE_TEST_EXISTS)) {
                g_test_skip("system.conf is not installed");
                return;
        }
        config = launcher_config_new();
        g_assert_true(launcher_config_load(config, "/usr/share/dbus-1/system.conf", &error));
        g_assert_no_error(error);
        policy = launcher_config_export_policy(config, FALSE, 999, NULL);
        g_assert_true(g_variant_is_of_type(policy, G_VARIANT_TYPE("(a(u(bta(btbs)a(btssssuutt)a(btssssuutt)))a(buu(bta("
                                                                  "btbs)a(btssssuutt)a(btssssuutt)))a(ss)bs)")));
        g_variant_unref(policy);
        launcher_config_free(config);
}

static void test_include_and_policy(void)
{
        LauncherConfig *config;
        GError *error = NULL;
        GVariant *policy;
        gchar *directory;
        gchar *root;
        gchar *dropin;

        directory = g_dir_make_tmp("openrc-dbus-broker-XXXXXX", &error);
        g_assert_no_error(error);
        root = g_build_filename(directory, "root.conf", NULL);
        dropin = g_build_filename(directory, "dropin.conf", NULL);
        g_assert_true(g_file_set_contents(
                dropin, "<busconfig><policy user='root'><allow own='org.example.Test'/></policy></busconfig>", -1,
                &error));
        g_assert_no_error(error);
        g_assert_true(g_file_set_contents(
                root,
                "<busconfig><listen>unix:path=/tmp/openrc-dbus-test</listen><servicedir>/tmp/services</"
                "servicedir><include>dropin.conf</include><policy context='default'><allow user='*'/><deny "
                "send_type='method_call'/><allow send_destination='org.freedesktop.DBus'/><allow "
                "receive_type='method_call'/></policy></busconfig>",
                -1, &error));
        g_assert_no_error(error);
        config = launcher_config_new();
        g_assert_true(launcher_config_load(config, root, &error));
        g_assert_no_error(error);
        g_assert_cmpstr(launcher_config_address(config), ==, "unix:path=/tmp/openrc-dbus-test");
        g_assert_cmpuint(launcher_config_service_dirs(config)->len, ==, 1);
        policy = launcher_config_export_policy(config, FALSE, 999, NULL);
        g_assert_true(g_variant_is_normal_form(policy));
        g_variant_unref(policy);
        launcher_config_free(config);
        g_assert_cmpint(g_remove(root), ==, 0);
        g_assert_cmpint(g_remove(dropin), ==, 0);
        g_assert_cmpint(g_rmdir(directory), ==, 0);
        g_free(root);
        g_free(dropin);
        g_free(directory);
}

static void test_invalid_include_fails(void)
{
        LauncherConfig *config;
        GError *error = NULL;
        gchar *directory = g_dir_make_tmp("broker-invalid-config-XXXXXX", &error);
        gchar *root;
        gchar *included;

        g_assert_no_error(error);
        root = g_build_filename(directory, "root.conf", NULL);
        included = g_build_filename(directory, "broken.conf", NULL);
        g_assert_true(g_file_set_contents(root, "<busconfig><include>broken.conf</include></busconfig>", -1, &error));
        g_assert_no_error(error);
        g_assert_true(g_file_set_contents(included, "<busconfig>", -1, &error));
        g_assert_no_error(error);
        config = launcher_config_new();
        g_assert_false(launcher_config_load(config, root, &error));
        g_assert_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE);
        g_clear_error(&error);
        launcher_config_free(config);
        g_assert_cmpint(g_remove(included), ==, 0);
        g_assert_cmpint(g_remove(root), ==, 0);
        g_assert_cmpint(g_rmdir(directory), ==, 0);
        g_free(included);
        g_free(root);
        g_free(directory);
}

static void test_unknown_identity_is_ignored(void)
{
        LauncherConfig *config;
        GVariant *policy;
        GError *error = NULL;
        gchar *directory = g_dir_make_tmp("broker-identity-config-XXXXXX", &error);
        gchar *root;
        gchar *printed;

        g_assert_no_error(error);
        root = g_build_filename(directory, "root.conf", NULL);
        g_assert_true(g_file_set_contents(root,
                                          "<busconfig><policy user='this-user-must-not-exist-7f31'><allow "
                                          "own='org.example.ShouldNotApply'/></policy>"
                                          "</busconfig>",
                                          -1, &error));
        g_assert_no_error(error);
        config = launcher_config_new();
        g_test_expect_message(NULL, G_LOG_LEVEL_WARNING, "*unknown user*");
        g_test_expect_message(NULL, G_LOG_LEVEL_WARNING, "*invalid D-Bus policy attribute combination*");
        g_assert_true(launcher_config_load(config, root, &error));
        g_test_assert_expected_messages();
        g_assert_no_error(error);
        policy = launcher_config_export_policy(config, FALSE, 999, NULL);
        printed = g_variant_print(policy, TRUE);
        g_assert_null(strstr(printed, "org.example.ShouldNotApply"));
        g_free(printed);
        g_variant_unref(policy);
        launcher_config_free(config);
        g_assert_cmpint(g_remove(root), ==, 0);
        g_assert_cmpint(g_rmdir(directory), ==, 0);
        g_free(root);
        g_free(directory);
}

static void test_standard_system_service_dirs(void)
{
        LauncherConfig *config;
        GPtrArray *dirs;
        GError *error = NULL;
        gchar *directory = g_dir_make_tmp("broker-service-dirs-XXXXXX", &error);
        gchar *root;

        g_assert_no_error(error);
        root = g_build_filename(directory, "root.conf", NULL);
        g_assert_true(g_file_set_contents(root, "<busconfig><standard_system_servicedirs/></busconfig>", -1, &error));
        g_assert_no_error(error);
        config = launcher_config_new();
        g_assert_true(launcher_config_load(config, root, &error));
        g_assert_no_error(error);
        dirs = launcher_config_service_dirs(config);
        g_assert_cmpuint(dirs->len, ==, 5);
        g_assert_cmpstr(g_ptr_array_index(dirs, 0), ==, "/etc/dbus-1/system-services");
        g_assert_cmpstr(g_ptr_array_index(dirs, 1), ==, "/run/dbus-1/system-services");
        g_assert_cmpstr(g_ptr_array_index(dirs, 4), ==, "/lib/dbus-1/system-services");
        launcher_config_free(config);
        g_assert_cmpint(g_remove(root), ==, 0);
        g_assert_cmpint(g_rmdir(directory), ==, 0);
        g_free(root);
        g_free(directory);
}

static void test_limits_and_apparmor(void)
{
        LauncherConfig *config;
        GError *error = NULL;
        gchar *directory = g_dir_make_tmp("broker-limits-XXXXXX", &error);
        gchar *root;

        g_assert_no_error(error);
        root = g_build_filename(directory, "root.conf", NULL);
        g_assert_true(g_file_set_contents(
                root,
                "<busconfig><apparmor mode='disabled'/><limit name='max_outgoing_bytes'>100</limit>"
                "<limit name='max_outgoing_unix_fds'>3</limit><limit name='max_connections_per_user'>4</limit>"
                "<limit name='max_match_rules_per_connection'>5</limit></busconfig>",
                -1, &error));
        g_assert_no_error(error);
        config = launcher_config_new();
        g_assert_true(launcher_config_load(config, root, &error));
        g_assert_no_error(error);
        g_assert_cmpuint(launcher_config_apparmor_mode(config), ==, 0);
        g_assert_cmpuint(launcher_config_max_bytes(config), ==, 400);
        g_assert_cmpuint(launcher_config_max_fds(config), ==, 12);
        g_assert_cmpuint(launcher_config_max_matches(config), ==, 20);
        launcher_config_free(config);
        g_assert_cmpint(g_remove(root), ==, 0);
        g_assert_cmpint(g_rmdir(directory), ==, 0);
        g_free(root);
        g_free(directory);
}

int main(int argc, char **argv)
{
        g_test_init(&argc, &argv, NULL);
        g_test_add_func("/config-policy/system-config", test_system_config);
        g_test_add_func("/config-policy/include-and-policy", test_include_and_policy);
        g_test_add_func("/config-policy/invalid-include", test_invalid_include_fails);
        g_test_add_func("/config-policy/unknown-identity", test_unknown_identity_is_ignored);
        g_test_add_func("/config-policy/standard-system-service-dirs", test_standard_system_service_dirs);
        g_test_add_func("/config-policy/limits-and-apparmor", test_limits_and_apparmor);
        return g_test_run();
}
