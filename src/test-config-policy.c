#include "config-policy.h"

#include <glib.h>
#include <glib/gstdio.h>

static void test_system_config(void) {
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
        g_assert_true(g_variant_is_of_type(policy, G_VARIANT_TYPE("(a(u(bta(btbs)a(btssssuutt)a(btssssuutt)))a(buu(bta(btbs)a(btssssuutt)a(btssssuutt)))a(ss)bs)")));
        g_variant_unref(policy);
        launcher_config_free(config);
}

static void test_include_and_policy(void) {
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
        g_assert_true(g_file_set_contents(dropin,
                                          "<busconfig><policy user='root'><allow own='org.example.Test'/></policy></busconfig>",
                                          -1, &error));
        g_assert_no_error(error);
        g_assert_true(g_file_set_contents(root,
                                          "<busconfig><listen>unix:path=/tmp/openrc-dbus-test</listen><servicedir>/tmp/services</servicedir><include>dropin.conf</include><policy context='default'><allow user='*'/><deny send_type='method_call'/><allow send_destination='org.freedesktop.DBus'/><allow receive_type='method_call'/></policy></busconfig>",
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

int main(int argc, char **argv) {
        g_test_init(&argc, &argv, NULL);
        g_test_add_func("/config-policy/system-config", test_system_config);
        g_test_add_func("/config-policy/include-and-policy", test_include_and_policy);
        return g_test_run();
}
