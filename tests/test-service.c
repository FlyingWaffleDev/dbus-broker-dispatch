#include "service.h"

#include <glib/gstdio.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_service(const gchar *directory, const gchar *filename, const gchar *contents)
{
        GError *error = NULL;
        gchar *path = g_build_filename(directory, filename, NULL);

        g_assert_true(g_file_set_contents(path, contents, -1, &error));
        g_assert_no_error(error);
        g_free(path);
}

static void remove_service(const gchar *directory, const gchar *filename)
{
        gchar *path = g_build_filename(directory, filename, NULL);
        g_assert_cmpint(g_remove(path), ==, 0);
        g_free(path);
}

static void test_invalid_entries_do_not_abort_scan(void)
{
        GError *error = NULL;
        gchar *directory = g_dir_make_tmp("broker-service-test-XXXXXX", &error);
        GPtrArray *directories = g_ptr_array_new_with_free_func(g_free);
        GHashTable *services = service_table_new();
        NssCache *nss = nss_cache_new();

        g_assert_no_error(error);
        g_ptr_array_add(directories, g_strdup(directory));
        write_service(directory, "org.example.Good.service",
                      "[D-BUS Service]\nName=org.example.Good\nExec=/bin/true\n");
        write_service(directory, "org.example.Unknown.service",
                      "[D-BUS Service]\nName=org.example.Unknown\nExec=/bin/true\n"
                      "User=this-user-must-not-exist-68f7\n");
        write_service(directory, "wrong.service",
                      "[D-BUS Service]\nName=org.example.Mismatch\nExec=/bin/true\n");
        write_service(directory, "org.example.MissingExec.service",
                      "[D-BUS Service]\nName=org.example.MissingExec\n");

        g_test_expect_message(NULL, G_LOG_LEVEL_WARNING, "*this-user-must-not-exist-68f7*");
        g_test_expect_message(NULL, G_LOG_LEVEL_WARNING, "*filename does not match*");
        g_test_expect_message(NULL, G_LOG_LEVEL_WARNING, "*missing Exec*");
        g_assert_true(service_table_scan(directories, nss, FALSE, services, &error));
        g_test_assert_expected_messages();
        g_assert_no_error(error);
        g_assert_cmpuint(g_hash_table_size(services), ==, 1);

        remove_service(directory, "org.example.Good.service");
        remove_service(directory, "org.example.Unknown.service");
        remove_service(directory, "wrong.service");
        remove_service(directory, "org.example.MissingExec.service");
        g_assert_cmpint(g_rmdir(directory), ==, 0);
        nss_cache_free(nss);
        g_hash_table_unref(services);
        g_ptr_array_unref(directories);
        g_free(directory);
}

static void test_inaccessible_directory_is_optional(void)
{
        GError *error = NULL;
        gchar *directory = g_dir_make_tmp("broker-service-permission-test-XXXXXX", &error);
        GPtrArray *directories = g_ptr_array_new_with_free_func(g_free);
        GHashTable *services = service_table_new();
        NssCache *nss = nss_cache_new();

        g_assert_no_error(error);
        if (geteuid() == 0) {
                g_test_skip("root can traverse a mode-000 service directory");
                goto out;
        }
        g_ptr_array_add(directories, g_strdup(directory));
        g_assert_cmpint(chmod(directory, 0000), ==, 0);
        g_test_expect_message(NULL, G_LOG_LEVEL_WARNING, "*Cannot access D-Bus service directory*");
        g_assert_true(service_table_scan(directories, nss, FALSE, services, &error));
        g_test_assert_expected_messages();
        g_assert_no_error(error);
        g_assert_cmpuint(g_hash_table_size(services), ==, 0);
        g_assert_cmpint(chmod(directory, 0700), ==, 0);

out:
        g_assert_cmpint(g_rmdir(directory), ==, 0);
        nss_cache_free(nss);
        g_hash_table_unref(services);
        g_ptr_array_unref(directories);
        g_free(directory);
}

int main(int argc, char **argv)
{
        g_test_init(&argc, &argv, NULL);
        g_test_add_func("/service/invalid-entries", test_invalid_entries_do_not_abort_scan);
        g_test_add_func("/service/inaccessible-directory", test_inaccessible_directory_is_optional);
        return g_test_run();
}
