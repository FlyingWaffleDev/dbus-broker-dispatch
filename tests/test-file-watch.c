#include "file-watch.h"

#include <glib/gstdio.h>

static void changed(gpointer data)
{
        guint *count = data;
        ++*count;
}

static void test_initially_absent_directory(void)
{
        GError *error = NULL;
        gchar *root = g_dir_make_tmp("broker-file-watch-XXXXXX", &error);
        gchar *nested = g_build_filename(root, "dbus-1", "services", NULL);
        gchar *file = g_build_filename(nested, "org.example.Test.service", NULL);
        GPtrArray *paths = g_ptr_array_new_with_free_func(g_free);
        guint count = 0;
        FileWatch *watch = file_watch_new(changed, &count);

        g_assert_no_error(error);
        g_ptr_array_add(paths, g_strdup(nested));
        g_assert_true(file_watch_set_paths(watch, paths, &error));
        g_assert_no_error(error);
        g_assert_cmpint(g_mkdir_with_parents(nested, 0700), ==, 0);
        g_assert_true(g_file_set_contents(file, "changed", -1, &error));
        g_assert_no_error(error);
        for (guint attempt = 0; attempt < 200 && count == 0; ++attempt)
                g_main_context_iteration(NULL, TRUE);
        g_assert_cmpuint(count, >, 0);

        file_watch_free(watch);
        g_ptr_array_unref(paths);
        g_assert_cmpint(g_remove(file), ==, 0);
        g_assert_cmpint(g_rmdir(nested), ==, 0);
        g_free(nested);
        nested = g_build_filename(root, "dbus-1", NULL);
        g_assert_cmpint(g_rmdir(nested), ==, 0);
        g_assert_cmpint(g_rmdir(root), ==, 0);
        g_free(file);
        g_free(nested);
        g_free(root);
}

int main(int argc, char **argv)
{
        g_test_init(&argc, &argv, NULL);
        g_test_add_func("/file-watch/initially-absent-directory", test_initially_absent_directory);
        return g_test_run();
}
