#include "nss-cache.h"

#include <pwd.h>

static void test_identity_snapshot(void)
{
        struct passwd *current = getpwuid(getuid());
        NssCache *cache = nss_cache_new();
        const NssUser *by_name;
        const NssUser *by_id;
        NssUser *retained;
        gchar *numeric;
        GError *error = NULL;
        gsize n_groups;

        g_assert_nonnull(current);
        by_name = nss_cache_lookup_user(cache, current->pw_name, &error);
        g_assert_no_error(error);
        g_assert_nonnull(by_name);
        numeric = g_strdup_printf("%u", (guint)getuid());
        by_id = nss_cache_lookup_user(cache, numeric, &error);
        g_assert_no_error(error);
        g_assert_true(by_name == by_id);
        g_assert_cmpuint(nss_user_uid(by_name), ==, getuid());
        g_assert_nonnull(nss_user_groups(by_name, &n_groups));
        g_assert_cmpuint(n_groups, >, 0);

        retained = nss_user_ref(by_name);
        nss_cache_free(cache);
        g_assert_cmpstr(nss_user_name(retained), ==, current->pw_name);
        g_assert_cmpuint(nss_user_uid(retained), ==, getuid());
        nss_user_unref(retained);
        g_free(numeric);
}

static void test_negative_cache(void)
{
        NssCache *cache = nss_cache_new();
        GError *error = NULL;

        g_assert_null(nss_cache_lookup_user(cache, "this-user-must-not-exist-9731", &error));
        g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
        g_clear_error(&error);
        g_assert_null(nss_cache_lookup_user(cache, "this-user-must-not-exist-9731", &error));
        g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
        g_clear_error(&error);
        nss_cache_free(cache);
}

int main(int argc, char **argv)
{
        g_test_init(&argc, &argv, NULL);
        g_test_add_func("/nss-cache/identity-snapshot", test_identity_snapshot);
        g_test_add_func("/nss-cache/negative-cache", test_negative_cache);
        return g_test_run();
}
