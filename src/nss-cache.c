#define _GNU_SOURCE
#include "nss-cache.h"

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct NssUser {
        gint ref_count;
        gchar *name;
        gchar *home;
        gchar *shell;
        uid_t uid;
        gid_t gid;
        gid_t *groups;
        gsize n_groups;
};

struct NssCache {
        GHashTable *users_by_name;
        GHashTable *users_by_uid;
        GHashTable *groups_by_name;
        GHashTable *groups_by_gid;
        GHashTable *missing_users;
        GHashTable *missing_groups;
};

static gboolean parse_id(const gchar *name, guint64 maximum, guint64 *id)
{
        return name && *name && g_ascii_string_to_unsigned(name, 10, 0, maximum, id, NULL);
}

static gsize nss_buffer_size(gint key)
{
        long size = sysconf(key);
        return size > 0 && size < 1024 * 1024 ? (gsize)size : 16384;
}

static gint compare_gids(gconstpointer left, gconstpointer right)
{
        const gid_t a = *(const gid_t *)left;
        const gid_t b = *(const gid_t *)right;
        return (a > b) - (a < b);
}

static struct passwd *lookup_passwd(const gchar *name, gboolean by_id, uid_t uid, gchar **buffer, GError **error)
{
        gsize size = nss_buffer_size(_SC_GETPW_R_SIZE_MAX);
        struct passwd entry;
        struct passwd *result = NULL;

        for (;;) {
                gint r;
                *buffer = g_realloc(*buffer, size);
                errno = 0;
                r = by_id ? getpwuid_r(uid, &entry, *buffer, size, &result)
                          : getpwnam_r(name, &entry, *buffer, size, &result);
                if (r == ERANGE && size < 16 * 1024 * 1024) {
                        size *= 2;
                        continue;
                }
                if (r != 0) {
                        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(r), "NSS user lookup for '%s': %s",
                                    name, g_strerror(r));
                        return NULL;
                }
                if (!result)
                        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "NSS user '%s' was not found", name);
                return result ? g_memdup2(result, sizeof(*result)) : NULL;
        }
}

static struct group *lookup_group(const gchar *name, gboolean by_id, gid_t gid, gchar **buffer, GError **error)
{
        gsize size = nss_buffer_size(_SC_GETGR_R_SIZE_MAX);
        struct group entry;
        struct group *result = NULL;

        for (;;) {
                gint r;
                *buffer = g_realloc(*buffer, size);
                errno = 0;
                r = by_id ? getgrgid_r(gid, &entry, *buffer, size, &result)
                          : getgrnam_r(name, &entry, *buffer, size, &result);
                if (r == ERANGE && size < 16 * 1024 * 1024) {
                        size *= 2;
                        continue;
                }
                if (r != 0) {
                        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(r), "NSS group lookup for '%s': %s",
                                    name, g_strerror(r));
                        return NULL;
                }
                if (!result)
                        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "NSS group '%s' was not found", name);
                return result ? g_memdup2(result, sizeof(*result)) : NULL;
        }
}

NssUser *nss_user_ref(const NssUser *user)
{
        if (user)
                g_atomic_int_inc((gint *)&user->ref_count);
        return (NssUser *)user;
}

void nss_user_unref(NssUser *user)
{
        if (!user || !g_atomic_int_dec_and_test(&user->ref_count))
                return;
        g_free(user->name);
        g_free(user->home);
        g_free(user->shell);
        g_free(user->groups);
        g_free(user);
}

static NssUser *nss_user_new(const struct passwd *entry, GError **error)
{
        NssUser *user = g_new0(NssUser, 1);
        gint count = 0;

        if (!entry->pw_name || !*entry->pw_name || entry->pw_uid == (uid_t)-1 ||
            entry->pw_gid == (gid_t)-1) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                            "NSS returned an invalid user record");
                g_free(user);
                return NULL;
        }
        user->ref_count = 1;
        user->name = g_strdup(entry->pw_name);
        user->home = g_strdup(entry->pw_dir && *entry->pw_dir ? entry->pw_dir : "/");
        user->shell = g_strdup(entry->pw_shell && *entry->pw_shell ? entry->pw_shell : "/bin/sh");
        user->uid = entry->pw_uid;
        user->gid = entry->pw_gid;

        if (getgrouplist(user->name, user->gid, NULL, &count) >= 0 || count <= 0) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                            "NSS returned an invalid supplementary-group list for '%s'", user->name);
                nss_user_unref(user);
                return NULL;
        }
        user->groups = g_new(gid_t, count);
        if (getgrouplist(user->name, user->gid, user->groups, &count) < 0) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                            "NSS supplementary-group lookup for '%s' changed while being read", user->name);
                nss_user_unref(user);
                return NULL;
        }
        user->n_groups = count;
        qsort(user->groups, user->n_groups, sizeof(*user->groups), compare_gids);
        for (gsize index = 1; index < user->n_groups;) {
                if (user->groups[index] == user->groups[index - 1]) {
                        memmove(&user->groups[index], &user->groups[index + 1],
                                (user->n_groups - index - 1) * sizeof(*user->groups));
                        --user->n_groups;
                } else {
                        ++index;
                }
        }
        return user;
}

NssCache *nss_cache_new(void)
{
        NssCache *cache = g_new0(NssCache, 1);
        cache->users_by_name = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                                     (GDestroyNotify)nss_user_unref);
        cache->users_by_uid = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                                    (GDestroyNotify)nss_user_unref);
        cache->groups_by_name = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        cache->groups_by_gid = g_hash_table_new(g_direct_hash, g_direct_equal);
        cache->missing_users = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        cache->missing_groups = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        return cache;
}

void nss_cache_free(NssCache *cache)
{
        if (!cache)
                return;
        g_hash_table_unref(cache->users_by_name);
        g_hash_table_unref(cache->users_by_uid);
        g_hash_table_unref(cache->groups_by_name);
        g_hash_table_unref(cache->groups_by_gid);
        g_hash_table_unref(cache->missing_users);
        g_hash_table_unref(cache->missing_groups);
        g_free(cache);
}

const NssUser *nss_cache_lookup_user(NssCache *cache, const gchar *name, GError **error)
{
        NssUser *user;
        guint64 parsed;
        gboolean by_id = parse_id(name, G_MAXUINT32 - 1, &parsed);
        gpointer uid_key = GUINT_TO_POINTER((guint)parsed);
        gchar *buffer = NULL;
        struct passwd *entry;

        g_return_val_if_fail(cache && name, NULL);
        user = by_id ? g_hash_table_lookup(cache->users_by_uid, uid_key)
                     : g_hash_table_lookup(cache->users_by_name, name);
        if (user)
                return user;
        if (g_hash_table_contains(cache->missing_users, name)) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "NSS user '%s' was not found", name);
                return NULL;
        }

        entry = lookup_passwd(name, by_id, (uid_t)parsed, &buffer, error);
        if (!entry) {
                if (error && *error && g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND))
                        g_hash_table_add(cache->missing_users, g_strdup(name));
                g_free(buffer);
                return NULL;
        }
        user = g_hash_table_lookup(cache->users_by_uid, GUINT_TO_POINTER((guint)entry->pw_uid));
        if (user) {
                g_hash_table_replace(cache->users_by_name, g_strdup(entry->pw_name),
                                     nss_user_ref(user));
                if (!by_id)
                        g_hash_table_replace(cache->users_by_name, g_strdup(name),
                                             nss_user_ref(user));
                g_free(entry);
                g_free(buffer);
                return user;
        }
        user = nss_user_new(entry, error);
        g_free(entry);
        g_free(buffer);
        if (!user)
                return NULL;
        g_hash_table_insert(cache->users_by_name, g_strdup(user->name), nss_user_ref(user));
        if (!by_id && !g_str_equal(name, user->name))
                g_hash_table_insert(cache->users_by_name, g_strdup(name), nss_user_ref(user));
        g_hash_table_insert(cache->users_by_uid, GUINT_TO_POINTER((guint)user->uid), nss_user_ref(user));
        uid_t resolved_uid = user->uid;
        nss_user_unref(user);
        return g_hash_table_lookup(cache->users_by_uid, GUINT_TO_POINTER((guint)resolved_uid));
}

gboolean nss_cache_lookup_uid(NssCache *cache, const gchar *name, uid_t *uid, GError **error)
{
        const NssUser *user = nss_cache_lookup_user(cache, name, error);
        if (!user)
                return FALSE;
        *uid = user->uid;
        return TRUE;
}

gboolean nss_cache_lookup_gid(NssCache *cache, const gchar *name, gid_t *gid, GError **error)
{
        guint64 parsed;
        gboolean by_id = parse_id(name, G_MAXUINT32 - 1, &parsed);
        gpointer gid_key = GUINT_TO_POINTER((guint)parsed);
        gpointer stored;
        gchar *buffer = NULL;
        struct group *entry;

        g_return_val_if_fail(cache && name && gid, FALSE);
        stored = by_id ? g_hash_table_lookup(cache->groups_by_gid, gid_key)
                       : g_hash_table_lookup(cache->groups_by_name, name);
        if (stored) {
                *gid = GPOINTER_TO_UINT(stored) - 1;
                return TRUE;
        }
        if (g_hash_table_contains(cache->missing_groups, name)) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "NSS group '%s' was not found", name);
                return FALSE;
        }
        entry = lookup_group(name, by_id, (gid_t)parsed, &buffer, error);
        if (!entry) {
                if (error && *error && g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND))
                        g_hash_table_add(cache->missing_groups, g_strdup(name));
                g_free(buffer);
                return FALSE;
        }
        if (entry->gr_gid == (gid_t)-1 || !entry->gr_name || !*entry->gr_name) {
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                            "NSS returned an invalid group record for '%s'", name);
                g_free(entry);
                g_free(buffer);
                return FALSE;
        }
        *gid = entry->gr_gid;
        g_hash_table_insert(cache->groups_by_name, g_strdup(entry->gr_name),
                            GUINT_TO_POINTER((guint)entry->gr_gid + 1));
        if (!by_id && !g_str_equal(name, entry->gr_name))
                g_hash_table_insert(cache->groups_by_name, g_strdup(name),
                                    GUINT_TO_POINTER((guint)entry->gr_gid + 1));
        g_hash_table_insert(cache->groups_by_gid, GUINT_TO_POINTER((guint)entry->gr_gid),
                            GUINT_TO_POINTER((guint)entry->gr_gid + 1));
        g_free(entry);
        g_free(buffer);
        return TRUE;
}

const gchar *nss_user_name(const NssUser *user) { return user->name; }
uid_t nss_user_uid(const NssUser *user) { return user->uid; }
gid_t nss_user_gid(const NssUser *user) { return user->gid; }
const gchar *nss_user_home(const NssUser *user) { return user->home; }
const gchar *nss_user_shell(const NssUser *user) { return user->shell; }
const gid_t *nss_user_groups(const NssUser *user, gsize *n_groups)
{
        if (n_groups)
                *n_groups = user->n_groups;
        return user->groups;
}
