#define _GNU_SOURCE
#include "nss-cache.h"
#include "util.h"

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSS_NOT_FOUND NSS_ERROR_NOT_FOUND
#define NSS_INVALID_DATA NSS_ERROR_INVALID_DATA

struct NssUser {
        atomic_uint ref_count;
        char *name;
        char *home;
        char *shell;
        uid_t uid;
        gid_t gid;
        gid_t *groups;
        size_t n_groups;
};

struct NssCache {
        StrMap users_by_name;
        U32Map users_by_uid;
        StrMap uids_by_name;
        U32Map uids_by_uid;
        StrMap groups_by_name;
        U32Map groups_by_gid;
        StrMap missing_users;
        StrMap missing_groups;
        bool passwd_loaded;
        bool group_loaded;
};

static size_t nss_buffer_size(int key)
{
        long size = sysconf(key);
        return size > 0 && size < 1024 * 1024 ? (size_t)size : 16384;
}

static int compare_gids(const void *left, const void *right)
{
        gid_t a = *(const gid_t *)left, b = *(const gid_t *)right;
        return (a > b) - (a < b);
}

static bool resize_buffer(char **buffer, size_t size, Error **error)
{
        char *replacement = realloc(*buffer, size);
        if (!replacement) {
                error_set(error, ENOMEM, "NSS lookup: out of memory");
                return false;
        }
        *buffer = replacement;
        return true;
}

static bool lookup_passwd(const char *name, bool by_id, uid_t uid, struct passwd *entry, char **buffer, Error **error)
{
        size_t size = nss_buffer_size(_SC_GETPW_R_SIZE_MAX);
        struct passwd *result = NULL;

        for (;;) {
                int r;
                if (!resize_buffer(buffer, size, error))
                        return false;
                r = by_id ? getpwuid_r(uid, entry, *buffer, size, &result)
                          : getpwnam_r(name, entry, *buffer, size, &result);
                if (r == ERANGE && size < 16 * 1024 * 1024) {
                        size *= 2;
                        continue;
                }
                if (r)
                        return error_set_errno(error, r, "NSS user lookup for '%s'", name);
                if (!result)
                        return error_set(error, NSS_NOT_FOUND, "NSS user '%s' was not found", name);
                return true;
        }
}

static bool lookup_group(const char *name, bool by_id, gid_t gid, struct group *entry, char **buffer, Error **error)
{
        size_t size = nss_buffer_size(_SC_GETGR_R_SIZE_MAX);
        struct group *result = NULL;

        for (;;) {
                int r;
                if (!resize_buffer(buffer, size, error))
                        return false;
                r = by_id ? getgrgid_r(gid, entry, *buffer, size, &result)
                          : getgrnam_r(name, entry, *buffer, size, &result);
                if (r == ERANGE && size < 16 * 1024 * 1024) {
                        size *= 2;
                        continue;
                }
                if (r)
                        return error_set_errno(error, r, "NSS group lookup for '%s'", name);
                if (!result)
                        return error_set(error, NSS_NOT_FOUND, "NSS group '%s' was not found", name);
                return true;
        }
}

NssUser *nss_user_ref(const NssUser *user)
{
        if (user)
                atomic_fetch_add_explicit((atomic_uint *)&user->ref_count, 1, memory_order_relaxed);
        return (NssUser *)user;
}

void nss_user_unref(NssUser *user)
{
        if (!user || atomic_fetch_sub_explicit(&user->ref_count, 1, memory_order_acq_rel) != 1)
                return;
        free(user->name);
        free(user->home);
        free(user->shell);
        free(user->groups);
        free(user);
}

static NssUser *nss_user_new(const struct passwd *entry, Error **error)
{
        NssUser *user;
        int needed = 16;
        gid_t *groups = NULL;

        if (!entry->pw_name || !*entry->pw_name || entry->pw_uid == (uid_t)-1 || entry->pw_gid == (gid_t)-1) {
                error_set(error, NSS_INVALID_DATA, "NSS returned an invalid user record");
                return NULL;
        }
        user = calloc(1, sizeof(*user));
        if (!user) {
                error_set(error, ENOMEM, "NSS user: out of memory");
                return NULL;
        }
        atomic_init(&user->ref_count, 1);
        user->name = strdup(entry->pw_name);
        user->home = strdup(entry->pw_dir && *entry->pw_dir ? entry->pw_dir : "/");
        user->shell = strdup(entry->pw_shell && *entry->pw_shell ? entry->pw_shell : "/bin/sh");
        user->uid = entry->pw_uid;
        user->gid = entry->pw_gid;
        if (!user->name || !user->home || !user->shell) {
                error_set(error, ENOMEM, "NSS user: out of memory");
                nss_user_unref(user);
                return NULL;
        }
        for (;;) {
                gid_t *resized = realloc(groups, (size_t)needed * sizeof(*groups));
                if (!resized) {
                        free(groups);
                        error_set(error, ENOMEM, "NSS supplementary groups: out of memory");
                        nss_user_unref(user);
                        return NULL;
                }
                groups = resized;
                int available = needed;
                if (getgrouplist(user->name, user->gid, groups, &available) >= 0) {
                        user->groups = groups;
                        user->n_groups = (size_t)available;
                        break;
                }
                if (available <= needed || available > 65536) {
                        free(groups);
                        error_set(error, NSS_INVALID_DATA, "NSS returned an invalid supplementary-group list for '%s'",
                                  user->name);
                        nss_user_unref(user);
                        return NULL;
                }
                needed = available;
        }
        if (user->n_groups > 1)
                qsort(user->groups, user->n_groups, sizeof(*user->groups), compare_gids);
        size_t out = 0;
        for (size_t i = 0; i < user->n_groups; ++i)
                if (!out || user->groups[i] != user->groups[out - 1])
                        user->groups[out++] = user->groups[i];
        user->n_groups = out;
        return user;
}

static void user_destroy(void *data)
{
        nss_user_unref(data);
}

static void cache_store_uid(NssCache *cache, const char *name, uid_t uid)
{
        if (!str_map_contains(&cache->uids_by_name, name)) {
                uid_t *value = malloc(sizeof(*value));
                if (value) {
                        *value = uid;
                        if (!str_map_set(&cache->uids_by_name, name, value))
                                free(value);
                }
        }
        if (!u32_map_contains(&cache->uids_by_uid, (uint32_t)uid)) {
                uid_t *value = malloc(sizeof(*value));
                if (value) {
                        *value = uid;
                        if (!u32_map_set(&cache->uids_by_uid, (uint32_t)uid, value))
                                free(value);
                }
        }
}

static void cache_store_gid(NssCache *cache, const char *name, gid_t gid)
{
        if (!str_map_contains(&cache->groups_by_name, name)) {
                gid_t *value = malloc(sizeof(*value));
                if (value) {
                        *value = gid;
                        if (!str_map_set(&cache->groups_by_name, name, value))
                                free(value);
                }
        }
        if (!u32_map_contains(&cache->groups_by_gid, (uint32_t)gid)) {
                gid_t *value = malloc(sizeof(*value));
                if (value) {
                        *value = gid;
                        if (!u32_map_set(&cache->groups_by_gid, (uint32_t)gid, value))
                                free(value);
                }
        }
}

/* Pre-load local /etc/passwd and /etc/group entries so policy UID/GID lookups
 * avoid glibc NSS and getgrouplist() calls at boot time (matching dbus-broker).
 * Misses still fall back to getpwnam_r()/getgrnam_r(). */
static void nss_cache_populate_passwd(NssCache *cache)
{
        FILE *file;
        char *line = NULL;
        size_t capacity = 0;

        if (cache->passwd_loaded)
                return;
        cache->passwd_loaded = true;
        file = fopen("/etc/passwd", "re");
        if (file) {
                while (getline(&line, &capacity, file) >= 0) {
                        char *colon1, *colon2, *colon3;
                        uint64_t parsed = 0;
                        if (!*line || *line == '#' || *line == '+' || *line == '-')
                                continue;
                        colon1 = strchr(line, ':');
                        if (!colon1 || colon1 == line)
                                continue;
                        colon2 = strchr(colon1 + 1, ':');
                        if (!colon2)
                                continue;
                        colon3 = strchr(colon2 + 1, ':');
                        if (!colon3)
                                continue;
                        *colon1 = '\0';
                        *colon3 = '\0';
                        if (parse_u64(colon2 + 1, UINT32_MAX - 1, &parsed))
                                cache_store_uid(cache, line, (uid_t)parsed);
                }
                free(line);
                fclose(file);
        }
        cache_store_uid(cache, "root", 0);
}

static void nss_cache_populate_group(NssCache *cache)
{
        FILE *file;
        char *line = NULL;
        size_t capacity = 0;

        if (cache->group_loaded)
                return;
        cache->group_loaded = true;
        file = fopen("/etc/group", "re");
        if (file) {
                while (getline(&line, &capacity, file) >= 0) {
                        char *colon1, *colon2, *colon3;
                        uint64_t parsed = 0;
                        if (!*line || *line == '#' || *line == '+' || *line == '-')
                                continue;
                        colon1 = strchr(line, ':');
                        if (!colon1 || colon1 == line)
                                continue;
                        colon2 = strchr(colon1 + 1, ':');
                        if (!colon2)
                                continue;
                        colon3 = strchr(colon2 + 1, ':');
                        if (!colon3)
                                continue;
                        *colon1 = '\0';
                        *colon3 = '\0';
                        if (parse_u64(colon2 + 1, UINT32_MAX - 1, &parsed))
                                cache_store_gid(cache, line, (gid_t)parsed);
                }
                free(line);
                fclose(file);
        }
        cache_store_gid(cache, "root", 0);
}

NssCache *nss_cache_new(void)
{
        NssCache *cache = calloc(1, sizeof(*cache));
        if (!cache)
                return NULL;
        str_map_init(&cache->users_by_name, user_destroy);
        u32_map_init(&cache->users_by_uid, user_destroy);
        str_map_init(&cache->uids_by_name, free);
        u32_map_init(&cache->uids_by_uid, free);
        str_map_init(&cache->groups_by_name, free);
        u32_map_init(&cache->groups_by_gid, free);
        str_map_init(&cache->missing_users, NULL);
        str_map_init(&cache->missing_groups, NULL);
        return cache;
}

void nss_cache_free(NssCache *cache)
{
        if (!cache)
                return;
        str_map_clear(&cache->users_by_name);
        u32_map_clear(&cache->users_by_uid);
        str_map_clear(&cache->uids_by_name);
        u32_map_clear(&cache->uids_by_uid);
        str_map_clear(&cache->groups_by_name);
        u32_map_clear(&cache->groups_by_gid);
        str_map_clear(&cache->missing_users);
        str_map_clear(&cache->missing_groups);
        free(cache);
}

const NssUser *nss_cache_lookup_user(NssCache *cache, const char *name, Error **error)
{
        uint64_t parsed = 0;
        bool by_id;
        NssUser *user;
        char *buffer = NULL;
        struct passwd entry;
        Error *local_error = NULL;

        if (!cache || !name) {
                error_set(error, EINVAL, "Invalid NSS user lookup");
                return NULL;
        }
        by_id = parse_u64(name, UINT32_MAX - 1, &parsed);
        user = by_id ? u32_map_get(&cache->users_by_uid, (uint32_t)parsed) : str_map_get(&cache->users_by_name, name);
        if (user)
                return user;
        if (str_map_contains(&cache->missing_users, name)) {
                error_set(error, NSS_NOT_FOUND, "NSS user '%s' was not found", name);
                return NULL;
        }
        if (!lookup_passwd(name, by_id, (uid_t)parsed, &entry, &buffer, &local_error)) {
                if (local_error && local_error->code == NSS_NOT_FOUND)
                        str_map_set(&cache->missing_users, name, NULL);
                if (error)
                        *error = local_error;
                else
                        error_free(local_error);
                free(buffer);
                return NULL;
        }
        /* Match by canonical name so aliased UIDs (such as root and toor) keep
         * distinct home, shell, and supplementary-group records. */
        user = entry.pw_name ? str_map_get(&cache->users_by_name, entry.pw_name) : NULL;
        if (!user) {
                user = nss_user_new(&entry, error);
                if (!user) {
                        free(buffer);
                        return NULL;
                }
                if (!str_map_set(&cache->users_by_name, user->name, user)) {
                        nss_user_unref(user);
                        free(buffer);
                        error_set(error, ENOMEM, "NSS cache: out of memory");
                        return NULL;
                }
        }
        if (!u32_map_contains(&cache->users_by_uid, (uint32_t)user->uid)) {
                NssUser *ref = nss_user_ref(user);
                if (!u32_map_set(&cache->users_by_uid, (uint32_t)user->uid, ref))
                        nss_user_unref(ref);
        }
        if (!by_id && !str_map_contains(&cache->users_by_name, name)) {
                NssUser *ref = nss_user_ref(user);
                if (!str_map_set(&cache->users_by_name, name, ref))
                        nss_user_unref(ref);
        }
        cache_store_uid(cache, user->name, user->uid);
        if (!by_id && strcmp(name, user->name) != 0)
                cache_store_uid(cache, name, user->uid);
        free(buffer);
        return user;
}

bool nss_cache_lookup_uid(NssCache *cache, const char *name, uid_t *uid, Error **error)
{
        uint64_t parsed = 0;
        bool by_id;
        uid_t *stored;
        const NssUser *user;
        char *buffer = NULL;
        struct passwd entry;
        Error *local_error = NULL;

        if (!cache || !name || !uid)
                return error_set(error, EINVAL, "Invalid NSS user lookup");
        nss_cache_populate_passwd(cache);
        by_id = parse_u64(name, UINT32_MAX - 1, &parsed);
        stored = by_id ? u32_map_get(&cache->uids_by_uid, (uint32_t)parsed) : str_map_get(&cache->uids_by_name, name);
        if (stored) {
                *uid = *stored;
                return true;
        }
        user = by_id ? u32_map_get(&cache->users_by_uid, (uint32_t)parsed) : str_map_get(&cache->users_by_name, name);
        if (user) {
                *uid = user->uid;
                return true;
        }
        if (str_map_contains(&cache->missing_users, name))
                return error_set(error, NSS_NOT_FOUND, "NSS user '%s' was not found", name);
        if (!lookup_passwd(name, by_id, (uid_t)parsed, &entry, &buffer, &local_error)) {
                if (local_error && local_error->code == NSS_NOT_FOUND)
                        str_map_set(&cache->missing_users, name, NULL);
                if (error)
                        *error = local_error;
                else
                        error_free(local_error);
                free(buffer);
                return false;
        }
        if (entry.pw_uid == (uid_t)-1 || !entry.pw_name || !*entry.pw_name) {
                free(buffer);
                return error_set(error, NSS_INVALID_DATA, "NSS returned an invalid user record for '%s'", name);
        }
        *uid = entry.pw_uid;
        cache_store_uid(cache, entry.pw_name, entry.pw_uid);
        if (!by_id && strcmp(name, entry.pw_name) != 0)
                cache_store_uid(cache, name, entry.pw_uid);
        free(buffer);
        return true;
}

bool nss_cache_lookup_gid(NssCache *cache, const char *name, gid_t *gid, Error **error)
{
        uint64_t parsed = 0;
        bool by_id;
        gid_t *stored;
        char *buffer = NULL;
        struct group entry;
        Error *local_error = NULL;

        if (!cache || !name || !gid)
                return error_set(error, EINVAL, "Invalid NSS group lookup");
        nss_cache_populate_group(cache);
        by_id = parse_u64(name, UINT32_MAX - 1, &parsed);
        stored = by_id ? u32_map_get(&cache->groups_by_gid, (uint32_t)parsed)
                       : str_map_get(&cache->groups_by_name, name);
        if (stored) {
                *gid = *stored;
                return true;
        }
        if (str_map_contains(&cache->missing_groups, name))
                return error_set(error, NSS_NOT_FOUND, "NSS group '%s' was not found", name);
        if (!lookup_group(name, by_id, (gid_t)parsed, &entry, &buffer, &local_error)) {
                if (local_error && local_error->code == NSS_NOT_FOUND)
                        str_map_set(&cache->missing_groups, name, NULL);
                if (error)
                        *error = local_error;
                else
                        error_free(local_error);
                free(buffer);
                return false;
        }
        if (entry.gr_gid == (gid_t)-1 || !entry.gr_name || !*entry.gr_name) {
                free(buffer);
                return error_set(error, NSS_INVALID_DATA, "NSS returned an invalid group record for '%s'", name);
        }
        *gid = entry.gr_gid;
        cache_store_gid(cache, entry.gr_name, entry.gr_gid);
        if (!by_id && strcmp(name, entry.gr_name) != 0)
                cache_store_gid(cache, name, entry.gr_gid);
        free(buffer);
        return true;
}

const char *nss_user_name(const NssUser *user)
{
        return user->name;
}
uid_t nss_user_uid(const NssUser *user)
{
        return user->uid;
}
gid_t nss_user_gid(const NssUser *user)
{
        return user->gid;
}
const char *nss_user_home(const NssUser *user)
{
        return user->home;
}
const char *nss_user_shell(const NssUser *user)
{
        return user->shell;
}
const gid_t *nss_user_groups(const NssUser *user, size_t *n_groups)
{
        if (n_groups)
                *n_groups = user->n_groups;
        return user->groups;
}
