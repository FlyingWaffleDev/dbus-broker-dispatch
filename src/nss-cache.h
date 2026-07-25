#pragma once

#include <gio/gio.h>
#include <sys/types.h>

typedef struct NssCache NssCache;
typedef struct NssUser NssUser;

NssCache *nss_cache_new(void);
void nss_cache_free(NssCache *cache);

const NssUser *nss_cache_lookup_user(NssCache *cache, const gchar *name, GError **error);
gboolean nss_cache_lookup_uid(NssCache *cache, const gchar *name, uid_t *uid, GError **error);
gboolean nss_cache_lookup_gid(NssCache *cache, const gchar *name, gid_t *gid, GError **error);

NssUser *nss_user_ref(const NssUser *user);
void nss_user_unref(NssUser *user);
const gchar *nss_user_name(const NssUser *user);
uid_t nss_user_uid(const NssUser *user);
gid_t nss_user_gid(const NssUser *user);
const gchar *nss_user_home(const NssUser *user);
const gchar *nss_user_shell(const NssUser *user);
const gid_t *nss_user_groups(const NssUser *user, gsize *n_groups);
