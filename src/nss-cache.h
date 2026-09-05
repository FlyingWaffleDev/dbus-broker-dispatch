#pragma once

#include <sys/types.h>

#include "util.h"

typedef struct NssCache NssCache;
typedef struct NssUser NssUser;

enum {
        /* Keep semantic results distinct from positive errno values. */
        NSS_ERROR_NOT_FOUND = -1,
        NSS_ERROR_INVALID_DATA = -2,
};

NssCache *nss_cache_new(void);
void nss_cache_free(NssCache *cache);

const NssUser *nss_cache_lookup_user(NssCache *cache, const char *name, Error **error);
bool nss_cache_lookup_uid(NssCache *cache, const char *name, uid_t *uid, Error **error);
bool nss_cache_lookup_gid(NssCache *cache, const char *name, gid_t *gid, Error **error);

NssUser *nss_user_ref(const NssUser *user);
void nss_user_unref(NssUser *user);
const char *nss_user_name(const NssUser *user);
uid_t nss_user_uid(const NssUser *user);
gid_t nss_user_gid(const NssUser *user);
const char *nss_user_home(const NssUser *user);
const char *nss_user_shell(const NssUser *user);
const gid_t *nss_user_groups(const NssUser *user, size_t *n_groups);
