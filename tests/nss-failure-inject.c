#define _GNU_SOURCE
#include "nss-cache.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bool __real_nss_cache_lookup_uid(NssCache *cache, const char *name, uid_t *uid, Error **error);
bool __real_nss_cache_lookup_gid(NssCache *cache, const char *name, gid_t *gid, Error **error);

static bool injected_lookup(Error **error)
{
        const char *path = getenv("DBD_TEST_NSS_FAILURE");
        int code;
        FILE *file = path ? fopen(path, "r") : NULL;
        assert(file && fscanf(file, "%d", &code) == 1);
        assert(fclose(file) == 0);
        if (code == INT_MAX)
                return false; /* Allocation of the Error itself failed. */
        if (code)
                return error_set(error, code, "Injected NSS lookup failure");
        return true;
}

bool __wrap_nss_cache_lookup_uid(NssCache *cache, const char *name, uid_t *uid, Error **error)
{
        if (strcmp(name, "dbd-test-identity") != 0)
                return __real_nss_cache_lookup_uid(cache, name, uid, error);
        if (!injected_lookup(error))
                return false;
        *uid = getuid();
        return true;
}

bool __wrap_nss_cache_lookup_gid(NssCache *cache, const char *name, gid_t *gid, Error **error)
{
        if (strcmp(name, "dbd-test-identity") != 0)
                return __real_nss_cache_lookup_gid(cache, name, gid, error);
        if (!injected_lookup(error))
                return false;
        *gid = getgid();
        return true;
}
