#define _GNU_SOURCE
#include "address.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

char *percent_escape(const char *value)
{
        static const char hex[] = "0123456789ABCDEF";
        StrBuf out = {0};
        for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
                bool appended;
                if (isalnum(*p) || strchr("_-./", *p)) {
                        appended = str_buf_append_n(&out, (const char *)p, 1);
                } else {
                        char escaped[] = {'%', hex[*p >> 4], hex[*p & 15]};
                        appended = str_buf_append_n(&out, escaped, sizeof(escaped));
                }
                if (!appended) {
                        str_buf_clear(&out);
                        return NULL;
                }
        }
        return str_buf_steal(&out);
}

static int hex_value(char value)
{
        if (value >= '0' && value <= '9')
                return value - '0';
        if (value >= 'a' && value <= 'f')
                return value - 'a' + 10;
        if (value >= 'A' && value <= 'F')
                return value - 'A' + 10;
        return -1;
}

char *socket_path_from_address(const char *address, Error **error)
{
        const char *encoded;
        StrBuf path = {0};
        if (!str_has_prefix(address, "unix:path=")) {
                error_set(error, ENOTSUP, "Only filesystem-backed unix:path= D-Bus addresses are supported");
                return NULL;
        }
        encoded = address + strlen("unix:path=");
        if (!*encoded || strpbrk(encoded, ",;")) {
                error_set(error, EINVAL, "Invalid D-Bus listener address: %s", address);
                return NULL;
        }
        for (const char *p = encoded; *p; ++p) {
                char byte = *p;
                if (*p == '%') {
                        int high, low;
                        /* p[2] must not be read before p[1] is known non-NUL. */
                        if (!p[1] || !p[2])
                                goto invalid;
                        high = hex_value(p[1]);
                        low = hex_value(p[2]);
                        if (high < 0 || low < 0)
                                goto invalid;
                        byte = (char)((high << 4) | low);
                        p += 2;
                        if (!byte)
                                goto invalid;
                }
                if (!str_buf_append_n(&path, &byte, 1))
                        goto invalid;
        }
        if (!path.data || !path_is_absolute(path.data))
                goto invalid;
        return str_buf_steal(&path);
invalid:
        str_buf_clear(&path);
        error_set(error, EINVAL, "The unix:path= listener must contain an absolute, valid escaped path");
        return NULL;
}
