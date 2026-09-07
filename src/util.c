#define _GNU_SOURCE
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool grow(void **memory, size_t *capacity, size_t element_size, size_t needed)
{
        size_t next = *capacity ? *capacity : 8;
        void *replacement;

        while (next < needed) {
                if (next > SIZE_MAX / 2)
                        return false;
                next *= 2;
        }
        if (element_size && next > SIZE_MAX / element_size)
                return false;
        replacement = realloc(*memory, next * element_size);
        if (!replacement)
                return false;
        *memory = replacement;
        *capacity = next;
        return true;
}

void error_free(Error *error)
{
        if (error) {
                free(error->message);
                free(error);
        }
}

void error_clear(Error **error)
{
        if (error) {
                error_free(*error);
                *error = NULL;
        }
}

static bool error_setv(Error **error, int code, const char *format, va_list arguments)
{
        Error *value;

        if (!error)
                return false;
        error_clear(error);
        value = calloc(1, sizeof(*value));
        if (!value)
                return false;
        value->code = code;
        if (vasprintf(&value->message, format, arguments) < 0) {
                free(value);
                return false;
        }
        *error = value;
        return false;
}

bool error_set(Error **error, int code, const char *format, ...)
{
        va_list arguments;
        bool result;

        va_start(arguments, format);
        result = error_setv(error, code, format, arguments);
        va_end(arguments);
        return result;
}

bool error_set_errno(Error **error, int error_number, const char *format, ...)
{
        va_list arguments;
        char *prefix = NULL;
        bool result;

        va_start(arguments, format);
        if (vasprintf(&prefix, format, arguments) < 0)
                prefix = NULL;
        va_end(arguments);
        result = error_set(error, error_number, "%s%s%s", prefix ? prefix : "", prefix ? ": " : "",
                           strerror(error_number));
        free(prefix);
        return result;
}

void error_prefix(Error **error, const char *format, ...)
{
        va_list arguments;
        char *prefix = NULL, *message;

        if (!error || !*error)
                return;
        va_start(arguments, format);
        if (vasprintf(&prefix, format, arguments) < 0)
                prefix = NULL;
        va_end(arguments);
        if (!prefix || asprintf(&message, "%s%s", prefix, (*error)->message) < 0) {
                free(prefix);
                return;
        }
        free(prefix);
        free((*error)->message);
        (*error)->message = message;
}

void ptr_vec_init(PtrVec *vec, DestroyFunc destroy)
{
        *vec = (PtrVec){.destroy = destroy};
}

void ptr_vec_clear(PtrVec *vec)
{
        if (vec->destroy)
                for (size_t i = 0; i < vec->len; ++i)
                        vec->destroy(vec->items[i]);
        free(vec->items);
        *vec = (PtrVec){.destroy = vec->destroy};
}

PtrVec *ptr_vec_new(DestroyFunc destroy)
{
        PtrVec *vec = malloc(sizeof(*vec));
        if (vec)
                ptr_vec_init(vec, destroy);
        return vec;
}

void ptr_vec_free(PtrVec *vec)
{
        if (vec) {
                ptr_vec_clear(vec);
                free(vec);
        }
}

bool ptr_vec_push(PtrVec *vec, void *value)
{
        if (vec->len == vec->capacity && !grow((void **)&vec->items, &vec->capacity, sizeof(*vec->items), vec->len + 1))
                return false;
        vec->items[vec->len++] = value;
        return true;
}

void *ptr_vec_remove(PtrVec *vec, size_t index)
{
        void *value;
        if (index >= vec->len)
                return NULL;
        value = vec->items[index];
        memmove(vec->items + index, vec->items + index + 1, (vec->len - index - 1) * sizeof(*vec->items));
        --vec->len;
        return value;
}

void ptr_vec_delete(PtrVec *vec, size_t index)
{
        void *value = ptr_vec_remove(vec, index);
        if (value && vec->destroy)
                vec->destroy(value);
}

void ptr_vec_sort(PtrVec *vec, int (*compare)(const void *, const void *))
{
        if (vec->len > 1)
                qsort(vec->items, vec->len, sizeof(*vec->items), compare);
}

void u32_vec_clear(U32Vec *vec)
{
        free(vec->items);
        *vec = (U32Vec){0};
}

bool u32_vec_push(U32Vec *vec, uint32_t value)
{
        if (vec->len == vec->capacity && !grow((void **)&vec->items, &vec->capacity, sizeof(*vec->items), vec->len + 1))
                return false;
        vec->items[vec->len++] = value;
        return true;
}

bool u32_vec_copy(U32Vec *to, const U32Vec *from)
{
        U32Vec candidate = {0};
        if (from->len && !grow((void **)&candidate.items, &candidate.capacity, sizeof(*candidate.items), from->len))
                return false;
        if (from->len)
                memcpy(candidate.items, from->items, from->len * sizeof(*from->items));
        candidate.len = from->len;
        u32_vec_clear(to);
        *to = candidate;
        return true;
}

static int compare_u32(const void *left, const void *right)
{
        uint32_t a = *(const uint32_t *)left, b = *(const uint32_t *)right;
        return (a > b) - (a < b);
}

void u32_vec_sort_unique(U32Vec *vec)
{
        if (vec->len < 2)
                return;
        qsort(vec->items, vec->len, sizeof(*vec->items), compare_u32);
        size_t out = 1;
        for (size_t i = 1; i < vec->len; ++i)
                if (vec->items[i] != vec->items[out - 1])
                        vec->items[out++] = vec->items[i];
        vec->len = out;
}

void str_map_init(StrMap *map, DestroyFunc destroy)
{
        *map = (StrMap){.destroy = destroy};
}

void str_map_clear(StrMap *map)
{
        for (size_t i = 0; i < map->len; ++i) {
                free(map->entries[i].key);
                if (map->destroy)
                        map->destroy(map->entries[i].value);
        }
        free(map->entries);
        free(map->buckets);
        *map = (StrMap){.destroy = map->destroy};
}

StrMap *str_map_new(DestroyFunc destroy)
{
        StrMap *map = malloc(sizeof(*map));
        if (map)
                str_map_init(map, destroy);
        return map;
}

void str_map_free(StrMap *map)
{
        if (map) {
                str_map_clear(map);
                free(map);
        }
}

static inline uint64_t hash_str(const char *str)
{
        uint64_t h = 14695981039346656037ULL;
        while (*str) {
                h ^= (uint8_t)*str++;
                h *= 1099511628211ULL;
        }
        return h;
}

static size_t str_map_find(const StrMap *map, const char *key)
{
        if (!map || map->len == 0)
                return SIZE_MAX;
        if (!map->buckets || map->n_buckets == 0) {
                for (size_t i = 0; i < map->len; ++i)
                        if (strcmp(map->entries[i].key, key) == 0)
                                return i;
                return SIZE_MAX;
        }
        size_t mask = map->n_buckets - 1;
        uint64_t h = hash_str(key);
        for (size_t probe = 0; probe < map->n_buckets; ++probe) {
                size_t b = (size_t)(h + probe) & mask;
                size_t idx = map->buckets[b];
                if (idx == SIZE_MAX)
                        return SIZE_MAX;
                if (strcmp(map->entries[idx].key, key) == 0)
                        return idx;
        }
        return SIZE_MAX;
}

void *str_map_get(const StrMap *map, const char *key)
{
        size_t index = str_map_find(map, key);
        return index == SIZE_MAX ? NULL : map->entries[index].value;
}

bool str_map_contains(const StrMap *map, const char *key)
{
        return str_map_find(map, key) != SIZE_MAX;
}

static bool str_map_rehash(StrMap *map, size_t new_n_buckets)
{
        /* Removal moves entries before rehashing, so reuse the buckets and
         * rebuild without an allocation that could fail. */
        if (new_n_buckets > SIZE_MAX / sizeof(size_t))
                return false;
        size_t *new_buckets = new_n_buckets == map->n_buckets ? map->buckets : malloc(new_n_buckets * sizeof(size_t));
        if (!new_buckets)
                return false;
        for (size_t i = 0; i < new_n_buckets; ++i)
                new_buckets[i] = SIZE_MAX;
        size_t mask = new_n_buckets - 1;
        for (size_t i = 0; i < map->len; ++i) {
                uint64_t h = hash_str(map->entries[i].key);
                for (size_t probe = 0; probe < new_n_buckets; ++probe) {
                        size_t b = (size_t)(h + probe) & mask;
                        if (new_buckets[b] == SIZE_MAX) {
                                new_buckets[b] = i;
                                break;
                        }
                }
        }
        if (new_buckets != map->buckets)
                free(map->buckets);
        map->buckets = new_buckets;
        map->n_buckets = new_n_buckets;
        return true;
}

bool str_map_set(StrMap *map, const char *key, void *value)
{
        size_t index = str_map_find(map, key);
        char *copy;

        if (index != SIZE_MAX) {
                if (map->destroy)
                        map->destroy(map->entries[index].value);
                map->entries[index].value = value;
                return true;
        }
        if (map->len >= map->n_buckets / 2) {
                size_t next_buckets = map->n_buckets ? map->n_buckets * 2 : 16;
                if (next_buckets < map->n_buckets || !str_map_rehash(map, next_buckets))
                        return false;
        }
        copy = strdup(key);
        if (!copy)
                return false;
        if (map->len == map->capacity &&
            !grow((void **)&map->entries, &map->capacity, sizeof(*map->entries), map->len + 1)) {
                free(copy);
                return false;
        }
        size_t new_idx = map->len;
        map->entries[new_idx] = (StrMapEntry){.key = copy, .value = value};
        map->len++;
        if (map->buckets && map->n_buckets > 0) {
                size_t mask = map->n_buckets - 1;
                uint64_t h = hash_str(copy);
                for (size_t probe = 0; probe < map->n_buckets; ++probe) {
                        size_t b = (size_t)(h + probe) & mask;
                        if (map->buckets[b] == SIZE_MAX) {
                                map->buckets[b] = new_idx;
                                break;
                        }
                }
        }
        return true;
}

void *str_map_remove(StrMap *map, const char *key)
{
        size_t index = str_map_find(map, key);
        void *value;
        if (index == SIZE_MAX)
                return NULL;
        value = map->entries[index].value;
        free(map->entries[index].key);
        if (index + 1 < map->len) {
                map->entries[index] = map->entries[map->len - 1];
        }
        --map->len;
        if (map->buckets && map->n_buckets > 0)
                str_map_rehash(map, map->n_buckets);
        return value;
}

static inline uint64_t hash_u32(uint32_t key)
{
        uint64_t x = key;
        x ^= x >> 16;
        x *= 0x45d9f3b;
        x ^= x >> 16;
        return x;
}

void u32_map_init(U32Map *map, DestroyFunc destroy)
{
        *map = (U32Map){.destroy = destroy};
}

void u32_map_clear(U32Map *map)
{
        if (map->destroy)
                for (size_t i = 0; i < map->len; ++i)
                        map->destroy(map->entries[i].value);
        free(map->entries);
        free(map->buckets);
        *map = (U32Map){.destroy = map->destroy};
}

U32Map *u32_map_new(DestroyFunc destroy)
{
        U32Map *map = malloc(sizeof(*map));
        if (map)
                u32_map_init(map, destroy);
        return map;
}

void u32_map_free(U32Map *map)
{
        if (map) {
                u32_map_clear(map);
                free(map);
        }
}

static size_t u32_map_find(const U32Map *map, uint32_t key)
{
        if (!map || map->len == 0)
                return SIZE_MAX;
        if (!map->buckets || map->n_buckets == 0) {
                for (size_t i = 0; i < map->len; ++i)
                        if (map->entries[i].key == key)
                                return i;
                return SIZE_MAX;
        }
        size_t mask = map->n_buckets - 1;
        uint64_t h = hash_u32(key);
        for (size_t probe = 0; probe < map->n_buckets; ++probe) {
                size_t b = (size_t)(h + probe) & mask;
                size_t idx = map->buckets[b];
                if (idx == SIZE_MAX)
                        return SIZE_MAX;
                if (map->entries[idx].key == key)
                        return idx;
        }
        return SIZE_MAX;
}

void *u32_map_get(const U32Map *map, uint32_t key)
{
        size_t index = u32_map_find(map, key);
        return index == SIZE_MAX ? NULL : map->entries[index].value;
}

bool u32_map_contains(const U32Map *map, uint32_t key)
{
        return u32_map_find(map, key) != SIZE_MAX;
}

static bool u32_map_rehash(U32Map *map, size_t new_n_buckets)
{
        /* Removal moves entries before rehashing, so reuse the buckets and
         * rebuild without an allocation that could fail. */
        if (new_n_buckets > SIZE_MAX / sizeof(size_t))
                return false;
        size_t *new_buckets = new_n_buckets == map->n_buckets ? map->buckets : malloc(new_n_buckets * sizeof(size_t));
        if (!new_buckets)
                return false;
        for (size_t i = 0; i < new_n_buckets; ++i)
                new_buckets[i] = SIZE_MAX;
        size_t mask = new_n_buckets - 1;
        for (size_t i = 0; i < map->len; ++i) {
                uint64_t h = hash_u32(map->entries[i].key);
                for (size_t probe = 0; probe < new_n_buckets; ++probe) {
                        size_t b = (size_t)(h + probe) & mask;
                        if (new_buckets[b] == SIZE_MAX) {
                                new_buckets[b] = i;
                                break;
                        }
                }
        }
        if (new_buckets != map->buckets)
                free(map->buckets);
        map->buckets = new_buckets;
        map->n_buckets = new_n_buckets;
        return true;
}

bool u32_map_set(U32Map *map, uint32_t key, void *value)
{
        size_t index = u32_map_find(map, key);
        if (index != SIZE_MAX) {
                if (map->destroy)
                        map->destroy(map->entries[index].value);
                map->entries[index].value = value;
                return true;
        }
        if (map->len >= map->n_buckets / 2) {
                size_t next_buckets = map->n_buckets ? map->n_buckets * 2 : 16;
                if (next_buckets < map->n_buckets || !u32_map_rehash(map, next_buckets))
                        return false;
        }
        if (map->len == map->capacity &&
            !grow((void **)&map->entries, &map->capacity, sizeof(*map->entries), map->len + 1))
                return false;
        size_t new_idx = map->len;
        map->entries[new_idx] = (U32MapEntry){.key = key, .value = value};
        map->len++;
        if (map->buckets && map->n_buckets > 0) {
                size_t mask = map->n_buckets - 1;
                uint64_t h = hash_u32(key);
                for (size_t probe = 0; probe < map->n_buckets; ++probe) {
                        size_t b = (size_t)(h + probe) & mask;
                        if (map->buckets[b] == SIZE_MAX) {
                                map->buckets[b] = new_idx;
                                break;
                        }
                }
        }
        return true;
}

void *u32_map_remove(U32Map *map, uint32_t key)
{
        size_t index = u32_map_find(map, key);
        void *value;
        if (index == SIZE_MAX)
                return NULL;
        value = map->entries[index].value;
        if (index + 1 < map->len) {
                map->entries[index] = map->entries[map->len - 1];
        }
        --map->len;
        if (map->buckets && map->n_buckets > 0)
                u32_map_rehash(map, map->n_buckets);
        return value;
}

void str_buf_clear(StrBuf *buffer)
{
        free(buffer->data);
        *buffer = (StrBuf){0};
}

bool str_buf_append_n(StrBuf *buffer, const char *text, size_t length)
{
        if (length > SIZE_MAX - buffer->len - 1)
                return false;
        if (buffer->len + length + 1 > buffer->capacity &&
            !grow((void **)&buffer->data, &buffer->capacity, 1, buffer->len + length + 1))
                return false;
        /* memcpy() forbids a null source even for a zero count, and callers
         * legitimately append an empty region from an unallocated buffer. */
        if (length)
                memcpy(buffer->data + buffer->len, text, length);
        buffer->len += length;
        buffer->data[buffer->len] = '\0';
        return true;
}

bool str_buf_append(StrBuf *buffer, const char *text)
{
        return str_buf_append_n(buffer, text, strlen(text));
}

bool str_buf_appendf(StrBuf *buffer, const char *format, ...)
{
        va_list arguments;
        char *text;
        bool result;
        va_start(arguments, format);
        if (vasprintf(&text, format, arguments) < 0)
                text = NULL;
        va_end(arguments);
        if (!text)
                return false;
        result = str_buf_append(buffer, text);
        free(text);
        return result;
}

char *str_buf_steal(StrBuf *buffer)
{
        char *result = buffer->data;
        *buffer = (StrBuf){0};
        return result ? result : strdup("");
}

char *str_dup(const char *text)
{
        return text ? strdup(text) : NULL;
}

char *str_printf(const char *format, ...)
{
        va_list arguments;
        char *text;
        va_start(arguments, format);
        if (vasprintf(&text, format, arguments) < 0)
                text = NULL;
        va_end(arguments);
        return text;
}

bool str_equal(const char *left, const char *right)
{
        return left == right || (left && right && strcmp(left, right) == 0);
}

bool str_has_prefix(const char *text, const char *prefix)
{
        return strncmp(text, prefix, strlen(prefix)) == 0;
}

bool str_has_suffix(const char *text, const char *suffix)
{
        size_t a = strlen(text), b = strlen(suffix);
        return a >= b && memcmp(text + a - b, suffix, b) == 0;
}

char *path_join(const char *left, const char *right)
{
        return str_printf("%s%s%s", left, *left && left[strlen(left) - 1] == '/' ? "" : "/", right);
}

char *path_dirname(const char *path)
{
        char *copy = strdup(path), *slash;
        if (!copy)
                return NULL;
        while (*copy && copy[1] && copy[strlen(copy) - 1] == '/')
                copy[strlen(copy) - 1] = '\0';
        slash = strrchr(copy, '/');
        if (!slash) {
                free(copy);
                return strdup(".");
        }
        if (slash == copy)
                slash[1] = '\0';
        else
                *slash = '\0';
        return copy;
}

bool path_is_absolute(const char *path)
{
        return path && path[0] == '/';
}

char *path_canonicalize(const char *path, const char *base)
{
        PtrVec parts;
        char *absolute, *copy, *save = NULL, *part;
        StrBuf out = {0};

        if (path_is_absolute(path))
                absolute = strdup(path);
        else if (base)
                absolute = path_join(base, path);
        else {
                char *cwd = getcwd(NULL, 0);
                absolute = cwd ? path_join(cwd, path) : NULL;
                free(cwd);
        }
        if (!absolute)
                return NULL;
        copy = absolute;
        ptr_vec_init(&parts, free);
        for (part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
                if (strcmp(part, ".") == 0 || !*part)
                        continue;
                if (strcmp(part, "..") == 0) {
                        if (parts.len)
                                free(ptr_vec_remove(&parts, parts.len - 1));
                        continue;
                }
                char *copy_part = strdup(part);
                if (!copy_part || !ptr_vec_push(&parts, copy_part)) {
                        free(copy_part);
                        ptr_vec_clear(&parts);
                        free(absolute);
                        return NULL;
                }
        }
        if (!str_buf_append(&out, "/"))
                goto memory;
        for (size_t i = 0; i < parts.len; ++i) {
                if ((i && !str_buf_append(&out, "/")) || !str_buf_append(&out, parts.items[i]))
                        goto memory;
        }
        ptr_vec_clear(&parts);
        free(absolute);
        return str_buf_steal(&out);
memory:
        str_buf_clear(&out);
        ptr_vec_clear(&parts);
        free(absolute);
        return NULL;
}

bool read_file(const char *path, char **contents, size_t *length, Error **error)
{
        int fd;
        StrBuf buffer = {0};
        char chunk[8192];
        ssize_t n;

        *contents = NULL;
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return error_set_errno(error, errno, "%s", path);
        while ((n = read(fd, chunk, sizeof(chunk))) > 0) {
                if (!str_buf_append_n(&buffer, chunk, (size_t)n)) {
                        close(fd);
                        str_buf_clear(&buffer);
                        return error_set(error, ENOMEM, "%s: out of memory", path);
                }
        }
        if (n < 0) {
                int saved = errno;
                close(fd);
                str_buf_clear(&buffer);
                return error_set_errno(error, saved, "%s", path);
        }
        close(fd);
        if (!buffer.data && !str_buf_append_n(&buffer, "", 0))
                return error_set(error, ENOMEM, "%s: out of memory", path);
        if (length)
                *length = buffer.len;
        *contents = str_buf_steal(&buffer);
        return true;
}

bool parse_u64(const char *text, uint64_t maximum, uint64_t *value)
{
        char *end;
        unsigned long long parsed;
        if (!text || !*text || *text == '-' || *text == '+')
                return false;
        errno = 0;
        parsed = strtoull(text, &end, 10);
        if (errno || *end || parsed > maximum)
                return false;
        *value = parsed;
        return true;
}
