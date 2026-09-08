#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct Error {
        int code;
        char *message;
} Error;

void error_free(Error *error);
void error_clear(Error **error);
bool error_set(Error **error, int code, const char *format, ...);
bool error_set_errno(Error **error, int error_number, const char *format, ...);
void error_prefix(Error **error, const char *format, ...);

typedef void (*DestroyFunc)(void *value);

typedef struct PtrVec {
        void **items;
        size_t len;
        size_t capacity;
        DestroyFunc destroy;
} PtrVec;

void ptr_vec_init(PtrVec *vec, DestroyFunc destroy);
void ptr_vec_clear(PtrVec *vec);
PtrVec *ptr_vec_new(DestroyFunc destroy);
void ptr_vec_free(PtrVec *vec);
bool ptr_vec_push(PtrVec *vec, void *value);
void *ptr_vec_remove(PtrVec *vec, size_t index);
void ptr_vec_delete(PtrVec *vec, size_t index);
void ptr_vec_sort(PtrVec *vec, int (*compare)(const void *, const void *));

typedef struct U32Vec {
        uint32_t *items;
        size_t len;
        size_t capacity;
} U32Vec;

void u32_vec_clear(U32Vec *vec);
bool u32_vec_push(U32Vec *vec, uint32_t value);
bool u32_vec_copy(U32Vec *to, const U32Vec *from);
void u32_vec_sort_unique(U32Vec *vec);

typedef struct StrMapEntry {
        char *key;
        void *value;
} StrMapEntry;

typedef struct StrMap {
        StrMapEntry *entries;
        size_t len;
        size_t capacity;
        size_t *buckets;
        size_t n_buckets;
        DestroyFunc destroy;
} StrMap;

void str_map_init(StrMap *map, DestroyFunc destroy);
void str_map_clear(StrMap *map);
StrMap *str_map_new(DestroyFunc destroy);
void str_map_free(StrMap *map);
void *str_map_get(const StrMap *map, const char *key);
bool str_map_contains(const StrMap *map, const char *key);
bool str_map_set(StrMap *map, const char *key, void *value);
void *str_map_remove(StrMap *map, const char *key);

typedef struct U32MapEntry {
        uint32_t key;
        void *value;
} U32MapEntry;

typedef struct U32Map {
        U32MapEntry *entries;
        size_t len;
        size_t capacity;
        size_t *buckets;
        size_t n_buckets;
        DestroyFunc destroy;
} U32Map;

void u32_map_init(U32Map *map, DestroyFunc destroy);
void u32_map_clear(U32Map *map);
U32Map *u32_map_new(DestroyFunc destroy);
void u32_map_free(U32Map *map);
void *u32_map_get(const U32Map *map, uint32_t key);
bool u32_map_contains(const U32Map *map, uint32_t key);
bool u32_map_set(U32Map *map, uint32_t key, void *value);
void *u32_map_remove(U32Map *map, uint32_t key);

typedef struct StrBuf {
        char *data;
        size_t len;
        size_t capacity;
} StrBuf;

void str_buf_clear(StrBuf *buffer);
bool str_buf_append_n(StrBuf *buffer, const char *text, size_t length);
bool str_buf_append(StrBuf *buffer, const char *text);
bool str_buf_appendf(StrBuf *buffer, const char *format, ...);
char *str_buf_steal(StrBuf *buffer);

char *str_dup(const char *text);
char *str_printf(const char *format, ...);
bool str_equal(const char *left, const char *right);
bool str_has_prefix(const char *text, const char *prefix);
bool str_has_suffix(const char *text, const char *suffix);
char *path_join(const char *left, const char *right);
char *path_dirname(const char *path);
/* Lexical normalization only: removes dot components without resolving symlinks. */
char *path_canonicalize(const char *path, const char *base);
bool path_is_absolute(const char *path);
bool read_file(const char *path, char **contents, size_t *length, Error **error);
bool read_file_limited(const char *path, size_t maximum, char **contents, size_t *length, Error **error);
bool parse_u64(const char *text, uint64_t maximum, uint64_t *value);
