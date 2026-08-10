#pragma once

#include "util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
        DBUS_MESSAGE_METHOD_CALL = 1,
        DBUS_MESSAGE_METHOD_RETURN = 2,
        DBUS_MESSAGE_ERROR = 3,
        DBUS_MESSAGE_SIGNAL = 4,
};

typedef struct DBusWriter {
        StrBuf bytes;
        bool failed;
} DBusWriter;

typedef struct DBusArray {
        size_t length_offset;
        size_t content_offset;
} DBusArray;

void dbus_writer_clear(DBusWriter *writer);
bool dbus_writer_align(DBusWriter *writer, size_t alignment);
bool dbus_writer_u8(DBusWriter *writer, uint8_t value);
bool dbus_writer_bool(DBusWriter *writer, bool value);
bool dbus_writer_u32(DBusWriter *writer, uint32_t value);
bool dbus_writer_u64(DBusWriter *writer, uint64_t value);
bool dbus_writer_string(DBusWriter *writer, const char *value);
bool dbus_writer_object_path(DBusWriter *writer, const char *value);
bool dbus_writer_signature(DBusWriter *writer, const char *value);
bool dbus_writer_array_begin(DBusWriter *writer, size_t element_alignment, DBusArray *array);
bool dbus_writer_array_end(DBusWriter *writer, DBusArray *array);
bool dbus_writer_variant_begin(DBusWriter *writer, const char *signature, size_t value_alignment);

typedef struct DBusReader {
        const uint8_t *bytes;
        size_t length;
        size_t offset;
        bool little_endian;
} DBusReader;

bool dbus_reader_align(DBusReader *reader, size_t alignment);
bool dbus_reader_u8(DBusReader *reader, uint8_t *value);
bool dbus_reader_bool(DBusReader *reader, bool *value);
bool dbus_reader_u32(DBusReader *reader, uint32_t *value);
bool dbus_reader_u64(DBusReader *reader, uint64_t *value);
bool dbus_reader_string(DBusReader *reader, const char **value, size_t *length);
bool dbus_reader_signature(DBusReader *reader, const char **value, size_t *length);
bool dbus_reader_array(DBusReader *reader, size_t element_alignment, DBusReader *array);

typedef struct DBusHeader {
        uint8_t type;
        uint8_t flags;
        uint32_t serial;
        uint32_t reply_serial;
        uint32_t unix_fds;
        char *path;
        char *interface;
        char *member;
        char *error_name;
        char *signature;
} DBusHeader;

void dbus_header_clear(DBusHeader *header);
bool dbus_message_build(DBusWriter *message, uint8_t type, uint8_t flags, uint32_t serial, uint32_t reply_serial,
                        const char *path, const char *interface, const char *member, const char *destination,
                        const char *error_name, const char *signature, uint32_t unix_fds, const DBusWriter *body,
                        Error **error);
bool dbus_message_parse(const uint8_t *bytes, size_t length, DBusHeader *header, DBusReader *body, size_t *consumed,
                        Error **error);
