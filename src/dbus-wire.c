#include "dbus-wire.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum {
        FIELD_PATH = 1,
        FIELD_INTERFACE = 2,
        FIELD_MEMBER = 3,
        FIELD_ERROR_NAME = 4,
        FIELD_REPLY_SERIAL = 5,
        FIELD_DESTINATION = 6,
        FIELD_SIGNATURE = 8,
        FIELD_UNIX_FDS = 9,
};

static bool append(DBusWriter *writer, const void *data, size_t length)
{
        if (writer->failed)
                return false;
        if (!str_buf_append_n(&writer->bytes, data, length))
                writer->failed = true;
        return !writer->failed;
}

void dbus_writer_clear(DBusWriter *writer)
{
        str_buf_clear(&writer->bytes);
        writer->failed = false;
}

bool dbus_writer_align(DBusWriter *writer, size_t alignment)
{
        static const uint8_t zeroes[8];
        size_t padding;
        if (!alignment || (alignment & (alignment - 1)) || alignment > sizeof(zeroes)) {
                writer->failed = true;
                return false;
        }
        padding = (alignment - writer->bytes.len % alignment) % alignment;
        return append(writer, zeroes, padding);
}

bool dbus_writer_u8(DBusWriter *writer, uint8_t value)
{
        return append(writer, &value, sizeof(value));
}

bool dbus_writer_u32(DBusWriter *writer, uint32_t value)
{
        return dbus_writer_align(writer, 4) && append(writer, &value, sizeof(value));
}

bool dbus_writer_bool(DBusWriter *writer, bool value)
{
        return dbus_writer_u32(writer, value ? 1 : 0);
}

bool dbus_writer_u64(DBusWriter *writer, uint64_t value)
{
        return dbus_writer_align(writer, 8) && append(writer, &value, sizeof(value));
}

bool dbus_writer_string(DBusWriter *writer, const char *value)
{
        size_t length = strlen(value);
        return length <= UINT32_MAX && dbus_writer_u32(writer, (uint32_t)length) && append(writer, value, length + 1);
}

bool dbus_writer_object_path(DBusWriter *writer, const char *value)
{
        return dbus_writer_string(writer, value);
}

bool dbus_writer_signature(DBusWriter *writer, const char *value)
{
        size_t length = strlen(value);
        return length <= UINT8_MAX && dbus_writer_u8(writer, (uint8_t)length) && append(writer, value, length + 1);
}

bool dbus_writer_array_begin(DBusWriter *writer, size_t element_alignment, DBusArray *array)
{
        if (!dbus_writer_align(writer, 4))
                return false;
        array->length_offset = writer->bytes.len;
        if (!dbus_writer_u32(writer, 0) || !dbus_writer_align(writer, element_alignment))
                return false;
        array->content_offset = writer->bytes.len;
        return true;
}

bool dbus_writer_array_end(DBusWriter *writer, DBusArray *array)
{
        size_t length = writer->bytes.len - array->content_offset;
        uint32_t encoded;
        if (writer->failed || length > UINT32_MAX || array->length_offset + 4 > writer->bytes.len) {
                writer->failed = true;
                return false;
        }
        encoded = (uint32_t)length;
        memcpy(writer->bytes.data + array->length_offset, &encoded, sizeof(encoded));
        return true;
}

bool dbus_writer_variant_begin(DBusWriter *writer, const char *signature, size_t value_alignment)
{
        return dbus_writer_signature(writer, signature) && dbus_writer_align(writer, value_alignment);
}

static bool reader_take(DBusReader *reader, size_t amount, const uint8_t **value)
{
        if (amount > reader->length - reader->offset)
                return false;
        if (value)
                *value = reader->bytes + reader->offset;
        reader->offset += amount;
        return true;
}

bool dbus_reader_align(DBusReader *reader, size_t alignment)
{
        size_t padding;
        if (!alignment || (alignment & (alignment - 1)) || alignment > 8)
                return false;
        padding = (alignment - reader->offset % alignment) % alignment;
        return reader_take(reader, padding, NULL);
}

bool dbus_reader_u8(DBusReader *reader, uint8_t *value)
{
        const uint8_t *bytes;
        if (!reader_take(reader, 1, &bytes))
                return false;
        *value = *bytes;
        return true;
}

static uint32_t swap32(uint32_t value)
{
        return __builtin_bswap32(value);
}

static uint64_t swap64(uint64_t value)
{
        return __builtin_bswap64(value);
}

bool dbus_reader_u32(DBusReader *reader, uint32_t *value)
{
        const uint8_t *bytes;
        uint32_t native;
        if (!dbus_reader_align(reader, 4) || !reader_take(reader, 4, &bytes))
                return false;
        memcpy(&native, bytes, sizeof(native));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        *value = reader->little_endian ? native : swap32(native);
#else
        *value = reader->little_endian ? swap32(native) : native;
#endif
        return true;
}

bool dbus_reader_bool(DBusReader *reader, bool *value)
{
        uint32_t encoded;
        if (!dbus_reader_u32(reader, &encoded) || encoded > 1)
                return false;
        *value = encoded;
        return true;
}

bool dbus_reader_u64(DBusReader *reader, uint64_t *value)
{
        const uint8_t *bytes;
        uint64_t native;
        if (!dbus_reader_align(reader, 8) || !reader_take(reader, 8, &bytes))
                return false;
        memcpy(&native, bytes, sizeof(native));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        *value = reader->little_endian ? native : swap64(native);
#else
        *value = reader->little_endian ? swap64(native) : native;
#endif
        return true;
}

bool dbus_reader_string(DBusReader *reader, const char **value, size_t *length)
{
        uint32_t encoded_length;
        const uint8_t *bytes;
        if (!dbus_reader_u32(reader, &encoded_length) || !reader_take(reader, (size_t)encoded_length + 1, &bytes) ||
            bytes[encoded_length] != 0 || memchr(bytes, 0, encoded_length))
                return false;
        *value = (const char *)bytes;
        if (length)
                *length = encoded_length;
        return true;
}

bool dbus_reader_signature(DBusReader *reader, const char **value, size_t *length)
{
        uint8_t encoded_length;
        const uint8_t *bytes;
        if (!dbus_reader_u8(reader, &encoded_length) || !reader_take(reader, (size_t)encoded_length + 1, &bytes) ||
            bytes[encoded_length] != 0 || memchr(bytes, 0, encoded_length))
                return false;
        *value = (const char *)bytes;
        if (length)
                *length = encoded_length;
        return true;
}

bool dbus_reader_array(DBusReader *reader, size_t element_alignment, DBusReader *array)
{
        uint32_t length;
        if (!dbus_reader_u32(reader, &length) || !dbus_reader_align(reader, element_alignment) ||
            length > reader->length - reader->offset)
                return false;
        *array = (DBusReader){
                .bytes = reader->bytes + reader->offset,
                .length = length,
                .little_endian = reader->little_endian,
        };
        reader->offset += length;
        return true;
}

static bool header_field_string(DBusWriter *fields, uint8_t code, const char *signature, size_t alignment,
                                const char *value)
{
        return dbus_writer_align(fields, 8) && dbus_writer_u8(fields, code) &&
               dbus_writer_variant_begin(fields, signature, alignment) &&
               (signature[0] == 'g' ? dbus_writer_signature(fields, value) : dbus_writer_string(fields, value));
}

static bool header_field_u32(DBusWriter *fields, uint8_t code, uint32_t value)
{
        return dbus_writer_align(fields, 8) && dbus_writer_u8(fields, code) &&
               dbus_writer_variant_begin(fields, "u", 4) && dbus_writer_u32(fields, value);
}

bool dbus_message_build(DBusWriter *message, uint8_t type, uint8_t flags, uint32_t serial, uint32_t reply_serial,
                        const char *path, const char *interface, const char *member, const char *destination,
                        const char *error_name, const char *signature, uint32_t unix_fds, const DBusWriter *body,
                        Error **error)
{
        DBusWriter fields = {0};
        /* Every writer primitive emits host order, so the declared byte order
         * must follow the host rather than being hardcoded little-endian. */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        uint8_t endian = 'B', version = 1;
#else
        uint8_t endian = 'l', version = 1;
#endif
        uint32_t body_length = body ? (uint32_t)body->bytes.len : 0;

        dbus_writer_clear(message);
        if (body && body->bytes.len > UINT32_MAX)
                goto invalid;
        if ((path && !header_field_string(&fields, FIELD_PATH, "o", 4, path)) ||
            (interface && !header_field_string(&fields, FIELD_INTERFACE, "s", 4, interface)) ||
            (member && !header_field_string(&fields, FIELD_MEMBER, "s", 4, member)) ||
            (destination && !header_field_string(&fields, FIELD_DESTINATION, "s", 4, destination)) ||
            (error_name && !header_field_string(&fields, FIELD_ERROR_NAME, "s", 4, error_name)) ||
            (reply_serial && !header_field_u32(&fields, FIELD_REPLY_SERIAL, reply_serial)) ||
            (signature && *signature && !header_field_string(&fields, FIELD_SIGNATURE, "g", 1, signature)) ||
            (unix_fds && !header_field_u32(&fields, FIELD_UNIX_FDS, unix_fds)))
                goto memory;
        if (!dbus_writer_u8(message, endian) || !dbus_writer_u8(message, type) || !dbus_writer_u8(message, flags) ||
            !dbus_writer_u8(message, version) || !dbus_writer_u32(message, body_length) ||
            !dbus_writer_u32(message, serial) || !dbus_writer_u32(message, (uint32_t)fields.bytes.len) ||
            !append(message, fields.bytes.data, fields.bytes.len) || !dbus_writer_align(message, 8) ||
            (body && !append(message, body->bytes.data, body->bytes.len)))
                goto memory;
        dbus_writer_clear(&fields);
        return true;
invalid:
        error_set(error, EOVERFLOW, "D-Bus message body is too large");
        dbus_writer_clear(&fields);
        dbus_writer_clear(message);
        return false;
memory:
        error_set(error, ENOMEM, "Cannot construct D-Bus message");
        dbus_writer_clear(&fields);
        dbus_writer_clear(message);
        return false;
}

void dbus_header_clear(DBusHeader *header)
{
        free(header->path);
        free(header->interface);
        free(header->member);
        free(header->error_name);
        free(header->signature);
        *header = (DBusHeader){0};
}

static bool copy_field(char **target, const char *value, size_t length)
{
        char *copy = malloc(length + 1);
        if (!copy)
                return false;
        memcpy(copy, value, length);
        copy[length] = 0;
        free(*target);
        *target = copy;
        return true;
}

/* Steps over a header field we do not consume. Only the fixed-size basic types
 * and strings can appear unescorted by a full type parser; anything else means
 * we can no longer locate the next field and must reject the message. */
static bool skip_basic_value(DBusReader *reader, char type)
{
        uint8_t byte;
        uint32_t word;
        uint64_t giant;
        const char *text;

        switch (type) {
        case 'y':
                return dbus_reader_u8(reader, &byte);
        case 'b':
        case 'i':
        case 'u':
                return dbus_reader_u32(reader, &word);
        case 'n':
        case 'q':
                return dbus_reader_align(reader, 2) && dbus_reader_u8(reader, &byte) && dbus_reader_u8(reader, &byte);
        case 'x':
        case 't':
        case 'd':
                return dbus_reader_u64(reader, &giant);
        case 's':
        case 'o':
                return dbus_reader_string(reader, &text, NULL);
        case 'g':
                return dbus_reader_signature(reader, &text, NULL);
        default:
                return false;
        }
}

static bool parse_fields(DBusReader fields, DBusHeader *header)
{
        while (fields.offset < fields.length) {
                uint8_t code;
                const char *variant_signature;
                size_t signature_length;

                if (!dbus_reader_align(&fields, 8) || !dbus_reader_u8(&fields, &code) ||
                    !dbus_reader_signature(&fields, &variant_signature, &signature_length) || signature_length != 1)
                        return false;
                if (variant_signature[0] == 'u') {
                        uint32_t value;
                        if (!dbus_reader_u32(&fields, &value))
                                return false;
                        if (code == FIELD_REPLY_SERIAL)
                                header->reply_serial = value;
                        else if (code == FIELD_UNIX_FDS)
                                header->unix_fds = value;
                } else if (variant_signature[0] == 's' || variant_signature[0] == 'o') {
                        const char *value;
                        size_t value_length;
                        char **target = code == FIELD_PATH ? &header->path :
                                        code == FIELD_INTERFACE ? &header->interface :
                                        code == FIELD_MEMBER ? &header->member :
                                        code == FIELD_ERROR_NAME ? &header->error_name : NULL;
                        if (!dbus_reader_string(&fields, &value, &value_length))
                                return false;
                        if (target && !copy_field(target, value, value_length))
                                return false;
                } else if (variant_signature[0] == 'g') {
                        const char *value;
                        size_t value_length;
                        if (!dbus_reader_signature(&fields, &value, &value_length))
                                return false;
                        if (code == FIELD_SIGNATURE && !copy_field(&header->signature, value, value_length))
                                return false;
                } else if (!skip_basic_value(&fields, variant_signature[0])) {
                        /* The spec requires unknown header fields to be
                         * ignored, so only an unskippable type is fatal. */
                        return false;
                }
        }
        return true;
}

bool dbus_message_parse(const uint8_t *bytes, size_t length, DBusHeader *header, DBusReader *body, size_t *consumed,
                        Error **error)
{
        DBusReader reader, fields;
        uint8_t endian, version;
        uint32_t body_length, fields_length;
        size_t body_offset, total;

        dbus_header_clear(header);
        if (length < 16)
                return error_set(error, EAGAIN, "Incomplete D-Bus fixed header");
        endian = bytes[0];
        if (endian != 'l' && endian != 'B')
                return error_set(error, EPROTO, "Invalid D-Bus byte order");
        reader = (DBusReader){.bytes = bytes, .length = length, .offset = 1, .little_endian = endian == 'l'};
        if (!dbus_reader_u8(&reader, &header->type) || !dbus_reader_u8(&reader, &header->flags) ||
            !dbus_reader_u8(&reader, &version) || !dbus_reader_u32(&reader, &body_length) ||
            !dbus_reader_u32(&reader, &header->serial) || !dbus_reader_u32(&reader, &fields_length) || version != 1 ||
            fields_length > 16 * 1024 * 1024 || body_length > 64 * 1024 * 1024)
                goto malformed;
        body_offset = 16 + fields_length;
        body_offset = (body_offset + 7) & ~(size_t)7;
        if (body_offset > SIZE_MAX - body_length)
                goto malformed;
        total = body_offset + body_length;
        if (length < total)
                return error_set(error, EAGAIN, "Incomplete D-Bus message");
        fields = (DBusReader){.bytes = bytes + 16, .length = fields_length, .little_endian = endian == 'l'};
        if (!parse_fields(fields, header))
                goto malformed;
        *body = (DBusReader){.bytes = bytes + body_offset, .length = body_length, .little_endian = endian == 'l'};
        *consumed = total;
        return true;
malformed:
        dbus_header_clear(header);
        return error_set(error, EPROTO, "Malformed D-Bus message");
}
