#define _GNU_SOURCE
#include "service-file.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static char *trim(char *text)
{
        char *end;
        while (isspace((unsigned char)*text))
                ++text;
        end = text + strlen(text);
        while (end > text && isspace((unsigned char)end[-1]))
                --end;
        *end = '\0';
        return text;
}

static char *unescape_value(const char *value, Error **error)
{
        StrBuf result = {0};
        for (const char *p = value; *p; ++p) {
                char escaped;
                if (*p != '\\') {
                        if (!str_buf_append_n(&result, p, 1))
                                goto memory;
                        continue;
                }
                if (!*++p) {
                        str_buf_clear(&result);
                        error_set(error, EINVAL, "Trailing backslash in service-file value");
                        return NULL;
                }
                switch (*p) {
                case 's':
                        escaped = ' ';
                        break;
                case 'n':
                        escaped = '\n';
                        break;
                case 't':
                        escaped = '\t';
                        break;
                case 'r':
                        escaped = '\r';
                        break;
                case '\\':
                        escaped = '\\';
                        break;
                default:
                        str_buf_clear(&result);
                        error_set(error, EINVAL, "Unsupported service-file escape '\\%c'", *p);
                        return NULL;
                }
                if (!str_buf_append_n(&result, &escaped, 1))
                        goto memory;
        }
        return str_buf_steal(&result);
memory:
        str_buf_clear(&result);
        error_set(error, ENOMEM, "Service-file value: out of memory");
        return NULL;
}

static bool set_field(char **field, const char *value, Error **error)
{
        char *copy = unescape_value(value, error);
        if (!copy)
                return false;
        free(*field);
        *field = copy;
        return true;
}

void service_file_clear(ServiceFile *file)
{
        free(file->name);
        free(file->exec);
        free(file->user);
        free(file->systemd_service);
        ptr_vec_clear(&file->arguments);
        *file = (ServiceFile){0};
}

bool service_exec_parse(const char *command, PtrVec *arguments, Error **error)
{
        PtrVec candidate;
        StrBuf word = {0};
        bool single = false, double_quote = false, escaped = false, have_word = false;

        ptr_vec_init(&candidate, free);
        for (const char *p = command;; ++p) {
                unsigned char c = (unsigned char)*p;
                if (!c && (single || double_quote)) {
                        error_set(error, EINVAL, "Unterminated quote in Exec command");
                        goto fail;
                }
                if (escaped) {
                        if (!c) {
                                error_set(error, EINVAL, "Trailing backslash in Exec command");
                                goto fail;
                        }
                        if (double_quote && c != '$' && c != '`' && c != '"' && c != '\\' && c != '\n')
                                if (!str_buf_append_n(&word, "\\", 1))
                                        goto memory;
                        if (c != '\n' && !str_buf_append_n(&word, (const char *)&c, 1))
                                goto memory;
                        escaped = false;
                        have_word = true;
                        continue;
                }
                if (!single && c == '\\') {
                        escaped = true;
                        have_word = true;
                        continue;
                }
                if (!double_quote && c == '\'') {
                        single = !single;
                        have_word = true;
                        continue;
                }
                if (!single && c == '"') {
                        double_quote = !double_quote;
                        have_word = true;
                        continue;
                }
                if (!single && !double_quote && (!c || isspace(c))) {
                        if (have_word) {
                                char *value = str_buf_steal(&word);
                                if (!value || !ptr_vec_push(&candidate, value)) {
                                        free(value);
                                        goto memory;
                                }
                                have_word = false;
                        }
                        if (!c)
                                break;
                        continue;
                }
                if (!single && !double_quote && c == '#' && !have_word) {
                        while (p[1] && p[1] != '\n')
                                ++p;
                        continue;
                }
                if (!str_buf_append_n(&word, (const char *)&c, 1))
                        goto memory;
                have_word = true;
        }
        if (!candidate.len || !*(char *)candidate.items[0]) {
                error_set(error, EINVAL, "Exec command is empty");
                goto fail;
        }
        ptr_vec_clear(arguments);
        *arguments = candidate;
        str_buf_clear(&word);
        return true;
memory:
        error_set(error, ENOMEM, "Exec command: out of memory");
fail:
        str_buf_clear(&word);
        ptr_vec_clear(&candidate);
        return false;
}

bool dbus_name_is_valid(const char *name)
{
        size_t length;
        bool component_start = true, dot = false;

        if (!name || !*name || name[0] == ':')
                return false;
        length = strlen(name);
        if (length > 255)
                return false;
        for (size_t i = 0; i < length; ++i) {
                unsigned char c = (unsigned char)name[i];
                if (c == '.') {
                        if (component_start)
                                return false;
                        component_start = true;
                        dot = true;
                        continue;
                }
                if (!(isalnum(c) || c == '_' || c == '-'))
                        return false;
                if (component_start && isdigit(c))
                        return false;
                component_start = false;
        }
        return dot && !component_start;
}

bool service_file_load(const char *path, ServiceFile *file, Error **error)
{
        ServiceFile candidate = {0};
        char *contents = NULL, *cursor, *line;
        size_t line_number = 0;
        bool section = false;

        ptr_vec_init(&candidate.arguments, free);
        if (!read_file_limited(path, 1024 * 1024, &contents, NULL, error))
                return false;
        cursor = contents;
        while ((line = strsep(&cursor, "\n"))) {
                char *value, *key;
                ++line_number;
                if (*line && line[strlen(line) - 1] == '\r')
                        line[strlen(line) - 1] = '\0';
                line = trim(line);
                if (!*line || *line == '#' || *line == ';')
                        continue;
                if (*line == '[') {
                        size_t n = strlen(line);
                        if (n < 2 || line[n - 1] != ']') {
                                error_set(error, EINVAL, "malformed section");
                                goto located;
                        }
                        line[n - 1] = '\0';
                        section = strcmp(line + 1, "D-BUS Service") == 0;
                        continue;
                }
                value = strchr(line, '=');
                if (!value) {
                        error_set(error, EINVAL, "expected key=value");
                        goto located;
                }
                *value++ = '\0';
                key = trim(line);
                value = trim(value);
                if (!section)
                        continue;
                if (strcmp(key, "Name") == 0) {
                        if (!set_field(&candidate.name, value, error))
                                goto located;
                } else if (strcmp(key, "Exec") == 0) {
                        if (!set_field(&candidate.exec, value, error))
                                goto located;
                } else if (strcmp(key, "User") == 0) {
                        if (!set_field(&candidate.user, value, error))
                                goto located;
                } else if (strcmp(key, "SystemdService") == 0) {
                        if (!set_field(&candidate.systemd_service, value, error))
                                goto located;
                }
        }
        if (candidate.exec && !service_exec_parse(candidate.exec, &candidate.arguments, error)) {
                /* Exec is parsed after the file, so no single line applies. */
                error_prefix(error, "%s: ", path);
                goto fail;
        }
        free(contents);
        service_file_clear(file);
        *file = candidate;
        return true;
located:
        error_prefix(error, "%s:%zu: ", path, line_number);
fail:
        free(contents);
        service_file_clear(&candidate);
        return false;
}
