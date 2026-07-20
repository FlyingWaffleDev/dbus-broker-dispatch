#include "config-policy.h"

#include <expat.h>
#include <grp.h>
#include <pwd.h>

#define BATCH_TYPE "(bta(btbs)a(btssssuutt)a(btssssuutt))"
#define UID_POLICY_TYPE "a(u" BATCH_TYPE ")"
#define GID_POLICY_TYPE "a(buu" BATCH_TYPE ")"

typedef enum {
        POLICY_CONTEXT_NONE,
        POLICY_CONTEXT_DEFAULT = 1,
        POLICY_CONTEXT_GROUP,
        POLICY_CONTEXT_USER,
        POLICY_CONTEXT_AT_CONSOLE,
        POLICY_CONTEXT_NO_CONSOLE,
        POLICY_CONTEXT_MANDATORY,
} PolicyContext;

typedef enum {
        POLICY_RULE_CONNECT,
        POLICY_RULE_OWN,
        POLICY_RULE_SEND,
        POLICY_RULE_RECV,
} PolicyRuleType;

typedef struct {
        PolicyRuleType type;
        gboolean allow;
        gboolean own_prefix;
        guint64 priority;
        gchar *name;
        gchar *path;
        gchar *interface;
        gchar *member;
        guint message_type;
        guint broadcast;
        guint64 min_fds;
        guint64 max_fds;
} PolicyRule;

struct LauncherConfig {
        GPtrArray *default_rules;
        GHashTable *user_rules;
        GHashTable *group_rules;
        GPtrArray *at_console_rules;
        GPtrArray *no_console_rules;
        GPtrArray *service_dirs;
        GHashTable *loaded_files;
        gchar *address;
        gchar *user;
        guint64 priority;
        gboolean uses_console_policy;
        guint apparmor_mode;
        guint64 max_outgoing_bytes;
        guint64 max_outgoing_fds;
        guint64 max_connections_per_user;
        guint64 max_matches_per_connection;
};

typedef struct {
        LauncherConfig *config;
        gchar *base_dir;
        PolicyContext context;
        guint uid;
        guint gid;
        const gchar *text_element;
        GString *text;
        gboolean include_ignore_missing;
        gchar *limit_name;
        XML_Parser parser;
        GError *error;
} ParserState;

static void policy_rule_free(PolicyRule *rule)
{
        if (!rule)
                return;
        g_free(rule->name);
        g_free(rule->path);
        g_free(rule->interface);
        g_free(rule->member);
        g_free(rule);
}

static void rule_array_free(gpointer value)
{
        g_ptr_array_unref(value);
}

LauncherConfig *launcher_config_new(void)
{
        LauncherConfig *config = g_new0(LauncherConfig, 1);

        config->default_rules = g_ptr_array_new_with_free_func((GDestroyNotify)policy_rule_free);
        config->user_rules = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, rule_array_free);
        config->group_rules = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, rule_array_free);
        config->at_console_rules = g_ptr_array_new_with_free_func((GDestroyNotify)policy_rule_free);
        config->no_console_rules = g_ptr_array_new_with_free_func((GDestroyNotify)policy_rule_free);
        config->service_dirs = g_ptr_array_new_with_free_func(g_free);
        config->loaded_files = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        config->apparmor_mode = 1;
        config->max_outgoing_bytes = G_GUINT64_CONSTANT(8) * 1024 * 1024;
        config->max_outgoing_fds = 64;
        config->max_connections_per_user = 64;
        config->max_matches_per_connection = 256;
        return config;
}

void launcher_config_free(LauncherConfig *config)
{
        if (!config)
                return;
        g_ptr_array_unref(config->default_rules);
        g_hash_table_unref(config->user_rules);
        g_hash_table_unref(config->group_rules);
        g_ptr_array_unref(config->at_console_rules);
        g_ptr_array_unref(config->no_console_rules);
        g_ptr_array_unref(config->service_dirs);
        g_hash_table_unref(config->loaded_files);
        g_free(config->address);
        g_free(config->user);
        g_free(config);
}

GPtrArray *launcher_config_service_dirs(LauncherConfig *config)
{
        return config->service_dirs;
}

const gchar *launcher_config_address(LauncherConfig *config)
{
        return config->address;
}

const gchar *launcher_config_user(LauncherConfig *config)
{
        return config->user;
}

gboolean launcher_config_uses_console_policy(LauncherConfig *config)
{
        return config->uses_console_policy;
}

guint launcher_config_apparmor_mode(LauncherConfig *config)
{
        return config->apparmor_mode;
}

void launcher_config_set_apparmor_mode(LauncherConfig *config, guint mode)
{
        config->apparmor_mode = mode;
}

static guint64 multiply_saturating(guint64 left, guint64 right)
{
        return left && right > G_MAXUINT64 / left ? G_MAXUINT64 : left * right;
}

guint64 launcher_config_max_bytes(LauncherConfig *config)
{
        return multiply_saturating(config->max_connections_per_user, config->max_outgoing_bytes);
}

guint64 launcher_config_max_fds(LauncherConfig *config)
{
        return multiply_saturating(config->max_connections_per_user, config->max_outgoing_fds);
}

guint64 launcher_config_max_matches(LauncherConfig *config)
{
        return multiply_saturating(config->max_connections_per_user, config->max_matches_per_connection);
}

static const gchar *attribute(const gchar **attributes, const gchar *name)
{
        for (; attributes && *attributes; attributes += 2)
                if (g_str_equal(attributes[0], name))
                        return attributes[1];
        return NULL;
}

static gboolean parse_uint(const gchar *text, guint *value)
{
        guint64 parsed;

        return text && g_ascii_string_to_unsigned(text, 10, 0, G_MAXUINT, &parsed, NULL) && ((*value = parsed), TRUE);
}

static gboolean lookup_uid(const gchar *name, guint *uid)
{
        struct passwd *entry;

        if (parse_uint(name, uid))
                return TRUE;
        entry = getpwnam(name);
        if (!entry)
                return FALSE;
        *uid = entry->pw_uid;
        return TRUE;
}

static gboolean lookup_gid(const gchar *name, guint *gid)
{
        struct group *entry;

        if (parse_uint(name, gid))
                return TRUE;
        entry = getgrnam(name);
        if (!entry)
                return FALSE;
        *gid = entry->gr_gid;
        return TRUE;
}

static guint parse_message_type(const gchar *value)
{
        if (!value)
                return 0;
        if (g_str_equal(value, "method_call"))
                return 1;
        if (g_str_equal(value, "method_return"))
                return 2;
        if (g_str_equal(value, "error"))
                return 3;
        if (g_str_equal(value, "signal"))
                return 4;
        return G_MAXUINT;
}

static guint parse_tristate(const gchar *value)
{
        if (!value)
                return 0;
        if (g_str_equal(value, "true") || g_str_equal(value, "yes"))
                return 1;
        if (g_str_equal(value, "false") || g_str_equal(value, "no"))
                return 2;
        return G_MAXUINT;
}

static gboolean parse_uint64(const gchar *text, guint64 default_value, guint64 *value)
{
        if (!text) {
                *value = default_value;
                return TRUE;
        }
        return g_ascii_string_to_unsigned(text, 10, 0, G_MAXUINT64, value, NULL);
}

/* The broker controller protocol represents an unconstrained match as an
 * empty string. D-Bus XML spells the same match as "*". */
static gchar *copy_match(const gchar *value)
{
        return g_strdup(value && !g_str_equal(value, "*") ? value : "");
}

static GPtrArray *rules_for_id(GHashTable *rules, guint id)
{
        GPtrArray *array = g_hash_table_lookup(rules, &id);

        if (!array) {
                guint *key = g_new(guint, 1);
                *key = id;
                array = g_ptr_array_new_with_free_func((GDestroyNotify)policy_rule_free);
                g_hash_table_insert(rules, key, array);
        }
        return array;
}

static void append_rule(ParserState *state, PolicyRule *rule, gboolean connection_target, gboolean group_target,
                        guint id)
{
        GPtrArray *rules;

        if (connection_target) {
                rules = group_target ? rules_for_id(state->config->group_rules, id)
                                     : rules_for_id(state->config->user_rules, id);
        } else if (state->context == POLICY_CONTEXT_USER) {
                rules = rules_for_id(state->config->user_rules, id);
        } else if (state->context == POLICY_CONTEXT_GROUP) {
                rules = rules_for_id(state->config->group_rules, id);
        } else if (state->context == POLICY_CONTEXT_AT_CONSOLE) {
                rules = state->config->at_console_rules;
        } else if (state->context == POLICY_CONTEXT_NO_CONSOLE) {
                rules = state->config->no_console_rules;
        } else {
                rules = state->config->default_rules;
        }
        g_ptr_array_add(rules, rule);
}

static void parse_rule(ParserState *state, const gchar *element, const gchar **attributes)
{
        const gchar *user = attribute(attributes, "user");
        const gchar *group = attribute(attributes, "group");
        const gchar *own = attribute(attributes, "own");
        const gchar *own_prefix = attribute(attributes, "own_prefix");
        const gchar *send_destination = attribute(attributes, "send_destination");
        const gchar *recv_sender = attribute(attributes, "receive_sender");
        const gchar *send_type = attribute(attributes, "send_type");
        const gchar *recv_type = attribute(attributes, "receive_type");
        gboolean has_send = send_destination || attribute(attributes, "send_path") ||
                            attribute(attributes, "send_interface") || attribute(attributes, "send_member") ||
                            attribute(attributes, "send_error") || send_type ||
                            attribute(attributes, "send_broadcast") || attribute(attributes, "send_requested_reply");
        gboolean has_recv = recv_sender || attribute(attributes, "receive_path") ||
                            attribute(attributes, "receive_interface") || attribute(attributes, "receive_member") ||
                            attribute(attributes, "receive_error") || recv_type ||
                            attribute(attributes, "receive_requested_reply");
        PolicyRule *rule = g_new0(PolicyRule, 1);
        guint id = state->context == POLICY_CONTEXT_USER    ? state->uid
                   : state->context == POLICY_CONTEXT_GROUP ? state->gid
                                                            : 0;
        gboolean connection_target = FALSE;
        gboolean group_target = FALSE;
        guint categories = (user || group) + (own || own_prefix) + has_send + has_recv;

        if (state->context == POLICY_CONTEXT_NONE)
                goto invalid;
        if (categories == 0 && attribute(attributes, "eavesdrop"))
                categories = 1;
        if (categories != 1 || (user && group) || (own && own_prefix) ||
            ((user || group) && (state->context == POLICY_CONTEXT_USER || state->context == POLICY_CONTEXT_GROUP)))
                goto invalid;

        rule->allow = g_str_equal(element, "allow");
        rule->priority = ((guint64)state->context << 56) | ++state->config->priority;
        rule->min_fds = 0;
        rule->max_fds = G_MAXUINT64;

        if (user || group) {
                rule->type = POLICY_RULE_CONNECT;
                connection_target = TRUE;
                group_target = group != NULL;
                if ((user && !g_str_equal(user, "*") && !lookup_uid(user, &id)) ||
                    (group && !g_str_equal(group, "*") && !lookup_gid(group, &id))) {
                        g_warning("Ignoring D-Bus policy rule for unknown %s '%s'", user ? "user" : "group",
                                  user ? user : group);
                        policy_rule_free(rule);
                        return;
                }
                if ((user && g_str_equal(user, "*")) || (group && g_str_equal(group, "*")))
                        connection_target = FALSE;
        } else if (own || own_prefix) {
                rule->type = POLICY_RULE_OWN;
                rule->own_prefix = own_prefix != NULL || g_str_equal(own, "*");
                rule->name = g_strdup(own_prefix ? own_prefix : (g_str_equal(own, "*") ? "" : own));
        } else if (has_send) {
                rule->type = POLICY_RULE_SEND;
                rule->name = copy_match(send_destination);
                rule->path = copy_match(attribute(attributes, "send_path"));
                rule->interface = copy_match(attribute(attributes, "send_interface"));
                rule->member = copy_match(attribute(attributes, "send_member"));
                rule->message_type = parse_message_type(send_type);
                rule->broadcast = parse_tristate(attribute(attributes, "send_broadcast"));
        } else {
                rule->type = POLICY_RULE_RECV;
                rule->name = copy_match(recv_sender);
                rule->path = copy_match(attribute(attributes, "receive_path"));
                rule->interface = copy_match(attribute(attributes, "receive_interface"));
                rule->member = copy_match(attribute(attributes, "receive_member"));
                rule->message_type = parse_message_type(recv_type);
        }

        if (rule->message_type == G_MAXUINT || rule->broadcast == G_MAXUINT ||
            !parse_uint64(attribute(attributes, "min_fds"), 0, &rule->min_fds) ||
            !parse_uint64(attribute(attributes, "max_fds"), G_MAXUINT64, &rule->max_fds) ||
            rule->min_fds > rule->max_fds) {
                g_warning("Ignoring invalid D-Bus policy rule");
                policy_rule_free(rule);
                return;
        }
        if ((rule->type == POLICY_RULE_SEND || rule->type == POLICY_RULE_RECV) &&
            (rule->message_type == 2 || rule->message_type == 3)) {
                policy_rule_free(rule);
                return;
        }
        if (g_strcmp0(attribute(attributes, "eavesdrop"), "true") == 0 && !rule->allow) {
                policy_rule_free(rule);
                return;
        }
        append_rule(state, rule, connection_target, group_target, id);
        return;

invalid:
        g_warning("Ignoring invalid D-Bus policy attribute combination");
        policy_rule_free(rule);
}

static gboolean load_file(LauncherConfig *config, const gchar *path, gboolean ignore_missing, GError **error);

static gchar *resolve_path(const gchar *base_dir, const gchar *path)
{
        if (g_path_is_absolute(path))
                return g_strdup(path);
        return g_build_filename(base_dir, path, NULL);
}

static void parser_start(void *data, const XML_Char *element, const XML_Char **attributes)
{
        ParserState *state = data;
        const gchar *context;

        if (g_str_equal(element, "policy")) {
                context = attribute(attributes, "context");
                state->context = POLICY_CONTEXT_DEFAULT;
                state->uid = state->gid = 0;
                if (!!attribute(attributes, "user") + !!attribute(attributes, "group") + !!context > 1) {
                        g_warning("Ignoring D-Bus policy with conflicting identity contexts");
                        state->context = POLICY_CONTEXT_NONE;
                } else if (attribute(attributes, "user")) {
                        state->context = POLICY_CONTEXT_USER;
                        if (!lookup_uid(attribute(attributes, "user"), &state->uid)) {
                                g_warning("Ignoring policy for unknown user '%s'", attribute(attributes, "user"));
                                state->context = POLICY_CONTEXT_NONE;
                        }
                } else if (attribute(attributes, "group")) {
                        state->context = POLICY_CONTEXT_GROUP;
                        if (!lookup_gid(attribute(attributes, "group"), &state->gid)) {
                                g_warning("Ignoring policy for unknown group '%s'", attribute(attributes, "group"));
                                state->context = POLICY_CONTEXT_NONE;
                        }
                } else if (context && g_str_equal(context, "mandatory")) {
                        state->context = POLICY_CONTEXT_MANDATORY;
                } else if (context && g_str_equal(context, "at_console")) {
                        state->context = POLICY_CONTEXT_AT_CONSOLE;
                        state->config->uses_console_policy = TRUE;
                } else if (context && g_str_equal(context, "no_console")) {
                        state->context = POLICY_CONTEXT_NO_CONSOLE;
                        state->config->uses_console_policy = TRUE;
                } else if (context && !g_str_equal(context, "default")) {
                        g_warning("Ignoring D-Bus policy with unknown context '%s'", context);
                        state->context = POLICY_CONTEXT_NONE;
                }
        } else if (g_str_equal(element, "apparmor")) {
                const gchar *mode = attribute(attributes, "mode");
                if (!mode || g_str_equal(mode, "enabled"))
                        state->config->apparmor_mode = 1;
                else if (g_str_equal(mode, "disabled"))
                        state->config->apparmor_mode = 0;
                else if (g_str_equal(mode, "required"))
                        state->config->apparmor_mode = 2;
                else
                        g_warning("Ignoring invalid AppArmor policy mode '%s'", mode);
        } else if (g_str_equal(element, "allow") || g_str_equal(element, "deny")) {
                parse_rule(state, element, attributes);
        } else if (g_str_equal(element, "include") || g_str_equal(element, "includedir") ||
                   g_str_equal(element, "servicedir") || g_str_equal(element, "listen") ||
                   g_str_equal(element, "user")) {
                state->text_element = element;
                state->include_ignore_missing = g_strcmp0(attribute(attributes, "ignore_missing"), "yes") == 0 ||
                                                g_strcmp0(attribute(attributes, "if_selinux_enabled"), "yes") == 0;
                g_string_truncate(state->text, 0);
        } else if (g_str_equal(element, "limit")) {
                state->text_element = element;
                g_free(state->limit_name);
                state->limit_name = g_strdup(attribute(attributes, "name"));
                g_string_truncate(state->text, 0);
        } else if (g_str_equal(element, "standard_system_servicedirs")) {
                g_ptr_array_add(state->config->service_dirs, g_strdup("/etc/dbus-1/system-services"));
                g_ptr_array_add(state->config->service_dirs, g_strdup("/run/dbus-1/system-services"));
                g_ptr_array_add(state->config->service_dirs, g_strdup("/usr/local/share/dbus-1/system-services"));
                g_ptr_array_add(state->config->service_dirs, g_strdup("/usr/share/dbus-1/system-services"));
                g_ptr_array_add(state->config->service_dirs, g_strdup("/lib/dbus-1/system-services"));
        } else if (g_str_equal(element, "standard_session_servicedirs")) {
                g_ptr_array_add(state->config->service_dirs,
                                g_build_filename(g_get_user_data_dir(), "dbus-1", "services", NULL));
                for (const gchar *const *dirs = g_get_system_data_dirs(); *dirs; ++dirs)
                        g_ptr_array_add(state->config->service_dirs,
                                        g_build_filename(*dirs, "dbus-1", "services", NULL));
        }
}

static gint compare_strings(gconstpointer a, gconstpointer b)
{
        return g_strcmp0(*(const gchar *const *)a, *(const gchar *const *)b);
}

static gboolean load_directory(LauncherConfig *config, const gchar *path, GError **error)
{
        GDir *directory;
        GError *directory_error = NULL;
        const gchar *name;
        GPtrArray *names;

        directory = g_dir_open(path, 0, &directory_error);
        if (!directory) {
                if (g_error_matches(directory_error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
                        g_clear_error(&directory_error);
                        return TRUE;
                }
                g_propagate_error(error, directory_error);
                return FALSE;
        }
        names = g_ptr_array_new_with_free_func(g_free);
        while ((name = g_dir_read_name(directory)))
                if (g_str_has_suffix(name, ".conf"))
                        g_ptr_array_add(names, g_strdup(name));
        g_dir_close(directory);
        g_ptr_array_sort(names, compare_strings);
        for (guint index = 0; index < names->len; ++index) {
                gchar *file = g_build_filename(path, g_ptr_array_index(names, index), NULL);
                if (!load_file(config, file, FALSE, error)) {
                        g_free(file);
                        g_ptr_array_unref(names);
                        return FALSE;
                }
                g_free(file);
        }
        g_ptr_array_unref(names);
        return TRUE;
}

static void parser_fail(ParserState *state, GError *error)
{
        if (!state->error)
                state->error = error;
        else
                g_error_free(error);
        XML_StopParser(state->parser, XML_FALSE);
}

static void parser_end(void *data, const XML_Char *element)
{
        ParserState *state = data;
        gchar *value;
        gchar *path;
        GError *error = NULL;

        if (g_str_equal(element, "policy")) {
                state->context = POLICY_CONTEXT_DEFAULT;
                return;
        }
        if (!state->text_element || !g_str_equal(element, state->text_element))
                return;
        value = g_strdup(state->text->str);
        g_strstrip(value);
        if (g_str_equal(element, "limit") && !*value) {
                g_set_error(&error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, "D-Bus limit '%s' has no value",
                            state->limit_name ? state->limit_name : "(unnamed)");
                parser_fail(state, g_steal_pointer(&error));
        }
        if (*value) {
                if (g_str_equal(element, "include")) {
                        path = resolve_path(state->base_dir, value);
                        if (!load_file(state->config, path, state->include_ignore_missing, &error)) {
                                g_prefix_error(&error, "Invalid D-Bus include %s: ", path);
                                parser_fail(state, g_steal_pointer(&error));
                        }
                        g_free(path);
                } else if (g_str_equal(element, "includedir")) {
                        path = resolve_path(state->base_dir, value);
                        if (!load_directory(state->config, path, &error)) {
                                g_prefix_error(&error, "Invalid D-Bus include directory %s: ", path);
                                parser_fail(state, g_steal_pointer(&error));
                        }
                        g_free(path);
                } else if (g_str_equal(element, "servicedir")) {
                        path = resolve_path(state->base_dir, value);
                        g_ptr_array_add(state->config->service_dirs, path);
                } else if (g_str_equal(element, "listen") && !state->config->address &&
                           g_str_has_prefix(value, "unix:path=")) {
                        state->config->address = g_strdup(value);
                } else if (g_str_equal(element, "user")) {
                        g_free(state->config->user);
                        state->config->user = g_strdup(value);
                } else if (g_str_equal(element, "limit")) {
                        guint64 parsed;
                        if (!state->limit_name ||
                            !g_ascii_string_to_unsigned(value, 10, 0, G_MAXUINT64, &parsed, NULL)) {
                                g_set_error(&error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                                            "Invalid D-Bus limit value '%s'", value);
                                parser_fail(state, g_steal_pointer(&error));
                        } else if (g_str_equal(state->limit_name, "max_outgoing_bytes")) {
                                state->config->max_outgoing_bytes = parsed;
                        } else if (g_str_equal(state->limit_name, "max_outgoing_unix_fds")) {
                                state->config->max_outgoing_fds = parsed;
                        } else if (g_str_equal(state->limit_name, "max_connections_per_user")) {
                                state->config->max_connections_per_user = parsed;
                        } else if (g_str_equal(state->limit_name, "max_match_rules_per_connection")) {
                                state->config->max_matches_per_connection = parsed;
                        }
                }
        }
        g_free(value);
        state->text_element = NULL;
        g_clear_pointer(&state->limit_name, g_free);
}

static void parser_text(void *data, const XML_Char *text, int length)
{
        ParserState *state = data;
        if (state->text_element)
                g_string_append_len(state->text, text, length);
}

static gboolean load_file(LauncherConfig *config, const gchar *path, gboolean ignore_missing, GError **error)
{
        gchar *canonical;
        gchar *contents;
        gsize length;
        XML_Parser parser;
        ParserState state = {.config = config, .context = POLICY_CONTEXT_DEFAULT};
        gboolean success = FALSE;

        canonical = g_canonicalize_filename(path, NULL);
        if (g_hash_table_contains(config->loaded_files, canonical)) {
                g_free(canonical);
                return TRUE;
        }
        if (!g_file_get_contents(canonical, &contents, &length, error)) {
                if (ignore_missing && g_error_matches(*error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
                        g_clear_error(error);
                        g_free(canonical);
                        return TRUE;
                }
                g_free(canonical);
                return FALSE;
        }
        if (length > (gsize)16 * 1024 * 1024) {
                g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "%s: D-Bus configuration exceeds 16 MiB",
                            canonical);
                g_free(contents);
                g_free(canonical);
                return FALSE;
        }
        g_hash_table_add(config->loaded_files, canonical);
        state.base_dir = g_path_get_dirname(canonical);
        state.text = g_string_new(NULL);
        parser = XML_ParserCreate(NULL);
        if (!parser) {
                g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE, "%s: cannot allocate XML parser", canonical);
                g_string_free(state.text, TRUE);
                g_free(state.base_dir);
                g_free(contents);
                return FALSE;
        }
        state.parser = parser;
        XML_SetUserData(parser, &state);
        XML_SetElementHandler(parser, parser_start, parser_end);
        XML_SetCharacterDataHandler(parser, parser_text);
        XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER);
        if (!XML_Parse(parser, contents, (int)length, TRUE)) {
                if (state.error)
                        g_propagate_error(error, g_steal_pointer(&state.error));
                else
                        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE, "%s:%lu: %s", canonical,
                                    (unsigned long)XML_GetCurrentLineNumber(parser),
                                    XML_ErrorString(XML_GetErrorCode(parser)));
        } else {
                success = TRUE;
        }
        XML_ParserFree(parser);
        g_string_free(state.text, TRUE);
        g_free(state.limit_name);
        g_free(state.base_dir);
        g_free(contents);
        return success;
}

gboolean launcher_config_load(LauncherConfig *config, const gchar *path, GError **error)
{
        return load_file(config, path, FALSE, error);
}

static GVariant *batch_from_rules(GPtrArray *base, GPtrArray *specific, gboolean default_connect)
{
        GVariantBuilder own, send, recv;
        gboolean connect = default_connect;
        /* Priority zero is the broker's implicit deny and is never selected.
         * Match the compatibility launcher's POLICY_PRIORITY_DEFAULT. */
        guint64 connect_priority = 1;
        GPtrArray *arrays[] = {base, specific, NULL};

        g_variant_builder_init(&own, G_VARIANT_TYPE("a(btbs)"));
        g_variant_builder_init(&send, G_VARIANT_TYPE("a(btssssuutt)"));
        g_variant_builder_init(&recv, G_VARIANT_TYPE("a(btssssuutt)"));
        for (guint array_index = 0; arrays[array_index]; ++array_index) {
                for (guint index = 0; index < arrays[array_index]->len; ++index) {
                        PolicyRule *rule = g_ptr_array_index(arrays[array_index], index);
                        if (rule->type == POLICY_RULE_CONNECT) {
                                if (rule->priority > connect_priority) {
                                        connect = rule->allow;
                                        connect_priority = rule->priority;
                                }
                        } else if (rule->type == POLICY_RULE_OWN) {
                                g_variant_builder_add(&own, "(btbs)", rule->allow, rule->priority, rule->own_prefix,
                                                      rule->name ? rule->name : "");
                        } else if (rule->type == POLICY_RULE_SEND) {
                                g_variant_builder_add(&send, "(btssssuutt)", rule->allow, rule->priority,
                                                      rule->name ? rule->name : "", rule->path ? rule->path : "",
                                                      rule->interface ? rule->interface : "",
                                                      rule->member ? rule->member : "", rule->message_type,
                                                      rule->broadcast, rule->min_fds, rule->max_fds);
                        } else if (rule->type == POLICY_RULE_RECV) {
                                g_variant_builder_add(&recv, "(btssssuutt)", rule->allow, rule->priority,
                                                      rule->name ? rule->name : "", rule->path ? rule->path : "",
                                                      rule->interface ? rule->interface : "",
                                                      rule->member ? rule->member : "", rule->message_type, 0,
                                                      rule->min_fds, rule->max_fds);
                        }
                }
        }
        return g_variant_new("(bt@a(btbs)@a(btssssuutt)@a(btssssuutt))", connect, connect_priority,
                             g_variant_builder_end(&own), g_variant_builder_end(&send), g_variant_builder_end(&recv));
}

static void add_uid_batches(GVariantBuilder *builder, LauncherConfig *config, gboolean user_scope)
{
        GHashTableIter iter;
        gpointer key;
        gpointer value;
        guint self = getuid();
        gboolean have_self = FALSE;

        g_variant_builder_add(builder, "(u@" BATCH_TYPE ")", G_MAXUINT32,
                              batch_from_rules(config->default_rules, NULL, FALSE));
        g_hash_table_iter_init(&iter, config->user_rules);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                gboolean is_self = *(guint *)key == self;
                g_variant_builder_add(builder, "(u@" BATCH_TYPE ")", *(guint *)key,
                                      batch_from_rules(config->default_rules, value, user_scope && is_self));
                have_self |= is_self;
        }

        /* dbus-daemon implicitly permits the UID that owns a session bus to
         * connect. dbus-broker denies by default, so model that fallback as a
         * UID-specific entry; do not grant other local users access. */
        if (user_scope && !have_self)
                g_variant_builder_add(builder, "(u@" BATCH_TYPE ")", self,
                                      batch_from_rules(config->default_rules, NULL, TRUE));
}

static void add_gid_batches(GVariantBuilder *builder, LauncherConfig *config)
{
        GHashTableIter iter;
        gpointer key;
        gpointer value;

        g_hash_table_iter_init(&iter, config->group_rules);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                guint gid = *(guint *)key;
                g_variant_builder_add(builder, "(buu@" BATCH_TYPE ")", TRUE, gid, gid,
                                      batch_from_rules(value, NULL, FALSE));
        }
}

static void add_console_batches(GVariantBuilder *builder, LauncherConfig *config, guint max_uid,
                                const GArray *console_uids)
{
        guint next = 0;

        if (config->no_console_rules->len == 0 && config->at_console_rules->len == 0)
                return;
        for (guint index = 0; console_uids && index < console_uids->len; ++index) {
                guint uid = g_array_index(console_uids, guint, index);
                if (uid > max_uid || uid < next)
                        continue;
                if (uid > next)
                        g_variant_builder_add(builder, "(buu@" BATCH_TYPE ")", FALSE, next, uid - 1,
                                              batch_from_rules(config->no_console_rules, NULL, FALSE));
                g_variant_builder_add(builder, "(buu@" BATCH_TYPE ")", FALSE, uid, uid,
                                      batch_from_rules(config->at_console_rules, NULL, FALSE));
                next = uid + 1;
        }
        if (next <= max_uid)
                g_variant_builder_add(builder, "(buu@" BATCH_TYPE ")", FALSE, next, max_uid,
                                      batch_from_rules(config->no_console_rules, NULL, FALSE));
        if (max_uid < G_MAXUINT)
                g_variant_builder_add(builder, "(buu@" BATCH_TYPE ")", FALSE, max_uid + 1, G_MAXUINT,
                                      batch_from_rules(config->at_console_rules, NULL, FALSE));
}

GVariant *launcher_config_export_policy(LauncherConfig *config, gboolean user_scope, guint system_uid_max,
                                        const GArray *console_uids)
{
        GVariantBuilder uids, gids, selinux;

        g_variant_builder_init(&uids, G_VARIANT_TYPE(UID_POLICY_TYPE));
        g_variant_builder_init(&gids, G_VARIANT_TYPE(GID_POLICY_TYPE));
        g_variant_builder_init(&selinux, G_VARIANT_TYPE("a(ss)"));
        /* dbus-daemon session.conf has no explicit connection grant: session
         * buses permit their owning user's local clients by default. System
         * buses remain deny-by-default unless their policy grants access. */
        add_uid_batches(&uids, config, user_scope);
        add_gid_batches(&gids, config);
        if (!user_scope)
                add_console_batches(&gids, config, system_uid_max, console_uids);
        return g_variant_new("(@" UID_POLICY_TYPE "@" GID_POLICY_TYPE "@a(ss)bs)", g_variant_builder_end(&uids),
                             g_variant_builder_end(&gids), g_variant_builder_end(&selinux), config->apparmor_mode != 0,
                             user_scope ? "session" : "system");
}
