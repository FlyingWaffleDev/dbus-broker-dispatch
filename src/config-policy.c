#include "config-policy-internal.h"
#include "config.h"

#include <expat.h>
#include <stdarg.h>
#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

typedef struct {
        LauncherConfig *config;
        gchar *base_dir;
        const gchar *file;
        PolicyContext context;
        guint uid;
        guint gid;
        const gchar *text_element;
        GString *text;
        gboolean include_ignore_missing;
        gboolean include_if_selinux;
        gboolean include_selinux_root_relative;
        gchar *limit_name;
        XML_Parser parser;
        GError *error;
        GPtrArray *elements;
        guint ignored_depth;
} ParserState;

static void optimize_rule_array(GPtrArray *rules);
static void optimize_rule_table(GHashTable *table);
static void optimize_strings(GPtrArray *strings);
static void parser_warning(ParserState *state, const gchar *format, ...);

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
        config->watch_paths = g_ptr_array_new_with_free_func(g_free);
        config->active_files = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        config->selinux_associations = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        config->nss = nss_cache_new();
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
        g_ptr_array_unref(config->watch_paths);
        g_hash_table_unref(config->active_files);
        g_hash_table_unref(config->selinux_associations);
        nss_cache_free(config->nss);
        g_free(config->address);
        g_free(config->user);
        g_free(config->bus_type);
        g_free(config);
}

GPtrArray *launcher_config_service_dirs(LauncherConfig *config)
{
        return config->service_dirs;
}

GPtrArray *launcher_config_watch_paths(LauncherConfig *config)
{
        return config->watch_paths;
}

NssCache *launcher_config_nss_cache(LauncherConfig *config)
{
        return config->nss;
}

const gchar *launcher_config_address(LauncherConfig *config)
{
        return config->address;
}

const gchar *launcher_config_user(LauncherConfig *config)
{
        return config->user;
}

const gchar *launcher_config_bus_type(LauncherConfig *config)
{
        return config->bus_type;
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

static gboolean lookup_uid(LauncherConfig *config, const gchar *name, guint *uid)
{
        uid_t resolved;
        GError *error = NULL;
        if (!nss_cache_lookup_uid(config->nss, name, &resolved, &error)) {
                g_clear_error(&error);
                return FALSE;
        }
        *uid = resolved;
        return TRUE;
}

static gboolean lookup_gid(LauncherConfig *config, const gchar *name, guint *gid)
{
        gid_t resolved;
        GError *error = NULL;
        if (!nss_cache_lookup_gid(config->nss, name, &resolved, &error)) {
                g_clear_error(&error);
                return FALSE;
        }
        *gid = resolved;
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
                if ((user && !g_str_equal(user, "*") && !lookup_uid(state->config, user, &id)) ||
                    (group && !g_str_equal(group, "*") && !lookup_gid(state->config, group, &id))) {
                        parser_warning(state, "ignoring D-Bus policy rule for unknown %s '%s'",
                                       user ? "user" : "group", user ? user : group);
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
                parser_warning(state, "ignoring invalid D-Bus policy rule");
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
        parser_warning(state, "ignoring invalid D-Bus policy attribute combination");
        policy_rule_free(rule);
}

static gboolean load_file(LauncherConfig *config, const gchar *path, gboolean ignore_missing, GError **error);

static gchar *resolve_path(const gchar *base_dir, const gchar *path)
{
        if (g_path_is_absolute(path))
                return g_strdup(path);
        return g_build_filename(base_dir, path, NULL);
}

static void parser_warning(ParserState *state, const gchar *format, ...)
{
        va_list arguments;
        gchar *message;

        va_start(arguments, format);
        message = g_strdup_vprintf(format, arguments);
        va_end(arguments);
        g_warning("%s:%lu: %s", state->file, (unsigned long)XML_GetCurrentLineNumber(state->parser), message);
        g_free(message);
}

static gboolean string_in(const gchar *value, const gchar *const *values)
{
        for (; *values; ++values)
                if (g_str_equal(value, *values))
                        return TRUE;
        return FALSE;
}

static gboolean element_is_bus_child(const gchar *element)
{
        static const gchar *const children[] = {
                "user", "type", "fork", "syslog", "keep_umask", "listen", "pidfile", "includedir",
                "standard_session_servicedirs", "standard_system_servicedirs", "servicedir", "servicehelper",
                "auth", "include", "policy", "limit", "selinux", "apparmor", NULL,
        };
        return string_in(element, children);
}

static gboolean validate_element(ParserState *state, const gchar *element)
{
        const gchar *parent = state->elements->len
                                      ? g_ptr_array_index(state->elements, state->elements->len - 1)
                                      : NULL;

        if (!parent)
                return g_str_equal(element, "busconfig");
        if (g_str_equal(parent, "busconfig"))
                return element_is_bus_child(element);
        if (g_str_equal(parent, "policy"))
                return g_str_equal(element, "allow") || g_str_equal(element, "deny");
        if (g_str_equal(parent, "selinux"))
                return g_str_equal(element, "associate");
        return FALSE;
}

static gboolean valid_boolean(const gchar *value)
{
        return g_str_equal(value, "true") || g_str_equal(value, "false");
}

static void validate_attributes(ParserState *state, const gchar *element, const gchar **attributes)
{
        static const gchar *const allow_deny[] = {
                "send_interface", "send_member", "send_error", "send_destination", "send_path", "send_type",
                "send_requested_reply", "send_broadcast", "receive_interface", "receive_member", "receive_error",
                "receive_sender", "receive_path", "receive_type", "receive_requested_reply", "eavesdrop",
                "min_fds", "max_fds", "own", "own_prefix", "user", "group", "log", NULL,
        };
        static const gchar *const no_attributes[] = {NULL};
        static const gchar *const include_attributes[] = {
                "ignore_missing", "if_selinux_enabled", "selinux_root_relative", NULL,
        };
        static const gchar *const policy_attributes[] = {"context", "user", "group", "at_console", NULL};
        static const gchar *const associate_attributes[] = {"own", "context", NULL};
        static const gchar *const apparmor_attributes[] = {"mode", NULL};
        static const gchar *const limit_attributes[] = {"name", NULL};
        static const gchar *const limit_names[] = {
                "max_incoming_bytes", "max_incoming_unix_fds", "max_outgoing_bytes",
                "max_outgoing_unix_fds", "max_message_size", "max_message_unix_fds",
                "service_start_timeout", "auth_timeout", "pending_fd_timeout", "max_completed_connections",
                "max_incomplete_connections", "max_connections_per_user", "max_pending_service_starts",
                "max_names_per_connection", "max_match_rules_per_connection", "max_replies_per_connection",
                "max_containers_per_user", "max_containers", "max_connections_per_container",
                "max_container_metadata_bytes", "reply_timeout", NULL,
        };
        const gchar *const *allowed = no_attributes;

        if (g_str_equal(element, "include"))
                allowed = include_attributes;
        else if (g_str_equal(element, "policy"))
                allowed = policy_attributes;
        else if (g_str_equal(element, "allow") || g_str_equal(element, "deny"))
                allowed = allow_deny;
        else if (g_str_equal(element, "associate"))
                allowed = associate_attributes;
        else if (g_str_equal(element, "apparmor"))
                allowed = apparmor_attributes;
        else if (g_str_equal(element, "limit"))
                allowed = limit_attributes;

        for (const gchar **item = attributes; item && *item; item += 2) {
                const gchar *name = item[0], *value = item[1];
                if (!string_in(name, allowed)) {
                        parser_warning(state, "unknown attribute %s=\"%s\" on <%s>", name, value, element);
                        continue;
                }
                if (g_str_equal(element, "include") &&
                    (g_str_equal(name, "ignore_missing") || g_str_equal(name, "if_selinux_enabled") ||
                     g_str_equal(name, "selinux_root_relative")) &&
                    !g_str_equal(value, "yes") && !g_str_equal(value, "no"))
                        parser_warning(state, "invalid value %s=\"%s\"", name, value);
                else if (g_str_equal(element, "policy") && g_str_equal(name, "context") &&
                         !g_str_equal(value, "default") && !g_str_equal(value, "mandatory"))
                        parser_warning(state, "invalid policy context=\"%s\"", value);
                else if (g_str_equal(element, "policy") && g_str_equal(name, "at_console") &&
                         !valid_boolean(value))
                        parser_warning(state, "invalid at_console=\"%s\"", value);
                else if ((g_str_has_suffix(name, "_requested_reply") || g_str_equal(name, "send_broadcast") ||
                          g_str_equal(name, "eavesdrop") || g_str_equal(name, "log")) &&
                         !valid_boolean(value))
                        parser_warning(state, "invalid boolean %s=\"%s\"", name, value);
                else if ((g_str_equal(name, "send_type") || g_str_equal(name, "receive_type")) &&
                         !g_str_equal(value, "method_call") && !g_str_equal(value, "method_return") &&
                         !g_str_equal(value, "signal") && !g_str_equal(value, "error"))
                        parser_warning(state, "invalid message type %s=\"%s\"", name, value);
                else if (g_str_equal(element, "apparmor") && g_str_equal(name, "mode") &&
                         !g_str_equal(value, "enabled") && !g_str_equal(value, "disabled") &&
                         !g_str_equal(value, "required"))
                        parser_warning(state, "invalid AppArmor mode=\"%s\"", value);
                else if (g_str_equal(element, "limit") && g_str_equal(name, "name") &&
                         !string_in(value, limit_names))
                        parser_warning(state, "invalid limit name=\"%s\"", value);
        }

        if (g_str_equal(element, "policy")) {
                guint contexts = (attribute(attributes, "context") != NULL) +
                                 (attribute(attributes, "user") != NULL) +
                                 (attribute(attributes, "group") != NULL) +
                                 (attribute(attributes, "at_console") != NULL);
                if (contexts == 0)
                        parser_warning(state, "missing context attribute on <policy>");
                else if (contexts > 1)
                        parser_warning(state, "conflicting context attributes on <policy>");
        } else if (g_str_equal(element, "limit") && !attribute(attributes, "name")) {
                parser_warning(state, "required attribute name missing on <limit>");
        } else if (g_str_equal(element, "associate")) {
                if (!attribute(attributes, "own"))
                        parser_warning(state, "required attribute own missing on <associate>");
                if (!attribute(attributes, "context"))
                        parser_warning(state, "required attribute context missing on <associate>");
        }
}

static void parser_start(void *data, const XML_Char *element, const XML_Char **attributes)
{
        ParserState *state = data;
        const gchar *context;

        if (state->ignored_depth) {
                ++state->ignored_depth;
                return;
        }
        if (!validate_element(state, element)) {
                parser_warning(state, "unknown or misplaced element <%s>; ignoring its subtree", element);
                state->ignored_depth = 1;
                return;
        }
        validate_attributes(state, element, attributes);
        g_ptr_array_add(state->elements, g_strdup(element));

        if (g_str_equal(element, "policy")) {
                context = attribute(attributes, "context");
                state->context = POLICY_CONTEXT_DEFAULT;
                state->uid = state->gid = 0;
                const gchar *at_console = attribute(attributes, "at_console");
                if (!!attribute(attributes, "user") + !!attribute(attributes, "group") + !!context +
                            !!at_console >
                    1) {
                        parser_warning(state, "ignoring D-Bus policy with conflicting identity contexts");
                        state->context = POLICY_CONTEXT_NONE;
                } else if (attribute(attributes, "user")) {
                        state->context = POLICY_CONTEXT_USER;
                        if (!lookup_uid(state->config, attribute(attributes, "user"), &state->uid)) {
                                parser_warning(state, "ignoring policy for unknown user '%s'",
                                               attribute(attributes, "user"));
                                state->context = POLICY_CONTEXT_NONE;
                        }
                } else if (attribute(attributes, "group")) {
                        state->context = POLICY_CONTEXT_GROUP;
                        if (!lookup_gid(state->config, attribute(attributes, "group"), &state->gid)) {
                                parser_warning(state, "ignoring policy for unknown group '%s'",
                                               attribute(attributes, "group"));
                                state->context = POLICY_CONTEXT_NONE;
                        }
                } else if (context && g_str_equal(context, "mandatory")) {
                        state->context = POLICY_CONTEXT_MANDATORY;
                } else if (at_console && g_str_equal(at_console, "true")) {
                        state->context = POLICY_CONTEXT_AT_CONSOLE;
                        state->config->uses_console_policy = TRUE;
                } else if (at_console && g_str_equal(at_console, "false")) {
                        state->context = POLICY_CONTEXT_NO_CONSOLE;
                        state->config->uses_console_policy = TRUE;
                } else if (context && !g_str_equal(context, "default")) {
                        parser_warning(state, "ignoring D-Bus policy with unknown context '%s'", context);
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
                        parser_warning(state, "ignoring invalid AppArmor policy mode '%s'", mode);
        } else if (g_str_equal(element, "allow") || g_str_equal(element, "deny")) {
                parse_rule(state, element, attributes);
        } else if (g_str_equal(element, "associate")) {
                const gchar *own = attribute(attributes, "own");
                const gchar *context_value = attribute(attributes, "context");
                if (own && context_value)
                        g_hash_table_replace(state->config->selinux_associations, g_strdup(own),
                                             g_strdup(context_value));
        } else if (g_str_equal(element, "include") || g_str_equal(element, "includedir") ||
                   g_str_equal(element, "servicedir") || g_str_equal(element, "listen") ||
                   g_str_equal(element, "user") || g_str_equal(element, "type")) {
                state->text_element = element;
                state->include_ignore_missing =
                        g_strcmp0(attribute(attributes, "ignore_missing"), "yes") == 0;
                state->include_if_selinux =
                        g_strcmp0(attribute(attributes, "if_selinux_enabled"), "yes") == 0;
                state->include_selinux_root_relative =
                        g_strcmp0(attribute(attributes, "selinux_root_relative"), "yes") == 0;
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
                const gchar *runtime = g_getenv("XDG_RUNTIME_DIR");
                if (runtime && g_path_is_absolute(runtime))
                        g_ptr_array_add(state->config->service_dirs,
                                        g_build_filename(runtime, "dbus-1", "services", NULL));
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

        g_ptr_array_add(config->watch_paths, g_canonicalize_filename(path, NULL));
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

        if (state->ignored_depth) {
                --state->ignored_depth;
                return;
        }
        if (state->elements->len == 0 ||
            !g_str_equal(element, g_ptr_array_index(state->elements, state->elements->len - 1))) {
                parser_warning(state, "internal element-stack mismatch at </%s>", element);
                return;
        }
        g_ptr_array_remove_index(state->elements, state->elements->len - 1);
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
                        gboolean selinux_enabled = FALSE;
                        const gchar *selinux_root = NULL;
#ifdef HAVE_SELINUX
                        selinux_enabled = is_selinux_enabled() > 0;
                        selinux_root = selinux_policy_root();
#endif
                        if (state->include_if_selinux && !selinux_enabled)
                                goto include_done;
                        if (state->include_selinux_root_relative && selinux_root &&
                            !g_path_is_absolute(value))
                                path = g_build_filename(selinux_root, value, NULL);
                        else
                                path = resolve_path(state->base_dir, value);
                        if (!load_file(state->config, path, state->include_ignore_missing, &error)) {
                                g_prefix_error(&error, "Invalid D-Bus include %s: ", path);
                                parser_fail(state, g_steal_pointer(&error));
                        }
                        g_free(path);
include_done:
                        ;
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
                } else if (g_str_equal(element, "type")) {
                        g_free(state->config->bus_type);
                        state->config->bus_type = g_strdup(value);
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
        if (!state->ignored_depth && state->text_element)
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
        g_ptr_array_add(config->watch_paths, g_strdup(canonical));
        if (g_hash_table_contains(config->active_files, canonical)) {
                g_warning("%s: recursive D-Bus configuration include ignored", canonical);
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
        g_hash_table_add(config->active_files, g_strdup(canonical));
        state.base_dir = g_path_get_dirname(canonical);
        state.file = canonical;
        state.text = g_string_new(NULL);
        state.elements = g_ptr_array_new_with_free_func(g_free);
        parser = XML_ParserCreate(NULL);
        if (!parser) {
                g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE, "%s: cannot allocate XML parser", canonical);
                g_string_free(state.text, TRUE);
                g_ptr_array_unref(state.elements);
                g_free(state.base_dir);
                g_free(contents);
                g_hash_table_remove(config->active_files, canonical);
                g_free(canonical);
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
        g_ptr_array_unref(state.elements);
        g_free(state.limit_name);
        g_free(state.base_dir);
        g_free(contents);
        g_hash_table_remove(config->active_files, canonical);
        g_free(canonical);
        return success;
}

gboolean launcher_config_load(LauncherConfig *config, const gchar *path, GError **error)
{
        if (!load_file(config, path, FALSE, error))
                return FALSE;
        optimize_rule_array(config->default_rules);
        optimize_rule_array(config->at_console_rules);
        optimize_rule_array(config->no_console_rules);
        optimize_rule_table(config->user_rules);
        optimize_rule_table(config->group_rules);
        optimize_strings(config->service_dirs);
        optimize_strings(config->watch_paths);
        return TRUE;
}

static gchar *rule_signature(const PolicyRule *rule)
{
        return g_strdup_printf("%u:%u:%u:%s:%s:%s:%s:%u:%u:%" G_GUINT64_FORMAT ":%" G_GUINT64_FORMAT,
                               rule->type, rule->allow, rule->own_prefix, rule->name ? rule->name : "",
                               rule->path ? rule->path : "", rule->interface ? rule->interface : "",
                               rule->member ? rule->member : "", rule->message_type, rule->broadcast,
                               rule->min_fds, rule->max_fds);
}

static void optimize_rule_array(GPtrArray *rules)
{
        GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

        /* Later rules have higher priority. An earlier byte-for-byte equivalent
         * rule with the same verdict can therefore never affect a decision. */
        for (guint index = rules->len; index > 0; --index) {
                PolicyRule *rule = g_ptr_array_index(rules, index - 1);
                gchar *signature = rule_signature(rule);
                if (g_hash_table_contains(seen, signature)) {
                        g_free(signature);
                        g_ptr_array_remove_index(rules, index - 1);
                } else {
                        g_hash_table_add(seen, signature);
                }
        }
        g_hash_table_unref(seen);
}

static void optimize_rule_table(GHashTable *table)
{
        GHashTableIter iterator;
        gpointer value;
        g_hash_table_iter_init(&iterator, table);
        while (g_hash_table_iter_next(&iterator, NULL, &value))
                optimize_rule_array(value);
}

static void optimize_strings(GPtrArray *strings)
{
        GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal);
        for (guint index = 0; index < strings->len;) {
                const gchar *value = g_ptr_array_index(strings, index);
                if (g_hash_table_contains(seen, value))
                        g_ptr_array_remove_index(strings, index);
                else {
                        g_hash_table_add(seen, (gpointer)value);
                        ++index;
                }
        }
        g_hash_table_unref(seen);
}
