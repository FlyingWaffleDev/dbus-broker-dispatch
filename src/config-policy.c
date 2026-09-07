#define _GNU_SOURCE
#include "config-policy-internal.h"
#include "config.h"
#include "log.h"

#include <dirent.h>
#include <errno.h>
#include <expat.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

typedef struct {
        LauncherConfig *config;
        char *base_dir;
        const char *file;
        PolicyContext context;
        uint32_t uid;
        uint32_t gid;
        const char *text_element;
        StrBuf *text;
        bool include_ignore_missing;
        bool include_if_selinux;
        bool include_selinux_root_relative;
        char *limit_name;
        XML_Parser parser;
        Error *error;
        PtrVec *elements;
        uint32_t ignored_depth;
} ParserState;

static void optimize_rule_array(PtrVec *rules);
static void optimize_rule_table(U32Map *table);
static void optimize_strings(PtrVec *strings);
static void parser_warning(ParserState *state, const char *format, ...);
static void parser_fail(ParserState *state, Error *error);

static void policy_rule_free(void *data)
{
        PolicyRule *rule = data;
        if (!rule)
                return;
        free(rule->name);
        free(rule->path);
        free(rule->interface);
        free(rule->member);
        free(rule);
}

static void rule_array_free(void *value)
{
        ptr_vec_free(value);
}

LauncherConfig *launcher_config_new(void)
{
        LauncherConfig *config = calloc(1, sizeof(*config));

        if (!config)
                return NULL;

        config->default_rules = ptr_vec_new(policy_rule_free);
        config->user_rules = u32_map_new(rule_array_free);
        config->group_rules = u32_map_new(rule_array_free);
        config->at_console_rules = ptr_vec_new(policy_rule_free);
        config->no_console_rules = ptr_vec_new(policy_rule_free);
        config->service_dirs = ptr_vec_new(free);
        config->watch_paths = ptr_vec_new(free);
        config->active_files = str_map_new(NULL);
        config->selinux_associations = str_map_new(free);
        config->nss = nss_cache_new();
        if (!config->default_rules || !config->user_rules || !config->group_rules || !config->at_console_rules ||
            !config->no_console_rules || !config->service_dirs || !config->watch_paths || !config->active_files ||
            !config->selinux_associations || !config->nss) {
                launcher_config_free(config);
                return NULL;
        }
        config->apparmor_mode = 1;
        config->max_outgoing_bytes = UINT64_C(8) * 1024 * 1024;
        config->max_outgoing_fds = 64;
        config->max_connections_per_user = 64;
        config->max_matches_per_connection = 256;
        return config;
}

void launcher_config_free(LauncherConfig *config)
{
        if (!config)
                return;
        ptr_vec_free(config->default_rules);
        u32_map_free(config->user_rules);
        u32_map_free(config->group_rules);
        ptr_vec_free(config->at_console_rules);
        ptr_vec_free(config->no_console_rules);
        ptr_vec_free(config->service_dirs);
        ptr_vec_free(config->watch_paths);
        str_map_free(config->active_files);
        str_map_free(config->selinux_associations);
        nss_cache_free(config->nss);
        free(config->address);
        free(config->user);
        free(config->bus_type);
        free(config->pid_file);
        free(config);
}

PtrVec *launcher_config_service_dirs(LauncherConfig *config)
{
        return config->service_dirs;
}

PtrVec *launcher_config_watch_paths(LauncherConfig *config)
{
        return config->watch_paths;
}

NssCache *launcher_config_nss_cache(LauncherConfig *config)
{
        return config->nss;
}

const char *launcher_config_address(LauncherConfig *config)
{
        return config->address;
}

const char *launcher_config_user(LauncherConfig *config)
{
        return config->user;
}

const char *launcher_config_bus_type(LauncherConfig *config)
{
        return config->bus_type;
}

bool launcher_config_uses_console_policy(LauncherConfig *config)
{
        return config->uses_console_policy;
}

bool launcher_config_keep_umask(LauncherConfig *config)
{
        return config->keep_umask;
}

bool launcher_config_fork(LauncherConfig *config)
{
        return config->fork;
}

bool launcher_config_syslog(LauncherConfig *config)
{
        return config->syslog;
}

const char *launcher_config_pid_file(LauncherConfig *config)
{
        return config->pid_file;
}

uint32_t launcher_config_apparmor_mode(LauncherConfig *config)
{
        return config->apparmor_mode;
}

void launcher_config_set_apparmor_mode(LauncherConfig *config, uint32_t mode)
{
        config->apparmor_mode = mode;
}

static uint64_t multiply_saturating(uint64_t left, uint64_t right)
{
        return left && right > UINT64_MAX / left ? UINT64_MAX : left * right;
}

uint64_t launcher_config_max_bytes(LauncherConfig *config)
{
        return multiply_saturating(config->max_connections_per_user, config->max_outgoing_bytes);
}

uint64_t launcher_config_max_fds(LauncherConfig *config)
{
        return multiply_saturating(config->max_connections_per_user, config->max_outgoing_fds);
}

uint64_t launcher_config_max_matches(LauncherConfig *config)
{
        return multiply_saturating(config->max_connections_per_user, config->max_matches_per_connection);
}

static const char *attribute(const char **attributes, const char *name)
{
        for (; attributes && *attributes; attributes += 2)
                if (str_equal(attributes[0], name))
                        return attributes[1];
        return NULL;
}

static void lookup_failed(ParserState *state, const char *kind, const char *name, Error *error)
{
        if (error && error->code == NSS_ERROR_NOT_FOUND) {
                parser_warning(state, "ignoring policy for unknown %s '%s'", kind, name);
                error_free(error);
                return;
        }
        if (!error)
                error_set(&error, ENOMEM, "Cannot resolve policy %s '%s'", kind, name);
        error_prefix(&error, "%s: policy %s '%s': ", state->file, kind, name);
        parser_fail(state, error);
}

static bool lookup_uid(ParserState *state, const char *name, uint32_t *uid)
{
        uid_t resolved;
        Error *error = NULL;
        if (!nss_cache_lookup_uid(state->config->nss, name, &resolved, &error)) {
                lookup_failed(state, "user", name, error);
                return false;
        }
        *uid = resolved;
        return true;
}

static bool lookup_gid(ParserState *state, const char *name, uint32_t *gid)
{
        gid_t resolved;
        Error *error = NULL;
        if (!nss_cache_lookup_gid(state->config->nss, name, &resolved, &error)) {
                lookup_failed(state, "group", name, error);
                return false;
        }
        *gid = resolved;
        return true;
}

static uint32_t parse_message_type(const char *value)
{
        if (!value)
                return 0;
        if (str_equal(value, "method_call"))
                return 1;
        if (str_equal(value, "method_return"))
                return 2;
        if (str_equal(value, "error"))
                return 3;
        if (str_equal(value, "signal"))
                return 4;
        return UINT32_MAX;
}

static uint32_t parse_tristate(const char *value)
{
        if (!value)
                return 0;
        if (str_equal(value, "true") || str_equal(value, "yes"))
                return 1;
        if (str_equal(value, "false") || str_equal(value, "no"))
                return 2;
        return UINT32_MAX;
}

static bool parse_uint64(const char *text, uint64_t default_value, uint64_t *value)
{
        if (!text) {
                *value = default_value;
                return true;
        }
        return parse_u64(text, UINT64_MAX, value);
}

/* The broker controller protocol represents an unconstrained match as an
 * empty string. D-Bus XML spells the same match as "*". */
static char *copy_match(const char *value)
{
        return str_dup(value && !str_equal(value, "*") ? value : "");
}

static PtrVec *rules_for_id(U32Map *rules, uint32_t id)
{
        PtrVec *array = u32_map_get(rules, id);

        if (!array) {
                array = ptr_vec_new(policy_rule_free);
                if (!array)
                        return NULL;
                if (!u32_map_set(rules, id, array)) {
                        ptr_vec_free(array);
                        return NULL;
                }
        }
        return array;
}

/* ptr_vec_push() of a NULL path would later reach opendir(); drop instead. */
static bool push_path(PtrVec *paths, char *path)
{
        if (!path)
                return false;
        if (!ptr_vec_push(paths, path)) {
                free(path);
                return false;
        }
        return true;
}

static void append_rule(ParserState *state, PolicyRule *rule, bool connection_target, bool group_target, uint32_t id)
{
        PtrVec *rules = NULL;

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
        if (!rules || !ptr_vec_push(rules, rule)) {
                policy_rule_free(rule);
                Error *error = NULL;
                error_set(&error, ENOMEM, "Out of memory appending policy rule");
                parser_fail(state, error);
                return;
        }
}

static void parse_rule(ParserState *state, const char *element, const char **attributes)
{
        const char *user = attribute(attributes, "user");
        const char *group = attribute(attributes, "group");
        const char *own = attribute(attributes, "own");
        const char *own_prefix = attribute(attributes, "own_prefix");
        const char *send_destination = attribute(attributes, "send_destination");
        const char *recv_sender = attribute(attributes, "receive_sender");
        const char *send_type = attribute(attributes, "send_type");
        const char *recv_type = attribute(attributes, "receive_type");
        const char *send_requested_reply = attribute(attributes, "send_requested_reply");
        const char *recv_requested_reply = attribute(attributes, "receive_requested_reply");
        /* dbus-broker tracks expected replies itself, so requested_reply is not
         * expressible in its policy. A rule that says nothing else would
         * otherwise widen into a match-everything rule. */
        bool only_send_requested_reply =
                send_requested_reply && !send_destination && !attribute(attributes, "send_path") &&
                !attribute(attributes, "send_interface") && !attribute(attributes, "send_member") &&
                !attribute(attributes, "send_error") && !send_type && !attribute(attributes, "send_broadcast");
        bool only_recv_requested_reply =
                recv_requested_reply && !recv_sender && !attribute(attributes, "receive_path") &&
                !attribute(attributes, "receive_interface") && !attribute(attributes, "receive_member") &&
                !attribute(attributes, "receive_error") && !recv_type;
        bool has_send = send_destination || attribute(attributes, "send_path") ||
                        attribute(attributes, "send_interface") || attribute(attributes, "send_member") ||
                        attribute(attributes, "send_error") || send_type || attribute(attributes, "send_broadcast") ||
                        send_requested_reply;
        bool has_recv = recv_sender || attribute(attributes, "receive_path") ||
                        attribute(attributes, "receive_interface") || attribute(attributes, "receive_member") ||
                        attribute(attributes, "receive_error") || recv_type || recv_requested_reply;
        PolicyRule *rule = calloc(1, sizeof(*rule));
        if (!rule) {
                Error *error = NULL;
                error_set(&error, ENOMEM, "Out of memory allocating policy rule");
                parser_fail(state, error);
                return;
        }
        uint32_t id = state->context == POLICY_CONTEXT_USER    ? state->uid
                      : state->context == POLICY_CONTEXT_GROUP ? state->gid
                                                               : 0;
        bool connection_target = false;
        bool group_target = false;
        uint32_t categories = (user || group) + (own || own_prefix) + has_send + has_recv;

        if (state->context == POLICY_CONTEXT_NONE)
                goto invalid;
        if (categories == 0 && attribute(attributes, "eavesdrop"))
                categories = 1;
        if (categories != 1 || (user && group) || (own && own_prefix) ||
            ((user || group) && (state->context == POLICY_CONTEXT_USER || state->context == POLICY_CONTEXT_GROUP)))
                goto invalid;

        rule->allow = str_equal(element, "allow");
        rule->priority = ((uint64_t)state->context << 56) | ++state->config->priority;
        rule->min_fds = 0;
        rule->max_fds = UINT64_MAX;

        if (user || group) {
                rule->type = POLICY_RULE_CONNECT;
                connection_target = true;
                group_target = group != NULL;
                if ((user && !str_equal(user, "*") && !lookup_uid(state, user, &id)) ||
                    (group && !str_equal(group, "*") && !lookup_gid(state, group, &id))) {
                        policy_rule_free(rule);
                        return;
                }
                if ((user && str_equal(user, "*")) || (group && str_equal(group, "*")))
                        connection_target = false;
        } else if (own || own_prefix) {
                rule->type = POLICY_RULE_OWN;
                rule->own_prefix = own_prefix != NULL || str_equal(own, "*");
                rule->name = str_dup(own_prefix ? own_prefix : (str_equal(own, "*") ? "" : own));
                if (!rule->name) {
                        policy_rule_free(rule);
                        Error *error = NULL;
                        error_set(&error, ENOMEM, "Out of memory copying rule name");
                        parser_fail(state, error);
                        return;
                }
        } else if (has_send) {
                rule->type = POLICY_RULE_SEND;
                rule->name = copy_match(send_destination);
                rule->path = copy_match(attribute(attributes, "send_path"));
                rule->interface = copy_match(attribute(attributes, "send_interface"));
                rule->member = copy_match(attribute(attributes, "send_member"));
                rule->message_type = parse_message_type(send_type);
                rule->broadcast = parse_tristate(attribute(attributes, "send_broadcast"));
                if (!rule->name || !rule->path || !rule->interface || !rule->member) {
                        policy_rule_free(rule);
                        Error *error = NULL;
                        error_set(&error, ENOMEM, "Out of memory copying rule fields");
                        parser_fail(state, error);
                        return;
                }
        } else {
                rule->type = POLICY_RULE_RECV;
                rule->name = copy_match(recv_sender);
                rule->path = copy_match(attribute(attributes, "receive_path"));
                rule->interface = copy_match(attribute(attributes, "receive_interface"));
                rule->member = copy_match(attribute(attributes, "receive_member"));
                rule->message_type = parse_message_type(recv_type);
                if (!rule->name || !rule->path || !rule->interface || !rule->member) {
                        policy_rule_free(rule);
                        Error *error = NULL;
                        error_set(&error, ENOMEM, "Out of memory copying rule fields");
                        parser_fail(state, error);
                        return;
                }
        }

        if (rule->message_type == UINT32_MAX || rule->broadcast == UINT32_MAX ||
            !parse_uint64(attribute(attributes, "min_fds"), 0, &rule->min_fds) ||
            !parse_uint64(attribute(attributes, "max_fds"), UINT64_MAX, &rule->max_fds) ||
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
        if ((rule->type == POLICY_RULE_SEND && only_send_requested_reply) ||
            (rule->type == POLICY_RULE_RECV && only_recv_requested_reply)) {
                parser_warning(state, "ignoring D-Bus policy rule that only constrains requested_reply; dbus-broker "
                                      "tracks expected replies itself");
                policy_rule_free(rule);
                return;
        }
        if (str_equal(attribute(attributes, "eavesdrop"), "true") && !rule->allow) {
                policy_rule_free(rule);
                return;
        }
        append_rule(state, rule, connection_target, group_target, id);
        return;

invalid:
        parser_warning(state, "ignoring invalid D-Bus policy attribute combination");
        policy_rule_free(rule);
}

static bool load_file(LauncherConfig *config, const char *path, bool ignore_missing, Error **error);

static char *resolve_path(const char *base_dir, const char *path)
{
        if (path_is_absolute(path))
                return str_dup(path);
        return path_join(base_dir, path);
}

static void parser_warning(ParserState *state, const char *format, ...)
{
        va_list arguments;
        char *message;

        va_start(arguments, format);
        if (vasprintf(&message, format, arguments) < 0)
                message = NULL;
        va_end(arguments);
        log_warning("%s:%lu: %s", state->file, (unsigned long)XML_GetCurrentLineNumber(state->parser),
                    message ? message : "out of memory while formatting warning");
        free(message);
}

static bool string_in(const char *value, const char *const *values)
{
        for (; *values; ++values)
                if (str_equal(value, *values))
                        return true;
        return false;
}

static bool element_is_bus_child(const char *element)
{
        static const char *const children[] = {
                "user",
                "type",
                "fork",
                "syslog",
                "keep_umask",
                "listen",
                "pidfile",
                "includedir",
                "standard_session_servicedirs",
                "standard_system_servicedirs",
                "servicedir",
                "servicehelper",
                "auth",
                "include",
                "policy",
                "limit",
                "selinux",
                "apparmor",
                NULL,
        };
        return string_in(element, children);
}

static bool validate_element(ParserState *state, const char *element)
{
        const char *parent = state->elements->len ? state->elements->items[state->elements->len - 1] : NULL;

        if (!parent)
                return str_equal(element, "busconfig");
        if (str_equal(parent, "busconfig"))
                return element_is_bus_child(element);
        if (str_equal(parent, "policy"))
                return str_equal(element, "allow") || str_equal(element, "deny");
        if (str_equal(parent, "selinux"))
                return str_equal(element, "associate");
        return false;
}

static bool valid_boolean(const char *value)
{
        return str_equal(value, "true") || str_equal(value, "false");
}

static void validate_attributes(ParserState *state, const char *element, const char **attributes)
{
        static const char *const allow_deny[] = {
                "send_interface",
                "send_member",
                "send_error",
                "send_destination",
                "send_path",
                "send_type",
                "send_requested_reply",
                "send_broadcast",
                "receive_interface",
                "receive_member",
                "receive_error",
                "receive_sender",
                "receive_path",
                "receive_type",
                "receive_requested_reply",
                "eavesdrop",
                "min_fds",
                "max_fds",
                "own",
                "own_prefix",
                "user",
                "group",
                "log",
                NULL,
        };
        static const char *const no_attributes[] = {NULL};
        static const char *const include_attributes[] = {
                "ignore_missing",
                "if_selinux_enabled",
                "selinux_root_relative",
                NULL,
        };
        static const char *const policy_attributes[] = {"context", "user", "group", "at_console", NULL};
        static const char *const associate_attributes[] = {"own", "context", NULL};
        static const char *const apparmor_attributes[] = {"mode", NULL};
        static const char *const limit_attributes[] = {"name", NULL};
        static const char *const limit_names[] = {
                "max_incoming_bytes",
                "max_incoming_unix_fds",
                "max_outgoing_bytes",
                "max_outgoing_unix_fds",
                "max_message_size",
                "max_message_unix_fds",
                "service_start_timeout",
                "auth_timeout",
                "pending_fd_timeout",
                "max_completed_connections",
                "max_incomplete_connections",
                "max_connections_per_user",
                "max_pending_service_starts",
                "max_names_per_connection",
                "max_match_rules_per_connection",
                "max_replies_per_connection",
                "max_containers_per_user",
                "max_containers",
                "max_connections_per_container",
                "max_container_metadata_bytes",
                "reply_timeout",
                NULL,
        };
        const char *const *allowed = no_attributes;

        if (str_equal(element, "include"))
                allowed = include_attributes;
        else if (str_equal(element, "policy"))
                allowed = policy_attributes;
        else if (str_equal(element, "allow") || str_equal(element, "deny"))
                allowed = allow_deny;
        else if (str_equal(element, "associate"))
                allowed = associate_attributes;
        else if (str_equal(element, "apparmor"))
                allowed = apparmor_attributes;
        else if (str_equal(element, "limit"))
                allowed = limit_attributes;

        for (const char **item = attributes; item && *item; item += 2) {
                const char *name = item[0], *value = item[1];
                if (!string_in(name, allowed)) {
                        parser_warning(state, "unknown attribute %s=\"%s\" on <%s>", name, value, element);
                        continue;
                }
                if (str_equal(element, "include") &&
                    (str_equal(name, "ignore_missing") || str_equal(name, "if_selinux_enabled") ||
                     str_equal(name, "selinux_root_relative")) &&
                    !str_equal(value, "yes") && !str_equal(value, "no"))
                        parser_warning(state, "invalid value %s=\"%s\"", name, value);
                else if (str_equal(element, "policy") && str_equal(name, "context") && !str_equal(value, "default") &&
                         !str_equal(value, "mandatory"))
                        parser_warning(state, "invalid policy context=\"%s\"", value);
                else if (str_equal(element, "policy") && str_equal(name, "at_console") && !valid_boolean(value))
                        parser_warning(state, "invalid at_console=\"%s\"", value);
                else if ((str_has_suffix(name, "_requested_reply") || str_equal(name, "send_broadcast") ||
                          str_equal(name, "eavesdrop") || str_equal(name, "log")) &&
                         !valid_boolean(value))
                        parser_warning(state, "invalid boolean %s=\"%s\"", name, value);
                else if ((str_equal(name, "send_type") || str_equal(name, "receive_type")) &&
                         !str_equal(value, "method_call") && !str_equal(value, "method_return") &&
                         !str_equal(value, "signal") && !str_equal(value, "error"))
                        parser_warning(state, "invalid message type %s=\"%s\"", name, value);
                else if (str_equal(element, "apparmor") && str_equal(name, "mode") && !str_equal(value, "enabled") &&
                         !str_equal(value, "disabled") && !str_equal(value, "required"))
                        parser_warning(state, "invalid AppArmor mode=\"%s\"", value);
                else if (str_equal(element, "limit") && str_equal(name, "name") && !string_in(value, limit_names))
                        parser_warning(state, "invalid limit name=\"%s\"", value);
        }

        if (str_equal(element, "policy")) {
                uint32_t contexts = (attribute(attributes, "context") != NULL) +
                                    (attribute(attributes, "user") != NULL) + (attribute(attributes, "group") != NULL) +
                                    (attribute(attributes, "at_console") != NULL);
                if (contexts == 0)
                        parser_warning(state, "missing context attribute on <policy>");
                else if (contexts > 1)
                        parser_warning(state, "conflicting context attributes on <policy>");
        } else if (str_equal(element, "limit") && !attribute(attributes, "name")) {
                parser_warning(state, "required attribute name missing on <limit>");
        } else if (str_equal(element, "associate")) {
                if (!attribute(attributes, "own"))
                        parser_warning(state, "required attribute own missing on <associate>");
                if (!attribute(attributes, "context"))
                        parser_warning(state, "required attribute context missing on <associate>");
        }
}

static void parser_start(void *data, const XML_Char *element, const XML_Char **attributes)
{
        ParserState *state = data;
        const char *context;

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
        char *element_name = str_dup(element);
        if (!element_name || !ptr_vec_push(state->elements, element_name)) {
                free(element_name);
                Error *error = NULL;
                error_set(&error, ENOMEM, "Out of memory tracking XML element");
                parser_fail(state, error);
                return;
        }

        if (str_equal(element, "policy")) {
                context = attribute(attributes, "context");
                state->context = POLICY_CONTEXT_DEFAULT;
                state->uid = state->gid = 0;
                const char *at_console = attribute(attributes, "at_console");
                if (!!attribute(attributes, "user") + !!attribute(attributes, "group") + !!context + !!at_console > 1) {
                        parser_warning(state, "ignoring D-Bus policy with conflicting identity contexts");
                        state->context = POLICY_CONTEXT_NONE;
                } else if (attribute(attributes, "user")) {
                        state->context = POLICY_CONTEXT_USER;
                        if (!lookup_uid(state, attribute(attributes, "user"), &state->uid)) {
                                state->context = POLICY_CONTEXT_NONE;
                        }
                } else if (attribute(attributes, "group")) {
                        state->context = POLICY_CONTEXT_GROUP;
                        if (!lookup_gid(state, attribute(attributes, "group"), &state->gid)) {
                                state->context = POLICY_CONTEXT_NONE;
                        }
                } else if (context && str_equal(context, "mandatory")) {
                        state->context = POLICY_CONTEXT_MANDATORY;
                } else if (at_console && str_equal(at_console, "true")) {
                        state->context = POLICY_CONTEXT_AT_CONSOLE;
                        state->config->uses_console_policy = true;
                } else if (at_console && str_equal(at_console, "false")) {
                        state->context = POLICY_CONTEXT_NO_CONSOLE;
                        state->config->uses_console_policy = true;
                } else if (at_console) {
                        parser_warning(state, "ignoring D-Bus policy with invalid at_console value '%s'", at_console);
                        state->context = POLICY_CONTEXT_NONE;
                } else if (context && !str_equal(context, "default")) {
                        parser_warning(state, "ignoring D-Bus policy with unknown context '%s'", context);
                        state->context = POLICY_CONTEXT_NONE;
                }
        } else if (str_equal(element, "keep_umask")) {
                state->config->keep_umask = true;
        } else if (str_equal(element, "fork")) {
                state->config->fork = true;
        } else if (str_equal(element, "syslog")) {
                state->config->syslog = true;
        } else if (str_equal(element, "apparmor")) {
                const char *mode = attribute(attributes, "mode");
                if (!mode || str_equal(mode, "enabled"))
                        state->config->apparmor_mode = 1;
                else if (str_equal(mode, "disabled"))
                        state->config->apparmor_mode = 0;
                else if (str_equal(mode, "required"))
                        state->config->apparmor_mode = 2;
                else
                        parser_warning(state, "ignoring invalid AppArmor policy mode '%s'", mode);
        } else if (str_equal(element, "allow") || str_equal(element, "deny")) {
                parse_rule(state, element, attributes);
        } else if (str_equal(element, "associate")) {
                const char *own = attribute(attributes, "own");
                const char *context_value = attribute(attributes, "context");
                if (own && context_value) {
                        char *context_copy = str_dup(context_value);
                        if (!context_copy || !str_map_set(state->config->selinux_associations, own, context_copy)) {
                                free(context_copy);
                                Error *error = NULL;
                                error_set(&error, ENOMEM, "Out of memory storing SELinux association");
                                parser_fail(state, error);
                                return;
                        }
                }
        } else if (str_equal(element, "include") || str_equal(element, "includedir") ||
                   str_equal(element, "servicedir") || str_equal(element, "listen") || str_equal(element, "user") ||
                   str_equal(element, "type") || str_equal(element, "pidfile") || str_equal(element, "auth") ||
                   str_equal(element, "servicehelper")) {
                state->text_element = element;
                state->include_ignore_missing = str_equal(attribute(attributes, "ignore_missing"), "yes");
                state->include_if_selinux = str_equal(attribute(attributes, "if_selinux_enabled"), "yes");
                state->include_selinux_root_relative = str_equal(attribute(attributes, "selinux_root_relative"), "yes");
                state->text->len = 0;
                if (state->text->data)
                        state->text->data[0] = 0;
        } else if (str_equal(element, "limit")) {
                state->text_element = element;
                free(state->limit_name);
                state->limit_name = str_dup(attribute(attributes, "name"));
                if (attribute(attributes, "name") && !state->limit_name) {
                        Error *error = NULL;
                        error_set(&error, ENOMEM, "Out of memory storing limit name");
                        parser_fail(state, error);
                        return;
                }
                state->text->len = 0;
                if (state->text->data)
                        state->text->data[0] = 0;
        } else if (str_equal(element, "standard_system_servicedirs")) {
                const char *dirs[] = {
                        "/etc/dbus-1/system-services",
                        "/run/dbus-1/system-services",
                        "/usr/local/share/dbus-1/system-services",
                        "/usr/share/dbus-1/system-services",
                        "/lib/dbus-1/system-services",
                };
                for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
                        char *path = str_dup(dirs[i]);
                        if (!push_path(state->config->service_dirs, path)) {
                                Error *error = NULL;
                                error_set(&error, ENOMEM, "Out of memory adding standard system servicedirs");
                                parser_fail(state, error);
                                return;
                        }
                }
        } else if (str_equal(element, "standard_session_servicedirs")) {
                const char *runtime = getenv("XDG_RUNTIME_DIR");
                const char *data_home = getenv("XDG_DATA_HOME");
                const char *home = getenv("HOME");
                char *base = NULL, *dbus = NULL;
                if (runtime && path_is_absolute(runtime)) {
                        dbus = path_join(runtime, "dbus-1/services");
                        if (!push_path(state->config->service_dirs, dbus)) {
                                Error *error = NULL;
                                error_set(&error, ENOMEM, "Out of memory adding standard session servicedirs");
                                parser_fail(state, error);
                                return;
                        }
                }
                if (data_home && path_is_absolute(data_home))
                        base = str_dup(data_home);
                else if (home && path_is_absolute(home))
                        base = path_join(home, ".local/share");
                if (base) {
                        dbus = path_join(base, "dbus-1/services");
                        free(base);
                        if (!push_path(state->config->service_dirs, dbus)) {
                                Error *error = NULL;
                                error_set(&error, ENOMEM, "Out of memory adding standard session servicedirs");
                                parser_fail(state, error);
                                return;
                        }
                }
                const char *system_dirs = getenv("XDG_DATA_DIRS");
                char *copy = str_dup(system_dirs && *system_dirs ? system_dirs : "/usr/local/share:/usr/share");
                if (!copy) {
                        Error *error = NULL;
                        error_set(&error, ENOMEM, "Out of memory adding standard session servicedirs");
                        parser_fail(state, error);
                        return;
                }
                char *cursor = copy, *directory;
                while ((directory = strsep(&cursor, ":"))) {
                        if (path_is_absolute(directory)) {
                                char *dir_path = path_join(directory, "dbus-1/services");
                                if (!push_path(state->config->service_dirs, dir_path)) {
                                        free(copy);
                                        Error *error = NULL;
                                        error_set(&error, ENOMEM, "Out of memory adding standard session servicedirs");
                                        parser_fail(state, error);
                                        return;
                                }
                        }
                }
                free(copy);
        }
}

static int compare_strings(const void *a, const void *b)
{
        return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static bool load_directory(LauncherConfig *config, const char *path, Error **error)
{
        DIR *directory;
        struct dirent *entry;
        PtrVec *names;

        char *watched = path_canonicalize(path, NULL);
        if (!watched || !ptr_vec_push(config->watch_paths, watched)) {
                free(watched);
                return error_set(error, ENOMEM, "%s: out of memory", path);
        }
        directory = opendir(path);
        if (!directory) {
                if (errno == ENOENT)
                        return true;
                return error_set_errno(error, errno, "%s", path);
        }
        names = ptr_vec_new(free);
        int read_error = 0;
        for (;;) {
                errno = 0;
                entry = readdir(directory);
                if (!entry) {
                        read_error = errno;
                        break;
                }
                if (str_has_suffix(entry->d_name, ".conf")) {
                        char *name = str_dup(entry->d_name);
                        if (!name || !ptr_vec_push(names, name)) {
                                free(name);
                                closedir(directory);
                                ptr_vec_free(names);
                                return error_set(error, ENOMEM, "%s: out of memory", path);
                        }
                }
        }
        if (read_error) {
                closedir(directory);
                ptr_vec_free(names);
                return error_set_errno(error, read_error, "%s", path);
        }
        closedir(directory);
        ptr_vec_sort(names, compare_strings);
        for (size_t index = 0; index < names->len; ++index) {
                char *file = path_join(path, names->items[index]);
                if (!load_file(config, file, false, error)) {
                        free(file);
                        ptr_vec_free(names);
                        return false;
                }
                free(file);
        }
        ptr_vec_free(names);
        return true;
}

static void parser_fail(ParserState *state, Error *error)
{
        if (!state->error)
                state->error = error;
        else
                error_free(error);
        XML_StopParser(state->parser, XML_FALSE);
}

static char *strip(char *value)
{
        char *start = value;
        char *end;
        while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')
                ++start;
        if (start != value)
                memmove(value, start, strlen(start) + 1);
        end = value + strlen(value);
        while (end > value && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
                --end;
        *end = 0;
        return value;
}

static void parser_end(void *data, const XML_Char *element)
{
        ParserState *state = data;
        char *value;
        char *path;
        Error *error = NULL;

        if (state->ignored_depth) {
                --state->ignored_depth;
                return;
        }
        if (state->elements->len == 0 || !str_equal(element, state->elements->items[state->elements->len - 1])) {
                parser_warning(state, "internal element-stack mismatch at </%s>", element);
                return;
        }
        ptr_vec_delete(state->elements, state->elements->len - 1);
        if (str_equal(element, "policy")) {
                state->context = POLICY_CONTEXT_DEFAULT;
                return;
        }
        if (!state->text_element || !str_equal(element, state->text_element))
                return;
        value = str_dup(state->text->data ? state->text->data : "");
        if (!value) {
                Error *nomem = NULL;
                error_set(&nomem, ENOMEM, "Out of memory processing element text");
                parser_fail(state, nomem);
                return;
        }
        strip(value);
        if (str_equal(element, "limit") && !*value) {
                error_set(&error, EINVAL, "D-Bus limit '%s' has no value",
                          state->limit_name ? state->limit_name : "(unnamed)");
                parser_fail(state, error);
                error = NULL;
        }
        if (*value) {
                if (str_equal(element, "include")) {
                        bool selinux_enabled = false;
                        const char *selinux_root = NULL;
#ifdef HAVE_SELINUX
                        selinux_enabled = is_selinux_enabled() > 0;
                        selinux_root = selinux_policy_root();
#endif
                        if (state->include_if_selinux && !selinux_enabled)
                                goto include_done;
                        if (state->include_selinux_root_relative && selinux_root && !path_is_absolute(value))
                                path = path_join(selinux_root, value);
                        else
                                path = resolve_path(state->base_dir, value);
                        if (!path) {
                                Error *nomem = NULL;
                                error_set(&nomem, ENOMEM, "Out of memory resolving include path");
                                parser_fail(state, nomem);
                        } else if (!load_file(state->config, path, state->include_ignore_missing, &error)) {
                                error_prefix(&error, "Invalid D-Bus include %s: ", path);
                                parser_fail(state, error);
                                error = NULL;
                        }
                        free(path);
                include_done:;
                } else if (str_equal(element, "includedir")) {
                        path = resolve_path(state->base_dir, value);
                        if (!path) {
                                Error *nomem = NULL;
                                error_set(&nomem, ENOMEM, "Out of memory resolving includedir path");
                                parser_fail(state, nomem);
                        } else if (!load_directory(state->config, path, &error)) {
                                error_prefix(&error, "Invalid D-Bus include directory %s: ", path);
                                parser_fail(state, error);
                                error = NULL;
                        }
                        free(path);
                } else if (str_equal(element, "servicedir")) {
                        path = resolve_path(state->base_dir, value);
                        if (!path || !push_path(state->config->service_dirs, path)) {
                                Error *nomem = NULL;
                                error_set(&nomem, ENOMEM, "Out of memory adding servicedir");
                                parser_fail(state, nomem);
                        }
                } else if (str_equal(element, "listen") && !state->config->address &&
                           str_has_prefix(value, "unix:path=")) {
                        state->config->address = str_dup(value);
                        if (!state->config->address) {
                                Error *nomem = NULL;
                                error_set(&nomem, ENOMEM, "Out of memory setting listen address");
                                parser_fail(state, nomem);
                        }
                } else if (str_equal(element, "user")) {
                        free(state->config->user);
                        state->config->user = str_dup(value);
                        if (!state->config->user) {
                                Error *nomem = NULL;
                                error_set(&nomem, ENOMEM, "Out of memory setting user");
                                parser_fail(state, nomem);
                        }
                } else if (str_equal(element, "auth")) {
                        /* dbus-broker only implements EXTERNAL and rejects
                         * every other mechanism during SASL. A config naming
                         * something else does not get what it asked for. */
                        if (!str_equal(value, "EXTERNAL"))
                                parser_warning(state, "ignoring <auth>%s</auth>; dbus-broker only implements EXTERNAL",
                                               value);
                } else if (str_equal(element, "servicehelper")) {
                        /* Activation switches user in the forked child rather
                         * than execing a setuid helper, so the path is unused. */
                        parser_warning(state,
                                       "ignoring <servicehelper>%s</servicehelper>; the dispatcher changes user "
                                       "in-process when activating services",
                                       value);
                } else if (str_equal(element, "pidfile")) {
                        free(state->config->pid_file);
                        state->config->pid_file = str_dup(value);
                        if (!state->config->pid_file) {
                                Error *nomem = NULL;
                                error_set(&nomem, ENOMEM, "Out of memory setting PID file");
                                parser_fail(state, nomem);
                        }
                } else if (str_equal(element, "type")) {
                        free(state->config->bus_type);
                        state->config->bus_type = str_dup(value);
                        if (!state->config->bus_type) {
                                Error *nomem = NULL;
                                error_set(&nomem, ENOMEM, "Out of memory setting bus type");
                                parser_fail(state, nomem);
                        }
                } else if (str_equal(element, "limit")) {
                        uint64_t parsed;
                        if (!state->limit_name || !parse_u64(value, UINT64_MAX, &parsed)) {
                                error_set(&error, EINVAL, "Invalid D-Bus limit value '%s'", value);
                                parser_fail(state, error);
                                error = NULL;
                        } else if (str_equal(state->limit_name, "max_outgoing_bytes")) {
                                state->config->max_outgoing_bytes = parsed;
                        } else if (str_equal(state->limit_name, "max_outgoing_unix_fds")) {
                                state->config->max_outgoing_fds = parsed;
                        } else if (str_equal(state->limit_name, "max_connections_per_user")) {
                                state->config->max_connections_per_user = parsed;
                        } else if (str_equal(state->limit_name, "max_match_rules_per_connection")) {
                                state->config->max_matches_per_connection = parsed;
                        }
                }
        }
        free(value);
        state->text_element = NULL;
        free(state->limit_name);
        state->limit_name = NULL;
}

static void parser_text(void *data, const XML_Char *text, int length)
{
        ParserState *state = data;
        if (!state->ignored_depth && state->text_element) {
                if (!str_buf_append_n(state->text, text, (size_t)length)) {
                        Error *nomem = NULL;
                        error_set(&nomem, ENOMEM, "Out of memory appending text");
                        parser_fail(state, nomem);
                }
        }
}

static bool load_file(LauncherConfig *config, const char *path, bool ignore_missing, Error **error)
{
        char *canonical;
        char *contents;
        size_t length;
        XML_Parser parser;
        ParserState state = {.config = config, .context = POLICY_CONTEXT_DEFAULT};
        bool success = false;

        canonical = path_canonicalize(path, NULL);
        char *watched = canonical ? str_dup(canonical) : NULL;
        if (!canonical || !watched || !ptr_vec_push(config->watch_paths, watched)) {
                free(watched);
                free(canonical);
                return error_set(error, ENOMEM, "%s: out of memory", path);
        }
        if (str_map_contains(config->active_files, canonical)) {
                log_warning("%s: recursive D-Bus configuration include ignored", canonical);
                free(canonical);
                return true;
        }
        if (!read_file(canonical, &contents, &length, error)) {
                if (ignore_missing && error && *error && (*error)->code == ENOENT) {
                        error_clear(error);
                        free(canonical);
                        return true;
                }
                free(canonical);
                return false;
        }
        if (length > (size_t)16 * 1024 * 1024) {
                error_set(error, EFBIG, "%s: D-Bus configuration exceeds 16 MiB", canonical);
                free(contents);
                free(canonical);
                return false;
        }
        if (!str_map_set(config->active_files, canonical, NULL)) {
                error_set(error, ENOMEM, "%s: out of memory", canonical);
                free(contents);
                free(canonical);
                return false;
        }
        state.base_dir = path_dirname(canonical);
        state.file = canonical;
        state.text = calloc(1, sizeof(*state.text));
        state.elements = ptr_vec_new(free);
        parser = XML_ParserCreate(NULL);
        if (!state.base_dir || !state.text || !state.elements || !parser) {
                error_set(error, ENOMEM, "%s: cannot allocate XML parser", canonical);
                if (state.text) {
                        str_buf_clear(state.text);
                        free(state.text);
                }
                ptr_vec_free(state.elements);
                if (parser)
                        XML_ParserFree(parser);
                free(state.base_dir);
                free(contents);
                str_map_remove(config->active_files, canonical);
                free(canonical);
                return false;
        }
        state.parser = parser;
        XML_SetUserData(parser, &state);
        XML_SetElementHandler(parser, parser_start, parser_end);
        XML_SetCharacterDataHandler(parser, parser_text);
        XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER);
        if (!XML_Parse(parser, contents, (int)length, true)) {
                if (state.error) {
                        if (error)
                                *error = state.error;
                        else
                                error_free(state.error);
                        state.error = NULL;
                } else {
                        error_set(error, EILSEQ, "%s:%lu: %s", canonical,
                                  (unsigned long)XML_GetCurrentLineNumber(parser),
                                  XML_ErrorString(XML_GetErrorCode(parser)));
                }
        } else {
                if (state.error) {
                        error_free(state.error);
                        state.error = NULL;
                }
                success = true;
        }
        XML_ParserFree(parser);
        str_buf_clear(state.text);
        free(state.text);
        ptr_vec_free(state.elements);
        free(state.limit_name);
        free(state.base_dir);
        free(contents);
        str_map_remove(config->active_files, canonical);
        free(canonical);
        return success;
}

bool launcher_config_load(LauncherConfig *config, const char *path, Error **error)
{
        if (!load_file(config, path, false, error))
                return false;
        optimize_rule_array(config->default_rules);
        optimize_rule_array(config->at_console_rules);
        optimize_rule_array(config->no_console_rules);
        optimize_rule_table(config->user_rules);
        optimize_rule_table(config->group_rules);
        optimize_strings(config->service_dirs);
        optimize_strings(config->watch_paths);
        return true;
}

static char *rule_signature(const PolicyRule *rule)
{
        return str_printf("%u:%u:%u:%s:%s:%s:%s:%u:%u:%" PRIu64 ":%" PRIu64, rule->type, rule->allow, rule->own_prefix,
                          rule->name ? rule->name : "", rule->path ? rule->path : "",
                          rule->interface ? rule->interface : "", rule->member ? rule->member : "", rule->message_type,
                          rule->broadcast, rule->min_fds, rule->max_fds);
}

typedef struct {
        char *signature;
        size_t index;
        uint64_t priority;
} RuleSignature;

static int compare_rule_signatures(const void *left, const void *right)
{
        const RuleSignature *a = left, *b = right;
        int order = strcmp(a->signature, b->signature);
        if (order)
                return order;
        if (a->priority != b->priority)
                return (a->priority > b->priority) - (a->priority < b->priority);
        return (a->index > b->index) - (a->index < b->index);
}

/* Keep the highest-priority equivalent rule. Mandatory and default rules share
 * an array, so file order alone does not determine priority.
 *
 * Sorting rather than scanning a linear-probe map keeps this O(n log n); large
 * generated policies made the previous form quadratic. */
static void optimize_rule_array(PtrVec *rules)
{
        size_t total = rules->len, kept = 0, built = 0;
        RuleSignature *signatures;
        bool *drop;

        if (total < 2)
                return;
        signatures = calloc(total, sizeof(*signatures));
        drop = calloc(total, sizeof(*drop));
        if (!signatures || !drop)
                goto out;
        for (; built < total; ++built) {
                signatures[built].signature = rule_signature(rules->items[built]);
                signatures[built].index = built;
                signatures[built].priority = ((PolicyRule *)rules->items[built])->priority;
                if (!signatures[built].signature)
                        goto out; /* Leave the rules untouched; dedup is optional. */
        }
        qsort(signatures, total, sizeof(*signatures), compare_rule_signatures);
        /* Equal signatures are now adjacent and ordered by priority, so every
         * entry but the last of each run is redundant. */
        for (size_t i = 0; i + 1 < total; ++i)
                if (strcmp(signatures[i].signature, signatures[i + 1].signature) == 0)
                        drop[signatures[i].index] = true;
        for (size_t i = 0; i < total; ++i) {
                if (drop[i])
                        policy_rule_free(rules->items[i]);
                else
                        rules->items[kept++] = rules->items[i];
        }
        rules->len = kept;
out:
        for (size_t i = 0; i < built; ++i)
                free(signatures[i].signature);
        free(signatures);
        free(drop);
}

static void optimize_rule_table(U32Map *table)
{
        for (size_t i = 0; i < table->len; ++i)
                optimize_rule_array(table->entries[i].value);
}

static void optimize_strings(PtrVec *strings)
{
        StrMap seen;
        str_map_init(&seen, NULL);
        for (size_t index = 0; index < strings->len;) {
                const char *value = strings->items[index];
                if (str_map_contains(&seen, value))
                        ptr_vec_delete(strings, index);
                else {
                        str_map_set(&seen, value, NULL);
                        ++index;
                }
        }
        str_map_clear(&seen);
}
