#pragma once

#include "config-policy.h"

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
        GPtrArray *watch_paths;
        GHashTable *active_files;
        GHashTable *selinux_associations;
        NssCache *nss;
        gchar *address;
        gchar *user;
        gchar *bus_type;
        guint64 priority;
        gboolean uses_console_policy;
        guint apparmor_mode;
        guint64 max_outgoing_bytes;
        guint64 max_outgoing_fds;
        guint64 max_connections_per_user;
        guint64 max_matches_per_connection;
};
