#pragma once

#include "config-policy.h"
#include "util.h"

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
        bool allow;
        bool own_prefix;
        uint64_t priority;
        char *name;
        char *path;
        char *interface;
        char *member;
        uint32_t message_type;
        uint32_t broadcast;
        uint64_t min_fds;
        uint64_t max_fds;
} PolicyRule;

struct LauncherConfig {
        PtrVec *default_rules;
        U32Map *user_rules;
        U32Map *group_rules;
        PtrVec *at_console_rules;
        PtrVec *no_console_rules;
        PtrVec *service_dirs;
        PtrVec *watch_paths;
        StrMap *active_files;
        StrMap *selinux_associations;
        NssCache *nss;
        char *address;
        char *user;
        char *bus_type;
        uint64_t priority;
        bool uses_console_policy;
        uint32_t apparmor_mode;
        uint64_t max_outgoing_bytes;
        uint64_t max_outgoing_fds;
        uint64_t max_connections_per_user;
        uint64_t max_matches_per_connection;
};
