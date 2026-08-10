#include "config-policy-internal.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool encode_own(DBusWriter *writer, const PolicyRule *rule)
{
        return dbus_writer_align(writer, 8) && dbus_writer_bool(writer, rule->allow) &&
               dbus_writer_u64(writer, rule->priority) && dbus_writer_bool(writer, rule->own_prefix) &&
               dbus_writer_string(writer, rule->name ? rule->name : "");
}

static bool encode_message(DBusWriter *writer, const PolicyRule *rule)
{
        return dbus_writer_align(writer, 8) && dbus_writer_bool(writer, rule->allow) &&
               dbus_writer_u64(writer, rule->priority) && dbus_writer_string(writer, rule->name ? rule->name : "") &&
               dbus_writer_string(writer, rule->path ? rule->path : "") &&
               dbus_writer_string(writer, rule->interface ? rule->interface : "") &&
               dbus_writer_string(writer, rule->member ? rule->member : "") &&
               dbus_writer_u32(writer, rule->message_type) &&
               dbus_writer_u32(writer, rule->type == POLICY_RULE_RECV ? 0 : rule->broadcast) &&
               dbus_writer_u64(writer, rule->min_fds) && dbus_writer_u64(writer, rule->max_fds);
}

static bool encode_batch(DBusWriter *writer, const PtrVec *base, const PtrVec *specific, bool default_connect)
{
        bool connect = default_connect;
        uint64_t connect_priority = 1;
        const PtrVec *sets[] = {base, specific, NULL};
        DBusArray own, send, receive;

        for (size_t set = 0; sets[set]; ++set)
                for (size_t i = 0; i < sets[set]->len; ++i) {
                        PolicyRule *rule = sets[set]->items[i];
                        if (rule->type == POLICY_RULE_CONNECT && rule->priority > connect_priority) {
                                connect = rule->allow;
                                connect_priority = rule->priority;
                        }
                }
        if (!dbus_writer_align(writer, 8) || !dbus_writer_bool(writer, connect) ||
            !dbus_writer_u64(writer, connect_priority) || !dbus_writer_array_begin(writer, 8, &own))
                return false;
        for (size_t set = 0; sets[set]; ++set)
                for (size_t i = 0; i < sets[set]->len; ++i) {
                        PolicyRule *rule = sets[set]->items[i];
                        if (rule->type == POLICY_RULE_OWN && !encode_own(writer, rule))
                                return false;
                }
        if (!dbus_writer_array_end(writer, &own) || !dbus_writer_array_begin(writer, 8, &send))
                return false;
        for (size_t set = 0; sets[set]; ++set)
                for (size_t i = 0; i < sets[set]->len; ++i) {
                        PolicyRule *rule = sets[set]->items[i];
                        if (rule->type == POLICY_RULE_SEND && !encode_message(writer, rule))
                                return false;
                }
        if (!dbus_writer_array_end(writer, &send) || !dbus_writer_array_begin(writer, 8, &receive))
                return false;
        for (size_t set = 0; sets[set]; ++set)
                for (size_t i = 0; i < sets[set]->len; ++i) {
                        PolicyRule *rule = sets[set]->items[i];
                        if (rule->type == POLICY_RULE_RECV && !encode_message(writer, rule))
                                return false;
                }
        return dbus_writer_array_end(writer, &receive);
}

static bool encode_uid_entry(DBusWriter *writer, uint32_t uid, LauncherConfig *config, const PtrVec *specific,
                             bool default_connect)
{
        return dbus_writer_align(writer, 8) && dbus_writer_u32(writer, uid) &&
               encode_batch(writer, config->default_rules, specific, default_connect);
}

static bool encode_gid_entry(DBusWriter *writer, bool is_group, uint32_t first, uint32_t last, const PtrVec *rules)
{
        return dbus_writer_align(writer, 8) && dbus_writer_bool(writer, is_group) && dbus_writer_u32(writer, first) &&
               dbus_writer_u32(writer, last) && encode_batch(writer, rules, NULL, false);
}

static int compare_string_pointers(const void *left, const void *right)
{
        return strcmp(*(const char *const *)left, *(const char *const *)right);
}

const char *launcher_config_policy_signature(void)
{
        return "(" UID_POLICY_TYPE GID_POLICY_TYPE "a(ss)bs)";
}

bool launcher_config_export_policy_wire(LauncherConfig *config, bool user_scope, uint32_t system_uid_max,
                                        const uint32_t *console_uids, size_t n_console_uids, DBusWriter *writer,
                                        Error **error)
{
        DBusArray uids, gids, selinux;
        uint32_t self = (uint32_t)getuid();
        bool have_self = false;
        PtrVec names;

        dbus_writer_clear(writer);
        if (!dbus_writer_array_begin(writer, 8, &uids) || !encode_uid_entry(writer, UINT32_MAX, config, NULL, false))
                goto memory;
        for (size_t i = 0; i < config->user_rules->len; ++i) {
                uint32_t uid = config->user_rules->entries[i].key;
                if (!encode_uid_entry(writer, uid, config, config->user_rules->entries[i].value,
                                      user_scope && uid == self))
                        goto memory;
                have_self |= uid == self;
        }
        if (user_scope && !have_self && !encode_uid_entry(writer, self, config, NULL, true))
                goto memory;
        if (!dbus_writer_array_end(writer, &uids) || !dbus_writer_array_begin(writer, 8, &gids))
                goto memory;
        for (size_t i = 0; i < config->group_rules->len; ++i) {
                uint32_t gid = config->group_rules->entries[i].key;
                if (!encode_gid_entry(writer, true, gid, gid, config->group_rules->entries[i].value))
                        goto memory;
        }
        if (config->no_console_rules->len || config->at_console_rules->len) {
                uint32_t next = 0;
                for (size_t i = 0; i < n_console_uids; ++i) {
                        uint32_t uid = console_uids[i];
                        if (uid > system_uid_max || uid < next)
                                continue;
                        if (uid > next && !encode_gid_entry(writer, false, next, uid - 1, config->no_console_rules))
                                goto memory;
                        if (!encode_gid_entry(writer, false, uid, uid, config->at_console_rules))
                                goto memory;
                        if (uid == UINT32_MAX) {
                                next = UINT32_MAX;
                                break;
                        }
                        next = uid + 1;
                }
                if (next <= system_uid_max &&
                    !encode_gid_entry(writer, false, next, system_uid_max, config->no_console_rules))
                        goto memory;
                if (system_uid_max < UINT32_MAX &&
                    !encode_gid_entry(writer, false, system_uid_max + 1, UINT32_MAX, config->at_console_rules))
                        goto memory;
        }
        if (!dbus_writer_array_end(writer, &gids) || !dbus_writer_array_begin(writer, 8, &selinux))
                goto memory;
        ptr_vec_init(&names, NULL);
        for (size_t i = 0; i < config->selinux_associations->len; ++i)
                if (!ptr_vec_push(&names, config->selinux_associations->entries[i].key)) {
                        ptr_vec_clear(&names);
                        goto memory;
                }
        ptr_vec_sort(&names, compare_string_pointers);
        for (size_t i = 0; i < names.len; ++i)
                if (!dbus_writer_align(writer, 4) || !dbus_writer_string(writer, names.items[i]) ||
                    !dbus_writer_string(writer, str_map_get(config->selinux_associations, names.items[i]))) {
                        ptr_vec_clear(&names);
                        goto memory;
                }
        ptr_vec_clear(&names);
        if (!dbus_writer_array_end(writer, &selinux) || !dbus_writer_bool(writer, config->apparmor_mode != 0) ||
            !dbus_writer_string(writer, config->bus_type ? config->bus_type : (user_scope ? "session" : "system")))
                goto memory;
        return true;
memory:
        dbus_writer_clear(writer);
        return error_set(error, ENOMEM, "Cannot encode D-Bus policy");
}
