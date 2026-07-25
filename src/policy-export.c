#include "config-policy-internal.h"
#include <unistd.h>

static GVariant *batch_from_rules(GPtrArray *base, GPtrArray *specific, gboolean default_connect)
{
        GVariantBuilder own, send, recv;
        gboolean connect = default_connect;
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
        GHashTableIter iterator;
        gpointer key, value;
        guint self = getuid();
        gboolean have_self = FALSE;

        g_variant_builder_add(builder, "(u@" BATCH_TYPE ")", G_MAXUINT32,
                              batch_from_rules(config->default_rules, NULL, FALSE));
        g_hash_table_iter_init(&iterator, config->user_rules);
        while (g_hash_table_iter_next(&iterator, &key, &value)) {
                gboolean is_self = *(guint *)key == self;
                g_variant_builder_add(builder, "(u@" BATCH_TYPE ")", *(guint *)key,
                                      batch_from_rules(config->default_rules, value, user_scope && is_self));
                have_self |= is_self;
        }
        if (user_scope && !have_self)
                g_variant_builder_add(builder, "(u@" BATCH_TYPE ")", self,
                                      batch_from_rules(config->default_rules, NULL, TRUE));
}

static void add_gid_batches(GVariantBuilder *builder, LauncherConfig *config)
{
        GHashTableIter iterator;
        gpointer key, value;
        g_hash_table_iter_init(&iterator, config->group_rules);
        while (g_hash_table_iter_next(&iterator, &key, &value))
                g_variant_builder_add(builder, "(buu@" BATCH_TYPE ")", TRUE, *(guint *)key, *(guint *)key,
                                      batch_from_rules(value, NULL, FALSE));
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
        GList *names;

        g_variant_builder_init(&uids, G_VARIANT_TYPE(UID_POLICY_TYPE));
        g_variant_builder_init(&gids, G_VARIANT_TYPE(GID_POLICY_TYPE));
        g_variant_builder_init(&selinux, G_VARIANT_TYPE("a(ss)"));
        names = g_hash_table_get_keys(config->selinux_associations);
        names = g_list_sort(names, (GCompareFunc)g_strcmp0);
        for (GList *item = names; item; item = item->next)
                g_variant_builder_add(&selinux, "(ss)", (const gchar *)item->data,
                                      (const gchar *)g_hash_table_lookup(config->selinux_associations, item->data));
        g_list_free(names);
        add_uid_batches(&uids, config, user_scope);
        add_gid_batches(&gids, config);
        if (!user_scope)
                add_console_batches(&gids, config, system_uid_max, console_uids);
        return g_variant_new("(@" UID_POLICY_TYPE "@" GID_POLICY_TYPE "@a(ss)bs)", g_variant_builder_end(&uids),
                             g_variant_builder_end(&gids), g_variant_builder_end(&selinux),
                             config->apparmor_mode != 0,
                             config->bus_type ? config->bus_type : (user_scope ? "session" : "system"));
}
