#pragma once

#include <gio/gio.h>

typedef struct LauncherConfig LauncherConfig;

LauncherConfig *launcher_config_new(void);
void launcher_config_free(LauncherConfig *config);
gboolean launcher_config_load(LauncherConfig *config, const gchar *path, GError **error);
GPtrArray *launcher_config_service_dirs(LauncherConfig *config);
const gchar *launcher_config_address(LauncherConfig *config);
gboolean launcher_config_uses_console_policy(LauncherConfig *config);
GVariant *launcher_config_export_policy(LauncherConfig *config,
                                        gboolean user_scope,
                                        guint system_uid_max,
                                        const GArray *console_uids);
