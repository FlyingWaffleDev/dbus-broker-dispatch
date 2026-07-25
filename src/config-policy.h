#pragma once

#include <gio/gio.h>
#include "nss-cache.h"

typedef struct LauncherConfig LauncherConfig;

LauncherConfig *launcher_config_new(void);
void launcher_config_free(LauncherConfig *config);
gboolean launcher_config_load(LauncherConfig *config, const gchar *path, GError **error);
GPtrArray *launcher_config_service_dirs(LauncherConfig *config);
GPtrArray *launcher_config_watch_paths(LauncherConfig *config);
NssCache *launcher_config_nss_cache(LauncherConfig *config);
const gchar *launcher_config_address(LauncherConfig *config);
const gchar *launcher_config_user(LauncherConfig *config);
const gchar *launcher_config_bus_type(LauncherConfig *config);
gboolean launcher_config_uses_console_policy(LauncherConfig *config);
guint launcher_config_apparmor_mode(LauncherConfig *config);
void launcher_config_set_apparmor_mode(LauncherConfig *config, guint mode);
guint64 launcher_config_max_bytes(LauncherConfig *config);
guint64 launcher_config_max_fds(LauncherConfig *config);
guint64 launcher_config_max_matches(LauncherConfig *config);
GVariant *launcher_config_export_policy(LauncherConfig *config, gboolean user_scope, guint system_uid_max,
                                        const GArray *console_uids);
