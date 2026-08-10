#pragma once

#include "dbus-wire.h"
#include "nss-cache.h"
#include "util.h"

typedef struct LauncherConfig LauncherConfig;

LauncherConfig *launcher_config_new(void);
void launcher_config_free(LauncherConfig *config);
bool launcher_config_load(LauncherConfig *config, const char *path, Error **error);
PtrVec *launcher_config_service_dirs(LauncherConfig *config);
PtrVec *launcher_config_watch_paths(LauncherConfig *config);
NssCache *launcher_config_nss_cache(LauncherConfig *config);
const char *launcher_config_address(LauncherConfig *config);
const char *launcher_config_user(LauncherConfig *config);
const char *launcher_config_bus_type(LauncherConfig *config);
bool launcher_config_uses_console_policy(LauncherConfig *config);
uint32_t launcher_config_apparmor_mode(LauncherConfig *config);
void launcher_config_set_apparmor_mode(LauncherConfig *config, uint32_t mode);
uint64_t launcher_config_max_bytes(LauncherConfig *config);
uint64_t launcher_config_max_fds(LauncherConfig *config);
uint64_t launcher_config_max_matches(LauncherConfig *config);

const char *launcher_config_policy_signature(void);
bool launcher_config_export_policy_wire(LauncherConfig *config, bool user_scope, uint32_t system_uid_max,
                                        const uint32_t *console_uids, size_t n_console_uids, DBusWriter *writer,
                                        Error **error);
