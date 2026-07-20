#pragma once

#include <security/pam_appl.h>

int dbus_dispatch_open_session(pam_handle_t *pamh, int argc, const char **argv);
int dbus_dispatch_close_session(pam_handle_t *pamh);
