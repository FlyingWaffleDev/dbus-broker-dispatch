#pragma once

#include "util.h"

/* Percent-escapes a path for use in a D-Bus unix:path= address. */
char *percent_escape(const char *value);
/* Decodes a unix:path= address. Returns NULL and sets error for anything that
 * is not an absolute, fully escaped filesystem path. */
char *socket_path_from_address(const char *address, Error **error);
