#define _GNU_SOURCE
#include "log.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static bool use_syslog;

void log_use_syslog(const char *identifier)
{
        openlog(identifier, LOG_PID, LOG_DAEMON);
        use_syslog = true;
}

void log_message(int priority, const char *format, ...)
{
        va_list arguments;

        va_start(arguments, format);
        if (use_syslog) {
                vsyslog(priority, format, arguments);
        } else {
                char *message = NULL;
                if (vasprintf(&message, format, arguments) >= 0) {
                        fprintf(stderr, "%s\n", message);
                        free(message);
                }
        }
        va_end(arguments);
}
