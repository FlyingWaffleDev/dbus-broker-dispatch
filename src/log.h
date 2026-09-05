#pragma once

#include <stdarg.h>
#include <syslog.h>

/* Diagnostics go to stderr until log_use_syslog() switches them to syslog.
 * The dispatcher calls that after daemonizing, where stderr is /dev/null. */
void log_use_syslog(const char *identifier);
void log_message(int priority, const char *format, ...) __attribute__((format(printf, 2, 3)));

#define log_error(...) log_message(LOG_ERR, __VA_ARGS__)
#define log_warning(...) log_message(LOG_WARNING, __VA_ARGS__)
#define log_notice(...) log_message(LOG_NOTICE, __VA_ARGS__)
#define log_info(...) log_message(LOG_INFO, __VA_ARGS__)
