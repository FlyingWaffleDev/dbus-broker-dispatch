#pragma once

#include "util.h"
#include <sys/types.h>

typedef bool (*ProcessChildSetup)(void *data, int *error_number);

typedef struct ProcessSpec {
        char *const *argv;
        char *const *environment;
        const char *working_directory;
        bool search_path;
        ProcessChildSetup child_setup;
        void *child_setup_data;
} ProcessSpec;

bool process_spawn(const ProcessSpec *spec, pid_t *pid, Error **error);
bool process_terminate(pid_t pid, int signal_number, Error **error);
bool process_wait(pid_t pid, int options, int *status, bool *exited, Error **error);
