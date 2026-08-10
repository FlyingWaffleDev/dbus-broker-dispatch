#pragma once

#include "util.h"

typedef struct ServiceFile {
        char *name;
        char *exec;
        char *user;
        char *systemd_service;
        PtrVec arguments;
} ServiceFile;

void service_file_clear(ServiceFile *file);
bool service_file_load(const char *path, ServiceFile *file, Error **error);
bool service_exec_parse(const char *command, PtrVec *arguments, Error **error);
bool dbus_name_is_valid(const char *name);
