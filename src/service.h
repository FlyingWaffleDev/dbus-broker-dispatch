#pragma once

#include "controller.h"
#include "nss-cache.h"
#include "util.h"

typedef struct Service Service;
typedef struct ServiceManager ServiceManager;
typedef StrMap ServiceTable;

ServiceManager *service_manager_new(void);
void service_manager_free(ServiceManager *manager);
void service_manager_set_controller(ServiceManager *manager, Controller *controller, const char *address,
                                    const char *bus_type);
ServiceTable *service_manager_table(ServiceManager *manager);
void service_manager_take_table(ServiceManager *manager, ServiceTable *services);

ServiceTable *service_table_new(void);
void service_table_free(ServiceTable *services);
bool service_table_scan(PtrVec *service_dirs, NssCache *nss, bool user_scope, ServiceTable *services, Error **error);
bool service_table_register_all(ServiceManager *manager, ServiceTable *services, Error **error);

Service *service_reference(Service *service);
bool service_equal(Service *left, Service *right);
bool service_register(ServiceManager *manager, Service *service, Error **error);
bool service_release(ServiceManager *manager, Service *service, Error **error);
bool service_manager_handle_packet(ServiceManager *manager, DBusPacket *packet, Error **error);
bool service_manager_reap(ServiceManager *manager, pid_t pid, int status);
