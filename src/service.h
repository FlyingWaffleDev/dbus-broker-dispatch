#pragma once

#include "nss-cache.h"
#include <gio/gio.h>

typedef struct Service Service;
typedef struct ServiceManager ServiceManager;

ServiceManager *service_manager_new(void);
void service_manager_free(ServiceManager *manager);
void service_manager_set_connection(ServiceManager *manager, GDBusConnection *controller, const gchar *address,
                                    const gchar *bus_type);
GHashTable *service_manager_table(ServiceManager *manager);
void service_manager_take_table(ServiceManager *manager, GHashTable *services);

GHashTable *service_table_new(void);
gboolean service_table_scan(GPtrArray *service_dirs, NssCache *nss, gboolean user_scope, GHashTable *services,
                            GError **error);
gboolean service_table_register_all(ServiceManager *manager, GHashTable *services, GError **error);

Service *service_reference(Service *service);
gboolean service_equal(Service *left, Service *right);
gboolean service_register(ServiceManager *manager, Service *service, GError **error);
gboolean service_release(ServiceManager *manager, Service *service, GError **error);

void service_manager_signal(GDBusConnection *connection, const gchar *sender, const gchar *path,
                            const gchar *interface, const gchar *signal, GVariant *parameters, gpointer data);
