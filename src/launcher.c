#define _GNU_SOURCE
#include "config.h"
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <gio/gunixsocketaddress.h>
#include <glib-unix.h>
#include <expat.h>
#include <getopt.h>
#include <pwd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_ELOGIND
#include <elogind/sd-login.h>
#endif

#define BATCH_TYPE "(bta(btbs)a(btssssuutt)a(btssssuutt))"
#define UID_POLICY_TYPE "a(u" BATCH_TYPE ")"
#define GID_POLICY_TYPE "a(buu" BATCH_TYPE ")"
typedef struct { gchar *name, *path, *exec, *user; guint64 serial; gboolean starting; } Service;
typedef struct {
 gboolean user, foreground, audit, console_policy; gchar *config, *address, *broker, *socket_path;
 guint system_uid_max; GPid broker_pid; GSocket *listener; GDBusConnection *controller;
 GHashTable *services; GPtrArray *service_dirs; GHashTable *environment; GArray *static_uids, *dynamic_uids;
 guint reload_source;
} Launcher;

static void service_free(Service *s) { if (!s) return; g_free(s->name); g_free(s->path); g_free(s->exec); g_free(s->user); g_free(s); }
static void die_error(const gchar *what, GError *e) { g_printerr("%s: %s\n", what, e ? e->message : "unknown error"); g_clear_error(&e); }

static GVariant *policy_batch(gboolean connect, gboolean permit_messages, guint64 priority) {
 GVariantBuilder own, send, recv;
 g_variant_builder_init(&own, G_VARIANT_TYPE("a(btbs)"));
 g_variant_builder_init(&send, G_VARIANT_TYPE("a(btssssuutt)"));
 g_variant_builder_init(&recv, G_VARIANT_TYPE("a(btssssuutt)"));
 if (permit_messages) {
  g_variant_builder_add(&own, "(btbs)", TRUE, priority, TRUE, "");
  g_variant_builder_add(&send, "(btssssuutt)", TRUE, priority, "", "", "", "", 0, 0, (guint64)0, G_MAXUINT64);
  g_variant_builder_add(&recv, "(btssssuutt)", TRUE, priority, "", "", "", "", 0, 0, (guint64)0, G_MAXUINT64);
 }
 return g_variant_new("(bt@a(btbs)@a(btssssuutt)@a(btssssuutt))", connect, priority,
                      g_variant_builder_end(&own), g_variant_builder_end(&send), g_variant_builder_end(&recv));
}
/* dbus-broker's policy wire format; rules are expanded by the broker, not XML. */
static GVariant *make_policy(Launcher *l) {
 GVariantBuilder uids, gids, selinux; GVariant *default_batch = policy_batch(TRUE, FALSE, 1);
 GVariant *controller_batch = policy_batch(TRUE, TRUE, 2);
 g_variant_builder_init(&uids, G_VARIANT_TYPE(UID_POLICY_TYPE));
 g_variant_builder_add(&uids, "(u@" BATCH_TYPE ")", G_MAXUINT32, default_batch);
 g_variant_builder_add(&uids, "(u@" BATCH_TYPE ")", (guint)getuid(), controller_batch);
 g_variant_builder_init(&gids, G_VARIANT_TYPE(GID_POLICY_TYPE));
 g_variant_builder_init(&selinux, G_VARIANT_TYPE("a(ss)"));
 return g_variant_new("(@" UID_POLICY_TYPE "@" GID_POLICY_TYPE "@a(ss)bs)",
                      g_variant_builder_end(&uids), g_variant_builder_end(&gids),
                      g_variant_builder_end(&selinux), FALSE, l->user ? "session" : "system");
}
#ifdef HAVE_ELOGIND
/* elogind is deliberately limited to policy classification; it is never used
 * to manage units or sessions.  Failed queries keep the previous UID set. */
static void refresh_console_users(Launcher *l) {
        uid_t *uids = NULL;
        int n = sd_get_uids(&uids);
        if (n < 0) { g_warning("elogind local-session query failed: %s", g_strerror(-n)); return; }
        if (!l->dynamic_uids) l->dynamic_uids = g_array_new(FALSE, FALSE, sizeof(guint));
        g_array_set_size(l->dynamic_uids, 0);
        for (int i = 0; i < n; ++i) {
                char **sessions = NULL;
                int ns = sd_uid_get_sessions(uids[i], 1, &sessions);
                for (int j = 0; ns > 0 && j < ns; ++j) {
                        char *seat = NULL;
                        if (sd_session_is_remote(sessions[j]) == 0 && sd_session_get_seat(sessions[j], &seat) >= 0 && seat && *seat) {
                                guint uid = uids[i]; g_array_append_val(l->dynamic_uids, uid);
                                free(seat); break;
                        }
                        free(seat);
                }
                if (sessions) { for (int j = 0; ns > 0 && j < ns; ++j) free(sessions[j]); free(sessions); }
        }
        free(uids);
}
#else
static void refresh_console_users(Launcher *l) { (void)l; }
#endif

static gboolean call(Launcher *l, const gchar *path, const gchar *iface, const gchar *method, GVariant *args, GError **error) {
 GVariant *reply = g_dbus_connection_call_sync(l->controller, NULL, path, iface, method, args, NULL,
                                                G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
 if (!reply) return FALSE;
 g_variant_unref(reply);
 return TRUE;
}
static gboolean set_policy(Launcher *l, GError **error) { return call(l, "/org/bus1/DBus/Listener/0", "org.bus1.DBus.Listener", "SetPolicy", g_variant_new("(v)", make_policy(l)), error); }

static gchar *service_object_path(const gchar *name) { gchar *escaped = g_strdup(name); for (gchar *p = escaped; *p; ++p) if (!g_ascii_isalnum(*p) && *p != '_') *p = '_'; gchar *r = g_strdup_printf("/org/bus1/DBus/Name/%s", escaped); g_free(escaped); return r; }
static gboolean register_service(Launcher *l, Service *s, GError **error) {
 guint uid = 0; struct passwd *pw;
 if (s->user && *s->user) { pw = getpwnam(s->user); if (!pw) { g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "Unknown service user %s", s->user); return FALSE; } uid = pw->pw_uid; }
 return call(l, "/org/bus1/DBus/Broker", "org.bus1.DBus.Broker", "AddName", g_variant_new("(osu)", s->path, s->name, uid), error);
}
static void reset_service(Launcher *l, Service *s, const gchar *why) { GError *e = NULL; call(l, s->path, "org.bus1.DBus.Name", "Reset", g_variant_new("(ts)", s->serial, why), &e); g_clear_error(&e); s->starting = FALSE; }
typedef struct { Launcher *launcher; Service *service; } Activation;
static void child_done(GPid pid, gint status, gpointer data) { Activation *a = data; if (!WIFEXITED(status) || WEXITSTATUS(status)) reset_service(a->launcher, a->service, "org.bus1.DBus.Name.Error.UnitFailure"); else a->service->starting = FALSE; g_spawn_close_pid(pid); g_free(a); }
static void activate(Launcher *l, Service *s, guint64 serial) {
 GError *e = NULL; gchar **argv = NULL; gchar **env;
 if (s->starting) return;
 s->starting = TRUE;
 s->serial = serial;
 if (!g_shell_parse_argv(s->exec, NULL, &argv, &e)) { die_error("Invalid service Exec", e); reset_service(l, s, "org.bus1.DBus.Name.Error.InvalidUnit"); return; }
 env = g_get_environ(); env = g_environ_setenv(env, "DBUS_STARTER_ADDRESS", l->address, TRUE); env = g_environ_setenv(env, "DBUS_STARTER_BUS_TYPE", l->user ? "session" : "system", TRUE);
 GPid pid;
 if (!g_spawn_async(NULL, argv, env, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &e)) { die_error("Service activation failed", e); reset_service(l, s, "org.bus1.DBus.Name.Error.StartupFailure"); } else { Activation *a = g_new(Activation, 1); *a=(Activation){l,s}; g_child_watch_add(pid, child_done, a); }
 g_strfreev(argv); g_strfreev(env); s->starting = FALSE;
}

static void on_signal(GDBusConnection *c, const gchar *sender, const gchar *path, const gchar *iface, const gchar *signal, GVariant *params, gpointer data) {
 Launcher *l = data; (void)c; (void)sender;
 if (g_str_equal(iface, "org.bus1.DBus.Name") && g_str_equal(signal, "Activate")) { Service *s = g_hash_table_lookup(l->services, path); if (s) { guint64 serial; g_variant_get(params, "(t)", &serial); activate(l, s, serial); } }
 else if (g_str_equal(iface, "org.bus1.DBus.Broker") && g_str_equal(signal, "SetActivationEnvironment")) { GVariant *dict; g_variant_get(params, "(@a{ss})", &dict); g_variant_unref(dict); }
}

typedef struct { Launcher *l; gboolean in_service_dir; } XmlState;
static void xml_start(void *data, const char *el, const char **attr) { XmlState *x = data; if (!strcmp(el, "standard_system_servicedirs") || !strcmp(el, "standard_session_servicedirs")) x->in_service_dir = TRUE; if (!strcmp(el, "policy")) for (; *attr; attr += 2) if (!strcmp(attr[0], "context") && (!strcmp(attr[1], "at_console") || !strcmp(attr[1], "no_console"))) x->l->console_policy = TRUE; }
static void xml_end(void *data, const char *el) { XmlState *x=data; if (!strcmp(el, "standard_system_servicedirs") || !strcmp(el, "standard_session_servicedirs")) x->in_service_dir=FALSE; }
static void xml_text(void *data, const XML_Char *s, int n) { XmlState *x=data; if (x->in_service_dir) { gchar *p=g_strndup(s,n); g_strstrip(p); if (*p) g_ptr_array_add(x->l->service_dirs,p); else g_free(p); } }
static gboolean parse_config(Launcher *l, GError **error) {
 gchar *contents=NULL; gsize n; XML_Parser p; XmlState x={l,FALSE};
 if (!l->config) return TRUE;
 if (!g_file_get_contents(l->config,&contents,&n,error)) return FALSE;
 p=XML_ParserCreate(NULL); XML_SetUserData(p,&x); XML_SetElementHandler(p,xml_start,xml_end); XML_SetCharacterDataHandler(p,xml_text);
 if (!XML_Parse(p,contents,n,TRUE)) { g_set_error(error,G_MARKUP_ERROR,G_MARKUP_ERROR_PARSE,"%s:%lu: %s",l->config,(unsigned long)XML_GetCurrentLineNumber(p),XML_ErrorString(XML_GetErrorCode(p))); XML_ParserFree(p); g_free(contents); return FALSE; }
 XML_ParserFree(p); g_free(contents); return TRUE;
}
static void add_default_dirs(Launcher *l) { if (l->user) { const gchar * const *data=g_get_system_data_dirs(); g_ptr_array_add(l->service_dirs,g_build_filename(g_get_user_data_dir(),"dbus-1","services",NULL)); for (;*data;++data) g_ptr_array_add(l->service_dirs,g_build_filename(*data,"dbus-1","services",NULL)); } else { g_ptr_array_add(l->service_dirs,g_strdup("/usr/share/dbus-1/system-services")); g_ptr_array_add(l->service_dirs,g_strdup("/etc/dbus-1/system-services")); } }
static gboolean load_services(Launcher *l, GError **error) {
 for (guint i=0;i<l->service_dirs->len;i++) { GDir *d; const gchar *n; d=g_dir_open(g_ptr_array_index(l->service_dirs,i),0,NULL); if(!d) continue; while((n=g_dir_read_name(d))) { gchar *file; GKeyFile *k; Service *s; if(!g_str_has_suffix(n,".service")) continue; file=g_build_filename(g_ptr_array_index(l->service_dirs,i),n,NULL); k=g_key_file_new(); if(g_key_file_load_from_file(k,file,G_KEY_FILE_NONE,NULL)) { gchar *name=g_key_file_get_string(k,"D-BUS Service","Name",NULL), *exec=g_key_file_get_string(k,"D-BUS Service","Exec",NULL); if(name && exec && !g_hash_table_contains(l->services,service_object_path(name))) { s=g_new0(Service,1); s->name=name; s->exec=exec; s->user=g_key_file_get_string(k,"D-BUS Service","User",NULL); s->path=service_object_path(name); g_hash_table_insert(l->services,g_strdup(s->path),s); } else { if(name && !exec) g_message("Ignoring systemd-only D-Bus service %s",file); g_free(name); g_free(exec); } } g_key_file_unref(k); g_free(file); } g_dir_close(d); }
 GHashTableIter it; gpointer key,val; g_hash_table_iter_init(&it,l->services); while(g_hash_table_iter_next(&it,&key,&val)) if(!register_service(l,val,error)) return FALSE; return TRUE;
}

static void controller_method(GDBusConnection *connection, const gchar *sender, const gchar *path, const gchar *interface, const gchar *method, GVariant *parameters, GDBusMethodInvocation *invocation, gpointer data) {
 Launcher *l=data; GError *e=NULL; (void)connection;(void)sender;(void)path;(void)interface;(void)parameters;
 if (!g_str_equal(method,"ReloadConfig")) { g_dbus_method_invocation_return_error(invocation, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "Unsupported controller method"); return; }
 if (!set_policy(l,&e)) { g_dbus_method_invocation_return_dbus_error(invocation,"org.bus1.DBus.Controller.Error.InvalidConfig",e->message); g_clear_error(&e); }
 else g_dbus_method_invocation_return_value(invocation,NULL);
}
static const GDBusInterfaceVTable controller_vtable = { .method_call = controller_method };
static gboolean on_hup(gpointer data) { Launcher *l=data; GError *e=NULL; if(!set_policy(l,&e)) { die_error("Reload failed",e); return G_SOURCE_CONTINUE; } g_message("Reloaded D-Bus policy"); return G_SOURCE_CONTINUE; }
static gboolean quit_loop(gpointer data) { g_main_loop_quit(data); return G_SOURCE_REMOVE; }
static void broker_exit(GPid pid, gint status, gpointer data) { GMainLoop *loop=data; g_warning("dbus-broker exited (%s)", WIFEXITED(status) ? "status" : "signal"); g_spawn_close_pid(pid); g_main_loop_quit(loop); }
static gboolean bind_listener(Launcher *l, GError **error) {
 GSocketAddress *a; GFile *f;
 l->listener=g_socket_new(G_SOCKET_FAMILY_UNIX,G_SOCKET_TYPE_STREAM,G_SOCKET_PROTOCOL_DEFAULT,error); if(!l->listener)return FALSE;
 f=g_file_new_for_path(l->socket_path); g_file_delete(f,NULL,NULL); g_object_unref(f);
 a=g_unix_socket_address_new(l->socket_path); if(!g_socket_bind(l->listener,a,FALSE,error) || !g_socket_listen(l->listener,error)) {g_object_unref(a);return FALSE;} g_object_unref(a); return TRUE;
}
static void child_setup(gpointer data) { int fd=GPOINTER_TO_INT(data); if(dup2(fd,3)<0)_exit(127); }
static gchar *read_machine_id(GError **error) {
 gchar *id = NULL; gsize len = 0;
 if (!g_file_get_contents("/etc/machine-id", &id, &len, error)) return NULL;
 g_strstrip(id);
 if (strlen(id) != 32) { g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "/etc/machine-id must contain a 32-character machine ID"); g_free(id); return NULL; }
 for (gchar *p = id; *p; ++p) if (!g_ascii_isxdigit(*p)) { g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "/etc/machine-id is not hexadecimal"); g_free(id); return NULL; }
 return id;
}
static gboolean start_broker(Launcher *l, GError **error) {
 int pair[2]; GSocket *s; GSocketConnection *sc; gchar *arg, *machine_arg, *machine_id; gchar *argv[4];
 if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)<0){g_set_error(error,G_IO_ERROR,g_io_error_from_errno(errno),"socketpair: %s",g_strerror(errno));return FALSE;}
 machine_id = read_machine_id(error); if (!machine_id) { close(pair[0]); close(pair[1]); return FALSE; }
 arg=g_strdup("--controller=3"); machine_arg=g_strdup_printf("--machine-id=%s", machine_id); argv[0]=l->broker; argv[1]=arg; argv[2]=machine_arg; argv[3]=NULL;
 g_message("Starting dbus-broker with machine ID %.8s...", machine_id);
 if(!g_spawn_async(NULL,argv,NULL,G_SPAWN_DO_NOT_REAP_CHILD,child_setup,GINT_TO_POINTER(pair[1]),&l->broker_pid,error)){close(pair[0]);close(pair[1]);g_free(arg);g_free(machine_arg);g_free(machine_id);return FALSE;} close(pair[1]);g_free(arg);g_free(machine_arg);g_free(machine_id);
 s=g_socket_new_from_fd(pair[0],error); if(!s)return FALSE; sc=G_SOCKET_CONNECTION(g_socket_connection_factory_create_connection(s)); g_object_unref(s);
 /* dbus-broker is the server on its controller socket (see controller_init()).
  * The controller must therefore initiate D-Bus SASL authentication as client. */
 l->controller=g_dbus_connection_new_sync(G_IO_STREAM(sc),NULL,G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,NULL,NULL,error); g_object_unref(sc); return l->controller!=NULL;
}
static gboolean add_listener(Launcher *l, GError **error) {
 GUnixFDList *fds=g_unix_fd_list_new(); gint idx=g_unix_fd_list_append(fds,g_socket_get_fd(l->listener),error); GVariant *reply;
 if(idx<0){g_object_unref(fds);return FALSE;}
 reply=g_dbus_connection_call_with_unix_fd_list_sync(l->controller,NULL,"/org/bus1/DBus/Broker","org.bus1.DBus.Broker","AddListener",g_variant_new("(ohv)","/org/bus1/DBus/Listener/0",idx,make_policy(l)),NULL,G_DBUS_CALL_FLAGS_NONE,-1,fds,NULL,NULL,error); g_object_unref(fds); if(!reply)return FALSE;g_variant_unref(reply);return TRUE;
}
static void usage(const gchar *p) { g_print("Usage: %s --scope=system|user [--config-file=PATH] [--address=ADDRESS] [--broker=PATH] [--system-uid-max=N] [--audit] [--foreground]\n",p); }
int main(int argc, char **argv) {
 Launcher l={0}; GError *e=NULL; GMainLoop *loop; gint c; guint64 max=999; const gchar *runtime; GDBusNodeInfo *info; guint reg;
 l.system_uid_max=999; l.services=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,(GDestroyNotify)service_free); l.service_dirs=g_ptr_array_new_with_free_func(g_free); l.environment=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,g_free);
 static const struct option opts[]={ {"scope",1,0,'s'},{"config-file",1,0,'c'},{"address",1,0,'a'},{"broker",1,0,'b'},{"system-uid-max",1,0,'m'},{"audit",0,0,'A'},{"foreground",0,0,'f'},{"help",0,0,'h'},{0} };
 while((c=getopt_long(argc,argv,"",opts,NULL))!=-1) switch(c){case's': if(!strcmp(optarg,"user"))l.user=TRUE;else if(strcmp(optarg,"system")){usage(argv[0]);return 2;}break;case'c':l.config=g_strdup(optarg);break;case'a':l.address=g_strdup(optarg);break;case'b':l.broker=g_strdup(optarg);break;case'm':if(!g_ascii_string_to_unsigned(optarg,10,0,G_MAXUINT,&max,&e)){die_error("--system-uid-max",e);return 2;}l.system_uid_max=max;break;case'A':l.audit=TRUE;break;case'f':l.foreground=TRUE;break;default:usage(argv[0]);return c=='h'?0:2;}
 if(optind!=argc){usage(argv[0]);return 2;} if(!l.broker)l.broker=g_strdup(DEFAULT_BROKER); if(!g_file_test(l.broker,G_FILE_TEST_IS_EXECUTABLE)){g_free(l.broker);l.broker=g_find_program_in_path("dbus-broker");} if(!l.broker){g_printerr("dbus-broker not found; use --broker=PATH\n");return 1;}
 if(l.user){runtime=g_get_user_runtime_dir();if(!runtime){g_printerr("XDG_RUNTIME_DIR is required for --scope=user\n");return 1;}l.socket_path=g_build_filename(runtime,"bus",NULL);}else l.socket_path=g_strdup("/run/dbus/system_bus_socket"); if(!l.address)l.address=g_strdup_printf("unix:path=%s",l.socket_path);
 if(!parse_config(&l,&e)){die_error("Invalid D-Bus configuration",e);return 1;} if (!l.user && l.console_policy) refresh_console_users(&l); add_default_dirs(&l);
 if(!bind_listener(&l,&e)||!start_broker(&l,&e)||!add_listener(&l,&e)||!load_services(&l,&e)){die_error("Cannot start launcher",e);return 1;}
 info=g_dbus_node_info_new_for_xml("<node><interface name='org.bus1.DBus.Controller'><method name='ReloadConfig'/></interface></node>",&e); if(!info){die_error("Controller API",e);return 1;} reg=g_dbus_connection_register_object(l.controller,"/org/bus1/DBus/Controller",info->interfaces[0],&controller_vtable,&l,NULL,&e); if(!reg){die_error("Controller API",e);return 1;}
 g_dbus_connection_signal_subscribe(l.controller,NULL,NULL,NULL,NULL,NULL,G_DBUS_SIGNAL_FLAGS_NONE,on_signal,&l,NULL); loop=g_main_loop_new(NULL,FALSE); g_child_watch_add(l.broker_pid,broker_exit,loop); g_unix_signal_add(SIGHUP,on_hup,&l); g_unix_signal_add(SIGTERM,quit_loop,loop); g_unix_signal_add(SIGINT,quit_loop,loop); g_main_loop_run(loop);
 g_dbus_connection_unregister_object(l.controller,reg); g_main_loop_unref(loop); g_dbus_node_info_unref(info); g_object_unref(l.controller); g_object_unref(l.listener); unlink(l.socket_path); return 0;
}
