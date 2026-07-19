#define _GNU_SOURCE
#include "config.h"
#include "config-policy.h"
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <gio/gunixsocketaddress.h>
#include <glib-unix.h>
#include <expat.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_ELOGIND
#include <elogind/sd-login.h>
#endif

typedef struct { gchar *name, *path, *exec, *user; guint64 serial; gboolean starting; } Service;
typedef struct {
 gboolean user, foreground, audit, daemonize; gchar *config, *address, *broker, *socket_path, *pid_file;
 guint system_uid_max; GPid broker_pid; GSocket *listener; GDBusConnection *controller;
 GHashTable *services; GPtrArray *service_dirs; GHashTable *environment; GArray *static_uids, *dynamic_uids;
 LauncherConfig *config_state;
 guint reload_source;
} Launcher;

static void service_free(Service *s) { if (!s) return; g_free(s->name); g_free(s->path); g_free(s->exec); g_free(s->user); g_free(s); }
static void die_error(const gchar *what, GError *e) { g_printerr("%s: %s\n", what, e ? e->message : "unknown error"); g_clear_error(&e); }

static gint compare_uids(gconstpointer left, gconstpointer right) {
 return (*(const guint *)left > *(const guint *)right) - (*(const guint *)left < *(const guint *)right);
}

static GArray *effective_console_uids(Launcher *l) {
 GArray *uids = g_array_new(FALSE, FALSE, sizeof(guint));
 if (l->static_uids) g_array_append_vals(uids, l->static_uids->data, l->static_uids->len);
 if (l->dynamic_uids) g_array_append_vals(uids, l->dynamic_uids->data, l->dynamic_uids->len);
 g_array_sort(uids, compare_uids);
 for (guint index = 1; index < uids->len;) {
  if (g_array_index(uids, guint, index) == g_array_index(uids, guint, index - 1)) g_array_remove_index(uids, index);
  else ++index;
 }
 return uids;
}

static void load_static_console_users(Launcher *l) {
 gchar **names;
 l->static_uids = g_array_new(FALSE, FALSE, sizeof(guint));
 if (!SYSTEM_CONSOLE_USERS[0]) return;
 names = g_strsplit(SYSTEM_CONSOLE_USERS, ",", -1);
 for (guint index = 0; names[index]; ++index) {
  struct passwd *entry = getpwnam(names[index]);
  if (!entry) g_warning("Ignoring unknown system-console user '%s'", names[index]);
  else { guint uid = entry->pw_uid; g_array_append_val(l->static_uids, uid); }
 }
 g_strfreev(names);
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
static GVariant *make_policy(Launcher *l, LauncherConfig *config) {
 GArray *uids = effective_console_uids(l);
 GVariant *policy = launcher_config_export_policy(config, l->user, l->system_uid_max, uids);
 g_array_unref(uids);
 return policy;
}
static gboolean reload_config(Launcher *l, GError **error);

static gchar *service_object_path(const gchar *name) { gchar *escaped = g_strdup(name); for (gchar *p = escaped; *p; ++p) if (!g_ascii_isalnum(*p) && *p != '_') *p = '_'; gchar *r = g_strdup_printf("/org/bus1/DBus/Name/%s", escaped); g_free(escaped); return r; }
static gboolean register_service(Launcher *l, Service *s, GError **error) {
 guint uid = 0; struct passwd *pw;
 if (s->user && *s->user) { pw = getpwnam(s->user); if (!pw) { g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "Unknown service user %s", s->user); return FALSE; } uid = pw->pw_uid; }
 return call(l, "/org/bus1/DBus/Broker", "org.bus1.DBus.Broker", "AddName", g_variant_new("(osu)", s->path, s->name, uid), error);
}
static void reset_service(Launcher *l, Service *s, const gchar *why) { GError *e = NULL; call(l, s->path, "org.bus1.DBus.Name", "Reset", g_variant_new("(ts)", s->serial, why), &e); g_clear_error(&e); s->starting = FALSE; }
typedef struct {
 Launcher *launcher;
 Service *service;
 gchar *user;
 uid_t uid;
 gid_t gid;
} Activation;
static void activation_free(Activation *a) { if (!a) return; g_free(a->user); g_free(a); }
static void activation_child_setup(gpointer data) {
 Activation *a = data;

 if (!a->user || (geteuid() == a->uid && getegid() == a->gid)) return;
 /* User= is meaningful for system service activation.  Do the privilege
  * transition in the child so the launcher itself remains the controller. */
 if (geteuid() != 0 || initgroups(a->user, a->gid) < 0 || setgid(a->gid) < 0 || setuid(a->uid) < 0)
  _exit(127);
}
static void child_done(GPid pid, gint status, gpointer data) { Activation *a = data; if (!WIFEXITED(status) || WEXITSTATUS(status)) reset_service(a->launcher, a->service, "org.bus1.DBus.Name.Error.UnitFailure"); else a->service->starting = FALSE; g_spawn_close_pid(pid); activation_free(a); }
static gchar **activation_environment(Launcher *l) {
 gchar **env = g_get_environ(); GHashTableIter iter; gpointer key, value;
 g_hash_table_iter_init(&iter, l->environment);
 while (g_hash_table_iter_next(&iter, &key, &value)) env = g_environ_setenv(env, key, value, TRUE);
 return env;
}
static void activate(Launcher *l, Service *s, guint64 serial) {
 GError *e = NULL; gchar **argv = NULL; gchar **env; struct passwd *pw = NULL; Activation *activation;
 if (s->starting) return;
 s->starting = TRUE;
 s->serial = serial;
 if (!g_shell_parse_argv(s->exec, NULL, &argv, &e)) { die_error("Invalid service Exec", e); reset_service(l, s, "org.bus1.DBus.Name.Error.InvalidUnit"); return; }
 if (s->user && *s->user) {
  pw = getpwnam(s->user);
  if (!pw) { g_set_error(&e, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "Unknown service user %s", s->user); die_error("Service activation failed", e); reset_service(l, s, "org.bus1.DBus.Name.Error.StartupFailure"); g_strfreev(argv); return; }
 }
 env = activation_environment(l); env = g_environ_setenv(env, "DBUS_STARTER_ADDRESS", l->address, TRUE); env = g_environ_setenv(env, "DBUS_STARTER_BUS_TYPE", l->user ? "session" : "system", TRUE);
 activation = g_new0(Activation, 1); activation->launcher = l; activation->service = s;
 if (pw) { activation->user = g_strdup(pw->pw_name); activation->uid = pw->pw_uid; activation->gid = pw->pw_gid; }
 GPid pid;
 if (!g_spawn_async(NULL, argv, env, G_SPAWN_DO_NOT_REAP_CHILD, activation_child_setup, activation, &pid, &e)) { die_error("Service activation failed", e); reset_service(l, s, "org.bus1.DBus.Name.Error.StartupFailure"); activation_free(activation); } else g_child_watch_add(pid, child_done, activation);
 g_strfreev(argv); g_strfreev(env);
}

static void on_signal(GDBusConnection *c, const gchar *sender, const gchar *path, const gchar *iface, const gchar *signal, GVariant *params, gpointer data) {
 Launcher *l = data; (void)c; (void)sender;
 if (g_str_equal(iface, "org.bus1.DBus.Name") && g_str_equal(signal, "Activate")) { Service *s = g_hash_table_lookup(l->services, path); if (s) { guint64 serial; g_variant_get(params, "(t)", &serial); activate(l, s, serial); } }
 else if (g_str_equal(iface, "org.bus1.DBus.Broker") && g_str_equal(signal, "SetActivationEnvironment")) {
  GVariant *dict; GVariantIter iter; gchar *key, *value;
  g_variant_get(params, "(@a{ss})", &dict); g_variant_iter_init(&iter, dict);
  while (g_variant_iter_next(&iter, "{ss}", &key, &value)) {
   if (*key && !strchr(key, '=')) g_hash_table_replace(l->environment, key, value);
   else { g_warning("Ignoring invalid D-Bus activation environment variable"); g_free(key); g_free(value); }
  }
  g_variant_unref(dict);
 }
}

static GHashTable *new_service_table(void) {
 return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)service_free);
}
static gboolean scan_services(GPtrArray *service_dirs, GHashTable *services, GError **error) {
 (void)error;
 for (guint i=0;i<service_dirs->len;i++) { GDir *d; const gchar *n; d=g_dir_open(g_ptr_array_index(service_dirs,i),0,NULL); if(!d) continue; while((n=g_dir_read_name(d))) { gchar *file; GKeyFile *k; Service *s; if(!g_str_has_suffix(n,".service")) continue; file=g_build_filename(g_ptr_array_index(service_dirs,i),n,NULL); k=g_key_file_new(); if(g_key_file_load_from_file(k,file,G_KEY_FILE_NONE,NULL)) { gchar *name=g_key_file_get_string(k,"D-BUS Service","Name",NULL), *exec=g_key_file_get_string(k,"D-BUS Service","Exec",NULL); if(name && exec) { gchar *path=service_object_path(name); if(!g_hash_table_contains(services,path)) { s=g_new0(Service,1); s->name=name; s->exec=exec; s->user=g_key_file_get_string(k,"D-BUS Service","User",NULL); s->path=path; g_hash_table_insert(services,g_strdup(s->path),s); } else { g_free(path); g_free(name); g_free(exec); } } else { if(name && !exec) g_message("Ignoring systemd-only D-Bus service %s",file); g_free(name); g_free(exec); } } g_key_file_unref(k); g_free(file); } g_dir_close(d); }
 return TRUE;
}
static gboolean register_services(Launcher *l, GHashTable *services, GError **error) {
 GHashTableIter it; gpointer key,val; g_hash_table_iter_init(&it,services); while(g_hash_table_iter_next(&it,&key,&val)) if(!register_service(l,val,error)) return FALSE; return TRUE;
}
static gboolean services_equal(Service *left, Service *right) {
 return g_strcmp0(left->name, right->name) == 0 && g_strcmp0(left->exec, right->exec) == 0 && g_strcmp0(left->user, right->user) == 0;
}
static gboolean release_service(Launcher *l, Service *service, GError **error) {
 return call(l, service->path, "org.bus1.DBus.Name", "Release", NULL, error);
}

static void controller_method(GDBusConnection *connection, const gchar *sender, const gchar *path, const gchar *interface, const gchar *method, GVariant *parameters, GDBusMethodInvocation *invocation, gpointer data) {
 Launcher *l=data; GError *e=NULL; (void)connection;(void)sender;(void)path;(void)interface;(void)parameters;
 if (!g_str_equal(method,"ReloadConfig")) { g_dbus_method_invocation_return_error(invocation, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "Unsupported controller method"); return; }
 if (!reload_config(l,&e)) { g_dbus_method_invocation_return_dbus_error(invocation,"org.bus1.DBus.Controller.Error.InvalidConfig",e->message); g_clear_error(&e); }
 else g_dbus_method_invocation_return_value(invocation,NULL);
}
static const GDBusInterfaceVTable controller_vtable = { .method_call = controller_method };
static gboolean reload_config(Launcher *l, GError **error) {
 LauncherConfig *candidate = launcher_config_new();
 GHashTable *candidate_services = new_service_table();
 GHashTableIter iter;
 gpointer key;
 gpointer value;
 const gchar *address;
 GVariant *policy;
 gboolean success;

 if (!launcher_config_load(candidate, l->config, error) ||
     !scan_services(launcher_config_service_dirs(candidate), candidate_services, error)) {
  launcher_config_free(candidate);
  g_hash_table_unref(candidate_services);
  return FALSE;
 }
 address = launcher_config_address(candidate);
 if (address && g_strcmp0(address, l->address) != 0) {
  g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "Reload cannot change the bus listener address");
  launcher_config_free(candidate);
  g_hash_table_unref(candidate_services);
  return FALSE;
 }
 policy = make_policy(l, candidate);
 success = call(l, "/org/bus1/DBus/Listener/0", "org.bus1.DBus.Listener", "SetPolicy", g_variant_new("(v)", policy), error);
 if (!success) { launcher_config_free(candidate); g_hash_table_unref(candidate_services); return FALSE; }
 g_hash_table_iter_init(&iter, l->services);
 while (g_hash_table_iter_next(&iter, &key, &value)) {
  Service *replacement = g_hash_table_lookup(candidate_services, key);
  if (!replacement || !services_equal(value, replacement))
   if (!release_service(l, value, error)) { launcher_config_free(candidate); g_hash_table_unref(candidate_services); return FALSE; }
 }
 g_hash_table_iter_init(&iter, candidate_services);
 while (g_hash_table_iter_next(&iter, &key, &value)) {
  Service *previous = g_hash_table_lookup(l->services, key);
  if (!previous || !services_equal(previous, value))
   if (!register_service(l, value, error)) { launcher_config_free(candidate); g_hash_table_unref(candidate_services); return FALSE; }
 }
 launcher_config_free(l->config_state);
 g_hash_table_unref(l->services);
 l->config_state = candidate;
 l->service_dirs = launcher_config_service_dirs(candidate);
 l->services = candidate_services;
 return TRUE;
}
static gboolean on_hup(gpointer data) { Launcher *l=data; GError *e=NULL; if(!reload_config(l,&e)) { die_error("Reload failed",e); return G_SOURCE_CONTINUE; } g_message("Reloaded D-Bus configuration policy"); return G_SOURCE_CONTINUE; }
static gboolean quit_loop(gpointer data) { g_main_loop_quit(data); return G_SOURCE_REMOVE; }
static void broker_exit(GPid pid, gint status, gpointer data) { GMainLoop *loop=data; g_warning("dbus-broker exited (%s)", WIFEXITED(status) ? "status" : "signal"); g_spawn_close_pid(pid); g_main_loop_quit(loop); }
static gboolean bind_listener(Launcher *l, GError **error) {
 GSocketAddress *a; GFile *f;
 l->listener=g_socket_new(G_SOCKET_FAMILY_UNIX,G_SOCKET_TYPE_STREAM,G_SOCKET_PROTOCOL_DEFAULT,error); if(!l->listener)return FALSE;
 f=g_file_new_for_path(l->socket_path); g_file_delete(f,NULL,NULL); g_object_unref(f);
 a=g_unix_socket_address_new(l->socket_path); if(!g_socket_bind(l->listener,a,FALSE,error) || !g_socket_listen(l->listener,error)) {g_object_unref(a);return FALSE;} g_object_unref(a);
 if (!l->user && chmod(l->socket_path, 0666) < 0) { g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno), "chmod %s: %s", l->socket_path, g_strerror(errno)); return FALSE; }
 return TRUE;
}
static void child_setup(gpointer data) {
 int fd = GPOINTER_TO_INT(data);
 if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || dup2(fd, 3) < 0) _exit(127);
}
static gchar *read_machine_id(GError **error) {
 gchar *id = NULL; gsize len = 0;
 if (!g_file_get_contents("/etc/machine-id", &id, &len, error)) return NULL;
 g_strstrip(id);
 if (strlen(id) != 32) { g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "/etc/machine-id must contain a 32-character machine ID"); g_free(id); return NULL; }
 for (gchar *p = id; *p; ++p) if (!g_ascii_isxdigit(*p)) { g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "/etc/machine-id is not hexadecimal"); g_free(id); return NULL; }
 return id;
}
static gboolean daemonize(Launcher *l, GError **error) {
 gchar *contents;

 if (!l->daemonize)
  return TRUE;
 if (daemon(0, 0) < 0) {
  g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno), "daemon: %s", g_strerror(errno));
  return FALSE;
 }
 if (!l->pid_file)
  return TRUE;
 contents = g_strdup_printf("%ld\n", (long)getpid());
 if (!g_file_set_contents(l->pid_file, contents, -1, error)) {
  g_free(contents);
  return FALSE;
 }
 g_free(contents);
 return TRUE;
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
 reply=g_dbus_connection_call_with_unix_fd_list_sync(l->controller,NULL,"/org/bus1/DBus/Broker","org.bus1.DBus.Broker","AddListener",g_variant_new("(ohv)","/org/bus1/DBus/Listener/0",idx,make_policy(l, l->config_state)),NULL,G_DBUS_CALL_FLAGS_NONE,-1,fds,NULL,NULL,error); g_object_unref(fds); if(!reply)return FALSE;g_variant_unref(reply);return TRUE;
}
static void usage(const gchar *p) { g_print("Usage: %s --scope=system|user [--config-file=PATH] [--address=ADDRESS] [--broker=PATH] [--pid-file=PATH] [--system-uid-max=N] [--audit] [--foreground]\n",p); }
int main(int argc, char **argv) {
 Launcher l={0}; GError *e=NULL; GMainLoop *loop; gint c; guint64 max=999; const gchar *runtime; const gchar *configured_address; GDBusNodeInfo *info; guint reg;
 l.system_uid_max=999; l.daemonize=TRUE; l.services=new_service_table(); l.environment=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,g_free);
 static const struct option opts[]={ {"scope",1,0,'s'},{"config-file",1,0,'c'},{"address",1,0,'a'},{"broker",1,0,'b'},{"pid-file",1,0,'p'},{"system-uid-max",1,0,'m'},{"audit",0,0,'A'},{"foreground",0,0,'f'},{"help",0,0,'h'},{0} };
 while((c=getopt_long(argc,argv,"",opts,NULL))!=-1) switch(c){case's': if(!strcmp(optarg,"user"))l.user=TRUE;else if(strcmp(optarg,"system")){usage(argv[0]);return 2;}break;case'c':l.config=g_strdup(optarg);break;case'a':l.address=g_strdup(optarg);break;case'b':l.broker=g_strdup(optarg);break;case'p':l.pid_file=g_strdup(optarg);break;case'm':if(!g_ascii_string_to_unsigned(optarg,10,0,G_MAXUINT,&max,&e)){die_error("--system-uid-max",e);return 2;}l.system_uid_max=max;break;case'A':l.audit=TRUE;break;case'f':l.foreground=TRUE;l.daemonize=FALSE;break;default:usage(argv[0]);return c=='h'?0:2;}
 if(optind!=argc){usage(argv[0]);return 2;} if(!l.broker)l.broker=g_strdup(DEFAULT_BROKER); if(!g_file_test(l.broker,G_FILE_TEST_IS_EXECUTABLE)){g_free(l.broker);l.broker=g_find_program_in_path("dbus-broker");} if(!l.broker){g_printerr("dbus-broker not found; use --broker=PATH\n");return 1;}
 if(l.user){runtime=g_get_user_runtime_dir();if(!runtime){g_printerr("XDG_RUNTIME_DIR is required for --scope=user\n");return 1;}l.socket_path=g_build_filename(runtime,"bus",NULL);}else l.socket_path=g_strdup("/run/dbus/system_bus_socket");
 if(!l.config) l.config=g_strdup(l.user ? "/usr/share/dbus-1/session.conf" : "/usr/share/dbus-1/system.conf");
 l.config_state=launcher_config_new(); if(!launcher_config_load(l.config_state,l.config,&e)){die_error("Invalid D-Bus configuration",e);return 1;} l.service_dirs=launcher_config_service_dirs(l.config_state);
 configured_address=launcher_config_address(l.config_state); if(!l.address && configured_address) l.address=g_strdup(configured_address); if(!l.address)l.address=g_strdup_printf("unix:path=%s",l.socket_path); if(g_str_has_prefix(l.address,"unix:path=")){g_free(l.socket_path);l.socket_path=g_strdup(l.address+strlen("unix:path="));}
 if (!l.user && launcher_config_uses_console_policy(l.config_state)) { load_static_console_users(&l); refresh_console_users(&l); }
 if(!scan_services(l.service_dirs,l.services,&e)||!daemonize(&l,&e)||!bind_listener(&l,&e)||!start_broker(&l,&e)||!add_listener(&l,&e)||!register_services(&l,l.services,&e)){die_error("Cannot start launcher",e);return 1;}
 info=g_dbus_node_info_new_for_xml("<node><interface name='org.bus1.DBus.Controller'><method name='ReloadConfig'/></interface></node>",&e); if(!info){die_error("Controller API",e);return 1;} reg=g_dbus_connection_register_object(l.controller,"/org/bus1/DBus/Controller",info->interfaces[0],&controller_vtable,&l,NULL,&e); if(!reg){die_error("Controller API",e);return 1;}
 g_dbus_connection_signal_subscribe(l.controller,NULL,NULL,NULL,NULL,NULL,G_DBUS_SIGNAL_FLAGS_NONE,on_signal,&l,NULL); loop=g_main_loop_new(NULL,FALSE); g_child_watch_add(l.broker_pid,broker_exit,loop); g_unix_signal_add(SIGHUP,on_hup,&l); g_unix_signal_add(SIGTERM,quit_loop,loop); g_unix_signal_add(SIGINT,quit_loop,loop); g_main_loop_run(loop);
 g_dbus_connection_unregister_object(l.controller,reg); g_main_loop_unref(loop); g_dbus_node_info_unref(info); g_object_unref(l.controller); g_object_unref(l.listener); unlink(l.socket_path); if(l.pid_file) unlink(l.pid_file); if(l.static_uids) g_array_unref(l.static_uids); if(l.dynamic_uids) g_array_unref(l.dynamic_uids); launcher_config_free(l.config_state); return 0;
}
