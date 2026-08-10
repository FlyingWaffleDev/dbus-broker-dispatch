#define _GNU_SOURCE
#include "config-policy.h"
#include "controller.h"
#include "dbus-transport.h"
#include "dbus-wire.h"
#include "nss-cache.h"
#include "process.h"
#include "service-file.h"
#include "service.h"
#include "util.h"
#include "watch.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void write_contents(const char *path, const char *contents)
{
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        size_t length = strlen(contents), offset = 0;
        assert(fd >= 0);
        while (offset < length) {
                ssize_t n = write(fd, contents + offset, length - offset);
                assert(n > 0);
                offset += (size_t)n;
        }
        assert(close(fd) == 0);
}

static void watch_called(void *data)
{
        ++*(unsigned int *)data;
}

static void test_watch(void)
{
        char root[] = "/tmp/dbd-native-watch-XXXXXX";
        char *parent, *target;
        unsigned int calls = 0;
        PtrVec paths;
        Error *error = NULL;
        struct pollfd inotify_poll, timer_poll;
        assert(mkdtemp(root));
        assert(asprintf(&parent, "%s/missing", root) >= 0);
        assert(asprintf(&target, "%s/services", parent) >= 0);
        Watch *watch = watch_new(watch_called, &calls, &error);
        assert(watch);
        ptr_vec_init(&paths, free);
        assert(ptr_vec_push(&paths, strdup(target)) && watch_set_paths(watch, &paths, &error));
        assert(mkdir(parent, 0700) == 0);
        inotify_poll = (struct pollfd){.fd = watch_inotify_fd(watch), .events = POLLIN};
        assert(poll(&inotify_poll, 1, 1000) == 1);
        assert(watch_dispatch_inotify(watch, &error));
        timer_poll = (struct pollfd){.fd = watch_timer_fd(watch), .events = POLLIN};
        assert(poll(&timer_poll, 1, 1000) == 1);
        assert(watch_dispatch_timer(watch, &error) && calls == 1);
        /* Replacing an inotify watch emits IN_IGNORED for the old descriptor.
         * Draining it must not rebuild the watcher again forever. */
        if (poll(&inotify_poll, 1, 100) == 1)
                assert(watch_dispatch_inotify(watch, &error));
        assert(poll(&inotify_poll, 1, 0) == 0);
        watch_free(watch);
        ptr_vec_clear(&paths);
        assert(rmdir(parent) == 0 && rmdir(root) == 0);
        free(target);
        free(parent);
}

static void test_config_nss_and_services(void)
{
        char directory[] = "/tmp/dbd-native-config-XXXXXX";
        char *config_path, *service_path;
        LauncherConfig *config;
        NssCache *nss;
        const NssUser *user;
        ServiceTable *services;
        PtrVec dirs;
        DBusWriter policy = {0};
        Error *error = NULL;

        assert(mkdtemp(directory));
        assert(asprintf(&config_path, "%s/test.conf", directory) >= 0);
        assert(asprintf(&service_path, "%s/org.example.Native.service", directory) >= 0);
        write_contents(config_path,
                       "<busconfig><listen>unix:path=/tmp/dbd-native-bus</listen>"
                       "<servicedir>/tmp/native-services</servicedir>"
                       "<policy context='default'><allow user='*'/><allow own='org.example.Native'/></policy>"
                       "</busconfig>");
        config = launcher_config_new();
        assert(config && launcher_config_load(config, config_path, &error));
        assert(strcmp(launcher_config_address(config), "unix:path=/tmp/dbd-native-bus") == 0);
        assert(launcher_config_service_dirs(config)->len == 1);
        assert(launcher_config_export_policy_wire(config, true, 999, NULL, 0, &policy, &error));
        assert(policy.bytes.len > 32);
        dbus_writer_clear(&policy);
        launcher_config_free(config);

        nss = nss_cache_new();
        assert(nss);
        user = nss_cache_lookup_user(nss, "0", &error);
        if (getuid() == 0)
                assert(user && nss_user_uid(user) == 0);
        else
                error_clear(&error);
        write_contents(service_path, "[D-BUS Service]\nName=org.example.Native\nExec=/bin/true\n");
        ptr_vec_init(&dirs, free);
        assert(ptr_vec_push(&dirs, strdup(directory)));
        services = service_table_new();
        assert(services && service_table_scan(&dirs, nss, true, services, &error));
        assert(services->len == 1);
        service_table_free(services);
        ptr_vec_clear(&dirs);
        nss_cache_free(nss);
        assert(unlink(service_path) == 0 && unlink(config_path) == 0 && rmdir(directory) == 0);
        free(service_path);
        free(config_path);
}

static void test_collections(void)
{
        PtrVec values;
        StrMap map;
        U32Vec numbers = {0};

        ptr_vec_init(&values, free);
        assert(ptr_vec_push(&values, strdup("one")));
        assert(ptr_vec_push(&values, strdup("two")));
        assert(values.len == 2 && strcmp(values.items[1], "two") == 0);
        ptr_vec_delete(&values, 0);
        assert(values.len == 1 && strcmp(values.items[0], "two") == 0);
        ptr_vec_clear(&values);

        str_map_init(&map, free);
        assert(str_map_set(&map, "key", strdup("value")));
        assert(strcmp(str_map_get(&map, "key"), "value") == 0);
        assert(str_map_contains(&map, "key"));
        free(str_map_remove(&map, "key"));
        assert(!str_map_contains(&map, "key"));
        str_map_clear(&map);

        assert(u32_vec_push(&numbers, 2));
        assert(u32_vec_push(&numbers, 1));
        assert(u32_vec_push(&numbers, 2));
        u32_vec_sort_unique(&numbers);
        assert(numbers.len == 2 && numbers.items[0] == 1 && numbers.items[1] == 2);
        u32_vec_clear(&numbers);
}

static void test_service_parser(void)
{
        char path[] = "/tmp/dbd-service-XXXXXX";
        const char data[] = "[D-BUS Service]\nName=org.example.Test\nExec=/bin/echo 'hello world' \"x\"\nUser=root\n";
        ServiceFile file = {0};
        Error *error = NULL;
        int fd = mkstemp(path);

        assert(fd >= 0);
        assert(write(fd, data, sizeof(data) - 1) == (ssize_t)(sizeof(data) - 1));
        assert(close(fd) == 0);
        assert(service_file_load(path, &file, &error));
        assert(!error);
        assert(strcmp(file.name, "org.example.Test") == 0);
        assert(file.arguments.len == 3);
        assert(strcmp(file.arguments.items[1], "hello world") == 0);
        assert(strcmp(file.arguments.items[2], "x") == 0);
        assert(dbus_name_is_valid(file.name));
        assert(!dbus_name_is_valid("1org.example"));
        service_file_clear(&file);
        assert(unlink(path) == 0);
}

static void test_process(void)
{
        char *const arguments[] = {"/bin/sh", "-c", "exit 23", NULL};
        char *const missing_arguments[] = {"/this/path/does/not/exist", NULL};
        ProcessSpec spec = {.argv = arguments};
        Error *error = NULL;
        pid_t pid;
        int status;
        bool exited;

        assert(process_spawn(&spec, &pid, &error));
        assert(process_wait(pid, 0, &status, &exited, &error));
        assert(exited && WIFEXITED(status) && WEXITSTATUS(status) == 23);
        spec.argv = missing_arguments;
        assert(!process_spawn(&spec, &pid, &error));
        assert(error && error->code == ENOENT);
        error_clear(&error);
}

static void test_dbus_wire(void)
{
        DBusWriter body = {0}, message = {0};
        DBusHeader header = {0};
        DBusReader reader;
        Error *error = NULL;
        size_t consumed;
        const char *path, *name;
        size_t length;
        uint32_t uid;

        assert(dbus_writer_object_path(&body, "/org/example/Test"));
        assert(dbus_writer_string(&body, "org.example.Test"));
        assert(dbus_writer_u32(&body, 1000));
        assert(dbus_message_build(&message, DBUS_MESSAGE_METHOD_CALL, 0, 7, 0, "/org/bus1/DBus/Broker",
                                  "org.bus1.DBus.Broker", "AddName", NULL, NULL, "osu", 0, &body, &error));
        assert(dbus_message_parse((uint8_t *)message.bytes.data, message.bytes.len, &header, &reader, &consumed,
                                  &error));
        assert(consumed == message.bytes.len && header.type == DBUS_MESSAGE_METHOD_CALL && header.serial == 7);
        assert(strcmp(header.path, "/org/bus1/DBus/Broker") == 0);
        assert(strcmp(header.interface, "org.bus1.DBus.Broker") == 0);
        assert(strcmp(header.member, "AddName") == 0 && strcmp(header.signature, "osu") == 0);
        assert(dbus_reader_string(&reader, &path, &length) && strcmp(path, "/org/example/Test") == 0);
        assert(dbus_reader_string(&reader, &name, &length) && strcmp(name, "org.example.Test") == 0);
        assert(dbus_reader_u32(&reader, &uid) && uid == 1000 && reader.offset == reader.length);
        dbus_header_clear(&header);
        dbus_writer_clear(&message);
        dbus_writer_clear(&body);
}

static void test_dbus_transport(void)
{
        int sockets[2], null_fd;
        DBusTransport sender, receiver;
        DBusWriter message = {0};
        DBusPacket packet = {0};
        Error *error = NULL;

        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
        null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        assert(null_fd >= 0);
        dbus_transport_init(&sender, sockets[0]);
        dbus_transport_init(&receiver, sockets[1]);
        assert(dbus_message_build(&message, DBUS_MESSAGE_METHOD_RETURN, 0, 4, 3, NULL, NULL, NULL, NULL, NULL, NULL, 1,
                                  NULL, &error));
        assert(dbus_transport_send(&sender, &message, &null_fd, 1, &error));
        assert(dbus_transport_receive(&receiver, &packet, &error));
        assert(packet.header.type == DBUS_MESSAGE_METHOD_RETURN && packet.header.reply_serial == 3);
        assert(packet.n_fds == 1 && fcntl(packet.fds[0], F_GETFD) >= 0);
        dbus_packet_clear(&packet);
        dbus_writer_clear(&message);
        close(null_fd);
        dbus_transport_clear(&sender);
        dbus_transport_clear(&receiver);
}

static void test_controller_peer(void)
{
        int sockets[2], status;
        pid_t broker;
        char *machine_id = NULL;
        size_t machine_length = 0;
        Error *error = NULL;
        Controller controller;

        if (!read_file("/etc/machine-id", &machine_id, &machine_length, &error)) {
                error_clear(&error);
                return;
        }
        while (machine_length && (machine_id[machine_length - 1] == '\n' || machine_id[machine_length - 1] == '\r'))
                machine_id[--machine_length] = 0;
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
        broker = fork();
        assert(broker >= 0);
        if (broker == 0) {
                char machine_argument[128];
                if (sockets[1] != 3) {
                        close(sockets[0]);
                        if (dup2(sockets[1], 3) < 0)
                                _exit(127);
                        close(sockets[1]);
                } else {
                        close(sockets[0]);
                        fcntl(3, F_SETFD, 0);
                }
                snprintf(machine_argument, sizeof(machine_argument), "--machine-id=%s", machine_id);
                execlp("dbus-broker", "dbus-broker", "--controller=3", machine_argument, "--max-bytes=8388608",
                       "--max-fds=64", "--max-matches=256", (char *)NULL);
                _exit(127);
        }
        close(sockets[1]);
        controller_init(&controller, sockets[0], NULL, NULL);
        assert(controller_authenticate(&controller, getuid(), &error));
        assert(controller_add_name(&controller, "/org/bus1/DBus/Name/_test", "org.example.NativeTest", getuid(),
                                   &error));
        controller_clear(&controller);
        while (waitpid(broker, &status, 0) < 0 && errno == EINTR)
                ;
        assert(WIFEXITED(status));
        free(machine_id);
}

int main(void)
{
        test_collections();
        test_watch();
        test_config_nss_and_services();
        test_service_parser();
        test_process();
        test_dbus_wire();
        test_dbus_transport();
        test_controller_peer();
        return 0;
}
