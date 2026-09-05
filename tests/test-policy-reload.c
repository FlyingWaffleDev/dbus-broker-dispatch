#define _GNU_SOURCE
#include "dbus-transport.h"
#include "dbus-wire.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void write_contents(const char *path, const char *contents)
{
        FILE *file = fopen(path, "w");
        assert(file && fputs(contents, file) >= 0 && fclose(file) == 0);
}

static void wait_for_exit(pid_t child, int expected)
{
        int status;
        pid_t result;
        do {
                result = waitpid(child, &status, 0);
        } while (result < 0 && errno == EINTR);
        assert(result == child && WIFEXITED(status) && WEXITSTATUS(status) == expected);
}

static pid_t start_dispatcher(const char *binary, const char *config)
{
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
                execl(binary, binary, "--scope=user", "--foreground", "--config-file", config, (char *)NULL);
                _exit(127);
        }
        return child;
}

static void call_bus(DBusTransport *bus, const char *member, bool denied)
{
        DBusWriter body = {0}, message = {0};
        DBusPacket reply = {0};
        Error *error = NULL;
        bool own = strcmp(member, "RequestName") == 0;
        uint32_t serial = dbus_transport_next_serial(bus);
        if (own)
                assert(dbus_writer_string(&body, "org.example.Forbidden") && dbus_writer_u32(&body, 0));
        assert(dbus_message_build(&message, DBUS_MESSAGE_METHOD_CALL, 0, serial, 0, "/org/freedesktop/DBus",
                                  "org.freedesktop.DBus", member, "org.freedesktop.DBus", NULL, own ? "su" : NULL, 0,
                                  &body, &error));
        assert(dbus_transport_send(bus, &message, NULL, 0, &error));
        do {
                dbus_packet_clear(&reply);
                assert(dbus_transport_receive(bus, &reply, &error));
        } while (reply.header.reply_serial != serial);
        assert(reply.header.type == (denied ? DBUS_MESSAGE_ERROR : DBUS_MESSAGE_METHOD_RETURN));
        if (own && denied)
                assert(reply.header.error_name &&
                       strcmp(reply.header.error_name, "org.freedesktop.DBus.Error.AccessDenied") == 0);
        dbus_packet_clear(&reply);
        dbus_writer_clear(&message);
        dbus_writer_clear(&body);
}

static void connect_bus(DBusTransport *bus, const char *path)
{
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        Error *error = NULL;
        int fd = -1;
        assert(strlen(path) < sizeof(address.sun_path));
        strcpy(address.sun_path, path);
        for (unsigned int i = 0; i < 500; ++i) {
                fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                assert(fd >= 0);
                if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0)
                        break;
                close(fd);
                fd = -1;
                usleep(10000);
        }
        assert(fd >= 0);
        dbus_transport_init(bus, fd);
        assert(dbus_transport_authenticate(bus, getuid(), &error));
        call_bus(bus, "Hello", false);
}

int main(int argc, char **argv)
{
        char runtime[] = "/tmp/dbd-policy-reload-XXXXXX";
        char *config, *socket_path, *fault;
        assert(argc == 2 && mkdtemp(runtime));
        config = path_join(runtime, "bus.conf");
        socket_path = path_join(runtime, "bus");
        fault = path_join(runtime, "failure");
        assert(config && socket_path && fault);
        assert(setenv("XDG_RUNTIME_DIR", runtime, 1) == 0);
        assert(setenv("DBD_TEST_NSS_FAILURE", fault, 1) == 0);
        for (unsigned int group = 0; group < 2; ++group) {
                char *xml = str_printf(
                        "<busconfig><type>session</type><listen>unix:path=%s</listen>"
                        "<policy context='default'><allow user='*'/><allow own='*'/>"
                        "<allow send_destination='*'/><allow receive_sender='*'/></policy>"
                        "<policy %s='dbd-test-identity'><deny own='org.example.Forbidden'/></policy></busconfig>",
                        socket_path, group ? "group" : "user");
                assert(xml);
                write_contents(config, xml);
                free(xml);
                char code[32];
                snprintf(code, sizeof(code), "%d", EIO);
                write_contents(fault, code);
                wait_for_exit(start_dispatcher(argv[1], config), 1);
                assert(access(socket_path, F_OK) < 0 && errno == ENOENT);

                write_contents(fault, "0");
                pid_t child = start_dispatcher(argv[1], config);
                DBusTransport bus;
                connect_bus(&bus, socket_path);
                call_bus(&bus, "RequestName", true);
                write_contents(fault, code);
                call_bus(&bus, "ReloadConfig", true);
                call_bus(&bus, "RequestName", true);
                /* Reconnection also receives the retained policy. */
                dbus_transport_clear(&bus);
                connect_bus(&bus, socket_path);
                call_bus(&bus, "RequestName", true);
                write_contents(fault, "0");
                call_bus(&bus, "ReloadConfig", false);
                call_bus(&bus, "RequestName", true);
                dbus_transport_clear(&bus);
                assert(kill(child, SIGTERM) == 0);
                wait_for_exit(child, 0);
                assert(access(socket_path, F_OK) < 0 && errno == ENOENT);
        }
        assert(unlink(config) == 0 && unlink(fault) == 0 && rmdir(runtime) == 0);
        free(config);
        free(socket_path);
        free(fault);
        return 0;
}
