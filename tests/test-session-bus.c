#define _GNU_SOURCE
#include "dbus-transport.h"
#include "dbus-wire.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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

static int connect_bus(const char *path)
{
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        assert(strlen(path) < sizeof(address.sun_path));
        strcpy(address.sun_path, path);
        for (unsigned int attempt = 0; attempt < 500; ++attempt) {
                int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                assert(fd >= 0);
                if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0)
                        return fd;
                close(fd);
                usleep(10000);
        }
        return -1;
}

static void call_bus(DBusTransport *transport, const char *member, DBusPacket *reply)
{
        DBusWriter message = {0};
        Error *error = NULL;
        uint32_t serial = dbus_transport_next_serial(transport);
        assert(dbus_message_build(&message, DBUS_MESSAGE_METHOD_CALL, 0, serial, 0, "/org/freedesktop/DBus",
                                  "org.freedesktop.DBus", member, "org.freedesktop.DBus", NULL, NULL, 0, NULL, &error));
        assert(dbus_transport_send(transport, &message, NULL, 0, &error));
        dbus_writer_clear(&message);
        do {
                dbus_packet_clear(reply);
                assert(dbus_transport_receive(transport, reply, &error));
        } while (reply->header.reply_serial != serial);
        assert(reply->header.type == DBUS_MESSAGE_METHOD_RETURN);
}

static void test_session_bus(const char *dispatcher, bool foreground, bool keep_umask)
{
        char runtime[] = "/tmp/dbd-session-XXXXXX";
        char *config, *socket_path, *contents, *service_path, *command_path, *marker, *pid_path;
        const char *username;
        struct passwd *password = getpwuid(getuid());
        DBusTransport transport;
        DBusPacket reply = {0};
        DBusReader names;
        Error *error = NULL;
        pid_t child;
        int fd, status, ready_pair[2];
        unsigned int service_umask;
        bool found = false;

        assert(password && mkdtemp(runtime));
        assert(chmod(runtime, 0700) == 0);
        username = password->pw_name;
        assert(asprintf(&config, "%s/session.conf", runtime) >= 0);
        assert(asprintf(&socket_path, "%s/bus", runtime) >= 0);
        assert(asprintf(&service_path, "%s/org.example.NativeActivation.service", runtime) >= 0);
        assert(asprintf(&command_path, "%s/activate", runtime) >= 0);
        assert(asprintf(&marker, "%s/activated", runtime) >= 0);
        assert(asprintf(&pid_path, "%s/dispatcher.pid", runtime) >= 0);
        char *command_contents;
        /* Publish the result only after the service has finished writing it. */
        assert(asprintf(&command_contents, "#!/bin/sh\numask > '%s.tmp'\nmv '%s.tmp' '%s'\nexit 1\n", marker, marker,
                        marker) >= 0);
        write_contents(command_path, command_contents);
        assert(chmod(command_path, 0700) == 0);
        char *service_contents;
        assert(asprintf(&service_contents, "[D-BUS Service]\nName=org.example.NativeActivation\nExec=%s\n",
                        command_path) >= 0);
        write_contents(service_path, service_contents);
        assert(asprintf(&contents,
                        "<busconfig><listen>unix:path=%s</listen><type>session</type>"
                        "<servicedir>%s</servicedir>%s%s"
                        "<policy context='default'><allow user='*'/><allow send_destination='org.freedesktop.DBus'/>"
                        "<allow receive_sender='*'/></policy><policy user='%s'><allow own='*'/></policy></busconfig>",
                        socket_path, runtime, keep_umask ? "<keep_umask/>" : "", foreground ? "" : "<fork/>",
                        username) >= 0);
        write_contents(config, contents);
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ready_pair) == 0);
        child = fork();
        assert(child >= 0);
        if (child == 0) {
                setenv("XDG_RUNTIME_DIR", runtime, 1);
                umask(0077);
                close(ready_pair[0]);
                if (!foreground) {
                        close(ready_pair[1]);
                        execl(dispatcher, dispatcher, "--scope=user", "--pid-file", pid_path, "--config-file", config,
                              (char *)NULL);
                        _exit(127);
                }
                assert(dup2(ready_pair[1], 3) == 3);
                assert(fcntl(3, F_SETFD, 0) == 0);
                if (ready_pair[1] != 3)
                        close(ready_pair[1]);
                execl(dispatcher, dispatcher, "--scope=user", "--foreground", "--ready-fd=3", "--config-file", config,
                      (char *)NULL);
                _exit(127);
        }
        close(ready_pair[1]);
        if (foreground) {
                struct pollfd ready_poll = {.fd = ready_pair[0], .events = POLLIN};
                char notification;
                assert(poll(&ready_poll, 1, 5000) > 0);
                assert(read(ready_pair[0], &notification, 1) == 1 && notification == 'R');
                /* No broker or activated service may keep this private channel open. */
                assert(poll(&ready_poll, 1, 1000) > 0);
                assert(read(ready_pair[0], &notification, 1) == 0);
        } else {
                /* The daemonizing parent exits only once the bus is ready.
                 * As a subreaper, we can also wait for the daemon at teardown. */
                while (waitpid(child, &status, 0) < 0 && errno == EINTR)
                        ;
                assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
                FILE *pid_file = fopen(pid_path, "r");
                long pid;
                assert(pid_file && fscanf(pid_file, "%ld", &pid) == 1 && pid > 0);
                assert(fclose(pid_file) == 0);
                child = (pid_t)pid;
        }
        close(ready_pair[0]);
        fd = connect_bus(socket_path);
        assert(fd >= 0);
        dbus_transport_init(&transport, fd);
        assert(dbus_transport_authenticate(&transport, getuid(), &error));
        call_bus(&transport, "Hello", &reply);
        assert(reply.header.signature && strcmp(reply.header.signature, "s") == 0);
        dbus_packet_clear(&reply);
        call_bus(&transport, "ListNames", &reply);
        assert(reply.header.signature && strcmp(reply.header.signature, "as") == 0);
        assert(dbus_reader_array(&reply.body, 4, &names));
        while (names.offset < names.length) {
                const char *name;
                size_t length;
                assert(dbus_reader_string(&names, &name, &length));
                found |= strcmp(name, "org.freedesktop.DBus") == 0;
        }
        assert(found);
        dbus_packet_clear(&reply);
        call_bus(&transport, "ReloadConfig", &reply);
        dbus_packet_clear(&reply);
        {
                DBusWriter body = {0}, message = {0};
                uint32_t serial = dbus_transport_next_serial(&transport);
                assert(dbus_writer_string(&body, "org.example.NativeActivation") && dbus_writer_u32(&body, 0));
                assert(dbus_message_build(&message, DBUS_MESSAGE_METHOD_CALL, 0, serial, 0, "/org/freedesktop/DBus",
                                          "org.freedesktop.DBus", "StartServiceByName", "org.freedesktop.DBus", NULL,
                                          "su", 0, &body, &error));
                assert(dbus_transport_send(&transport, &message, NULL, 0, &error));
                dbus_writer_clear(&message);
                dbus_writer_clear(&body);
        }
        for (unsigned int attempt = 0; attempt < 500 && access(marker, F_OK) < 0; ++attempt)
                usleep(10000);
        assert(access(marker, F_OK) == 0);
        dbus_transport_clear(&transport);
        assert(kill(child, SIGTERM) == 0);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR)
                ;
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        FILE *result = fopen(marker, "r");
        assert(result && fscanf(result, "%o", &service_umask) == 1);
        assert(fclose(result) == 0);
        assert(unlink(marker) == 0 && unlink(service_path) == 0 && unlink(command_path) == 0 && unlink(config) == 0);
        assert(rmdir(runtime) == 0);
        free(service_contents);
        free(command_contents);
        free(marker);
        free(command_path);
        free(service_path);
        free(contents);
        free(socket_path);
        free(config);
        free(pid_path);
        assert(service_umask == (foreground || keep_umask ? 0077 : 0022));
}

int main(int argc, char **argv)
{
        assert(argc == 2);
        assert(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
        test_session_bus(argv[1], true, false);
        test_session_bus(argv[1], true, true);
        test_session_bus(argv[1], false, false);
        test_session_bus(argv[1], false, true);
        return 0;
}
