#define _GNU_SOURCE
#include "address.h"
#include "dbus-transport.h"
#include "dbus-wire.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void wait_for_exit(pid_t child, int expected)
{
        int status;
        pid_t result;
        do {
                result = waitpid(child, &status, 0);
        } while (result < 0 && errno == EINTR);
        assert(result == child && WIFEXITED(status) && WEXITSTATUS(status) == expected);
}

static void call_bus(DBusTransport *transport, const char *member)
{
        DBusWriter message = {0};
        DBusPacket reply = {0};
        Error *error = NULL;
        uint32_t serial = dbus_transport_next_serial(transport);
        assert(dbus_message_build(&message, DBUS_MESSAGE_METHOD_CALL, 0, serial, 0, "/org/freedesktop/DBus",
                                  "org.freedesktop.DBus", member, "org.freedesktop.DBus", NULL, NULL, 0, NULL, &error));
        assert(dbus_transport_send(transport, &message, NULL, 0, &error));
        dbus_writer_clear(&message);
        do {
                dbus_packet_clear(&reply);
                assert(dbus_transport_receive(transport, &reply, &error));
        } while (reply.header.reply_serial != serial);
        assert(reply.header.type == DBUS_MESSAGE_METHOD_RETURN);
        dbus_packet_clear(&reply);
}

static void connect_bus(DBusTransport *transport, const char *path)
{
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        Error *error = NULL;
        int fd = -1;
        assert(strlen(path) < sizeof(address.sun_path));
        strcpy(address.sun_path, path);
        for (unsigned int attempt = 0; attempt < 500; ++attempt) {
                fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                assert(fd >= 0);
                if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0)
                        break;
                close(fd);
                fd = -1;
                usleep(10000);
        }
        assert(fd >= 0);
        dbus_transport_init(transport, fd);
        assert(dbus_transport_authenticate(transport, getuid(), &error));
        call_bus(transport, "Hello");
}

static void run_command(const char *wrapper, const char *self, const char *runtime, const char *parent_address,
                        const char *nested)
{
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
                execl(wrapper, wrapper, "--", self, "--command", runtime, parent_address, nested, wrapper,
                      (char *)NULL);
                _exit(127);
        }
        wait_for_exit(child, 42);
}

static void check_runtime(const char *runtime, const char *allowed)
{
        DIR *directory = opendir(runtime);
        struct dirent *entry;
        assert(directory);
        while ((entry = readdir(directory))) {
                assert(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
                       (allowed && strcmp(entry->d_name, allowed) == 0));
        }
        assert(closedir(directory) == 0);
}

int main(int argc, char **argv)
{
        if (argc == 6 && strcmp(argv[1], "--command") == 0) {
                const char *address = getenv("DBUS_SESSION_BUS_ADDRESS");
                DBusTransport transport;
                Error *error = NULL;
                struct stat st;
                assert(getenv("XDG_RUNTIME_DIR") && strcmp(getenv("XDG_RUNTIME_DIR"), argv[2]) == 0);
                assert(address && strcmp(address, argv[3]) != 0);
                char *socket_path = socket_path_from_address(address, &error);
                assert(socket_path && strncmp(socket_path, argv[2], strlen(argv[2])) == 0);
                char *directory = path_dirname(socket_path);
                assert(directory && strcmp(directory, argv[2]) != 0);
                assert(lstat(directory, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == getuid() &&
                       (st.st_mode & 0777) == 0700);
                connect_bus(&transport, socket_path);
                if (strcmp(argv[4], "yes") == 0)
                        run_command(argv[5], argv[0], argv[2], address, "no");
                call_bus(&transport, "ListNames");
                dbus_transport_clear(&transport);
                free(directory);
                free(socket_path);
                return 42;
        }

        /* Exercise D-Bus address escaping as well as an already occupied user bus. */
        char runtime[] = "/tmp/dbd-run- %,XXXXXX";
        char *socket_path, *path, *launcher_dir, *escaped, *address;
        DBusTransport existing;
        struct stat before, after;
        pid_t child, dispatcher;
        assert(argc == 3 && mkdtemp(runtime));
        assert(setenv("XDG_RUNTIME_DIR", runtime, 1) == 0);
        launcher_dir = path_dirname(argv[2]);
        path = str_printf("%s:/usr/bin:/bin", launcher_dir);
        assert(path && setenv("PATH", path, 1) == 0);
        socket_path = path_join(runtime, "bus");
        escaped = percent_escape(socket_path);
        address = str_printf("unix:path=%s", escaped);
        assert(socket_path && escaped && address);
        assert(setenv("DBUS_SESSION_BUS_ADDRESS", address, 1) == 0);

        run_command(argv[1], argv[0], runtime, address, "yes");
        check_runtime(runtime, NULL);

        dispatcher = fork();
        assert(dispatcher >= 0);
        if (dispatcher == 0) {
                execl(argv[2], argv[2], "--scope=user", "--foreground", "--address", address, (char *)NULL);
                _exit(127);
        }
        connect_bus(&existing, socket_path);
        assert(lstat(socket_path, &before) == 0);
        run_command(argv[1], argv[0], runtime, address, "yes");
        assert(lstat(socket_path, &after) == 0 && before.st_dev == after.st_dev && before.st_ino == after.st_ino);
        call_bus(&existing, "ListNames");
        check_runtime(runtime, "bus");
        dbus_transport_clear(&existing);
        assert(kill(dispatcher, SIGTERM) == 0);
        wait_for_exit(dispatcher, 0);

        child = fork();
        assert(child >= 0);
        if (child == 0) {
                execl(argv[1], argv[1], "--", "/nonexistent/dbd-test-command", (char *)NULL);
                _exit(126);
        }
        wait_for_exit(child, 127);
        check_runtime(runtime, NULL);

        child = fork();
        assert(child >= 0);
        if (child == 0) {
                execl(argv[1], argv[1], "--", "/bin/sh", "-c", "kill -TERM $$", (char *)NULL);
                _exit(127);
        }
        wait_for_exit(child, 128 + SIGTERM);
        check_runtime(runtime, NULL);

        char *fake_dispatcher = path_join(runtime, "dbus-broker-dispatch");
        assert(fake_dispatcher && symlink("/bin/false", fake_dispatcher) == 0);
        child = fork();
        assert(child >= 0);
        if (child == 0) {
                assert(setenv("PATH", runtime, 1) == 0);
                execl(argv[1], argv[1], "--", "/bin/true", (char *)NULL);
                _exit(127);
        }
        wait_for_exit(child, 1);
        assert(unlink(fake_dispatcher) == 0);
        assert(rmdir(runtime) == 0);
        free(fake_dispatcher);
        free(address);
        free(escaped);
        free(launcher_dir);
        free(path);
        free(socket_path);
        return 0;
}
