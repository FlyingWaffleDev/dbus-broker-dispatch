#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
        char runtime[] = "/tmp/dbd-run-session-XXXXXX";
        char *marker, *socket_path, *path, *launcher_dir;
        pid_t child;
        int status, fd;
        char address[1024] = {0};
        assert(argc == 3 && mkdtemp(runtime));
        assert(asprintf(&marker, "%s/address", runtime) >= 0);
        assert(asprintf(&socket_path, "%s/bus", runtime) >= 0);
        launcher_dir = strdup(argv[2]);
        assert(launcher_dir);
        char *slash = strrchr(launcher_dir, '/');
        if (slash)
                *slash = 0;
        else {
                free(launcher_dir);
                launcher_dir = strdup(".");
                assert(launcher_dir);
        }
        assert(asprintf(&path, "%s:%s", launcher_dir, getenv("PATH") ? getenv("PATH") : "/usr/bin:/bin") >= 0);
        child = fork();
        assert(child >= 0);
        if (child == 0) {
                setenv("XDG_RUNTIME_DIR", runtime, 1);
                setenv("PATH", path, 1);
                setenv("MARKER", marker, 1);
                execl(argv[1], argv[1], "--", "/bin/sh", "-c",
                      "printf %s \"$DBUS_SESSION_BUS_ADDRESS\" > \"$MARKER\"; exit 42", (char *)NULL);
                _exit(127);
        }
        while (waitpid(child, &status, 0) < 0 && errno == EINTR)
                ;
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 42);
        fd = open(marker, O_RDONLY | O_CLOEXEC);
        assert(fd >= 0);
        ssize_t n = read(fd, address, sizeof(address) - 1);
        assert(n > 0 && close(fd) == 0);
        char expected[1024];
        assert(snprintf(expected, sizeof(expected), "unix:path=%s", socket_path) > 0);
        assert(strcmp(address, expected) == 0);
        assert(access(socket_path, F_OK) < 0 && errno == ENOENT);
        assert(unlink(marker) == 0 && rmdir(runtime) == 0);
        free(launcher_dir);
        free(path);
        free(socket_path);
        free(marker);
        return 0;
}
