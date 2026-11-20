#define _GNU_SOURCE
/* These assertions have side effects and must survive NDEBUG builds. */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t spawn_dispatcher(const char *dispatcher, const char *runtime, const char *config, int ready_fd)
{
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
                assert(dup2(ready_fd, 3) == 3 && fcntl(3, F_SETFD, 0) == 0);
                assert(setenv("XDG_RUNTIME_DIR", runtime, 1) == 0);
                execl(dispatcher, dispatcher, "--scope=user", "--foreground", "--ready-fd=3", "--config-file", config,
                      (char *)NULL);
                _exit(127);
        }
        return child;
}

static void expect_failed_exit(pid_t child)
{
        int status;
        for (unsigned int i = 0; i < 200; ++i) {
                pid_t reaped = waitpid(child, &status, WNOHANG);
                if (reaped == child) {
                        assert(WIFEXITED(status) && WEXITSTATUS(status) == 1);
                        return;
                }
                assert(reaped == 0 || (reaped < 0 && errno == EINTR));
                usleep(10000);
        }
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        assert(!"Failed dispatcher did not exit promptly");
}

static void expect_startup_failure(const char *dispatcher, const char *runtime, const char *config)
{
        int pair[2];
        char notification;
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
        pid_t child = spawn_dispatcher(dispatcher, runtime, config, pair[1]);
        close(pair[1]);
        struct pollfd pfd = {.fd = pair[0], .events = POLLIN};
        int result = poll(&pfd, 1, 2000);
        if (result <= 0) {
                kill(child, SIGKILL);
                waitpid(child, NULL, 0);
        }
        assert(result > 0);
        assert(read(pair[0], &notification, 1) == 1 && notification == 'F');
        close(pair[0]);
        expect_failed_exit(child);
}

/* A start whose readiness report reaches nobody must not leave a bus behind:
 * whoever asked for it has stopped waiting and will never stop it. */
static void expect_abandoned_startup(const char *dispatcher, const char *runtime, const char *config)
{
        int pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
        close(pair[0]);
        pid_t child = spawn_dispatcher(dispatcher, runtime, config, pair[1]);
        close(pair[1]);
        expect_failed_exit(child);
}

int main(int argc, char **argv)
{
        char runtime[] = "/tmp/dbd-startup-XXXXXX";
        char config[256];
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        struct stat before, after;
        assert(argc == 2 && mkdtemp(runtime));
        assert(snprintf(config, sizeof(config), "%s/session.conf", runtime) > 0);
        assert(snprintf(address.sun_path, sizeof(address.sun_path), "%s/bus", runtime) > 0);

        /* Failures before daemonization must close and report on the channel. */
        expect_startup_failure(argv[1], runtime, config);
        FILE *file = fopen(config, "w");
        assert(file);
        assert(fprintf(file,
                       "<busconfig><type>session</type><listen>unix:path=%s</listen>"
                       "<policy context='default'><allow user='*'/><allow own='*'/>"
                       "<allow send_destination='*'/></policy></busconfig>",
                       address.sun_path) > 0);
        assert(fclose(file) == 0);

        int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(listener >= 0 && bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
        assert(listen(listener, 1) == 0 && lstat(address.sun_path, &before) == 0);
        expect_startup_failure(argv[1], runtime, config);
        /* Drain the connection from the first, successful liveness probe. */
        int probe = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        assert(probe >= 0);
        close(probe);

        /* Fill the Unix listener's backlog. A blocking probe would hang here. */
        int clients[2];
        for (unsigned int i = 0; i < 2; ++i) {
                clients[i] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
                assert(clients[i] >= 0 && connect(clients[i], (struct sockaddr *)&address, sizeof(address)) == 0);
        }
        expect_startup_failure(argv[1], runtime, config);
        assert(lstat(address.sun_path, &after) == 0);
        assert(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
        for (unsigned int i = 0; i < 2; ++i)
                close(clients[i]);
        close(listener);

        /* The socket is stale now, so this start gets as far as reporting. */
        expect_abandoned_startup(argv[1], runtime, config);
        assert(lstat(address.sun_path, &after) < 0 && errno == ENOENT);
        assert(unlink(config) == 0 && rmdir(runtime) == 0);
        return 0;
}
