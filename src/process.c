#define _GNU_SOURCE
#include "process.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void close_nointr(int fd)
{
        if (fd >= 0)
                while (close(fd) < 0 && errno == EINTR)
                        ;
}

static void child_fail(int fd, int error_number)
{
        ssize_t written;
        do
                written = write(fd, &error_number, sizeof(error_number));
        while (written < 0 && errno == EINTR);
        _exit(127);
}

bool process_spawn(const ProcessSpec *spec, pid_t *pid, Error **error)
{
        int failure_pipe[2];
        pid_t child;
        int child_error = 0;
        size_t received = 0;

        if (!spec || !spec->argv || !spec->argv[0] || !pid)
                return error_set(error, EINVAL, "Invalid process specification");
        if (pipe2(failure_pipe, O_CLOEXEC) < 0)
                return error_set_errno(error, errno, "Cannot create exec status pipe");
        child = fork();
        if (child < 0) {
                int saved = errno;
                close_nointr(failure_pipe[0]);
                close_nointr(failure_pipe[1]);
                return error_set_errno(error, saved, "Cannot fork %s", spec->argv[0]);
        }
        if (child == 0) {
                int setup_error = 0;
                close_nointr(failure_pipe[0]);
                if (spec->working_directory && chdir(spec->working_directory) < 0)
                        child_fail(failure_pipe[1], errno);
                if (spec->child_setup && !spec->child_setup(spec->child_setup_data, &setup_error))
                        child_fail(failure_pipe[1], setup_error ? setup_error : EPERM);
                if (spec->environment) {
                        if (spec->search_path)
                                execvpe(spec->argv[0], spec->argv, spec->environment);
                        else
                                execve(spec->argv[0], spec->argv, spec->environment);
                } else if (spec->search_path) {
                        execvp(spec->argv[0], spec->argv);
                } else {
                        execv(spec->argv[0], spec->argv);
                }
                child_fail(failure_pipe[1], errno);
        }
        close_nointr(failure_pipe[1]);
        while (received < sizeof(child_error)) {
                ssize_t n = read(failure_pipe[0], (char *)&child_error + received, sizeof(child_error) - received);
                if (n > 0) {
                        received += (size_t)n;
                        continue;
                }
                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0) {
                        int saved = errno;
                        close_nointr(failure_pipe[0]);
                        kill(child, SIGKILL);
                        while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
                                ;
                        return error_set_errno(error, saved, "Cannot read exec status for %s", spec->argv[0]);
                }
                break;
        }
        close_nointr(failure_pipe[0]);
        if (received) {
                while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
                        ;
                return error_set_errno(error, child_error, "Cannot execute %s", spec->argv[0]);
        }
        *pid = child;
        return true;
}

bool process_terminate(pid_t pid, int signal_number, Error **error)
{
        if (kill(pid, signal_number) < 0 && errno != ESRCH)
                return error_set_errno(error, errno, "Cannot signal process %ld", (long)pid);
        return true;
}

bool process_wait(pid_t pid, int options, int *status, bool *exited, Error **error)
{
        pid_t result;
        do
                result = waitpid(pid, status, options);
        while (result < 0 && errno == EINTR);
        if (result < 0)
                return error_set_errno(error, errno, "Cannot wait for process %ld", (long)pid);
        if (exited)
                *exited = result == pid;
        return true;
}
