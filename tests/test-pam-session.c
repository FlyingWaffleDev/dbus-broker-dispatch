#define _GNU_SOURCE
#include <security/pam_appl.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static struct pam_conv conversation = {0};

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

static pam_handle_t *start_pam(const char *directory, const char *runtime)
{
        struct passwd *user = getpwuid(getuid());
        pam_handle_t *handle = NULL;
        char *assignment;
        assert(user);
        assert(pam_start_confdir("dispatch-test", user->pw_name, &conversation, directory, &handle) == PAM_SUCCESS);
        assert(asprintf(&assignment, "XDG_RUNTIME_DIR=%s", runtime) >= 0);
        assert(pam_putenv(handle, assignment) == PAM_SUCCESS);
        free(assignment);
        return handle;
}

int main(int argc, char **argv)
{
        char runtime[] = "/tmp/dbd-pam-XXXXXX";
        char *config, *pam_config, *socket_path, *state_path, *contents, *pam_contents, *expected, *pid_path;
        pam_handle_t *first, *second;
        struct stat pid_stat, state_stat;
        assert(argc == 3 && mkdtemp(runtime));
        assert(chmod(runtime, 0700) == 0);
        assert(asprintf(&config, "%s/session.conf", runtime) >= 0);
        assert(asprintf(&pam_config, "%s/dispatch-test", runtime) >= 0);
        assert(asprintf(&socket_path, "%s/bus", runtime) >= 0);
        assert(asprintf(&state_path, "%s/.dbus-broker-dispatch.pam", runtime) >= 0);
        assert(asprintf(&pid_path, "%s/dbus-broker-dispatch.pid", runtime) >= 0);
        assert(asprintf(&contents,
                        "<busconfig><keep_umask/><listen>unix:path=%s</listen><policy context='default'>"
                        "<allow user='*'/><allow send_destination='org.freedesktop.DBus'/>"
                        "<allow receive_sender='*'/></policy></busconfig>",
                        socket_path) >= 0);
        assert(asprintf(&pam_contents, "session required %s dispatcher=%s config-file=%s\n", argv[1], argv[2],
                        config) >= 0);
        write_contents(config, contents);
        write_contents(pam_config, pam_contents);
        first = start_pam(runtime, runtime);
        mode_t previous_umask = umask(0027);
        assert(pam_open_session(first, 0) == PAM_SUCCESS);
        assert(umask(previous_umask) == 0027);
        /* keep_umask must preserve the caller's mask through the PAM child.
         * PID files request 0644; PAM state files have explicit 0600 modes. */
        assert(stat(pid_path, &pid_stat) == 0 && stat(state_path, &state_stat) == 0);
        assert(asprintf(&expected, "unix:path=%s", socket_path) >= 0);
        assert(pam_getenv(first, "DBUS_SESSION_BUS_ADDRESS") &&
               strcmp(pam_getenv(first, "DBUS_SESSION_BUS_ADDRESS"), expected) == 0);
        assert(access(socket_path, F_OK) == 0);
        second = start_pam(runtime, runtime);
        assert(pam_open_session(second, 0) == PAM_SUCCESS);
        assert(pam_close_session(first, 0) == PAM_SUCCESS);
        assert(access(socket_path, F_OK) == 0);
        assert(pam_end(first, PAM_SUCCESS) == PAM_SUCCESS);
        assert(pam_close_session(second, 0) == PAM_SUCCESS);
        assert(pam_end(second, PAM_SUCCESS) == PAM_SUCCESS);
        for (unsigned int attempt = 0; attempt < 500 && access(socket_path, F_OK) == 0; ++attempt)
                usleep(10000);
        assert(access(socket_path, F_OK) < 0 && errno == ENOENT);
        unlink(state_path);
        assert(unlink(config) == 0 && unlink(pam_config) == 0 && rmdir(runtime) == 0);
        free(expected);
        free(pam_contents);
        free(contents);
        free(state_path);
        free(socket_path);
        free(pam_config);
        free(config);
        free(pid_path);
        assert((pid_stat.st_mode & 0777) == 0640);
        assert((state_stat.st_mode & 0777) == 0600);
        return 0;
}
