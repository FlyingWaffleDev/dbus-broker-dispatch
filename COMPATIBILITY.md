| Capability           | broker-launch |           dispatch |
| -------------------- | ------------: | -----------------: |
| D-Bus XML policy     |             ✓ |                  ✓ |
| `Exec=` activation   |             ✓ |                  ✓ |
| `SystemdService=`    |             ✓ | Exec fallback only |
| config reload        |             ✓ |                  ✓ |
| user bus             |             ✓ |                  ✓ |
| system bus           |             ✓ |                  ✓ |
| AppArmor             |             ✓ |                  ✓ |
| SELinux associations |             ✓ |                  ✓ |
| systemd dependency   |           yes |                 no |
| OpenRC               |             — |             tested |
| runit                |             — |          simulated |
| s6                   |             — |          simulated |
| dinit                |             — |          simulated |

## Daemonizing

`<fork/>` decides whether the dispatcher backgrounds itself, as it does for
`dbus-daemon`; `--fork` and `--foreground` are its `--fork` and `--nofork`.
`<pidfile>` is honoured, and `--pid-file` overrides it. The stock system
configuration ships `<fork/>` and the stock session configuration does not, so
launchers that need a background session bus pass `--fork` explicitly; the PAM
module and the OpenRC services do.

`<syslog/>` sends diagnostics to syslog even in the foreground. Daemonizing
implies it, because standard error is `/dev/null` from that point. Warnings
raised while the configuration is still being parsed necessarily predate the
switch and go to standard error, as they do for `dbus-daemon`.

`<auth>` and `<servicehelper>` cannot be honoured, so each one now warns instead
of being silently dropped. dbus-broker implements only the EXTERNAL mechanism
and rejects the rest during SASL, and activation changes user in the forked
child rather than execing a setuid helper.

## Broker diagnostics

dbus-broker is started with `--log` on a stream socket, which selects its
plain-line log mode; the dispatcher reads that socket and re-emits each line
through its own logging, so policy denials and SASL violations reach standard
error or syslog with everything else. Without this the broker gets no log
descriptor at all and discards its diagnostics.

dbus-broker-launch instead connects the broker to `/run/systemd/journal/socket`
and fails to start when that socket is absent, so it offers no usable model
here. The broker prefixes each line with `LOG_MAKEPRI(facility, severity)`; the
dispatcher forwards the severity and applies its own facility.

## Activation umask

The dispatcher follows dbus-daemon: it installs `0022` when it daemonizes and
otherwise keeps the mask it inherited. `--foreground` and `<keep_umask/>` both
suppress the `0022` default. Activated services inherit whichever mask the bus
ended up with, so a session that starts the bus with a restrictive mask can
choose whether that mask reaches its applications.

The listening socket is not affected either way. As in
[`_dbus_listen_unix_socket()`](https://gitlab.freedesktop.org/dbus/dbus/-/blob/master/dbus/dbus-sysdeps-unix.c),
the dispatcher chmods it to `0777` and only warns if that fails; access is
controlled by the bus policy and by the parent directory, which must be trusted
and, for a user bus, owned by the caller.

This mirrors [`_dbus_become_daemon()`](https://github.com/d-bus/dbus/blob/master/dbus/dbus-sysdeps-util-unix.c),
which sets `umask(022)` in the daemon child unless `keep_umask` is set, and is
skipped entirely under `--nofork`. The PAM launcher therefore forces no mask of
its own; the session's configuration decides.

[dbus-broker-launch](https://github.com/bus1/dbus-broker/blob/main/src/launch/service.c)
delegates activation to systemd, including transient units for `Exec=` services.
Those services use systemd's `UMask=` settings rather than the launcher's mask.
[Systemd defaults](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
are `0022` for system units and the user manager's mask for user units, typically
also `0022`. The dispatcher does not implement these systemd overrides.
