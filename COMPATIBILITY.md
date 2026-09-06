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

`<syslog/>` is ignored: the dispatcher switches to syslog whenever it
daemonizes, since standard error is `/dev/null` from that point. `<auth>` and
`<servicehelper>` are also ignored, matching dbus-broker-launch; dbus-broker
only speaks EXTERNAL, and activation drops privileges in-process.

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
