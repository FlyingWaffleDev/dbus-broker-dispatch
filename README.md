# OpenRC D-Bus broker launcher

`dbus-broker-openrc-launch` is a systemd-free controller for `dbus-broker`.
It creates the public Unix listener, starts the broker with a private peer
controller socket, registers service activation names, and implements the
controller-side reload API.  It is intended for OpenRC systems.

The launcher reads the standard D-Bus XML configuration and its includes and
drop-ins. It exports `default`, `mandatory`, user, group, `at_console`, and
`no_console` policy contexts to dbus-broker. By default it daemonizes itself;
pass `--foreground` when an external supervisor owns its lifecycle, and use
`--pid-file=PATH` to write the daemon PID for an init system.

Build with `meson setup build`; add `-Delogind=true` only when libelogind is
available.  The optional elogind dependency is used only for policy
`at_console`/`no_console` user classification and never for service control.
