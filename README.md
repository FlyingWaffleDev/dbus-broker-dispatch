# OpenRC D-Bus broker launcher

`dbus-broker-openrc-launch` is a systemd-free controller for `dbus-broker`.
It creates the public Unix listener, starts the broker with a private peer
controller socket, registers service activation names, and implements the
controller-side reload API.  It is intended for OpenRC systems.

Build with `meson setup build`; add `-Delogind=true` only when libelogind is
available.  The optional elogind dependency is used only for policy
`at_console`/`no_console` user classification and never for service control.
