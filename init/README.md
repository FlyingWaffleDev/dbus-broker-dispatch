# Init definitions

This directory contains service definitions for the system and user buses. A
package should install only the definitions for its target init system.

The system service is named `dbus`. It creates `/run/dbus`, ensures that
`/etc/machine-id` exists, and runs `dbus-broker-dispatch --scope=system`.

The user service is also named `dbus`, but belongs to the user's service
manager. It requires `XDG_RUNTIME_DIR` in the service environment. Applications
normally find its socket at `$XDG_RUNTIME_DIR/bus`.

Install the files as follows:

- OpenRC: install `openrc/dbus.initd` as `/etc/init.d/dbus`,
  `openrc/dbus.confd` as `/etc/conf.d/dbus`, and `openrc/dbus.user.initd` as
  `/etc/user/init.d/dbus`. When the PAM module is disabled,
  `openrc/dbus-broker-dispatch.sh` can be installed in `/etc/profile.d`.
- s6: install `s6/system/dbus` or `s6/user/dbus` as a service directory in the
  appropriate scan directory.
- Dinit: install `dinit/system/dbus` in a system service-description directory
  or `dinit/user/dbus` in a user service-description directory.
- runit: install `runit/system/dbus` or `runit/user/dbus` as a service directory
  in the appropriate `runsvdir`.

The s6 and runit `run` files must remain executable.
