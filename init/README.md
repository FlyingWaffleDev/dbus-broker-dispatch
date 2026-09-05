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

## Login-shell fallback without PAM

Each init directory also contains `dbus-broker-dispatch.sh`. With PAM support
disabled, install the selected script in `/etc/profile.d`. Use distinct names
such as `dbus-broker-dispatch-runit.sh` when packaging several backends.
These files must be sourced by the login shell so the exported bus address
reaches the desktop and its applications.

The scripts preserve an existing `DBUS_SESSION_BUS_ADDRESS`. Otherwise they
reuse the socket at `$XDG_RUNTIME_DIR/bus`, or request that the user supervisor
start its `dbus` service, wait up to five seconds for the socket to appear,
and export its address. The new runit, dinit, and s6 scripts percent-encode the
socket path. Failed starts leave the address unset and do not abort login.
They do not remove sockets or stop services on logout.

An existing user service manager is required. Installing these scripts does
not launch `runsvdir`, `s6-svscan`, or a user Dinit instance. Arrange for your
session setup to start the manager as the user, after the runtime directory
has been created, and to manage its lifetime across concurrent logins. It
must pass the same `XDG_RUNTIME_DIR` to the service. Starting a system service
manager as PID 1 does not create a service manager for every logged-in user.
For sessions without such a manager, use the PAM integration instead.

| Backend | Default user-service location | Override before sourcing profile.d |
| --- | --- | --- |
| runit | `$HOME/service/dbus` | `DBUS_BROKER_DISPATCH_RUNIT_SERVICE`, absolute service-directory path |
| s6 | `$XDG_RUNTIME_DIR/service/dbus` | `DBUS_BROKER_DISPATCH_S6_SERVICE`, absolute service-directory path |
| dinit | Service named `dbus`, control socket `$XDG_RUNTIME_DIR/dinitctl` | `DBUS_BROKER_DISPATCH_DINIT_SOCKET`, absolute user control-socket path |

For runit, copy the packaged user service directory to `$HOME/service/dbus`
and have the user's `runsvdir` supervise `$HOME/service`. This follows the
[upstream user-services example](https://smarden.org/runit/faq).
The profile script uses [`sv up`](https://smarden.org/runit/sv.8) with an
absolute path, so it never falls back to the system service directory or
`SVDIR`.

For s6, copy the packaged user service directory to
`$XDG_RUNTIME_DIR/service/dbus` during session setup, before the user's
[`s6-svscan`](https://skarnet.org/software/s6/s6-svscan.html) starts scanning
`$XDG_RUNTIME_DIR/service`. Recreate it when the runtime directory is recreated.
Alternatively, use a persistent writable directory and set the override.
If adding a service to an already running scan tree, request a rescan with
`s6-svscanctl -a /absolute/path/to/scan-directory`.
The profile script uses [`s6-svc -u`](https://skarnet.org/software/s6/s6-svc.html).
It checks for the bus socket itself; the service does not implement s6
readiness notifications. These are plain s6 services, not s6-rc definitions.

For Dinit, ensure the user instance can find the supplied `dbus` description.
Gentoo installs it in `/etc/dinit.d/user`, one of Dinit's default user search
directories. A manager configured with explicit `--services-dir` options
must include that directory or a copy of the description. The script uses
`dinitctl --user --socket-path "$XDG_RUNTIME_DIR/dinitctl" start --no-wait dbus`,
with a five-second control-command timeout in addition to the socket wait.
The explicit socket path prevents an inherited `DINIT_SOCKET_PATH` from
selecting the system manager. See the upstream
[Dinit](https://github.com/davmac314/dinit/blob/master/doc/manpages/dinit.8.m4)
and [dinitctl](https://github.com/davmac314/dinit/blob/master/doc/manpages/dinitctl.8.m4)
manuals. The script requires the `timeout` utility from coreutils.

If installing multiple backends, set `DBUS_BROKER_DISPATCH_INIT` to `openrc`,
`runit`, `dinit`, or `s6` before the profile hooks run. A value of `none`
disables all of them. On Gentoo, an earlier profile fragment such as
`/etc/profile.d/00-dbus-broker-dispatch.sh` can set this and any path override:

```sh
export DBUS_BROKER_DISPATCH_INIT=runit
export DBUS_BROKER_DISPATCH_RUNIT_SERVICE="${HOME}/service/dbus"
```

With no selector, each installed hook may try its own backend until one
publishes an address. Select one explicitly when several user supervisors
could manage the bus. The scripts never replace an address supplied by a
previous hook, SSH forwarding, or `dbus-broker-run-session`.

These hooks only cover sessions that source `/etc/profile.d`; they do not
cover SDDM's separate greeter session or other non-login-shell sessions.
Their supervisor commands follow upstream documentation, but the non-OpenRC
integrations have not been tested in full boot or desktop sessions.

Run `python3 tests/test-init-profile.py` from the source root to check the
hooks with simulated service-control commands and temporary Unix sockets.
