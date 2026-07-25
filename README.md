# dbus-broker-dispatch

`dbus-broker-dispatch` is an init-agnostic controller for
[`dbus-broker`](https://github.com/bus1/dbus-broker). It creates the public
Unix listener, starts an unprivileged broker with a private controller socket,
loads standard D-Bus XML policy, and provides service activation and reloads.
The companion Gentoo overlay supplies `dbus-broker-dispatch-openrc`; the
dispatcher itself does not call or depend on OpenRC.

This is pre-release software. Test it in a disposable system before replacing
the system or desktop-session bus on a primary machine.

## Features

- System and user buses backed by filesystem `unix:path=` sockets.
- Standard, mandatory, user, group, `at_console`, and `no_console` policy.
- Standard service-directory precedence and direct `Exec=` activation without
  a shell.
- System-service `User=` privilege transitions, including supplementary-group
  removal.
- Activation-environment propagation and `DBUS_STARTER_*` variables.
- Transactional configuration reloads through SIGHUP or the broker reload API.
- Debounced automatic reloads for configuration files, include directories,
  and service directories, including paths that do not exist at startup.
- D-Bus resource limits mapped to the broker's per-user quotas.
- Optional live elogind session monitoring for console-sensitive policy.
- AppArmor feature detection and `enabled`, `disabled`, and `required` modes.
- Consistent per-generation NSS identity snapshots for policy and activated
  service users, including supplementary groups.
- Upstream-compatible configuration structure and attribute diagnostics,
  SELinux name associations, custom bus types, and optimized policy batches.
- A `dbus-run-session`-style wrapper for isolated user buses.
- An optional PAM session module that starts one shared user bus after the
  session manager has created a secure `XDG_RUNTIME_DIR`.

`SystemdService=` is ignored when an `Exec=` command is available. A service
that contains only `SystemdService=` is not registered; this project never
starts systemd units or maps them to another service manager.

## Build and test

```sh
meson setup build --buildtype=release
meson compile -C build
meson test -C build --print-errorlogs
```

The PAM module is built automatically when Linux-PAM is available. Require or
disable it explicitly with `-Dpam=enabled` or `-Dpam=disabled`; override its
installation directory with `-Dpam-module-dir=/lib64/security` when a
distribution keeps PAM modules outside the normal prefix.

Enable elogind policy updates with `-Delogind=true`. Configure additional
users that should always receive `at_console` policy with, for example,
`-Dsystem-console-users=root,rescue`.

SELinux-aware conditional and policy-root-relative includes are enabled
automatically when libselinux is available. Select this explicitly with
`-Dselinux=enabled` or `-Dselinux=disabled`. SELinux `<associate>` mappings are
exported regardless; libselinux is only needed to query the active policy and
its root.

For a sanitizer build:

```sh
meson setup build-asan --buildtype=debugoptimized \
  -Db_sanitize=address,undefined -Dwarning_level=3
meson test -C build-asan --print-errorlogs
```

## Usage

Run in the foreground under a supervisor:

```sh
dbus-broker-dispatch --scope=system --foreground
dbus-broker-dispatch --scope=user --foreground
```

Run one command in a private session bus:

```sh
dbus-broker-run-session -- command arg...
```

The dispatcher requires an explicit `--scope`. It accepts `--config-file`,
`--address`, `--broker`, `--pid-file`, `--system-uid-max`, and `--audit`.
Omit `--foreground` to self-daemonize. The OpenRC system service uses that
mode to match Gentoo's reference `dbus` service; the OpenRC user service uses
self-daemonizing mode as well.

## PAM user-bus startup

`pam_dbus_broker_dispatch.so` is an optional session module for systems that
have no per-user service manager. Add it after the module that creates
`XDG_RUNTIME_DIR` (normally `pam_elogind.so`):

```text
-session optional pam_dbus_broker_dispatch.so
```

On open-session it validates that the runtime directory is an absolute,
user-owned `0700` directory, serializes concurrent starts, and launches
`dbus-broker-dispatch --scope=user` with the target user's credentials. It
then publishes `DBUS_SESSION_BUS_ADDRESS` through the PAM environment. Multiple
PAM sessions share the same module-owned bus; the last close-session stops it.
An already-active bus owned by another integration mechanism is reused but is
never claimed or stopped.

The module does not create or chown runtime directories. A missing
`XDG_RUNTIME_DIR` returns `PAM_IGNORE`, so ordering after `pam_elogind` (or an
equivalent session-runtime provider) is required. The optional PAM control
flag is recommended during initial deployment so a bus failure cannot prevent
login. Add the line only to session stacks whose processes should inherit a
user bus.

Module arguments are limited to `debug`, `dispatcher=/absolute/path`, and
`config-file=/absolute/path`. The path overrides are intended for development
and controlled deployments; normal installations need no arguments.

## Current compatibility boundary

- Only filesystem-backed `unix:path=` listeners are accepted. Abstract and
  non-Unix transports are intentionally rejected.
- Container policy and several legacy dbus-daemon-only limits are not
  implemented. The four limits used by dbus-broker are honored:
  `max_outgoing_bytes`, `max_outgoing_unix_fds`,
  `max_connections_per_user`, and `max_match_rules_per_connection`.

Before a wider release, add a project license file and replace the placeholder
repository URLs in the companion overlay.
