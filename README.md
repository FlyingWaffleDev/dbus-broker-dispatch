# Non-systemd launcher for dbus-broker

`dbus-broker-openrc-launch` is an init-agnostic controller for
[`dbus-broker`](https://github.com/bus1/dbus-broker). It creates the public
Unix listener, starts an unprivileged broker with a private controller socket,
loads standard D-Bus XML policy, and provides service activation and reloads.
The companion Gentoo overlay supplies the OpenRC integration; the controller
itself does not call or depend on OpenRC.

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
- D-Bus resource limits mapped to the broker's per-user quotas.
- Optional live elogind session monitoring for console-sensitive policy.
- AppArmor feature detection and `enabled`, `disabled`, and `required` modes.
- A `dbus-run-session`-style wrapper for isolated user buses.

`SystemdService=` is ignored when an `Exec=` command is available. A service
that contains only `SystemdService=` is not registered; this project never
starts systemd units or maps them to another service manager.

## Build and test

```sh
meson setup build --buildtype=release
meson compile -C build
meson test -C build --print-errorlogs
```

Enable elogind policy updates with `-Delogind=true`. Configure additional
users that should always receive `at_console` policy with, for example,
`-Dsystem-console-users=root,rescue`.

For a sanitizer build:

```sh
meson setup build-asan --buildtype=debugoptimized \
  -Db_sanitize=address,undefined -Dwarning_level=3
meson test -C build-asan --print-errorlogs
```

## Usage

Run under a supervisor in the foreground:

```sh
dbus-broker-openrc-launch --scope=system --foreground
dbus-broker-openrc-launch --scope=user --foreground
```

Run one command in a private session bus:

```sh
dbus-broker-openrc-run-session -- command arg...
```

The launcher requires an explicit `--scope`. It accepts `--config-file`,
`--address`, `--broker`, `--pid-file`, `--system-uid-max`, and `--audit`.
Daemonization remains available by omitting `--foreground`, but supervised
foreground mode gives the init system accurate startup and failure reporting.

## Current compatibility boundary

- Only filesystem-backed `unix:path=` listeners are accepted. Abstract and
  non-Unix transports are intentionally rejected.
- SELinux `<associate>` mappings and SELinux-root-relative includes are not yet
  exported. Do not deploy this as a system bus on an SELinux-enforcing host.
- Configuration-file and service-directory changes take effect on an explicit
  reload; there is no filesystem watcher.
- Container policy and several legacy dbus-daemon-only limits are not
  implemented. The four limits used by dbus-broker are honored:
  `max_outgoing_bytes`, `max_outgoing_unix_fds`,
  `max_connections_per_user`, and `max_match_rules_per_connection`.

Before a wider release, add a project license file and replace the placeholder
repository URLs in the companion overlay.
