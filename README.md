# dbus-broker-dispatch

`dbus-broker-dispatch` runs [`dbus-broker`](https://github.com/bus1/dbus-broker)
without systemd. It opens the public Unix socket, starts an unprivileged broker,
loads standard D-Bus XML policy, activates services, and reloads configuration.
It works with any supervisor and does not depend on a particular service
manager.

Service definitions for OpenRC, s6, Dinit, and runit are in [`init`](init/).
Packagers can install the definitions for their target init system.

This is pre-release software. Test it on a disposable system before replacing
the system bus or your main desktop session bus.

## What it supports

- System and user buses on filesystem-backed `unix:path=` sockets
- Standard D-Bus policy for users, groups, mandatory rules, `at_console`, and
  `no_console`
- The standard service-directory search order and direct `Exec=` activation
  without a shell
- System service users, cleared supplementary groups, activation environment
  updates, and `DBUS_STARTER_*` variables
- Transactional reloads from SIGHUP, the broker reload API, or watched config
  and service directories
- Broker quotas derived from the four D-Bus limits that `dbus-broker` uses
- Optional elogind monitoring for console-sensitive policy
- AppArmor detection and the `enabled`, `disabled`, and `required` config modes
- SELinux name associations and optional SELinux-aware config includes
- A fixed NSS identity snapshot for each config generation
- Custom bus types and optimized policy batches
- `dbus-broker-run-session`, an isolated user-bus wrapper
- An optional PAM module for systems without a per-user service manager

`SystemdService=` does not make this project start a systemd unit. If a service
file also has `Exec=`, the dispatcher uses that command. It does not register a
service file that has only `SystemdService=`.

## Requirements

The dispatcher uses libc and Linux interfaces for D-Bus authentication, wire
encoding, Unix file descriptor transport, process supervision, file watching,
and service activation. Expat is the only required library. Elogind, Linux-PAM,
and libselinux are optional.

## Build and test

```sh
meson setup build --buildtype=release
meson compile -C build
meson test -C build --print-errorlogs
```

Meson detects the PAM and SELinux dependencies by default. The relevant build
options are:

- `-Dpam=enabled` or `-Dpam=disabled` requires or disables the PAM module.
- `-Dpam-module-dir=/lib64/security` changes its install directory.
- `-Delogind=true` enables live console-policy updates.
- `-Dsystem-console-users=root,rescue` always treats the listed users as
  `at_console`.
- `-Dselinux=enabled` or `-Dselinux=disabled` requires or disables SELinux-aware
  config includes.

The dispatcher exports SELinux `<associate>` mappings even without libselinux.
It needs libselinux only to query the active policy and its root.

For an AddressSanitizer and UndefinedBehaviorSanitizer build:

```sh
meson setup build-asan --buildtype=debugoptimized \
  -Db_sanitize=address,undefined -Dwarning_level=3
meson test -C build-asan --print-errorlogs
```

## Run the dispatcher

Under a supervisor, keep the dispatcher in the foreground:

```sh
dbus-broker-dispatch --scope=system --foreground
dbus-broker-dispatch --scope=user --foreground
```

`--scope` is required. Without `--foreground`, the dispatcher forks into the
background. Use `dbus-broker-dispatch --help` for the full option list.

The default config files are `/usr/share/dbus-1/system.conf` and
`/usr/share/dbus-1/session.conf`. The default sockets are
`/run/dbus/system_bus_socket` and `$XDG_RUNTIME_DIR/bus`.

To run one command on a temporary user bus:

```sh
dbus-broker-run-session -- command arg...
```

The wrapper returns the command's exit status and removes the bus when the
command exits.

## Start user buses from PAM

`pam_dbus_broker_dispatch.so` is for systems without a per-user service
manager. Add it after the module that creates `XDG_RUNTIME_DIR`, usually
`pam_elogind.so`:

```text
-session optional pam_dbus_broker_dispatch.so
```

When a PAM session opens, the module checks that `XDG_RUNTIME_DIR` is an
absolute, user-owned `0700` directory. It serializes concurrent starts, runs a
user-scope dispatcher with the user's credentials, and adds
`DBUS_SESSION_BUS_ADDRESS` to the PAM environment. Sessions for the same user
share one module-owned bus. The last session to close stops it.

If another integration already owns a live bus, the module reuses it but does
not stop it. The module never creates or changes ownership of a runtime
directory. A missing runtime directory returns `PAM_IGNORE`, which makes module
ordering important.

Keep the module optional during initial testing so a bus failure cannot block
login. Add it only to session stacks whose processes need a user bus.

The accepted module arguments are `debug`, `dispatcher=/absolute/path`, and
`config-file=/absolute/path`. The path overrides are for development or
controlled deployments. Installed systems normally need no arguments.

## Known limits

- The dispatcher accepts only filesystem-backed `unix:path=` listeners. It
  rejects abstract sockets and non-Unix transports.
- Container policy and several limits used only by `dbus-daemon` are not
  implemented. The dispatcher supports `max_outgoing_bytes`,
  `max_outgoing_unix_fds`, `max_connections_per_user`, and
  `max_match_rules_per_connection`.

The companion overlay still contains placeholder repository URLs. Replace them
before publishing a release.
