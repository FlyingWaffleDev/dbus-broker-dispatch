# dbus-broker-dispatch

[![CI](https://github.com/FlyingWaffleDev/dbus-broker-dispatch/actions/workflows/ci.yml/badge.svg)](https://github.com/FlyingWaffleDev/dbus-broker-dispatch/actions/workflows/ci.yml)

`dbus-broker-dispatch` runs [`dbus-broker`](https://github.com/bus1/dbus-broker)
without systemd. It opens the public Unix socket, starts an unprivileged broker,
loads standard D-Bus XML policy, activates services, and reloads configuration.
It works with any supervisor and does not depend on a particular service
manager.

Service definitions for OpenRC, s6, Dinit, and runit are in [`init`](init/).
Packagers can install the definitions for their target init system.

This project is experimental and was developed with substantial assistance from 
AI coding agents. The implementation has been manually reviewed, tested under 
sanitizers, exercised through automated tests, and is now running as the system 
and session D-Bus controller on a Gentoo/OpenRC KDE workstation (my desktop PC).
Independent review, particularly of security-sensitive and compatibility-sensitive 
behavior, is strongly encouraged. What started as "Hey, I heard AI has gotten good. 
I wonder if that's actually true.", quickly became this fully working product. 
From the beginning I have worked to ensure that everything is functional, starting 
with testing in a QEMU VM from boot, through SDDM, into KDE. The runit, dinit, and 
s6 integrations are untested, but follow upstream documentation and have simulated 
tests. I want to make this software actually useful and usable, so please try it out.

For those who want to give it a go, I have made a Gentoo ebuild available in my
[`waffle-builds`](https://github.com/FlyingWaffleDev/waffle-builds) overlay, along with a compatibility patched `at-spi2-core`.

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

`--scope` is required. Backgrounding follows `dbus-daemon`: the dispatcher stays
in the foreground unless the configuration carries `<fork/>` or `--fork` is
given, and `--foreground` overrides both. Use `dbus-broker-dispatch --help` for
the full option list.

In the foreground the dispatcher writes diagnostics to standard error. In the
background it writes them to syslog, because standard error is `/dev/null`
there. Check the system log when a backgrounded dispatcher misbehaves.

Supervisors can pass `--foreground --ready-fd=FD`, where FD is an inherited,
connected Unix stream socket numbered 3 or higher. The dispatcher sends one
byte, `R`, after configuring the broker and listener, or `F` on startup failure,
then closes the descriptor. EOF without `R` also means startup failed.
The descriptor is not inherited by executed brokers or activated services.
This private handshake distinguishes the new dispatcher from an existing bus
at the same public address. The supervisor should enforce its own startup
deadline.

Starting a second dispatcher on a socket that is already served fails without
disturbing the running one. The dispatcher removes only the socket and PID file
it created itself.

The default config files are `/usr/share/dbus-1/system.conf` and
`/usr/share/dbus-1/session.conf`. The default sockets are
`/run/dbus/system_bus_socket` and `$XDG_RUNTIME_DIR/bus`.

To run one command on a temporary user bus:

```sh
dbus-broker-run-session -- command arg...
```

The wrapper creates a private temporary bus beneath `XDG_RUNTIME_DIR`, even
when a user bus already exists. It sets `DBUS_SESSION_BUS_ADDRESS` for the
command and leaves `XDG_RUNTIME_DIR` unchanged. Nested invocations each get
their own bus. The wrapper returns the command's exit status and removes its
socket and temporary directory when the command exits.

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

For login-shell startup without PAM, see the [init setup instructions](init/README.md).
OpenRC, runit, Dinit, and s6 each have a profile fallback that starts the user
service and publishes its address. The non-OpenRC fallbacks require an
already-configured user supervisor.

## Known limits

- The dispatcher accepts only filesystem-backed `unix:path=` listeners. It
  rejects abstract sockets and non-Unix transports.
- Container policy and several limits used only by `dbus-daemon` are not
  implemented. The dispatcher supports `max_outgoing_bytes`,
  `max_outgoing_unix_fds`, `max_connections_per_user`, and
  `max_match_rules_per_connection`.
- Policy rules whose only condition is `send_requested_reply` or
  `receive_requested_reply` are ignored with a warning. `dbus-broker` tracks
  expected replies itself, so there is nothing left for such a rule to match
  narrowly.

## License

Licensed GPLv3 to match dbus-broker.