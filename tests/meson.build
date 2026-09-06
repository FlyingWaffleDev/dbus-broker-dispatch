nss_wrap_args = ['-Wl,--wrap=nss_cache_lookup_uid', '-Wl,--wrap=nss_cache_lookup_gid']

test_native = executable(
  'test-native',
  [
    'test-native.c',
    'nss-failure-inject.c',
    '../src/util.c',
    '../src/log.c',
    '../src/address.c',
    '../src/process.c',
    '../src/service-file.c',
    '../src/dbus-wire.c',
    '../src/dbus-transport.c',
    '../src/controller.c',
    '../src/event.c',
    '../src/watch.c',
    '../src/config-policy.c',
    '../src/policy-wire.c',
    '../src/nss-cache.c',
    '../src/service.c',
  ],
  dependencies: deps,
  include_directories: [src_inc, root_inc],
  link_args: nss_wrap_args,
)
test('native', test_native)

test_session_bus = executable(
  'test-session-bus',
  ['test-session-bus.c', '../src/util.c', '../src/log.c', '../src/dbus-wire.c', '../src/dbus-transport.c'],
  include_directories: src_inc,
)
test('session-bus', test_session_bus, args: [dbus_broker_dispatch.full_path()], depends: [dbus_broker_dispatch], timeout: 30)

test_startup = executable('test-startup', 'test-startup.c')
test('startup', test_startup, args: [dbus_broker_dispatch.full_path()], depends: [dbus_broker_dispatch], timeout: 15)

test_run_session = executable(
  'test-run-session',
  ['test-run-session.c', '../src/address.c', '../src/util.c', '../src/log.c', '../src/dbus-wire.c', '../src/dbus-transport.c'],
  include_directories: src_inc,
)
test(
  'run-session',
  test_run_session,
  args: [dbus_broker_run_session.full_path(), dbus_broker_dispatch.full_path()],
  depends: [dbus_broker_run_session, dbus_broker_dispatch],
  timeout: 30,
)

if pam.found()
  test_pam_session = executable('test-pam-session', 'test-pam-session.c', dependencies: pam)
  test(
    'pam-session',
    test_pam_session,
    args: [pam_dbus_broker_dispatch.full_path(), dbus_broker_dispatch.full_path()],
    depends: [pam_dbus_broker_dispatch, dbus_broker_dispatch],
    timeout: 30,
  )
endif

# Fault injection is linked only into this test dispatcher, never the installed one.
test_nss_dispatcher = executable(
  'test-nss-dispatcher',
  dispatcher_sources + files('nss-failure-inject.c'),
  dependencies: deps,
  include_directories: [src_inc, root_inc],
  link_args: nss_wrap_args,
)
test_policy_reload = executable(
  'test-policy-reload',
  ['test-policy-reload.c', '../src/util.c', '../src/log.c', '../src/dbus-wire.c', '../src/dbus-transport.c'],
  include_directories: src_inc,
)
test(
  'policy-reload',
  test_policy_reload,
  args: [test_nss_dispatcher.full_path()],
  depends: [test_nss_dispatcher],
  timeout: 30,
)

# The login profile hooks are shell, not compiled. Exercise them against mock
# service managers so they never touch the host's buses or init system.
python = find_program('python3', required: false)
if python.found()
  test('init-profile', python, args: [files('test-init-profile.py')], timeout: 120)
endif
