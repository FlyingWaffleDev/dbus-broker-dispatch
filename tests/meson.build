test_native = executable(
  'test-native',
  [
    'test-native.c',
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
)
test('native', test_native)

test_session_bus = executable(
  'test-session-bus',
  ['test-session-bus.c', '../src/util.c', '../src/log.c', '../src/dbus-wire.c', '../src/dbus-transport.c'],
  include_directories: src_inc,
)
test('session-bus', test_session_bus, args: [dbus_broker_dispatch.full_path()], depends: [dbus_broker_dispatch], timeout: 30)

test_run_session = executable('test-run-session', 'test-run-session.c')
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
