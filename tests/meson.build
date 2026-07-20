test_config_policy = executable(
  'test-config-policy',
  ['test-config-policy.c', '../src/config-policy.c'],
  dependencies: deps,
  include_directories: src_inc,
)
test('config-policy', test_config_policy)

test_session_bus = executable(
  'test-session-bus',
  'test-session-bus.c',
  dependencies: [glib, gio],
  include_directories: src_inc,
)
test(
  'session-bus',
  test_session_bus,
  args: [dbus_broker_dispatch.full_path()],
  timeout: 30,
)

test_run_session = executable(
  'test-run-session',
  'test-run-session.c',
  dependencies: [glib],
)
test(
  'run-session',
  test_run_session,
  args: [
    dbus_broker_run_session.full_path(),
    dbus_broker_dispatch.full_path(),
  ],
  timeout: 30,
)
