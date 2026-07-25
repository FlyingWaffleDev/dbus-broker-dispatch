test_config_policy = executable(
  'test-config-policy',
  ['test-config-policy.c', '../src/config-policy.c', '../src/policy-export.c', '../src/nss-cache.c'],
  dependencies: deps,
  include_directories: [src_inc, root_inc],
)
test('config-policy', test_config_policy)

test_nss_cache = executable(
  'test-nss-cache',
  ['test-nss-cache.c', '../src/nss-cache.c'],
  dependencies: [glib, gio],
  include_directories: src_inc,
)
test('nss-cache', test_nss_cache)

test_file_watch = executable(
  'test-file-watch',
  ['test-file-watch.c', '../src/file-watch.c'],
  dependencies: [glib, gio],
  include_directories: src_inc,
)
test('file-watch', test_file_watch, timeout: 10)

test_service = executable(
  'test-service',
  ['test-service.c', '../src/service.c', '../src/nss-cache.c'],
  dependencies: [glib, gio],
  include_directories: src_inc,
)
test('service', test_service)

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

if pam.found()
  test_pam_session = executable(
    'test-pam-session',
    'test-pam-session.c',
    dependencies: [glib, gio, pam],
  )
  test(
    'pam-session',
    test_pam_session,
    args: [pam_dbus_broker_dispatch.full_path(), dbus_broker_dispatch.full_path()],
    timeout: 30,
  )
endif
