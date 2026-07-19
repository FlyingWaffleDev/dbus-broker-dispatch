project('dbus-broker-openrc-launcher', 'c', version: '0.1.0',
        default_options: ['c_std=c11', 'warning_level=2'])

glib = dependency('glib-2.0', version: '>= 2.56')
gio = dependency('gio-2.0')
gio_unix = dependency('gio-unix-2.0')
expat = dependency('expat')
conf = configuration_data()
conf.set_quoted('DEFAULT_BROKER', get_option('prefix') / get_option('libexecdir') / 'dbus-broker')
conf.set_quoted('SYSTEM_CONSOLE_USERS', ','.join(get_option('system-console-users')))
if get_option('elogind')
  elogind = dependency('libelogind', required: true)
  conf.set('HAVE_ELOGIND', 1)
else
  elogind = disabler()
endif
configure_file(output: 'config.h', configuration: conf)

deps = [glib, gio, gio_unix, expat]
if get_option('elogind')
  deps += elogind
endif
dbus_broker_openrc_launch = executable('dbus-broker-openrc-launch', ['src/launcher.c', 'src/config-policy.c'], dependencies: deps, install: true)
executable('dbus-broker-openrc-run-session', 'src/run-session.c', dependencies: [glib], install: true)

test_config_policy = executable('test-config-policy', ['src/test-config-policy.c', 'src/config-policy.c'], dependencies: deps)
test('config-policy', test_config_policy)
test_session_bus = executable('test-session-bus', 'src/test-session-bus.c', dependencies: [glib, gio])
test('session-bus', test_session_bus, args: [dbus_broker_openrc_launch.full_path()])
