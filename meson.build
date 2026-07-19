project('openrc-broker-launcher', 'c', version: '0.1.0',
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
executable('dbus-broker-openrc-launch', 'src/launcher.c', dependencies: deps, install: true)
executable('dbus-broker-openrc-run-session', 'src/run-session.c', dependencies: [glib], install: true)
install_data('openrc/dbus', install_dir: get_option('libdir') / 'openrc' / 'init.d')
install_data('README.md', install_dir: get_option('datadir') / 'doc' / 'openrc-broker-launcher')
