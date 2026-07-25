project('dbus-broker-dispatch', 'c', version: '0.1.0',
        default_options: ['c_std=c11', 'warning_level=3'])

glib = dependency('glib-2.0', version: '>= 2.56')
gio = dependency('gio-2.0')
gio_unix = dependency('gio-unix-2.0')
expat = dependency('expat')
selinux = dependency('libselinux', required: get_option('selinux'))
conf = configuration_data()
conf.set_quoted('PROJECT_VERSION', meson.project_version())
conf.set_quoted('DEFAULT_BROKER', get_option('prefix') / get_option('libexecdir') / 'dbus-broker')
conf.set_quoted('DEFAULT_DISPATCHER', get_option('prefix') / get_option('bindir') / 'dbus-broker-dispatch')
conf.set_quoted('SYSTEM_CONSOLE_USERS', ','.join(get_option('system-console-users')))
if get_option('elogind')
  elogind = dependency('libelogind', required: true)
  conf.set('HAVE_ELOGIND', 1)
else
  elogind = disabler()
endif
if selinux.found()
  conf.set('HAVE_SELINUX', 1)
endif
configure_file(output: 'config.h', configuration: conf)

deps = [glib, gio, gio_unix, expat]
if selinux.found()
  deps += selinux
endif
if get_option('elogind')
  deps += elogind
endif
src_inc = include_directories('src')
root_inc = include_directories('.')
dbus_broker_dispatch = executable(
  'dbus-broker-dispatch',
  [
    'src/launcher.c',
    'src/config-policy.c',
    'src/policy-export.c',
    'src/nss-cache.c',
    'src/file-watch.c',
    'src/service.c',
  ],
  dependencies: deps,
  include_directories: src_inc,
  install: true,
)

dbus_broker_run_session = executable(
  'dbus-broker-run-session',
  'src/run-session.c',
  dependencies: [glib],
  include_directories: src_inc,
  install: true,
)

pam = dependency('pam', required: get_option('pam'))
if pam.found()
  pam_module_dir = get_option('pam-module-dir')
  if pam_module_dir == ''
    pam_module_dir = get_option('prefix') / get_option('libdir') / 'security'
  endif
  pam_dbus_broker_dispatch = shared_module(
    'pam_dbus_broker_dispatch',
    'src/pam-dbus-broker-dispatch.c',
    name_prefix: '',
    dependencies: [pam],
    include_directories: src_inc,
    install: true,
    install_dir: pam_module_dir,
  )
endif

subdir('tests')
