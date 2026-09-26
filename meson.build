project('dbus-broker-dispatch', 'c', version: '0.1.0', license: 'GPL-3.0-or-later',
        default_options: ['c_std=c11', 'warning_level=3'])

expat = dependency('expat')
selinux = dependency('libselinux', required: get_option('selinux'))
elogind = dependency('libelogind', required: get_option('elogind'))
broker = get_option('broker')
if broker == ''
  broker = get_option('prefix') / get_option('bindir') / 'dbus-broker'
endif
conf = configuration_data()
conf.set_quoted('PROJECT_VERSION', meson.project_version())
conf.set_quoted('DEFAULT_BROKER', broker)
conf.set_quoted('DEFAULT_DISPATCHER', get_option('prefix') / get_option('bindir') / 'dbus-broker-dispatch')
conf.set_quoted('SYSTEM_CONSOLE_USERS', ','.join(get_option('system-console-users')))
if elogind.found()
  conf.set('HAVE_ELOGIND', 1)
endif
if selinux.found()
  conf.set('HAVE_SELINUX', 1)
endif
configure_file(output: 'config.h', configuration: conf)

deps = [expat]
if selinux.found()
  deps += selinux
endif
if elogind.found()
  deps += elogind
endif
src_inc = include_directories('src')
root_inc = include_directories('.')
dispatcher_sources = files(
    'src/util.c',
    'src/log.c',
    'src/address.c',
    'src/process.c',
    'src/service-file.c',
    'src/dbus-wire.c',
    'src/dbus-transport.c',
    'src/controller.c',
    'src/event.c',
    'src/watch.c',
    'src/launcher.c',
    'src/config-policy.c',
    'src/policy-wire.c',
    'src/nss-cache.c',
    'src/service.c',
)
dbus_broker_dispatch = executable(
  'dbus-broker-dispatch',
  dispatcher_sources,
  dependencies: deps,
  include_directories: src_inc,
  install: true,
)

dbus_broker_run_session = executable(
  'dbus-broker-run-session',
  ['src/run-session.c', 'src/address.c', 'src/process.c', 'src/util.c'],
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
