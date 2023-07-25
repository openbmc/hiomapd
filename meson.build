project(
  'hiomapd',
  'c', 'cpp',
  version: '1.0',
  default_options: [
    'buildtype=debugoptimized',
    'cpp_std=c++23',
    'warning_level=3',
    'werror=true',
  ],
  meson_version: '>=1.1.1',
)

# GCC doesn't allow VLAs when compiled with "-Wpedantic" but some of the
# shared C/C++ headers leverage them.  Turn off "-Wpedantic" for C++.
add_project_arguments('-Wno-pedantic', language: 'cpp')

conf_data = configuration_data()
conf_data.set_quoted('PACKAGE_VERSION', meson.project_version())
if get_option('vpnor').allowed()
  conf_data.set('VIRTUAL_PNOR_ENABLED', 1)
  conf_data.set_quoted('PARTITION_TOC_FILE', 'pnor.toc')
  conf_data.set_quoted('PARTITION_FILES_RO_LOC', '/var/lib/phosphor-software-manager/pnor/ro')
  conf_data.set_quoted('PARTITION_FILES_RW_LOC', '/var/lib/phosphor-software-manager/pnor/rw')
  conf_data.set_quoted('PARTITION_FILES_PRSV_LOC', '/var/lib/phosphor-software-manager/pnor/prsv')
  conf_data.set_quoted('PARTITION_FILES_PATCH_LOC', '/usr/local/share/pnor')
endif
configure_file(
  output: 'config.h',
  configuration: conf_data,
)

libsystemd_dep = dependency('libsystemd')

mboxd_sources = files(
  'common.c',
  'control.c',
  'control_dbus.c',
  'control_legacy.c',
  'lpc.c',
  'mtd.c',
  'protocol.c',
  'transport_dbus.c',
  'windows.c',
  'file/backend.c',
  'mtd/backend.c',
)

mboxd_deps = [
  libsystemd_dep,
]

if get_option('vpnor').allowed()
  subdir('vpnor')
endif

mboxd_lib = static_library(
  'mboxd-lib',
  mboxd_sources,
  dependencies: mboxd_deps,
)

mboxd_dep = declare_dependency(
  link_with: mboxd_lib,
  dependencies: mboxd_deps,
)

executable(
  'mboxd',
  'mboxd.c',
  mboxd_sources,
  dependencies: mboxd_dep,
  install: true,
  install_dir: get_option('sbindir')
)

executable(
  'mboxctl',
  'mboxctl.c',
  dependencies: [
    libsystemd_dep,
  ],
  install: true,
  install_dir: get_option('sbindir')
)

if get_option('tests').allowed()
  subdir('test')
  if get_option('vpnor').allowed()
    subdir('vpnor/test')
  endif
endif
