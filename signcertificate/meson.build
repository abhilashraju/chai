
conf_data = configuration_data()
signcert_includes = include_directories(['../include'])

executable(
  'signcert',
  'main.cpp',
  include_directories: signcert_includes,
  dependencies:openssl_dep,
  install: true,
  install_dir: get_option('bindir'))

