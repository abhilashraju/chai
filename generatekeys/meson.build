
conf_data = configuration_data()
createcert_includes = include_directories(['../include'])

executable(
  'generatekeys',
  'main.cpp',
  include_directories: createcert_includes,
  dependencies:openssl_dep,
  install: true,
  install_dir: get_option('bindir'))

