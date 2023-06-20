
conf_data = configuration_data()
chi_server_includes = include_directories(['../include','../thirdparty/stdexec/include'])

executable(
  'chai_server',
  'main.cpp',
  include_directories: chi_server_includes,
  dependencies: [
  ],
  install: true,
  install_dir: get_option('bindir'))

