
conf_data = configuration_data()


chai_client_includes = include_directories(['../include','../thirdparty/stdexec/include'])



executable(
  'chai_client',
  'main.cpp',
  include_directories: chai_client_includes,
  dependencies: [
  ],
  install: true,
  install_dir: get_option('bindir'))