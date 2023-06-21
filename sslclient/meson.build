
conf_data = configuration_data()


chai_client_includes = include_directories(['../include','../thirdparty/stdexec/include'])



executable(
  'chai_sslclient',
  'main.cpp',
  include_directories: chai_client_includes,
  dependencies:openssl_dep,
  install: true,
  install_dir: get_option('bindir'))