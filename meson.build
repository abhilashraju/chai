project(
  'chai',
  'cpp',
  version: '0.1',
  meson_version: '>=0.58.0',
  default_options: [
    'warning_level=3',
    'cpp_std=c++20',
  ])
openssl_dep = dependency('openssl', version: '>=1.1.1')
subdir('client')
subdir('server')
subdir('sslserver')