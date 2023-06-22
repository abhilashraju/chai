#pragma once
#include "chaisock.hpp"
#include "sslerrors.hpp"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
namespace chai {
template <class T> struct DeleterOf;
template <> struct DeleterOf<BIO> {
  void operator()(BIO *p) const { BIO_free_all(p); }
};
template <> struct DeleterOf<BIO_METHOD> {
  void operator()(BIO_METHOD *p) const { BIO_meth_free(p); }
};
template <> struct DeleterOf<SSL_CTX> {
  void operator()(SSL_CTX *p) const { SSL_CTX_free(p); }
};
template <> struct DeleterOf<SSL> {
  void operator()(SSL *p) const { SSL_free(p); }
};

template <class OpenSSLType>
using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;
inline void initSsl() {
  SSL_library_init();
  SSL_load_error_strings();
  // ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
}
inline SSlErrors execute(int result, SSL *ssl) {
  if (result <= 0) {
    return SSlErrors(SSL_get_error(ssl, result));
  }
  return SSlErrors::None;
}

template <typename Derived> struct ssl_sock_base {
  Derived &self() { return static_cast<Derived &>(*this); }
  const Derived &self() const { return static_cast<const Derived &>(*this); }
  template <typename Buffer> int read_all(Buffer &buffer) {
    return read(*this, buffer);
  }
  template <typename Buffer>
  friend int read(ssl_sock_base &stream, Buffer &buff) {
    auto r = readssl(stream, buff);
    if (r.second == SSlErrors::WantRead) {
      return 1;
    }
    return r.first;
  }

  template <typename Buffer>
  friend auto readssl(ssl_sock_base &stream, Buffer &buff) {
    constexpr int MAXSIZE = 1024;
    auto readsofar = 0;
    SSlErrors r = SSlErrors::None;
    while (true) {
      size_t read = 0;
      r = execute(SSL_read_ex(stream.self().ssl(), buff.prepare(MAXSIZE),
                              MAXSIZE, &read),
                  stream.self().ssl());
      if (r != SSlErrors::None && r != SSlErrors::WantRead) {
        throw socket_exception(reason(r) + std::string(strerror(errno)));
      }
      if (read == 0 && r != SSlErrors::WantRead) {
        stream.self().base().set_eof(true);
        return std::make_pair(readsofar, r);
      }
      readsofar += read;
      buff.commit(read);
      if (read < MAXSIZE) {
        break;
      }
    }
    return std::make_pair(readsofar, r);
  }
  auto readsome(char *buff, int size) {
    size_t read = 0;
    auto r =
        execute(SSL_read_ex(self().ssl(), buff, size, &read), self().ssl());
    if (r != SSlErrors::None && r != SSlErrors::WantRead) {
      throw socket_exception(reason(r));
    }
    if (read == 0 && r != SSlErrors::WantRead) {
      self().base().set_eof(true);
    }
    return std::make_pair(read, r);
  }
  template <typename Buffer>
  friend auto send(const ssl_sock_base &stream, Buffer buff) {
    size_t written = 0;
    auto r = execute(SSL_write_ex(stream.self().ssl(), buff.data(),
                                  buff.read_length(), &written),
                     stream.self().ssl());
    if (r != SSlErrors::None && r != SSlErrors::WantWrite) {
      throw socket_exception(reason(r));
    }
    return std::make_pair(written, r);
  }
};
struct ssl_client_sock : ssl_sock_base<ssl_client_sock> {
  sock_base base_;
  UniquePtr<SSL_CTX> ctx_;
  UniquePtr<SSL> ssl_;
  ssl_client_sock(sock_base b) : base_(std::move(b)) {
    ctx_.reset(SSL_CTX_new(SSLv23_client_method()));
    // if(!SSL_CTX_load_verify_locations(ctx.get(),"path/to/truststore.pem",nullptr))
    // {
    //     // Handle error loading trust store
    // }
    ssl_.reset(SSL_new(ctx_.get()));
    SSL_set_fd(ssl(), base_.fd());
  }
  ssl_client_sock(const ssl_client_sock &) = delete;
  ssl_client_sock(ssl_client_sock &&) = default;
  ~ssl_client_sock() {
    if (ssl())
      SSL_shutdown(ssl());
  }
  SSlErrors startHandShake() { return execute(SSL_connect(ssl()), ssl()); }
  SSL *ssl() const { return ssl_.get(); }
  sock_base &base() { return base_; }
  auto &fd() { return base().fd(); }
};
struct ssl_server_sock : ssl_sock_base<ssl_server_sock> {
  sock_base base_;
  SSL_CTX *ctx_;
  UniquePtr<SSL> ssl_;
  ssl_server_sock(sock_base b, SSL_CTX *c) : base_(std::move(b)), ctx_(c) {
    // if(!SSL_CTX_load_verify_locations(ctx.get(),"path/to/truststore.pem",nullptr))
    // {
    //     // Handle error loading trust store
    // }
    ssl_.reset(SSL_new(ctx_));
    SSL_set_fd(ssl(), base_.fd());
  }
  ~ssl_server_sock() { SSL_shutdown(ssl()); }
  SSlErrors startHandShake() {
    if (int r = SSL_accept(ssl()); r <= 0) {
      return SSlErrors(SSL_get_error(ssl(), r));
    }
    return SSlErrors::None;
  }
  SSL *ssl() const { return ssl_.get(); }
  sock_base &base() { return base_; }
  auto &fd() { return base().fd(); }

public:
  static SSL_CTX *getServerContext(const std::string &cert,
                                   const std::string &privk,
                                   const std::string &truststr) {
    static UniquePtr<SSL_CTX> ctx(makeContext(cert, privk, truststr));
    return ctx.get();
  }

private:
  static SSL_CTX *makeContext(const std::string &cert, const std::string &privk,
                              const std::string &truststr) {
    auto ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_use_certificate_file(ctx, cert.data(), SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, privk.data(), SSL_FILETYPE_PEM);
    // if (!SSL_CTX_load_verify_locations(ctx, truststr.data(),
    // nullptr)) {
    //     // Handle error loading trust store
    // }
    return ctx;
  }
};

} // namespace chai
