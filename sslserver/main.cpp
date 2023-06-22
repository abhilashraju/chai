// Server side C/C++ program to demonstrate unifex based chat server
// programming

#include "chai_ssl_sock.hpp"

#include <chai.hpp>
#include <exec/static_thread_pool.hpp>
#define PORT 8089
#include <iostream>
using namespace chai;
template <typename Handler>
struct broadcast_ssl_handler : broadcast_handler<Handler, ssl_server_sock> {
  using BASE_TYPE = broadcast_handler<Handler, ssl_server_sock>;
  SSL_CTX *sslCtx{nullptr};
  auto spawn(auto &scope, auto &context, auto newsock) const {
    std::unique_ptr<ssl_server_sock> clientsock(
        new ssl_server_sock(std::move(newsock), sslCtx));
    set_blocked(clientsock->base(), false);
    if (auto err = clientsock->startHandShake(); err != SSlErrors::None) {
      if (err != SSlErrors::WantRead && err != SSlErrors::WantWrite &&
          err != SSlErrors::WantConnect && err != SSlErrors::WantAccept) {
        std::cout << "HandShake Error " << reason(err);
        return;
      }
    }
    BASE_TYPE::getClientList().add_client(clientsock.release());
  }

  auto handle_read(int fd) const {
    auto sock = BASE_TYPE::getClientList().find(fd);
    if (sock) {
      std::string str;
      string_buffer buf(str);
      auto n = readssl(*sock.value(), buf);
      if (n.second == SSlErrors::None && n.first == 0) {
        BASE_TYPE::getClientList().remove_client(sock.value());
        return false; // socket closed by remote
      }
      if (n.first > 0) {
        BASE_TYPE::getClientList().broadcast(BASE_TYPE::request_handler(buf));
      }
    }
    return true;
  }
  broadcast_ssl_handler(SSL_CTX *c, Handler &&handler)
      : BASE_TYPE(std::forward<Handler>(handler)), sslCtx(c) {}
  broadcast_ssl_handler(const broadcast_ssl_handler &) = delete;
  broadcast_ssl_handler(broadcast_ssl_handler &&other)
      : BASE_TYPE(std::move(other)) {
    sslCtx = std::move(other.sslCtx);
  }
  broadcast_ssl_handler &operator=(const broadcast_ssl_handler &) = delete;
  broadcast_ssl_handler &operator=(broadcast_ssl_handler &&) = delete;
};
int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  bool broad_cast = (argc > 1)
                        ? ((argv[1] == std::string("broadcast")) ? true : false)
                        : true;
  try {
    exec::static_thread_pool context;
    initSsl();
    auto sslctx = ssl_server_sock::getServerContext(
        "/home/abhilash/work/chai/certs/server-certificate.pem",
        "/home/abhilash/work/chai/certs/server-private-key.pem",
        "path/to/truststore.pem");
    if (broad_cast) {
      stdexec::sync_wait(
          make_listener("127.0.0.1", PORT) |
          process_clients(context, broadcast_ssl_handler(sslctx, [](auto buff) {
                            return buff;
                          })));
    } else {
      stdexec::sync_wait(
          make_listener("127.0.0.1", PORT) |
          process_clients(
              context, peer_to_peer_handler([](auto buff) { return buff; })));
    }
  } catch (std::exception &e) {
    printf("%s", e.what());
  }

  return 0;
}
