// Server side C/C++ program to demonstrate unifex based chat server
// programming

#include "chai_ssl_sock.hpp"

#include <chai.hpp>
#include <exec/static_thread_pool.hpp>
#define PORT 8089
#include <iostream>
using namespace chai;

int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  bool broad_cast = (argc > 1)
                        ? ((argv[1] == std::string("broadcast")) ? true : false)
                        : true;
  const char *servcert =
      "/home/abhilash/work/chai/certs/server-certificate.pem";
  const char *servkey = "/home/abhilash/work/chai/certs/server-private-key.pem";

  if (argc > 2) {
    servcert = argv[1];
    servkey = argv[2];
  }

  try {
    exec::static_thread_pool context;
    initSsl();
    auto sslctx = ssl_server_sock::getServerContext(servcert, servkey,
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
