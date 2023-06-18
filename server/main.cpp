// Server side C/C++ program to demonstrate unifex based chat server
// programming

#include <chai.hpp>
#include <exec/static_thread_pool.hpp>
#define PORT 8089

using namespace chai;

int main(int argc, char const* argv[]) {
  (void)argc;
  (void)argv;
  bool broad_cast = (argc > 1)
      ? ((argv[1] == std::string("broadcast")) ? true : false)
      : true;
  try {
    exec::static_thread_pool context;

    if (broad_cast) {
      stdexec::sync_wait(
          make_listener("127.0.0.1", PORT) |
          process_clients(
              context, broadcast_handler([](auto buff) { return buff; })));

    } else {
      stdexec::sync_wait(
          make_listener("127.0.0.1", PORT) |
          process_clients(
              context, peer_to_peer_handler([](auto buff) { return buff; })));
    }

  } catch (std::exception& e) {
    printf("%s", e.what());
  }

  return 0;
}
