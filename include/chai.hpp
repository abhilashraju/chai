#pragma once
#include "chaisock.hpp"
#include "buffer.hpp"
#include "errors.hpp"
#include "reactor.hpp"
// #include <stdexec/execution.hpp>
// #include <exec/repeat_effect_until.hpp>
#include <sys/select.h>

#include <variant>
#include <sstream>
#include <exec/async_scope.hpp>
#include <exec/repeat_effect_until.hpp>
// #include <exec/retry_when.hpp>
#include <stdexec/execution.hpp>
namespace chai {

inline auto make_listener(auto address, auto port) {
  return stdexec::just()|stdexec::then([=]() {
    sock_base* listener = new sock_base;

    int retries = 0;
    bool connected = false;
    while (!connected && retries < 5) {
      try {
        listener->bind({address, port});
        listen(*listener);
        connected = true;
      } catch (std::exception& e) {
        retries++;
        sleep(10);
      }
    }
    if (!connected) {
      throw std::runtime_error("Not Able to listen . Port may be in use...\n");
    }
    return listener;
  });
}

template <typename Context, typename Handler>
struct handle_clients {
  Context& context;
  Handler handler;
  handle_clients(Context& C, Handler h) : context(C), handler(std::move(h)) {}
  auto get() const {
    return stdexec::then([=](auto l) {
      std::unique_ptr<sock_base> listener(l);
      exec::async_scope scope;
      ConnectionReactor reactor(
          [&](sock_base newconnection) {
            handler.spawn(scope, context, std::move(newconnection));
            
          },
          [&](int fd) { return handler.handle_read(fd); });
      reactor.run(*listener);

      return std::string("Server Started");
    });
  }
  template <typename Sender>
  inline friend auto operator|(Sender&& sender, handle_clients&& clihandler) {
    return sender | clihandler.get();
  }
};
template <typename Context, typename H>
inline auto process_clients(Context& where, H handler) {
  return handle_clients(where, std::move(handler));
}

template <typename Handler>
struct peer_to_peer_handler {
  using Request_Handler = Handler;
  Request_Handler request_handler;
  static constexpr bool broad_casting = false;
  peer_to_peer_handler(Request_Handler handler)
    : request_handler(std::move(handler)) {}
  auto spawn(auto& scope, auto& context, auto newconnection) const {
    scope.spawn(stdexec::on(
        context.get_scheduler(), handleConnection(std::move(newconnection))));
  }
  auto handle_read(int fd) const { return false; }
  auto handleConnection(sock_base newsock) const {
    auto newclient = stdexec::just(new sock_base(std::move(newsock)));
    auto responder = stdexec::then([=](auto newsock) {
      std::unique_ptr<sock_base> sock(newsock);
      try {
        while (true) {
          std::string str;
          string_buffer buf(str);
          int n = read(*sock, buf);
          if (n == 0) {
            throw socket_exception(std::string("EOF"));
          }
          send(*sock, request_handler(buf));
        }
      } catch (std::exception& e) {
        printf("%s", e.what());
      }
    });
    auto session = newclient | responder;
    return session;
  }
};
template <typename T>
inline peer_to_peer_handler<T> make_peer_to_peer_handler(T handler) {
  return peer_to_peer_handler<T>(handler);
}
template <typename Handler>
struct broadcast_handler {
  using Request_Handler = Handler;
  Request_Handler request_handler;
  static constexpr bool broad_casting = true;
  struct ClientList {
    std::vector<std::unique_ptr<sock_base>> clients;
    std::mutex client_mutex;
    void broadcast(auto buf) {
      std::lock_guard<std::mutex> guard(client_mutex);
      for (auto& c : clients) {
        send(*c, buf);
      }
    }
    void add_client(sock_base* client) {
      std::lock_guard<std::mutex> guard(client_mutex);
      clients.emplace_back(client);
    }
    void remove_client(sock_base* client) {
      std::lock_guard<std::mutex> guard(client_mutex);
      clients.erase(
          std::remove_if(std::begin(clients), std::end(clients), [&](auto& e) {
            return e.get() == client;
          }));
    }
    std::optional<sock_base*> find(int fd) {
      std::lock_guard<std::mutex> guard(client_mutex);
      auto const& iter =
          std::find_if(cbegin(clients), cend(clients), [=](const auto& sock) {
            return sock->fd_ == fd;
          });
      if (iter != cend(clients)) {
        return std::optional(iter->get());
      }
      return std::nullopt;
    }
  };
  static auto& getClientList() {
    static ClientList gclient_lists;
    return gclient_lists;
  }

  broadcast_handler(Request_Handler handler)
    : request_handler(std::move(handler)) {}

  auto spawn(auto& scope, auto& context, auto newsock) const {
    getClientList().add_client(new sock_base(std::move(newsock)));
  }
  auto handle_read(int fd) const {
    auto sock = getClientList().find(fd);
    if (sock) {
      std::string str;
      string_buffer buf(str);
      auto n = read(*sock.value(), buf);
      if (n <= 0) {
        getClientList().remove_client(sock.value());
        return false;  // socket closed by remote
      }
      getClientList().broadcast(request_handler(buf));
    }
    return true;
  }
};

template <class... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;
inline auto handle_error(auto... handlers) {
  return stdexec::let_error([=](auto exptr) {
    try {
      std::rethrow_exception(exptr);
    } catch (const std::exception& e) {
      std::variant<std::exception> v(e);
      std::visit(overloaded{handlers...}, v);
    }
    return stdexec::just();
  });
}

inline auto read_data(auto& stream, auto& buff) {
  if (int n; (n = read(stream, buff)) > 0) {
    printf("%s", buff.data());
    return n;
  }
  throw socket_exception("client closed");
}
inline auto write_data(auto& stream, auto& buff) {
  if (int n; (n = send(stream, buff)) > 0) {
    buff.consume(n);
  }
}

inline auto spawn_clients(auto client_agent, auto newconnection, auto do_work) {
  struct async_context {
    ~async_context(){
        // scope->request_stop();
    }
    sock_base stream;
    // stdexec::async_scope* scope{new stdexec::async_scope()};//need to find a way to fix memleak;
    stdexec::in_place_stop_source stop_src;
    std::string v;
    string_buffer buff{v};
    stdexec::in_place_stop_token token{stop_src.get_token()};
    async_context(sock_base conn) : stream(std::move(conn)) {}
  };
  auto context = new async_context(std::move(newconnection));
  auto work =
      stdexec::just(context)|stdexec::then(
          [=](auto context) { return std::unique_ptr<async_context>(context); }) |
      stdexec::let_value([=](auto& context) {
        auto child_work =
            stdexec::just(context.get()) |stdexec::then([](auto contextptr) {
              return read_data(contextptr->stream, contextptr->buff);
            }) |
            stdexec::let_value([=, contextptr = context.get()](auto& len) {
              auto client_work =
                  do_work(contextptr->buff.read_view(), contextptr->stop_src);
              return client_work;
            }) |
            stdexec::let_value([contextptr = context.get()](auto& buff) {
              string_buffer strbuff(buff);
              write_data(contextptr->stream, strbuff);
              contextptr->buff.consume_all();
              return stdexec::just();
            }) |
            exec::repeat_effect_until([contextptr = context.get()]() {
              if (contextptr->token.stop_requested()) {
                close(contextptr->stream);
                throw std::runtime_error("Client Closed");
              }
              return contextptr->token.stop_requested();
            })|
            // exec::retry_when([](std::exception_ptr ex) mutable {
            //   try {
            //     std::rethrow_exception(ex);
            //   } catch (application_error& error) {
            //   }
            //   return stdexec::just();
            // }) |
            handle_error([contextptr = context.get()](auto& v) {
              //    contextptr->stop_src.request_stop();
              printf("client closed\n");
              close(contextptr->stream);
//              exec::sync_wait(contextptr->scope.cleanup());
            });
        return child_work;
      });

  context->scope->spawn_on(client_agent, work);
}
inline auto spawn_http_clients(auto client_agent, auto newconnection, auto do_work) {
  struct async_context {
    ~async_context(){
        scope->request_stop();
    }
    sock_stream<std::stringstream> stream;
    exec::async_scope* scope{new exec::async_scope()};//need to find a way to fix memleak;
    stdexec::in_place_stop_source stop_src;
    stdexec::in_place_stop_token token{stop_src.get_token()};
    async_context(sock_base conn) : stream(std::move(conn)) {}
  };
  auto context = new async_context(std::move(newconnection));
  auto work =
      stdexec::just(std::unique_ptr<async_context>(context)) |
      stdexec::let_value([=](auto& context) {
        auto child_work =stdexec::just(context.get()) |
            stdexec::then([](auto contextptr) {
//              std::string v;
//              string_buffer buff{v};
//              read_data(contextptr->stream.base(),buff);
//              contextptr->stream.buff<<buff.data();
//              buff.consume_all();
              contextptr->stream.read();
              return &contextptr->stream;
            }) |
            stdexec::let_value([=, contextptr = context.get()](auto& stream) {
              auto client_work =
                  do_work(stream, contextptr->stop_src);
              return client_work;
            }) |
            stdexec::let_value([contextptr = context.get()](auto& buff) {
              string_buffer strbuff(buff);
              write_data(contextptr->stream.base(), strbuff);

              return stdexec::just();
            }) |
            exec::repeat_effect_until([contextptr = context.get()]() {
              if (contextptr->token.stop_requested()) {
                close(contextptr->stream.base());
                throw std::runtime_error("Client Closed");
              }
              return contextptr->token.stop_requested();
            })|
            // exec::retry_when([](std::exception_ptr ex) mutable {
            //   try {
            //     std::rethrow_exception(ex);
            //   } catch (application_error& error) {
            //   }
            //   return stdexec::just();
            // }) |
            handle_error([contextptr = context.get()](auto& v) {
              //    contextptr->stop_src.request_stop();
              printf("client closed\n");
              close(contextptr->stream.base());
//              exec::sync_wait(contextptr->scope.cleanup());
            });
        return child_work;
      });

  context->scope->spawn_on(client_agent, work);
}
inline auto acceptor(auto listener_agent) {
  return stdexec::on(listener_agent) | stdexec::then([](auto listener) {
           auto newsock = accept(*listener);
           return newsock;
         });
}
inline auto peer_to_peer_sender(auto agent, auto worker) {
  return stdexec::then([=, worker = std::move(worker)](auto newconn) {
    return spawn_http_clients(agent, std::move(newconn), std::move(worker));
  });
}

inline auto listen_for_peer_to_peer_connection(
    auto agent, auto token, auto client_agent, auto worker) {
  return stdexec::let_value([=](auto& listener) {
    return stdexec::just(listener) | acceptor(agent) |
        peer_to_peer_sender(client_agent, std::move(worker)) |
        exec::repeat_effect_until([=]() { return token.stop_requested(); });
  });
}
}  // namespace bingo
