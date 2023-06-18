#pragma once
#include "chaisock.hpp"
#include "reactor.hpp"
#include <condition_variable>
#include <iostream>
#include <stdio.h>
namespace chai {
template <typename stream> struct async_stream {

  stream &self() { return static_cast<stream &>(*this); }
  template <typename Handler> auto on_read(Handler handler) {

    GenericReactor &reactor = GenericReactor::get_reactor();
    reactor.add_handler(self().get_fd(), [&]() {
      std::string str;
      string_buffer buf(str);
      int bytes = self().on_read_handler(buf);
      handler(buf);
      return true;
    });
  }
  template <typename Handler> auto sync_read(auto &buf, Handler handler) {
    std::mutex m;
    std::condition_variable cv;
    bool ready = false;

    GenericReactor &reactor = GenericReactor::get_reactor();
    std::exception_ptr eptr;
    reactor.add_handler(self().get_fd(), [&](GenericReactor::Reason reason) {
      int bytes{0};
      if (reason == GenericReactor::Reason::Trigger) {
        bytes = self().on_read_handler(buf);
        try {
          if (bytes <= 0) {
            throw std::runtime_error(std::string("socket error: ") +
                                     strerror(errno));
          }
        } catch (const std::exception &e) {
          eptr = std::current_exception(); // capture
        }
      }

      ready = true;
      cv.notify_one();
      return bytes > 0;
    });
    std::unique_lock lk(m);
    cv.wait(lk, [&] { return ready; });
    if (eptr) {
      std::rethrow_exception(eptr);
    }
    return handler();
  }
};

struct async_sock : async_stream<async_sock> {
  sock_base sock;

  int get_fd() { return sock.fd_; }

  int on_read_handler(auto &buff) { return read(sock, buff); }
};
struct async_io : async_stream<async_io> {
  int get_fd() { return fileno(stdin); }
  int on_read_handler(auto &buff) {
    constexpr size_t MAX = 1024;
    if (char *data; (data = fgets(buff.prepare(MAX), MAX, stdin)) != nullptr) {
      buff.commit(strlen(data));
      return buff.read_length();
    }
    return 0;
  }
};
} // namespace bingo
