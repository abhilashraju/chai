#pragma once
#include "reactor.hpp"
#include <exec/async_scope.hpp>
#include <exec/inline_scheduler.hpp>
#include <stdexec/execution.hpp>
#include <exec/static_thread_pool.hpp>
namespace chai {
struct io_context {
  exec::async_scope scope;
  exec::inline_scheduler main_thread;
  stdexec::in_place_stop_source stop_src;
  template <typename work> void spawn(work &&w) {
    scope.spawn(stdexec::on(main_thread, std::forward<work>(w)));
  }
  template <typename... Senders> void spawn_all(Senders... senders) {

    (scope.spawn(stdexec::on(main_thread, std::forward<Senders>(senders))), ...);
  }
  void run() { GenericReactor::get_reactor().run(stop_src.get_token()); }
  auto get_token() { return stop_src.get_token(); }
  auto request_stop() { scope.request_stop();return stop_src.request_stop(); }
};

struct thread_data {
  stdexec::in_place_stop_source remote_stop_src;
  std::string data;
  string_buffer buff{data};
  auto &get_buffer() { return buff; }
  auto get_token() { return remote_stop_src.get_token(); }
  void request_stop() { remote_stop_src.request_stop(); }
};
} // namespace bingo
