// Client side C/C++ program to demonstrate Sender/Reciever Based Sockets
// programming
#include "async_stream.hpp"

#include "io_context.hpp"
#include "stream_processor.hpp"
#include <exec/repeat_effect_until.hpp>
#include <exec/single_thread_context.hpp>
#include <exec/static_thread_pool.hpp>
#include <iostream>
#include <sstream>
#include <stdexec/execution.hpp>
#include <thread>

int PORT = 8089;

int main(int argc, char const *argv[]) {
  using namespace chai;
  io_context context;
  exec::single_thread_context io_thread;
  exec::single_thread_context net_thread;

  async_sock client(sock_base{});
  std::string ip = "127.0.0.1";
  if (argc > 1) {
    ip = argv[1];
  }

  connect(client.sock, {ip, PORT});

  thread_data remotedata;
  async_io io;
  thread_data io_data;
  auto clean_up = [&]() {
    remotedata.request_stop();
    io_data.request_stop();
    context.request_stop();
  };
  auto workTask = stdexec::schedule(net_thread.get_scheduler()) |
                  wait_for_io(client, remotedata.get_buffer()) |
                  stdexec::then([&](auto) {
                    std::cout << remotedata.get_buffer().data();
                    remotedata.get_buffer().consume_all();
                  }) |
                  stdexec::then([token = remotedata.get_token()]() {
                    return token.stop_requested();
                  });
  auto work = exec::repeat_effect_until(std::move(workTask)) |
              handle_error([&](auto &e) {
                std::cout << "Server Error \n";
                clean_up();
              });

  auto uiTask = stdexec::schedule(io_thread.get_scheduler()) |
                wait_for_io(io, io_data.get_buffer()) |
                stdexec::then([&](auto) {
                  send(client.sock, io_data.get_buffer());
                  io_data.get_buffer().consume_all();
                }) |
                stdexec::then([token = io_data.get_token()]() {
                  return token.stop_requested();
                });
  auto ui =
      exec::repeat_effect_until(std::move(uiTask)) | handle_error([&](auto &e) {
        std::cout << "Client Error\n";
        clean_up();
      });
  context.spawn_all(std::move(work), std::move(ui));
  context.run();
  return 0;
}
