// Client side C/C++ program to demonstrate Sender/Reciever Based Sockets
// programming
#include "async_stream.hpp"
#include "chai_ssl_sock.hpp"
#include "io_context.hpp"
#include "stream_processor.hpp"
#include "utils/command_line_parser.hpp"

#include <exec/repeat_effect_until.hpp>
#include <exec/single_thread_context.hpp>
#include <exec/static_thread_pool.hpp>
#include <stdexec/execution.hpp>

#include <iostream>
#include <map>
#include <sstream>
#include <thread>
int PORT = 8089;

int main(int argc, const char* argv[])
{
    using namespace chai;
    initSsl();
    io_context context;
    exec::single_thread_context io_thread;
    exec::single_thread_context net_thread;

    sock_base clientsock;
    std::string address = "127.0.0.1";

    auto [ip, certPath, priKey, trustStore] =
        getArgs(parseCommandline(argc, argv), "-ip", "-c", "-p", "-t");
    if (!ip.empty())
    {
        address = ip.data();
    }
    connect(clientsock, {address, PORT});

    auto sslClientSock =
        (certPath.empty())
            ? ssl_client_sock(std::move(clientsock), true)
            : ssl_client_sock(
                  std::move(clientsock),
                  ssl_client_sock::getSslVarifyContext(
                      certPath.data(), priKey.data(), trustStore.data()));
    async_ssl_sock sslstream(std::move(sslClientSock));
    thread_data remotedata;
    async_io io;
    thread_data io_data;
    auto clean_up = [&]() {
        remotedata.request_stop();
        io_data.request_stop();
        context.request_stop();
    };

    auto start = stdexec::schedule(net_thread.get_scheduler());
    auto workTask = wait_for_io(sslstream, remotedata.get_buffer()) |
                    stdexec::then([&](auto) {
                        std::cout << remotedata.get_buffer().data();
                        remotedata.get_buffer().consume_all();
                    }) |
                    stdexec::then([token = remotedata.get_token()]() {
                        return token.stop_requested();
                    });
    auto work = exec::repeat_effect_until(std::move(start | workTask)) |
                handle_error([&](auto& e) {
                    std::cout << "Server Error \n";
                    clean_up();
                });

    auto uiTask = stdexec::schedule(io_thread.get_scheduler()) |
                  wait_for_io(io, io_data.get_buffer()) |
                  stdexec::then([&](auto) {
                      send(sslstream.sock, io_data.get_buffer());
                      io_data.get_buffer().consume_all();
                  }) |
                  stdexec::then([token = io_data.get_token()]() {
                      return token.stop_requested();
                  });
    auto ui = exec::repeat_effect_until(std::move(uiTask)) |
              handle_error([&](auto& e) {
                  std::cout << "Client Error\n";
                  clean_up();
              });
    context.spawn_all(std::move(work), std::move(ui));
    context.run();
    return 0;
}
