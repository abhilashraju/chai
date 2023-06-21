// Server side C/C++ program to demonstrate unifex based chat server
// programming

#include "chai_ssl_sock.hpp"

#include <chai.hpp>
#include <exec/static_thread_pool.hpp>
#define PORT 8089
#include <iostream>
using namespace chai;
template <typename Handler>
struct broadcast_ssl_handler : broadcast_handler<Handler, ssl_server_sock>
{
    using BASE_TYPE = broadcast_handler<Handler, ssl_server_sock>;
    SSL_CTX* sslCtx{nullptr};
    auto spawn(auto& scope, auto& context, auto newsock) const
    {
        auto clientsock = new ssl_server_sock(std::move(newsock), sslCtx);
        BASE_TYPE::getClientList().add_client(clientsock);
    }
    broadcast_ssl_handler(SSL_CTX* c, Handler&& handler) :
        BASE_TYPE(std::forward<Handler>(handler)), sslCtx(c)
    {}
};
int main(int argc, const char* argv[])
{
    (void)argc;
    (void)argv;
    bool broad_cast =
        (argc > 1) ? ((argv[1] == std::string("broadcast")) ? true : false)
                   : true;
    try
    {
        exec::static_thread_pool context;
        initSsl();
        auto sslctx = ssl_server_sock::getServerContext(
            "/Users/abhilashraju/work/cpp/ssl/keys/server-certificate.pem",
            "/Users/abhilashraju/work/cpp/ssl/keys/server-private-key.pem",
            "path/to/truststore.pem");
        if (broad_cast)
        {
            stdexec::sync_wait(
                make_listener("127.0.0.1", PORT) |
                process_clients(context,
                                broadcast_ssl_handler(
                                    sslctx, [](auto buff) { return buff; })));
        }
        else
        {
            stdexec::sync_wait(
                make_listener("127.0.0.1", PORT) |
                process_clients(context, peer_to_peer_handler(
                                             [](auto buff) { return buff; })));
        }
    }
    catch (std::exception& e)
    {
        printf("%s", e.what());
    }

    return 0;
}
