// Server side C/C++ program to demonstrate unifex based chat server
// programming

#include "chai_ssl_sock.hpp"
#include "utils/command_line_parser.hpp"

#include <chai.hpp>
#include <exec/static_thread_pool.hpp>
#define PORT 8089
#include <iostream>
using namespace chai;

int main(int argc, const char* argv[])
{
    (void)argc;
    (void)argv;

    // const char* servcert =
    //     "/home/abhilash/work/chai/certs/server-certificate.pem";
    // const char* servkey =
    //     "/home/abhilash/work/chai/certs/server-private-key.pem";
    // const char* certLocation = "/etc/ssl/certs";

    auto [peertopeer, servcert, servkey, certLocation] =
        getArgs(parseCommandline(argc, argv), "-m", "-c", "-p", "-t");
    if (servcert.empty() || servkey.empty() || certLocation.empty())
    {
        std::cout << "ssl details missing\n";
        std::cout
            << "./chai_sslserver -c certificat_file -k privkey_file -t truststore_location\n";
        return 0;
    }
    bool broad_cast =
        peertopeer.empty() ? true : (peertopeer == "peertopeer" ? false : true);
    try
    {
        exec::static_thread_pool context;
        initSsl();
        auto sslctx = ssl_server_sock::getSslVarifyContext(
            servcert.data(), servkey.data(), certLocation.data());
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
                process_clients(context,
                                peer_to_peer_ssl_handler(
                                    sslctx, [](auto buff) { return buff; })));
        }
    }
    catch (std::exception& e)
    {
        printf("%s", e.what());
    }

    return 0;
}
