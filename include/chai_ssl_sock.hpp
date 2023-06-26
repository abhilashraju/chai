#pragma once
#include "async_stream.hpp"
#include "chai.hpp"
#include "sslerrors.hpp"
#include "sslverifycallback.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
namespace chai
{
int mydata_index = 0;
mydata_t mycontextdata;
template <class T>
struct DeleterOf;
template <>
struct DeleterOf<BIO>
{
    void operator()(BIO* p) const
    {
        BIO_free_all(p);
    }
};
template <>
struct DeleterOf<BIO_METHOD>
{
    void operator()(BIO_METHOD* p) const
    {
        BIO_meth_free(p);
    }
};
template <>
struct DeleterOf<SSL_CTX>
{
    void operator()(SSL_CTX* p) const
    {
        SSL_CTX_free(p);
    }
};
template <>
struct DeleterOf<SSL>
{
    void operator()(SSL* p) const
    {
        SSL_free(p);
    }
};

template <class OpenSSLType>
using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;
inline void initSsl()
{
    SSL_library_init();
    SSL_load_error_strings();
    // ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}
inline SSlErrors execute(int result, SSL* ssl)
{
    if (result <= 0)
    {
        return SSlErrors(SSL_get_error(ssl, result));
    }
    return SSlErrors::None;
}

template <typename Derived>
struct ssl_sock_base
{
    bool handshakeDone{false};
    bool isHandshakeDone() const
    {
        return handshakeDone;
    }
    void setHandshakeDone(bool v)
    {
        handshakeDone = v;
    }
    Derived& self()
    {
        return static_cast<Derived&>(*this);
    }
    const Derived& self() const
    {
        return static_cast<const Derived&>(*this);
    }
    template <typename Buffer>
    int read_all(Buffer& buffer)
    {
        return read(*this, buffer);
    }
    template <typename Buffer>
    friend int read(ssl_sock_base& stream, Buffer& buff)
    {
        auto r = readssl(stream, buff);
        if (r.second == SSlErrors::WantRead)
        {
            return 1;
        }
        return r.first;
    }

    template <typename Buffer>
    friend auto readssl(ssl_sock_base& stream, Buffer& buff)
    {
        constexpr int MAXSIZE = 1024;
        auto readsofar = 0;
        SSlErrors r = SSlErrors::None;
        while (true)
        {
            size_t read = 0;
            r = execute(SSL_read_ex(stream.self().ssl(), buff.prepare(MAXSIZE),
                                    MAXSIZE, &read),
                        stream.self().ssl());
            if (r != SSlErrors::None && r != SSlErrors::WantRead)
            {
                throw socket_exception(reason(r) +
                                       std::string(strerror(errno)));
            }
            if (read == 0 && stream.isHandshakeDone())
            {
                stream.self().base().set_eof(true);
                return std::make_pair(readsofar, r);
            }
            readsofar += read;
            buff.commit(read);
            if (read < MAXSIZE)
            {
                break;
            }
        }
        return std::make_pair(readsofar, r);
    }
    auto readsome(char* buff, int size)
    {
        size_t read = 0;
        auto r = execute(SSL_read_ex(self().ssl(), buff, size, &read),
                         self().ssl());
        if (r != SSlErrors::None && r != SSlErrors::WantRead)
        {
            throw socket_exception(reason(r));
        }
        if (read == 0 && isHandshakeDone())
        {
            self().base().set_eof(true);
        }
        return std::make_pair(read, r);
    }
    template <typename Buffer>
    friend auto send(const ssl_sock_base& stream, Buffer buff)
    {
        size_t written = 0;
        auto r = execute(SSL_write_ex(stream.self().ssl(), buff.data(),
                                      buff.read_length(), &written),
                         stream.self().ssl());
        if (r != SSlErrors::None && r != SSlErrors::WantWrite)
        {
            throw socket_exception(reason(r));
        }
        return std::make_pair(written, r);
    }

  protected:
    static SSL_CTX* getSslVarifyContext(bool server, const std::string& cert,
                                        const std::string& privk,
                                        const std::string& truststr,
                                        bool verifypeer = false)
    {
        static UniquePtr<SSL_CTX> ctx(
            makeContext(server, cert, privk, truststr, verifypeer));

        return ctx.get();
    }
    static SSL_CTX* makeContext(bool server, const std::string& cert,
                                const std::string& privk,
                                const std::string& truststr, bool verifypeer)
    {
        auto ctx = SSL_CTX_new(server ? SSLv23_server_method()
                                      : SSLv23_client_method());
        if (!SSL_CTX_use_certificate_file(ctx, cert.data(), SSL_FILETYPE_PEM))
        {
            throw std::runtime_error("Invallid certificate file");
        }
        if (!SSL_CTX_use_PrivateKey_file(ctx, privk.data(), SSL_FILETYPE_PEM))
        {
            throw std::runtime_error("Invallid Private key file");
        }

        if (!SSL_CTX_load_verify_locations(ctx, nullptr, truststr.data()))
        {
            throw std::runtime_error(
                "Invallid certification trust store file or location");
        }
        enablePeerVarification(ctx, verifypeer);
        return ctx;
    }
    static void enablePeerVarification(SSL_CTX* context, bool verifypeer)
    {
        if (verifypeer)
        {
            mydata_index = SSL_get_ex_new_index(0, (void*)"mydata index", NULL,
                                                NULL, NULL);

            int verify_depth = 6;
            SSL_CTX_set_verify_depth(context, verify_depth + 1);
            mycontextdata.verify_depth = verify_depth;
            mycontextdata.always_continue = true;
            SSL_CTX_set_ex_data(context, mydata_index, &mycontextdata);
            SSL_CTX_set_verify(
                context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                [](int preverify_ok, X509_STORE_CTX* ctx) {
                // You can implement custom verification logic here
                // For simplicity, we'll return preverify_ok for now
                return verify_callback(preverify_ok, ctx);
                });
        }
    }
};
struct ssl_client_sock : ssl_sock_base<ssl_client_sock>
{
    using BASECLASS = ssl_sock_base<ssl_client_sock>;
    sock_base base_;
    UniquePtr<SSL_CTX> ctx_;
    UniquePtr<SSL> ssl_;
    ssl_client_sock(sock_base b, bool verifypeer = false,
                    const char* ssltruststore = "/etc/ssl/certs") :
        base_(std::move(b))
    {
        ctx_.reset(SSL_CTX_new(SSLv23_client_method()));
        if (!SSL_CTX_load_verify_locations(ctx_.get(), nullptr, ssltruststore))
        {
            throw std::runtime_error("Error in setring trust store dir");
        }
        enablePeerVarification(ctx_.get(), verifypeer);
        ssl_.reset(SSL_new(ctx_.get()));
        SSL_set_fd(ssl(), base_.fd());
        set_blocked(base(), false);

        if (auto err = startHandShake(); err != SSlErrors::None)
        {}
    }
    ssl_client_sock(sock_base b, SSL_CTX* ctx) : base_(std::move(b))
    {
        ctx_.reset(ctx);
        ssl_.reset(SSL_new(ctx_.get()));
        SSL_set_fd(ssl(), base_.fd());
        set_blocked(base(), false);
        if (auto err = startHandShake(); err != SSlErrors::None)
        {}
    }
    ssl_client_sock(const ssl_client_sock&) = delete;
    ssl_client_sock(ssl_client_sock&&) = default;
    ~ssl_client_sock()
    {
        if (ssl())
            SSL_shutdown(ssl());
    }
    SSlErrors startHandShake()
    {
        return execute(SSL_connect(ssl()), ssl());
    }
    SSL* ssl() const
    {
        return ssl_.get();
    }
    SSL_CTX* context() const
    {
        return ctx_.get();
    }
    sock_base& base()
    {
        return base_;
    }
    auto& fd()
    {
        return base().fd();
    }
    static SSL_CTX* getSslVarifyContext(const std::string& cert,
                                        const std::string& privk,
                                        const std::string& truststr)
    {
        BASECLASS::getSslVarifyContext(false, cert, privk, truststr);
    }
};
struct ssl_server_sock : ssl_sock_base<ssl_server_sock>
{
    using BASECLASS = ssl_sock_base<ssl_server_sock>;
    sock_base base_;
    SSL_CTX* ctx_;
    UniquePtr<SSL> ssl_;
    ssl_server_sock(sock_base b, SSL_CTX* c) : base_(std::move(b)), ctx_(c)
    {
        ssl_.reset(SSL_new(ctx_));
        SSL_set_fd(ssl(), base_.fd());
    }
    ~ssl_server_sock()
    {
        SSL_shutdown(ssl());
    }
    SSlErrors startHandShake()
    {
        if (int r = SSL_accept(ssl()); r <= 0)
        {
            return SSlErrors(SSL_get_error(ssl(), r));
        }
        auto peer = SSL_get_peer_certificate(ssl());
        if (peer)
        {
            auto vr = SSL_get_verify_result(ssl());
            if (vr == X509_V_OK)
            {
                return SSlErrors::None;
            }
            return SSlErrors(vr);
        }
        return SSlErrors::None;
    }

    SSL* ssl() const
    {
        return ssl_.get();
    }
    SSL_CTX* context() const
    {
        return ctx_;
    }
    sock_base& base()
    {
        return base_;
    }
    auto& fd()
    {
        return base().fd();
    }
    static SSL_CTX* getSslVarifyContext(const std::string& cert,
                                        const std::string& privk,
                                        const std::string& truststr)
    {
        BASECLASS::getSslVarifyContext(true, cert, privk, truststr);
    }
};
template <typename SSL_SOCK>
inline bool handleHandshake(SSL_SOCK& sock, SSlErrors result)
{
    if (!sock.isHandshakeDone())
    {
        if (result == SSlErrors::ErrorSsl || result == SSlErrors::ErrorSysCall)
        {
            throw std::runtime_error(reason(result));
        }
        if (result != SSlErrors::None)
        {
            return false;
        }
        sock.setHandshakeDone(true);
    }
    return true;
}
template <typename Handler>
struct broadcast_ssl_handler : broadcast_handler<Handler, ssl_server_sock>
{
    using BASE_TYPE = broadcast_handler<Handler, ssl_server_sock>;
    SSL_CTX* sslCtx{nullptr};
    auto spawn(auto& scope, auto& context, auto newsock) const
    {
        std::unique_ptr<ssl_server_sock> clientsock(
            new ssl_server_sock(std::move(newsock), sslCtx));
        set_blocked(clientsock->base(), false);
        if (auto err = clientsock->startHandShake(); err != SSlErrors::None)
        {
            if (err != SSlErrors::WantRead && err != SSlErrors::WantWrite &&
                err != SSlErrors::WantConnect && err != SSlErrors::WantAccept)
            {
                return;
            }
            // throw socket_exception(std::string("Hand Shake Error"));
        }
        BASE_TYPE::getClientList().add_client(clientsock.release());
    }

    auto handle_read(int fd) const
    {
        auto sock = BASE_TYPE::getClientList().find(fd);
        try
        {
            if (sock)
            {
                std::string str;
                string_buffer buf(str);
                auto n = readssl(*sock.value(), buf);
                if (handleHandshake(*sock.value(), n.second))
                {
                    if (n.first == 0)
                    {
                        BASE_TYPE::getClientList().remove_client(sock.value());
                        return false; // socket closed by remote
                    }
                    if (n.first > 0)
                    {
                        BASE_TYPE::getClientList().broadcast(
                            BASE_TYPE::request_handler(buf));
                    }
                }
            }
            return true;
        }
        catch (std::exception& e)
        {
            BASE_TYPE::getClientList().remove_client(sock.value());
        }
        return false;
    }
    broadcast_ssl_handler(SSL_CTX* c, Handler&& handler) :
        BASE_TYPE(std::forward<Handler>(handler)), sslCtx(c)
    {}
    broadcast_ssl_handler(const broadcast_ssl_handler&) = delete;
    broadcast_ssl_handler(broadcast_ssl_handler&& other) :
        BASE_TYPE(std::move(other))
    {
        sslCtx = std::move(other.sslCtx);
    }
    broadcast_ssl_handler& operator=(const broadcast_ssl_handler&) = delete;
    broadcast_ssl_handler& operator=(broadcast_ssl_handler&&) = delete;
};
template <typename Handler>
struct peer_to_peer_ssl_handler
{
    using Request_Handler = Handler;
    Request_Handler request_handler;
    static constexpr bool broad_casting = false;
    SSL_CTX* sslCtx{nullptr};
    peer_to_peer_ssl_handler(SSL_CTX* ctx, Request_Handler handler) :
        request_handler(std::move(handler)), sslCtx(ctx)
    {}
    auto spawn(auto& scope, auto& context, auto newconnection) const
    {
        scope.spawn(stdexec::on(context.get_scheduler(),
                                handleConnection(std::move(newconnection))));
    }
    auto handle_read(int fd) const
    {
        return false;
    }
    auto make_ssl_socket(sock_base&& newsock, auto sslCtx) const
    {
        return stdexec::just(
            std::make_unique<ssl_server_sock>(std::move(newsock), sslCtx));
    }
    auto start_hand_shake() const
    {
        return stdexec::then([](auto sock) {
            // sset_blocked(sock->base(), false);
            if (auto err = sock->startHandShake(); err != SSlErrors::None)
            {
                if (err != SSlErrors::WantRead && err != SSlErrors::WantWrite &&
                    err != SSlErrors::WantConnect &&
                    err != SSlErrors::WantAccept)
                {
                    throw socket_exception(std::string("Hand Shake Error"));
                }
            }
            sock->setHandshakeDone(true);
            return sock;
        });
    }
    auto process_read() const
    {
        return stdexec::then([=](auto sock) {
            // std::unique_ptr<ssl_server_sock> sock(newsock);

            while (true)
            {
                std::string str;
                string_buffer buf(str);
                auto n = readssl(*sock, buf);
                if (handleHandshake(*sock, n.second))
                {
                    if (n.first == 0)
                    {
                        throw socket_exception(std::string("EOF"));
                    }
                    if (n.first > 0)
                    {
                        send(*sock, request_handler(buf));
                    }
                }
            }
        });
    }
    auto handleConnection(sock_base newsock) const
    {
        auto session =
            make_ssl_socket(std::move(newsock), sslCtx) | start_hand_shake() |
            process_read() |
            handle_error([&](std::exception& v) { printf("%s", v.what()); });
        return session;
    }
};

struct async_ssl_sock : async_stream<async_ssl_sock>
{
    ssl_client_sock sock;
    async_ssl_sock(ssl_client_sock&& s) : sock(std::move(s)) {}
    int get_fd()
    {
        return sock.fd();
    }

    auto on_read_handler(auto& buff)
    {
        auto n = readssl(sock, buff);
        if (handleHandshake(sock, n.second))
        {
            return n.first;
        }
        // still handshake going on
        return 1;
    }
};
} // namespace chai
