#include "chaisock.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
namespace chai
{
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
template <typename Derived>
struct ssl_sock_base
{
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
        constexpr int MAXSIZE = 1024;
        auto read = 0;
        while (true)
        {
            int r = SSL_read(stream.self().ssl(), buff.prepare(MAXSIZE),
                             MAXSIZE);
            if (r < 0)
            {
                if (errno == EINTR)
                    continue;
                throw socket_exception(strerror(r));
            }
            if (r == 0)
            {
                stream.self().base().set_eof(true);
                break;
            }
            read += r;
            buff.commit(r);
            if (r < MAXSIZE)
            {
                break;
            }
        }
        return read;
    }
    int readsome(char* buff, int size)
    {
        int r = SSL_read(self().ssl(), buff, size);
        if (r < 0)
        {
            if (errno != EINTR)
                throw socket_exception(strerror(r));
        }
        if (r == 0)
        {
            self().base().set_eof(true);
        }
        return r;
    }
    template <typename Buffer>
    friend int send(const ssl_sock_base& stream, Buffer buff)
    {
        int r = SSL_write(stream.self().ssl(), buff.data(), buff.read_length());
        if (r < 0)
        {
            throw socket_exception(strerror(r));
        }
        return r;
    }
};
struct ssl_client_sock : ssl_sock_base<ssl_client_sock>
{
    sock_base base_;
    UniquePtr<SSL_CTX> ctx_;
    UniquePtr<SSL> ssl_;
    ssl_client_sock(sock_base b) : base_(std::move(b))
    {
        ctx_.reset(SSL_CTX_new(SSLv23_client_method()));
        // if(!SSL_CTX_load_verify_locations(ctx.get(),"path/to/truststore.pem",nullptr))
        // {
        //     // Handle error loading trust store
        // }
        ssl_.reset(SSL_new(ctx_.get()));
        SSL_set_fd(ssl(), base_.fd());
    }
    ~ssl_client_sock()
    {
        SSL_shutdown(ssl());
    }
    bool startHandShake()
    {
        if (SSL_connect(ssl()) != 1)
        {
            return false;
        }
        return true;
    }
    SSL* ssl() const
    {
        return ssl_.get();
    }
    sock_base& base()
    {
        return base_;
    }
    auto& fd()
    {
        return base().fd();
    }
};
struct ssl_server_sock : ssl_sock_base<ssl_server_sock>
{
    sock_base base_;
    SSL_CTX* ctx_;
    UniquePtr<SSL> ssl_;
    ssl_server_sock(sock_base b, SSL_CTX* c) : base_(std::move(b)), ctx_(c)
    {
        // if(!SSL_CTX_load_verify_locations(ctx.get(),"path/to/truststore.pem",nullptr))
        // {
        //     // Handle error loading trust store
        // }
        ssl_.reset(SSL_new(ctx_));
        SSL_set_fd(ssl(), base_.fd());
    }
    ~ssl_server_sock()
    {
        SSL_shutdown(ssl());
    }
    bool startHandShake()
    {
        if (SSL_accept(ssl()) <= 0)
        {
            return false;
        }
        return true;
    }
    SSL* ssl() const
    {
        return ssl_.get();
    }
    sock_base& base()
    {
        return base_;
    }
    auto& fd()
    {
        return base().fd();
    }

  public:
    static SSL_CTX* getServerContext(const std::string& cert,
                                     const std::string& privk,
                                     const std::string& truststr)
    {
        static UniquePtr<SSL_CTX> ctx(makeContext(cert, privk, truststr));
    }

  private:
    static SSL_CTX* makeContext(const std::string& cert,
                                const std::string& privk,
                                const std::string& truststr)
    {
        auto ctx = SSL_CTX_new(SSLv23_server_method());
        SSL_CTX_use_certificate_file(ctx, cert.data(), SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx, privk.data(), SSL_FILETYPE_PEM);
        // if (!SSL_CTX_load_verify_locations(ctx, truststr.data(),
        // nullptr)) {
        //     // Handle error loading trust store
        // }
        return ctx;
    }
};

} // namespace chai
