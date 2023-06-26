#pragma once
#include "sslerrors.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
namespace chai
{
typedef struct
{
    int verbose_mode;
    int verify_depth;
    int always_continue;
} mydata_t;
extern int mydata_index;

inline int verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
    char buf[256];
    X509* err_cert;
    int err, depth;
    SSL* ssl;
    mydata_t* mydata;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    /*
     * Retrieve the pointer to the SSL of the connection currently treated
     * and the application specific data stored into the SSL object.
     */
    ssl = (SSL*)X509_STORE_CTX_get_ex_data(
        ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    SSL_CTX* sslctx = SSL_get_SSL_CTX(ssl);
    mydata = (mydata_t*)SSL_CTX_get_ex_data(sslctx, mydata_index);

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    /*
     * Catch a too long certificate chain. The depth limit set using
     * SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
     * that whenever the "depth>verify_depth" condition is met, we
     * have violated the limit and want to log this error condition.
     * We must do it here, because the CHAIN_TOO_LONG error would not
     * be found explicitly; only errors introduced by cutting off the
     * additional certificates would be logged.
     */
    if (depth > mydata->verify_depth)
    {
        preverify_ok = 0;
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err);
    }
    if (!preverify_ok)
    {
        printf("verify error:num=%d:%s:depth=%d:%s\n", err,
               X509_verify_cert_error_string(err), depth, buf);
    }
    else if (mydata->verbose_mode)
    {
        printf("depth=%d:%s\n", depth, buf);
    }

    /*
     * At this point, err contains the last verification error. We can use
     * it for something special
     */
    if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT))
    {
        X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
        printf("issuer= %s\n", buf);
    }

    if (mydata->always_continue)
        return 1;
    else
        return preverify_ok;
}
} // namespace chai
