#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace chai {
enum class SSlErrors {
  None = SSL_ERROR_NONE,
  WantRead = SSL_ERROR_WANT_READ,
  WantWrite = SSL_ERROR_WANT_WRITE,
  WantConnect = SSL_ERROR_WANT_CONNECT,
  WantAccept = SSL_ERROR_WANT_ACCEPT,
  WantLookup = SSL_ERROR_WANT_X509_LOOKUP,
  WantAsync = SSL_ERROR_WANT_ASYNC,
  WantAsyncJob = SSL_ERROR_WANT_ASYNC_JOB,
  WantClientHelloCB = SSL_ERROR_WANT_CLIENT_HELLO_CB,
  ErrorSysCall = SSL_ERROR_SYSCALL,
  ErrorSsl = SSL_ERROR_SSL

};
const char *reason(SSlErrors err) {
  switch (err) {
  case SSlErrors::None:
    return "SSL_ERROR_NONE";
  case SSlErrors::WantRead:
    return "SSL_ERROR_WANT_READ";
  case SSlErrors::WantWrite:
    return "SSL_ERROR_WANT_WRITE";
  case SSlErrors::WantConnect:
    return "SSL_ERROR_WANT_CONNECT";
  case SSlErrors::WantAccept:
    return " SSL_ERROR_WANT_ACCEPT";
  case SSlErrors::WantLookup:
    return " SSL_ERROR_WANT_X509_LOOKUP";
  case SSlErrors::WantAsync:
    return " SSL_ERROR_WANT_ASYNC";
  case SSlErrors::WantAsyncJob:
    return "SSL_ERROR_WANT_ASYNC_JOB";
  case SSlErrors::WantClientHelloCB:
    return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
  case SSlErrors::ErrorSysCall:
    return " SSL_ERROR_SYSCALL";
  case SSlErrors::ErrorSsl:
    return "SSL_ERROR_SSL";
  }
}
} // namespace chai