#pragma once
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <iostream>
namespace chai
{
// Function to handle OpenSSL errors
inline void handleOpenSSLErrors()
{
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("OpenSSL error occurred.");
}

// Function to create a self-signed certificate
inline X509* signCertificate(X509_REQ* req, EVP_PKEY* caPrivateKey)
{
    X509* cert = X509_new();
    if (!cert)
    {
        handleOpenSSLErrors();
    }

    // Set the version and serial number
    if (!X509_set_version(cert, 2L))
    {
        handleOpenSSLErrors();
    }
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // Set the validity period
    time_t now = time(nullptr);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

    // Set the subject and issuer
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    X509_set_issuer_name(cert, X509_get_subject_name(cert));

    // Set the public key
    X509_set_pubkey(cert, X509_REQ_get_pubkey(req));

    // Sign the certificate
    if (!X509_sign(cert, caPrivateKey, EVP_sha256()))
    {
        handleOpenSSLErrors();
    }

    return cert;
}
inline bool signCertificate(std::string_view caPrivateKeyPath,
                            std::string_view csrFilePath,
                            std::string_view signedCertPath)
{
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Load CA private key

    FILE* caPrivateKeyFile = fopen(caPrivateKeyPath.data(), "r");
    if (!caPrivateKeyFile)
    {
        std::cerr << "Failed to open CA private key file." << std::endl;
        return 1;
    }
    EVP_PKEY* caPrivateKey = PEM_read_PrivateKey(caPrivateKeyFile, nullptr,
                                                 nullptr, nullptr);
    fclose(caPrivateKeyFile);
    if (!caPrivateKey)
    {
        handleOpenSSLErrors();
    }

    // Load the CSR

    FILE* csrFile = fopen(csrFilePath.data(), "r");
    if (!csrFile)
    {
        std::cerr << "Failed to open CSR file." << std::endl;
        return 1;
    }
    X509_REQ* req = PEM_read_X509_REQ(csrFile, nullptr, nullptr, nullptr);
    fclose(csrFile);
    if (!req)
    {
        handleOpenSSLErrors();
    }

    // Sign the certificate
    X509* cert = signCertificate(req, caPrivateKey);

    // Save the signed certificate to a file
    FILE* signedCertFile = fopen(signedCertPath.data(), "w");
    if (!signedCertFile)
    {
        std::cerr << "Failed to create signed certificate file." << std::endl;
        return 1;
    }
    if (!PEM_write_X509(signedCertFile, cert))
    {
        handleOpenSSLErrors();
    }
    fclose(signedCertFile);

    // Cleanup
    X509_free(cert);
    X509_REQ_free(req);
    EVP_PKEY_free(caPrivateKey);
    EVP_cleanup();

    std::cout << "Certificate signing complete." << std::endl;

    return 0;
}
inline X509_REQ* generateCSR(EVP_PKEY* privateKey, std::string_view subjectName)
{
    X509_REQ* req = X509_REQ_new();
    if (!req)
    {
        handleOpenSSLErrors();
    }

    // Set the subject name
    X509_NAME* name = X509_NAME_new();
    if (!name)
    {
        handleOpenSSLErrors();
    }
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)subjectName.data(), -1, -1,
                               0);
    X509_REQ_set_subject_name(req, name);

    // Set the public key
    X509_REQ_set_pubkey(req, privateKey);

    // Sign the CSR
    if (!X509_REQ_sign(req, privateKey, EVP_sha256()))
    {
        handleOpenSSLErrors();
    }

    return req;
}
inline void generateCSRFile(std::string_view subjectName,
                            std::string_view csrFilePath)
{
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate an RSA private key
    EVP_PKEY* privateKey = EVP_PKEY_new();
    if (!privateKey)
    {
        handleOpenSSLErrors();
    }
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    if (!rsa)
    {
        handleOpenSSLErrors();
    }
    if (!EVP_PKEY_set1_RSA(privateKey, rsa))
    {
        handleOpenSSLErrors();
    }
    RSA_free(rsa);

    // Generate the CSR
    X509_REQ* req = generateCSR(privateKey, subjectName);

    // Save the CSR to a file

    FILE* csrFile = fopen(csrFilePath.data(), "w");
    if (!csrFile)
    {
        std::cerr << "Failed to create CSR file." << std::endl;
        return;
    }
    if (!PEM_write_X509_REQ(csrFile, req))
    {
        handleOpenSSLErrors();
    }
    fclose(csrFile);

    // Cleanup
    X509_REQ_free(req);
    EVP_PKEY_free(privateKey);
    EVP_cleanup();

    std::cout << "CSR generation complete." << std::endl;
}
inline void generateCapublickey(std::string_view outfilename)
{
    auto privateKeyFilePath = std::string(outfilename) + "_priv_key.pem";
    FILE* privateKeyFile = fopen(privateKeyFilePath.c_str(), "r");
    if (!privateKeyFile)
    {
        std::cerr << "Failed to open CA private key file." << std::endl;
        return;
    }
    EVP_PKEY* privateKey = PEM_read_PrivateKey(privateKeyFile, nullptr, nullptr,
                                               nullptr);
    fclose(privateKeyFile);
    if (!privateKey)
    {
        handleOpenSSLErrors();
    }

    // Extract the CA public key
    RSA* rsaPrivateKey = EVP_PKEY_get1_RSA(privateKey);
    if (!rsaPrivateKey)
    {
        handleOpenSSLErrors();
    }
    EVP_PKEY* publicKey = EVP_PKEY_new();
    if (!publicKey)
    {
        handleOpenSSLErrors();
    }
    if (!EVP_PKEY_assign_RSA(publicKey, rsaPrivateKey))
    {
        handleOpenSSLErrors();
    }

    // Save the CA public key to a file
    auto publicKeyFilePath = outfilename.data() + std::string("pub_key.pem");
    FILE* publicKeyFile = fopen(publicKeyFilePath.c_str(), "w");
    if (!publicKeyFile)
    {
        std::cerr << "Failed to create CA public key file." << std::endl;
        return;
    }
    if (!PEM_write_PUBKEY(publicKeyFile, publicKey))
    {
        handleOpenSSLErrors();
    }
    fclose(publicKeyFile);

    // Cleanup
    EVP_PKEY_free(privateKey);
    EVP_PKEY_free(publicKey);
    EVP_cleanup();

    std::cout << "CA public key generation complete." << std::endl;
}

inline void generateCakeypairs(std::string_view outfilename)
{
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate an RSA private key for the CA
    EVP_PKEY* privateKey = EVP_PKEY_new();
    if (!privateKey)
    {
        handleOpenSSLErrors();
    }
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    if (!rsa)
    {
        handleOpenSSLErrors();
    }
    if (!EVP_PKEY_assign_RSA(privateKey, rsa))
    {
        handleOpenSSLErrors();
    }

    // Save the CA private key to a file
    auto privateKeyFilePath = std::string(outfilename.data()) + "_priv_key.pem";
    FILE* privateKeyFile = fopen(privateKeyFilePath.c_str(), "w");
    if (!privateKeyFile)
    {
        std::cerr << "Failed to create CA private key file." << std::endl;
        return;
    }
    if (!PEM_write_PrivateKey(privateKeyFile, privateKey, nullptr, nullptr, 0,
                              nullptr, nullptr))
    {
        handleOpenSSLErrors();
    }
    fclose(privateKeyFile);
    // Cleanup
    EVP_PKEY_free(privateKey);

    std::cout << "CA private key generation complete." << std::endl;
    generateCapublickey(outfilename);
    return;
}

} // namespace chai
