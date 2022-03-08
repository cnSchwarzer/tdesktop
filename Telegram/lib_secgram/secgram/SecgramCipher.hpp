#pragma once
#include "SecgramData.hpp"
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/pem.h>
#include <openssl/aead.h>

class SecgramEncryptor {
    EVP_CIPHER_CTX *ctx;

  public:
    SecgramEncryptor(buf key, buf iv) {
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    }
    ~SecgramEncryptor() { EVP_CIPHER_CTX_free(ctx); }
    buf encrypt(buf data) {
        int len;
        buf ret(data.size());
        EVP_EncryptUpdate(ctx, ret.data(), &len, data.data(), data.size());
        return ret;
    }
};

class SecgramDecryptor {
    EVP_CIPHER_CTX *ctx;

  public:
    SecgramDecryptor(buf key, buf iv) {
        ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    }
    ~SecgramDecryptor() { EVP_CIPHER_CTX_free(ctx); }
    buf decrypt(buf data) {
        int len;
        buf ret(data.size());
        EVP_DecryptUpdate(ctx, ret.data(), &len, data.data(), data.size());
        return ret;
    }
};
