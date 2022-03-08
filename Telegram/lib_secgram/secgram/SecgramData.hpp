#pragma once

#include <memory>
#include <vector>
#include <string>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

using buf = std::vector<uint8_t>;

struct SecgramUser {
    uint64_t peerId;
    EC_KEY* publicVerifyKey = nullptr;
    EC_KEY* privateSignKey = nullptr;
};

struct SecgramSession { 
    uint64_t localPeerId;
    uint64_t remotePeerId; 

    buf key;
    buf iv;
};  