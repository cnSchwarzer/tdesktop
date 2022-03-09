#include "SecgramCore.hpp"
#include "SecgramData.hpp"
#include "json.hpp"

#include <cstdio>
#include <openssl/aead.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/pem.h>
#include <random>

using njson = nlohmann::json;

SecgramCore::SecgramCore(std::string password, std::string root) {
    dirRoot = root;
    this->password = password;
    fprintf(stderr, "Root %s\n", root.c_str());

    if (!password.empty()) {
        auto configBytes = read_all_bytes(dirRoot + "/config.json");
        auto config = decryptConfig(configBytes);
        if (config.size() && config.find("Secgram") == 0) {
            loadConfig(config.substr(7));
            configured = true;
        } else {
            fprintf(stderr, "Failed to load config\n");
        }
    } else {
        fprintf(stderr, "Empty password\n");
    }
}

void SecgramCore::test() {
    auto ava = eckey_gen();
    auto avaSv = eckey_gen();
    auto avaPub = eckey_pub(ava);
    auto avaSign = ecdsa_sign(avaPub, avaSv);

    auto bella = eckey_gen();
    auto bellaSv = eckey_gen();
    auto bellaPub = eckey_pub(bella);
    auto bellaSign = ecdsa_sign(bellaPub, bellaSv);

    auto avaVerify = ecdsa_verify(avaPub, avaSign, avaSv);
    auto bellaVerify = ecdsa_verify(bellaPub, bellaSign, bellaSv);

    auto avaKey = ecdh_compute_key(bellaPub, ava);
    auto bellaKey = ecdh_compute_key(avaPub, bella);

    auto cmp = avaKey.size() == bellaKey.size() && memcmp(avaKey.data(), bellaKey.data(), avaKey.size()) == 0;
    fprintf(stderr, "Handshake test result = %d\n", cmp);

    buf aesKey(avaKey.data(), avaKey.data() + 32);
    buf aesIv(avaKey.data() + 32, avaKey.data() + 44);
    std::string text = "TestTestTestTestTestTestTestTest111";
    buf plain = str_to_buf(text);
    auto cipher = aes_gcm_encrypt(aesKey, aesIv, plain);
    auto plain2 = aes_gcm_decrypt(aesKey, aesIv, cipher);
    cmp = buf_to_str(plain) == text;

    fprintf(stderr, "AES test result = %d\n", cmp);
}

buf SecgramCore::read_all_bytes(std::string path) {
    auto fp = fopen(path.c_str(), "r");
    if (!fp) {
        fprintf(stderr, "Failed to read %s\n", path.c_str());
        return buf();
    }

    fseek(fp, 0, SEEK_END);
    auto fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buf ret(fileSize);
    fread(ret.data(), 1, fileSize, fp);

    fclose(fp);
    return ret;
}

std::string SecgramCore::read_all_texts(std::string path) {
    auto bytes = read_all_bytes(path);
    return std::string((char *)bytes.data(), bytes.size());
}

void SecgramCore::write_all_bytes(std::string path, buf bytes) {
    auto fp = fopen(path.c_str(), "w");
    if (!fp) {
        fprintf(stderr, "Failed to write %s\n", path.c_str());
        return;
    }

    fwrite(bytes.data(), 1, bytes.size(), fp);
    fclose(fp);
}

void SecgramCore::write_all_texts(std::string path, std::string s) { write_all_bytes(path, buf(s.begin(), s.end())); }

std::string SecgramCore::decryptConfig(buf b) {

    // Expand Key
    auto extracted = hkdf_extract(str_to_buf(password), str_to_buf("SecgramPassword"));
    auto expanded = hkdf_expand(extracted, str_to_buf("SecgramPasswordExpanded"), 44);

    auto key = expanded.data();
    auto iv = expanded.data() + 32;

    buf decrypted = aes_gcm_decrypt(buf(key, key + 32), buf(iv, iv + 12), b);

    return buf_to_str(decrypted);
}

buf SecgramCore::aes_gcm_decrypt(buf key, buf iv, buf cipherWithTag) {
    int len, ret;
    buf cipher(cipherWithTag.data(), cipherWithTag.data() + cipherWithTag.size() - 16);
    buf tag(cipherWithTag.data() + cipherWithTag.size() - 16, cipherWithTag.data() + cipherWithTag.size());
    buf decrypted(cipher.size());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());
    EVP_DecryptUpdate(ctx, decrypted.data(), &len, cipher.data(), cipher.size());
    ret = EVP_DecryptFinal_ex(ctx, nullptr, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ret == 1 ? decrypted : str_to_buf("AES GCM TAG Verify Failed.");
}

buf SecgramCore::aes_gcm_encrypt(buf key, buf iv, buf plain) {
    int len, ret;
    buf encrypted(plain.size());
    buf tag(16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, encrypted.data(), &len, plain.data(), plain.size());
    ret = EVP_EncryptFinal_ex(ctx, nullptr, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data());
    EVP_CIPHER_CTX_free(ctx);
    encrypted.insert(encrypted.end(), tag.begin(), tag.end());
    return encrypted;
}

buf SecgramCore::aes_gcm_decrypt_notag(buf key, buf iv, buf cipher) {
    int len, ret;
    buf decrypted(cipher.size());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, decrypted.data(), &len, cipher.data(), cipher.size());
    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

buf SecgramCore::aes_gcm_encrypt_notag(buf key, buf iv, buf plain) {
    int len, ret;
    buf encrypted(plain.size());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, encrypted.data(), &len, plain.data(), plain.size());
    EVP_CIPHER_CTX_free(ctx);
    return encrypted;
}

void SecgramCore::loadConfig(std::string json) {
    auto j = njson::parse(json);
    certStoreVersion = j["cert_store_version"].get<std::string>();
    fprintf(stderr, "Cert store version %s\n", certStoreVersion.c_str());
    for (auto cert : j["certs"]) {
        uint64_t peerId = cert["peer_id"].get<uint64_t>();
        std::string priKey = cert.contains("pri_key") ? !cert["pri_key"].is_null() ? cert["pri_key"].get<std::string>() : std::string() : std::string();
        std::string pubKey = cert["pub_key"].get<std::string>();
        auto u = std::make_shared<SecgramUser>();
        if (!priKey.empty()) {
            u->privateSignKey = eckey_load_private(priKey);
        }
        u->publicVerifyKey = eckey_load_public(pubKey);
        u->peerId = peerId;

        users[peerId] = u;

        fprintf(stderr, "Load cert %llu pub %p pri %p\n", peerId, u->publicVerifyKey, u->privateSignKey);
    }
}

buf SecgramCore::base64_encode(buf data) {
    static constexpr char sEncodingTable[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                              'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                                              's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

    size_t in_len = data.size();
    size_t out_len = 4 * ((in_len + 2) / 3);
    buf ret(out_len);
    size_t i;
    char *p = reinterpret_cast<char *>(ret.data());

    for (i = 0; i < in_len - 2; i += 3) {
        *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
        *p++ = sEncodingTable[((data[i] & 0x3) << 4) | ((int)(data[i + 1] & 0xF0) >> 4)];
        *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2) | ((int)(data[i + 2] & 0xC0) >> 6)];
        *p++ = sEncodingTable[data[i + 2] & 0x3F];
    }
    if (i < in_len) {
        *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
        if (i == (in_len - 1)) {
            *p++ = sEncodingTable[((data[i] & 0x3) << 4)];
            *p++ = '=';
        } else {
            *p++ = sEncodingTable[((data[i] & 0x3) << 4) | ((int)(data[i + 1] & 0xF0) >> 4)];
            *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2)];
        }
        *p++ = '=';
    }

    return ret;
}

buf SecgramCore::base64_decode(buf input) {
    static constexpr unsigned char kDecodingTable[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        62, 64, 64, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};

    size_t in_len = input.size();
    if (in_len % 4 != 0)
        return buf();

    size_t out_len = in_len / 4 * 3;
    if (input[in_len - 1] == '=')
        out_len--;
    if (input[in_len - 2] == '=')
        out_len--;

    buf out(out_len);

    for (size_t i = 0, j = 0; i < in_len;) {
        uint32_t a = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];
        uint32_t b = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];
        uint32_t c = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];
        uint32_t d = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];

        uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

        if (j < out_len)
            out[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < out_len)
            out[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < out_len)
            out[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return out;
}

EC_KEY *SecgramCore::eckey_gen() {
    auto *ecKey = EC_KEY_new();
    auto *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
    EC_KEY_set_group(ecKey, group);
    EC_KEY_generate_key(ecKey);
    return ecKey;
}

buf SecgramCore::eckey_pub(EC_KEY *key) {
    auto point = EC_KEY_get0_public_key(key);
    auto group = EC_KEY_get0_group(key);
    auto size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    auto ret = buf(size);
    size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, ret.data(), ret.size(), nullptr);
    ret.resize(size);
    return ret;
}

EC_KEY *SecgramCore::eckey_load_private(std::string s) {
    auto *bio = BIO_new(BIO_s_mem());

    int bio_ret = BIO_write(bio, static_cast<const char *>(s.c_str()), s.size());
    if (bio_ret <= 0) {
        BIO_free(bio);
        return nullptr;
    }

    EC_KEY *ecKey = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!ecKey) {
        return nullptr;
    }

    return ecKey;
}
std::string SecgramCore::eckey_save_private(EC_KEY *k) {
    auto *bio = BIO_new(BIO_s_mem());

    PEM_write_bio_ECPrivateKey(bio, k, nullptr, nullptr, 0, nullptr, nullptr);

    auto bytes = BIO_get_mem_data(bio, NULL);
    std::string ret(bytes, '\0');

    int bio_ret = BIO_read(bio, ret.data(), ret.size());
    BIO_free(bio);

    if (bio_ret <= 0) {
        return std::string();
    }

    return ret;
}

EC_KEY *SecgramCore::eckey_load_public(std::string s) {
    auto *bio = BIO_new(BIO_s_mem());

    int bio_ret = BIO_write(bio, static_cast<const char *>(s.c_str()), s.size());
    if (bio_ret <= 0) {
        BIO_free(bio);
        return nullptr;
    }

    EC_KEY *ecKey = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!ecKey) {
        return nullptr;
    }

    return ecKey;
}
std::string SecgramCore::eckey_save_public(EC_KEY *k) {
    auto *bio = BIO_new(BIO_s_mem());

    PEM_write_bio_EC_PUBKEY(bio, k);

    auto bytes = BIO_get_mem_data(bio, NULL);
    std::string ret(bytes, '\0');

    int bio_ret = BIO_read(bio, ret.data(), ret.size());
    BIO_free(bio);

    if (bio_ret <= 0) {
        return std::string();
    }

    return ret;
}

buf SecgramCore::ecdsa_sign(buf publicKey, EC_KEY *signKey) {
    auto size = ECDSA_size(signKey);
    auto ret = buf(size);
    unsigned int sig_len;
    ECDSA_sign(0, publicKey.data(), publicKey.size(), ret.data(), &sig_len, signKey);
    ret.resize(sig_len);
    return ret;
}

bool SecgramCore::ecdsa_verify(buf publicKey, buf signature, EC_KEY *verifyKey) {
    return ECDSA_verify(0, publicKey.data(), publicKey.size(), signature.data(), signature.size(), verifyKey) == 1;
}

buf SecgramCore::ecdh_compute_key(buf publicKey, EC_KEY *privateKey) {
    auto group = EC_KEY_get0_group(privateKey);
    auto pub = EC_POINT_new(group);
    EC_POINT_oct2point(group, pub, publicKey.data(), publicKey.size(), nullptr);
    buf ret(128);
    auto size = ECDH_compute_key(ret.data(), ret.size(), pub, privateKey, nullptr);
    ret.resize(size);
    EC_POINT_free(pub);
    return ret;
}

buf SecgramCore::hkdf_extract(buf key, buf salt) {

    size_t hash_len = 32;

    buf extracted(hash_len);
    size_t outlen = hash_len;

    size_t ret = HKDF_extract(extracted.data(), &outlen, EVP_sha256(), key.data(), key.size(), salt.data(), salt.size());

    extracted.resize(outlen);
    return extracted;
}

buf SecgramCore::hkdf_expand(buf extracted, buf info, size_t length) {

    buf expanded(length);

    size_t ret = HKDF_expand(expanded.data(), length, EVP_sha256(), extracted.data(), extracted.size(), info.data(), info.size());

    return expanded;
}

std::string SecgramCore::getDatabaseBasePath() { return basePath + "/account-" + std::to_string((uint64_t)currentAuthKeyId) + "/postbox"; }

std::string SecgramCore::getBasicInfo() {
    struct __attribute__((packed)) BasicInfo {
        int32_t configured;
        char certStoreVersion[128];
        uint64_t peerId;
        uint64_t authKeyId;
    };

    BasicInfo basic = {};
    basic.configured = configured ? 0xffffffff : 0;

    memcpy(basic.certStoreVersion, certStoreVersion.c_str(), certStoreVersion.size());
    basic.peerId = currentPeerId;
    basic.authKeyId = currentAuthKeyId;

    std::string ret((char *)&basic, sizeof(BasicInfo));
    return ret;
}

std::string SecgramCore::getPassword() { return password; }

void SecgramCore::setConfig(buf config) { write_all_bytes(dirRoot + "/config.json", config); }

std::shared_ptr<SecgramSession> SecgramCore::getSession(uint64_t localPeerId, uint64_t remotePeer) {

    if (remotePeer == localPeerId)
        return std::shared_ptr<SecgramSession>(nullptr);

    for (auto sess : sessions) {
        if (sess->localPeerId == localPeerId && sess->remotePeerId == remotePeer) {
            fprintf(stderr, "Secgram use temp session %llu %llu\n", localPeerId, remotePeer);
            return sess;
        }
    }

    return nullptr;
}

std::shared_ptr<SecgramSession> SecgramCore::getDefaultSession(uint64_t localPeerId, uint64_t remotePeerId) {

    if (remotePeerId == localPeerId)
        return std::shared_ptr<SecgramSession>(nullptr);

    fprintf(stderr, "Secgram use default session %llu %llu\n", localPeerId, remotePeerId);

    for (auto sess : defaultSessions) {
        if (sess->localPeerId == localPeerId && sess->remotePeerId == remotePeerId) {
            return sess;
        }
    }

    // Create default session
    if (users.contains(localPeerId) && users.contains(remotePeerId)) {
        auto local = users[localPeerId];
        auto remote = users[remotePeerId];
        auto pri = local->privateSignKey;
        auto pub = eckey_pub(remote->publicVerifyKey);
        if (pri == nullptr) {
            pri = remote->privateSignKey;
            pub = eckey_pub(local->publicVerifyKey);
        }

        if (pri != nullptr) {
            auto key = ecdh_compute_key(pub, pri);
            auto extract = hkdf_extract(key, str_to_buf("DefaultSession"));
            auto expand = hkdf_expand(extract, str_to_buf("DefaultSession"), 44);

            auto ckey = buf(expand.data(), expand.data() + 32);
            auto civ = buf(expand.data() + 32, expand.data() + 44);

            auto sess = std::make_shared<SecgramSession>();
            sess->localPeerId = localPeerId;
            sess->remotePeerId = remotePeerId;
            sess->key = ckey;
            sess->iv = civ;

            defaultSessions.push_back(sess);
            return sess;
        }
    }

    return std::shared_ptr<SecgramSession>(nullptr);
}

std::string SecgramCore::encryptTextMessage(uint64_t localPeerId, uint64_t remotePeerId, std::string content) {
    if (content.empty())
        return content;

    uint8_t type = 0;
    auto sess = getSession(localPeerId, remotePeerId);
    if (sess == nullptr) {
        sess = getDefaultSession(localPeerId, remotePeerId);
    } else {
        type = 0xff;
    }

    if (sess == nullptr) {
        fprintf(stderr, "Secgram skip encrypt text %llu %llu\n", localPeerId, remotePeerId);
        return content;
    }

    auto local = users[localPeerId];
    auto remote = users[remotePeerId];
    std::string text = "Secg";
    int length = content.size();
    text += std::string((char *)&length, 4);
    text += content;

    if (content == ".sec" && local->privateSignKey != nullptr) {
        fprintf(stderr, "Secgram 1 create new temp session\n");
        auto sessKey = eckey_gen();
        auto sessKeyPub = eckey_pub(sessKey);
        auto sessKeyPubSign = ecdsa_sign(sessKeyPub, local->privateSignKey);

        PendingSession p;
        p.localKey = sessKey;
        p.localPub = sessKeyPub;
        p.localPubSign = sessKeyPubSign;
        pendingSessions[remotePeerId] = p;

        int len = sessKeyPub.size();
        text += std::string((char *)&len, 4);
        text += buf_to_str(sessKeyPub);
        len = sessKeyPubSign.size();
        text += std::string((char *)&len, 4);
        text += buf_to_str(sessKeyPubSign);

    } else if (content == ".ok" && pendingSessions.contains(remotePeerId)) {
        fprintf(stderr, "Secgram 3 accept new temp session\n");
        auto p = pendingSessions[remotePeerId];

        if (!p.remotePub.empty() && !p.remotePubSign.empty()) {
            auto verify = ecdsa_verify(p.remotePub, p.remotePubSign, remote->publicVerifyKey);
            fprintf(stderr, "Secgram verify %d\n", verify);

            if (verify) {
                auto sharedKey = ecdh_compute_key(p.remotePub, p.localKey);

                auto extract = hkdf_extract(sharedKey, str_to_buf("DefaultSession"));
                auto expand = hkdf_expand(extract, str_to_buf("DefaultSession"), 88);

                auto ckey = buf(expand.data(), expand.data() + 32);
                auto civ = buf(expand.data() + 32, expand.data() + 44);

                auto sess = std::make_shared<SecgramSession>();
                sess->localPeerId = localPeerId;
                sess->remotePeerId = remotePeerId;
                sess->key = ckey;
                sess->iv = civ;

                sessions.push_back(sess);
                fprintf(stderr, "Secgram new temp session created\n");

                int len = p.localPub.size();
                text += std::string((char *)&len, 4);
                text += buf_to_str(p.localPub);
                len = p.localPubSign.size();
                text += std::string((char *)&len, 4);
                text += buf_to_str(p.localPubSign);

                pendingSessions.erase(remotePeerId);
                uint64_t sessId = *(uint64_t*)sharedKey.data();
                showPopup("Security Enhanced", "Temporary Session ID\n" + std::to_string(sessId));
            }
        }
    }

    buf encrypted = aes_gcm_encrypt(sess->key, sess->iv, str_to_buf(text));
    buf typeTag = buf(&type, &type + 1);
    encrypted.insert(encrypted.begin(), typeTag.begin(), typeTag.end());
    auto bytes = base64_encode(encrypted);

    return buf_to_str(bytes);
}

std::string SecgramCore::decryptTextMessage(uint64_t localPeerId, uint64_t remotePeerId, std::string content) {
    if (content.empty())
        return content;

    auto local = users[localPeerId];
    auto remote = users[remotePeerId];
    auto bytesAll = base64_decode(str_to_buf(content));
    if (bytesAll.size() < 1)
        return content;

    auto type = bytesAll[0];
    if (type != 0 && type != 0xff) {
        return content;
    }

    std::shared_ptr<SecgramSession> sess = nullptr;
    if (type == 0) {
        sess = getDefaultSession(localPeerId, remotePeerId);
        std::erase_if(sessions, [&](const auto &item) { return item->localPeerId == localPeerId && item->remotePeerId == remotePeerId; });
    } else if (type == 0xff) {
        sess = getSession(localPeerId, remotePeerId);
    }

    if (sess == nullptr) {
        fprintf(stderr, "Secgram skip decrypt text %llu %llu\n", localPeerId, remotePeerId);
        return content;
    }

    auto bytes = buf(bytesAll.begin() + 1, bytesAll.end());
    buf decrypted = aes_gcm_decrypt(sess->key, sess->iv, bytes);
    std::string ret = content;

    if (decrypted.size() > 8) {
        std::string tag = buf_to_str(buf(decrypted.data(), decrypted.data() + 4));
        if (tag == "Secg") {
            int size = *(int *)(decrypted.data() + 4);
            std::string text = buf_to_str(buf(decrypted.data() + 8, decrypted.data() + 8 + size));
            buf param = buf(decrypted.begin() + 8 + size, decrypted.end());
            ret = text;

            if (localPeerId == currentPeerId && !param.empty()) {
                if (text == ".sec") {
                    fprintf(stderr, "Secgram 2 receive new temp session\n");
                    int pubSize = *(int *)param.data();
                    buf pubKey = buf(param.data() + 4, param.data() + 4 + pubSize);
                    int signSize = *(int *)(param.data() + 4 + pubSize);
                    buf pubSign = buf(param.begin() + 8 + pubSize, param.end());

                    auto sessKey = eckey_gen();
                    auto sessKeyPub = eckey_pub(sessKey);
                    auto sessKeyPubSign = ecdsa_sign(sessKeyPub, local->privateSignKey);

                    PendingSession p;
                    p.localKey = sessKey;
                    p.localPub = sessKeyPub;
                    p.localPubSign = sessKeyPubSign;
                    p.remotePub = pubKey;
                    p.remotePubSign = pubSign;
                    pendingSessions[remotePeerId] = p;

                } else if (text == ".ok") {
                    fprintf(stderr, "Secgram 4 confirm new temp session\n");
                    int pubSize = *(int *)param.data();
                    buf pubKey = buf(param.data() + 4, param.data() + 4 + pubSize);
                    int signSize = *(int *)(param.data() + 4 + pubSize);
                    buf pubSign = buf(param.begin() + 8 + pubSize, param.end());

                    auto p = pendingSessions[remotePeerId];
                    p.remotePub = pubKey;
                    p.remotePubSign = pubSign;

                    auto verify = ecdsa_verify(p.remotePub, p.remotePubSign, remote->publicVerifyKey);
                    fprintf(stderr, "Secgram verify %d\n", verify);

                    if (verify) {
                        auto sharedKey = ecdh_compute_key(p.remotePub, p.localKey);

                        auto extract = hkdf_extract(sharedKey, str_to_buf("DefaultSession"));
                        auto expand = hkdf_expand(extract, str_to_buf("DefaultSession"), 88);

                        auto ckey = buf(expand.data(), expand.data() + 32);
                        auto civ = buf(expand.data() + 32, expand.data() + 44);

                        auto sess = std::make_shared<SecgramSession>();
                        sess->localPeerId = localPeerId;
                        sess->remotePeerId = remotePeerId;
                        sess->key = ckey;
                        sess->iv = civ;

                        sessions.push_back(sess);
                        fprintf(stderr, "Secgram new temp session created\n");
                        pendingSessions.erase(remotePeerId);

                        uint64_t sessId = *(uint64_t*)sharedKey.data();
                        showPopup("Security Enhanced", "Temporary Session ID\n" + std::to_string(sessId));
                    }
                }
            }
        }
    }

    return ret;
}

uint64_t SecgramCore::randomUInt64() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    return dis(gen);
}

void SecgramCore::linkMediaWithPeers(uint64_t mediaId, uint64_t senderId, uint64_t receiverId) {
    SRPeerInfo i;
    i.senderId = senderId;
    i.receiverId = receiverId;
    srPeerInfos[mediaId] = i;
    fprintf(stderr, "Secgram link media %llu to %llu %llu\n", mediaId, senderId, receiverId);
}

uint64_t SecgramCore::createMediaEncryptor(uint64_t mediaId) {
    if (!srPeerInfos.contains(mediaId)) {
        fprintf(stderr, "Secgram skip encrypt media %llu\n", mediaId);
        return 0;
    }

    auto info = srPeerInfos[mediaId];
    auto sess = getDefaultSession(info.senderId, info.receiverId);
    if (sess == nullptr) {
        fprintf(stderr, "Secgram skip encrypt media %llu\n", mediaId);
        return 0;
    }

    auto e = new SecgramEncryptor(sess->key, sess->iv);
    auto id = randomUInt64();
    fprintf(stderr, "Secgram encrypt media %llu %llu\n", mediaId, id);
    encryptors[id] = e;
    return id;
}
uint64_t SecgramCore::createMediaDecryptor(uint64_t mediaId) {

    if (!srPeerInfos.contains(mediaId)) {
        fprintf(stderr, "Secgram skip decrypt media %llu\n", mediaId);
        return 0;
    }

    auto info = srPeerInfos[mediaId];
    auto sess = getDefaultSession(info.receiverId, info.senderId);
    if (sess == nullptr) {
        fprintf(stderr, "Secgram skip decrypt media %llu\n", mediaId);
        return 0;
    }

    auto d = new SecgramDecryptor(sess->key, sess->iv);
    auto id = randomUInt64();
    fprintf(stderr, "Secgram decrypt media %llu %llu\n", mediaId, id);
    decryptors[id] = d;
    return id;
}
buf SecgramCore::encryptMedia(uint64_t encryptorId, buf data) {
    if (!encryptors.contains(encryptorId)) {
        return data;
    }
    auto e = encryptors[encryptorId];
    fprintf(stderr, "Secgram encrypt %llu %d\n", encryptorId, data.size());
    return e->encrypt(data);
}
buf SecgramCore::decryptMedia(uint64_t decryptorId, buf data) {
    if (!decryptors.contains(decryptorId)) {
        return data;
    }
    auto d = decryptors[decryptorId];
    fprintf(stderr, "Secgram decrypt %llu %d\n", decryptorId, data.size());
    return d->decrypt(data);
}
void SecgramCore::freeMediaEncryptor(uint64_t encryptorId) {
    if (!encryptors.contains(encryptorId)) {
        return;
    }

    fprintf(stderr, "Secgram encrypt free %llu\n", encryptorId);
    delete encryptors[encryptorId];
    encryptors.erase(encryptorId);
}
void SecgramCore::freeMediaDecryptor(uint64_t decryptorId) {
    if (!decryptors.contains(decryptorId)) {
        return;
    }

    fprintf(stderr, "Secgram decrypt free %llu\n", decryptorId);
    delete decryptors[decryptorId];
    decryptors.erase(decryptorId);
}

void SecgramCore::linkCallWithPeers(uint64_t callId, uint64_t localId, uint64_t remoteId) {
    LRPeerInfo i;
    i.localId = localId;
    i.remoteId = remoteId;
    lrPeerInfos[callId] = i;
    fprintf(stderr, "Secgram link call %llu to %llu %llu\n", callId, localId, remoteId);
}

buf SecgramCore::encryptCallData(uint64_t callId, buf data) {
    if (!lrPeerInfos.contains(callId)) {
        fprintf(stderr, "Secgram skip encrypt call %llu\n", callId);
        return data;
    }

    auto info = lrPeerInfos[callId];
    auto sess = getDefaultSession(info.localId, info.remoteId);
    if (sess == nullptr) {
        fprintf(stderr, "Secgram skip encrypt call %llu\n", callId);
        return data;
    }

    fprintf(stderr, "Secgram encrypt call %llu\n", callId);
    return aes_gcm_encrypt_notag(sess->key, sess->iv, data);
}

buf SecgramCore::decryptCallData(uint64_t callId, buf data) {
    if (!lrPeerInfos.contains(callId)) {
        fprintf(stderr, "Secgram skip decrypt call %llu\n", callId);
        return data;
    }

    auto info = lrPeerInfos[callId];
    auto sess = getDefaultSession(info.localId, info.remoteId);
    if (sess == nullptr) {
        fprintf(stderr, "Secgram skip decrypt call %llu\n", callId);
        return data;
    }

    fprintf(stderr, "Secgram decrypt call %llu\n", callId);
    return aes_gcm_decrypt_notag(sess->key, sess->iv, data);
}
