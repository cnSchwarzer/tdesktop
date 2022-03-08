#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <string>
#include <functional>

#include "SecgramCipher.hpp"
#include "SecgramConfigServer.hpp"
#include "SecgramData.hpp"

class SecgramCore {

    struct SRPeerInfo {
        uint64_t senderId;
        uint64_t receiverId;
    };
    struct LRPeerInfo {
        uint64_t localId;
        uint64_t remoteId;
    };
    struct PendingSession {
        EC_KEY* localKey;
        buf localPub;
        buf localPubSign;
        buf remotePub;
        buf remotePubSign;
    };

    public : SecgramCore(std::string password, std::string root);

    static void test();
    static uint64_t randomUInt64();

    static void write_all_texts(std::string path, std::string s);
    static void write_all_bytes(std::string path, buf b);
    static std::string read_all_texts(std::string path);
    static buf read_all_bytes(std::string path);

    static buf str_to_buf(std::string s) { return buf(s.begin(), s.end()); }
    static std::string buf_to_str(buf s) { return std::string((char *)s.data(), s.size()); }

    static bool is_base64(buf s);
    static buf base64_encode(buf s);
    static buf base64_decode(buf s);

    static buf aes_gcm_decrypt(buf key, buf iv, buf cipherWithTag);
    static buf aes_gcm_encrypt(buf key, buf iv, buf plain);
    static buf aes_gcm_decrypt_notag(buf key, buf iv, buf cipher);
    static buf aes_gcm_encrypt_notag(buf key, buf iv, buf plain);

    static EC_KEY *eckey_gen();
    static buf eckey_pub(EC_KEY *);
    static EC_KEY *eckey_load_private(std::string s);
    static std::string eckey_save_private(EC_KEY *k);
    static EC_KEY *eckey_load_public(std::string s);
    static std::string eckey_save_public(EC_KEY *k);

    static buf ecdsa_sign(buf publicKey, EC_KEY *signKey);
    static bool ecdsa_verify(buf publicKey, buf signature, EC_KEY *verifyKey);
    static buf ecdh_compute_key(buf publicKey, EC_KEY *privateKey);
    static buf hkdf_extract(buf key, buf salt);
    static buf hkdf_expand(buf extracted, buf info, size_t length);

    bool isConfigured() { return configured; }
    void runServer() { server.run(); }
    void setBasePath(std::string path) { basePath = path; }
    void setCurrentPeerId(int64_t id) { currentPeerId = id; }
    void setCurrentAuthKeyId(int64_t id) { currentAuthKeyId = id; }
    std::string getDatabaseBasePath();
    std::string getBasicInfo();
    std::string getPassword();
    void setConfig(buf config);

    std::string encryptTextMessage(uint64_t localPeerId, uint64_t remotePeerId, std::string content);
    std::string decryptTextMessage(uint64_t localPeerId, uint64_t remotePeerId, std::string content); 

    void linkMediaWithPeers(uint64_t mediaId, uint64_t senderId, uint64_t receiverId);
    uint64_t createMediaEncryptor(uint64_t mediaId);
    uint64_t createMediaDecryptor(uint64_t mediaId);
    buf encryptMedia(uint64_t encryptorId, buf data);
    buf decryptMedia(uint64_t decryptorId, buf data);
    void freeMediaEncryptor(uint64_t encryptorId);
    void freeMediaDecryptor(uint64_t decryptorId);

    void linkCallWithPeers(uint64_t callId, uint64_t localId, uint64_t remoteId);
    buf encryptCallData(uint64_t callId, buf data);
    buf decryptCallData(uint64_t callId, buf data);
    void setShowPopup(std::function<void(std::string, std::string)> func) {
        showPopup = func;
    }

  private:
    SecgramConfigServer server = SecgramConfigServer(this);

    std::function<void(std::string, std::string)> showPopup;

    std::string dirRoot;
    std::map<uint64_t, std::shared_ptr<SecgramUser>> users;
    std::vector<std::shared_ptr<SecgramSession>> defaultSessions;
    std::vector<std::shared_ptr<SecgramSession>> sessions;
    std::map<uint64_t, SRPeerInfo> srPeerInfos;
    std::map<uint64_t, LRPeerInfo> lrPeerInfos;

    std::map<uint64_t, SecgramEncryptor *> encryptors;
    std::map<uint64_t, SecgramDecryptor *> decryptors;

    std::map<uint64_t, PendingSession> pendingSessions;

    bool configured = false;
    int64_t currentPeerId = 0;
    int64_t currentAuthKeyId = 0;
    std::string basePath;
    std::string certStoreVersion;
    std::string password;

    std::string decryptConfig(buf b);
    void loadConfig(std::string json);
    std::shared_ptr<SecgramSession> getDefaultSession(uint64_t localPeerId, uint64_t remotePeerId);
    std::shared_ptr<SecgramSession> getSession(uint64_t localPeerId, uint64_t remotePeerId);
};
