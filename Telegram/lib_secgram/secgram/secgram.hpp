#pragma once

#include <string>
#include <functional>
#include <vector>
#include <cstdint>
 
using buf = std::vector<uint8_t>;

class SecgramCore;
class __attribute__((visibility("default"))) Secgram {
    SecgramCore* core;
  public:
    static Secgram *init(std::string pwd, std::string path);
    static Secgram *me();
    
    void runServer();
    bool isConfigured();
    void setShowPopup(std::function<void(std::string, std::string)> func);

    std::string encryptTextMessage(std::string data, uint64_t senderId, uint64_t receiverId);
    std::string decryptTextMessage(std::string data);

    void linkMediaWithPeers(int64_t mediaId, uint64_t senderId, uint64_t receiverId);
    uint64_t createMediaEncryptor(int64_t mediaId);
    uint64_t createMediaDecryptor(int64_t mediaId);
    buf encryptMedia(uint64_t encrpytorId, buf data);
    buf decryptMedia(uint64_t decrpytorId, buf data);
    void freeMediaEncryptor(uint64_t encryptorId);
    void freeMediaDecryptor(uint64_t decryptorId);

    void linkCallWithPeers(uint64_t callId, uint64_t localId, uint64_t remoteId);
    buf encryptCallData(uint64_t callId, buf data);
    buf decryptCallData(uint64_t callId, buf data);
 
    void setCurrentPeerId(uint64_t peerId, uint64_t authKeyId);
    std::string getPassword();
};   
