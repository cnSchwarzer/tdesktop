#include "secgram.hpp"
#include "SecgramCore.hpp"

using buf = std::vector<uint8_t>;

static Secgram *instance;

Secgram *Secgram::me() { return instance; }

Secgram *Secgram::init(std::string pwd, std::string path) {
    instance = new Secgram();
    instance->core = new SecgramCore(pwd, path);
    return instance;
}

void Secgram::runServer() { core->runServer(); }

bool Secgram::isConfigured() { return core->isConfigured(); }

void Secgram::setShowPopup(std::function<void(std::string, std::string)> func) { core->setShowPopup(func); }

std::string Secgram::encryptTextMessage(std::string data, uint64_t senderId, uint64_t receiverId) {
    return core->encryptTextMessage(senderId, receiverId, data);
}
std::string Secgram::decryptTextMessage(std::string data) {
    return core->decryptTextMessage(data);
}

void Secgram::linkMediaWithPeers(int64_t mediaId, uint64_t senderId, uint64_t receiverId) {
    core->linkMediaWithPeers(mediaId, senderId, receiverId);
}
uint64_t Secgram::createMediaEncryptor(int64_t mediaId) { return core->createMediaEncryptor(mediaId); }
uint64_t Secgram::createMediaDecryptor(int64_t mediaId) { return core->createMediaDecryptor(mediaId); }
buf Secgram::encryptMedia(uint64_t encrpytorId, buf data) {
    buf ret = core->encryptMedia(encrpytorId, buf((char *)data.data(), (char*)data.data() + data.size()));
    return ret;
}
buf Secgram::decryptMedia(uint64_t decrpytorId, buf data) {
    buf ret = core->decryptMedia(decrpytorId, buf((char *)data.data(), (char*)data.data() + data.size()));
    return ret;
}
void Secgram::freeMediaEncryptor(uint64_t encryptorId) { core->freeMediaEncryptor(encryptorId); }
void Secgram::freeMediaDecryptor(uint64_t decryptorId) { core->freeMediaDecryptor(decryptorId); }

void Secgram::linkCallWithPeers(uint64_t callId, uint64_t localId, uint64_t remoteId) {
    core->linkCallWithPeers(callId, localId, remoteId);
}
buf Secgram::encryptCallData(uint64_t callId, buf data) {
    buf ret = core->encryptCallData(callId, data);
    return ret;
}
buf Secgram::decryptCallData(uint64_t callId, buf data) {
    buf ret = core->decryptCallData(callId, data);
    return ret;
}
 
void Secgram::setCurrentPeerId(uint64_t peerId, uint64_t authKeyId) {
    core->setCurrentPeerId(peerId);
    core->setCurrentAuthKeyId(authKeyId);
}
std::string Secgram::getPassword() { return core->getPassword(); }
