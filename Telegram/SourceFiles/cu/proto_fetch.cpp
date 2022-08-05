#include "cu/proto_fetch.h"
#include "cu/json.hpp" 

using njson = nlohmann::json;

void Cu::ProtoFetch::start(std::function<void(MTP::ProxyData)> callback) {
    _callback = callback;
    DEBUG_LOG(("Fetch proto"));
    _manager = std::make_unique<QNetworkAccessManager>(this);
    _manager->setAutoDeleteReplies(true);
    _manager->setProxy(QNetworkProxy::DefaultProxy);
    connect(_manager.get(), &QNetworkAccessManager::finished, this, &Cu::ProtoFetch::onFinish);
    _manager->get(QNetworkRequest(QUrl("https://res.wintogo.biz/config/proto.txt"))); 
}

void Cu::ProtoFetch::onFinish(QNetworkReply* reply) {
    auto resp = reply->readAll();
    if (!reply->error()) {
        auto j = njson::parse(resp.data());
        DEBUG_LOG(("Fetched proto"));
        if (j["ok"].get<bool>()) {
            auto data = j["data"];
            auto server = data["server"].get<std::string>();
            auto port = data["port"].get<int>();
            auto secret = data["secret"].get<std::string>();
            MTP::ProxyData proto;
            proto.type = MTP::ProxyData::Type::Mtproto;
            proto.host = QString(server.c_str());
            proto.port = port;
            proto.password = QString(secret.c_str());
            _callback(proto);
        }
    }
}
