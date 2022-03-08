#include "SecgramConfigServer.hpp"
#include "SecgramCore.hpp"
#include <vector>

void SecgramConfigServer::run() {
    if (!wsserver.init("0.0.0.0", 43644)) {
        std::cout << "wsserver init failed: " << wsserver.getLastError() << std::endl;
        return;
    }
    admincmd_help = "Server help:\n"
                    "login password\n"
                    "echo str\n"
                    "stop\n";

    running = true;
    ws_thr = std::thread([this]() {
        while (running.load(std::memory_order_relaxed)) {
            wsserver.poll(this);
            std::this_thread::yield();
        }
    });

    std::cout << "Server running..." << std::endl;
}

void SecgramConfigServer::stop() {
    running = false;
    ws_thr.join();
    std::cout << "Server stopped..." << std::endl;
}

bool SecgramConfigServer::onWSConnect(WSConn &conn, const char *request_uri, const char *host, const char *origin, const char *protocol, const char *extensions,
                                      char *resp_protocol, uint32_t resp_protocol_size, char *resp_extensions, uint32_t resp_extensions_size) {
    struct sockaddr_in addr;
    conn.getPeername(addr);
    std::cout << "ws connection from: " << inet_ntoa(addr.sin_addr) << ":" << ntohs(addr.sin_port) << std::endl;
    std::cout << "request_uri: " << request_uri << std::endl;
    std::cout << "host: " << host << std::endl;
    if (origin) {
        std::cout << "origin: " << origin << std::endl;
    }
    if (protocol) {
        std::cout << "protocol: " << protocol << std::endl;
    }
    if (extensions) {
        std::cout << "extensions: " << extensions << std::endl;
    }
    return true;
}

void SecgramConfigServer::onWSClose(WSConn &conn, uint16_t status_code, const char *reason) {
    std::cout << "ws close, status_code: " << status_code << ", reason: " << reason << std::endl;
}

void SecgramConfigServer::onWSMsg(WSConn &conn, uint8_t opcode, const uint8_t *payload, uint32_t pl_len) {
    if (opcode == websocket::OPCODE_PING) {
        conn.send(websocket::OPCODE_PONG, payload, pl_len);
        return;
    }
    const char *data = (const char *)payload;
    if (opcode == websocket::OPCODE_BINARY || opcode == websocket::OPCODE_TEXT) {
        std::string resp = onCMD(conn.user_data, data, pl_len);
        if (resp.size())
            conn.send(websocket::OPCODE_BINARY, (const uint8_t *)resp.data(), resp.size());
    }
}

void SecgramConfigServer::onWSSegment(WSConn &conn, uint8_t opcode, const uint8_t *payload, uint32_t pl_len, uint32_t pl_start_idx, bool fin) {
    std::cout << "error: onWSSegment should not be called" << std::endl;
}

std::string SecgramConfigServer::onCMD(CMDConnData &conn, const char *buf, int size) {
    std::string resp;
    auto cmd = *(int32_t *)buf;
    auto data = buf + 4;
    auto dataSize = size - 4;

    // Get Database
    switch (cmd) {
    case CmdType::GetBasicInfo: {
        resp = core->getBasicInfo();
        break;
    }
    case CmdType::GetDatabaseFile: {
        auto dbFile = core->getDatabaseBasePath() + "/db/db_sqlite";
        auto bytes = SecgramCore::read_all_bytes(dbFile);
        resp = std::string((char *)bytes.data(), bytes.size());
        break;
    }
    case CmdType::SetConfig: {
        auto pwdReal = core->getPassword();
        auto pwdLen = *(int32_t *)data;
        data += 4;
        if (pwdLen > 64) {
            resp = "Wrong Password";
            break;
        }
        auto pwd = std::string((char *)data, pwdLen);
        data += pwdLen;
        if (pwd != pwdReal && !pwdReal.empty()) {
            resp = "Wrong Password";
            break;
        }
        auto configLen = *(int32_t *)data;
        data += 4;
        auto config = std::vector<uint8_t>((uint8_t *)data, (uint8_t *)data + configLen);
        core->setConfig(config);

        resp = "OK";
    }
    }
    int length = resp.size();
    resp = std::string((char *)&length, 4) + resp;
    resp = std::string((char *)&cmd, 4) + resp;
    return resp;
}
