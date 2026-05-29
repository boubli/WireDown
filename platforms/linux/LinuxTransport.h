#pragma once
#include "../../core/include/ITransport.h"
#include <string>

class LinuxTransport : public ITransport {
public:
    LinuxTransport(const char* host, uint16_t port);
    ~LinuxTransport();
    void connect() override;
    void disconnect() override;
    bool isConnected() override;
    void send(const std::string& payload) override;
    void poll() override;
    void setMessageCallback(MessageCallback cb) override;

private:
    std::string host;
    uint16_t port;
    int sockfd;
    bool connected;
    MessageCallback msgCb;
};
