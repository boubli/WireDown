#pragma once
#include "../../../core/include/ITransport.h"
#include <ArduinoWebsockets.h>
#include <Arduino.h>
#include "esp_wifi.h"

using namespace websockets;

class Esp32Transport : public ITransport {
public:
    Esp32Transport(const char* host, uint16_t port, const char* path);
    void connect() override;
    void disconnect() override;
    bool isConnected() override;
    void send(const std::string& payload) override;
    void poll() override;
    void setMessageCallback(MessageCallback cb) override;

private:
    WebsocketsClient wsClient;
    const char* wsHost;
    uint16_t wsPort;
    const char* wsPath;
    bool connected;
    MessageCallback msgCb;

    void onWsMessage(WebsocketsMessage msg);
    void onWsEvent(WebsocketsEvent event, String data);
};
