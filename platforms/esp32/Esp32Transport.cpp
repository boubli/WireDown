#include "Esp32Transport.h"
#include <stdio.h>

Esp32Transport::Esp32Transport(const char* host, uint16_t port, const char* path) 
    : wsHost(host), wsPort(port), wsPath(path), connected(false), msgCb(nullptr) {
    wsClient.onMessage([this](WebsocketsMessage msg) { this->onWsMessage(msg); });
    wsClient.onEvent([this](WebsocketsEvent event, String data) { this->onWsEvent(event, data); });
}

void Esp32Transport::connect() {
    String url = String("ws://") + wsHost + ":" + wsPort + wsPath;
    Serial.printf("[WS] Connecting to %s ...\n", url.c_str());
    wsClient.connect(url);
}

void Esp32Transport::disconnect() {
    wsClient.close();
}

bool Esp32Transport::isConnected() {
    return connected;
}

void Esp32Transport::send(const std::string& payload) {
    if (connected) {
        wsClient.send(String(payload.c_str()));
    }
}

void Esp32Transport::poll() {
    wsClient.poll();
}

void Esp32Transport::setMessageCallback(MessageCallback cb) {
    msgCb = cb;
}

void Esp32Transport::onWsMessage(WebsocketsMessage msg) {
    if (msgCb) {
        msgCb(msg.data().c_str());
    }
}

void Esp32Transport::onWsEvent(WebsocketsEvent event, String data) {
    if (event == WebsocketsEvent::ConnectionOpened) {
        connected = true;
        Serial.println("[WS] Connected");
        
        // Send initial hello matching original code
        char hello[256];
        uint8_t mac[6];
        esp_wifi_get_mac(WIFI_IF_STA, mac);
        snprintf(hello, sizeof(hello), "{\"type\":\"esp32_hello\",\"uptime\":%lu,\"sensor_mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\"}",
                 millis(), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        send(std::string(hello));
        
    } else if (event == WebsocketsEvent::ConnectionClosed) {
        connected = false;
        Serial.println("[WS] Disconnected");
    } else if (event == WebsocketsEvent::GotPing) {
        wsClient.pong();
    }
}
