#pragma once
#include "../../../core/include/INetworkInterface.h"
#include <Arduino.h>
#include "esp_wifi.h"

class Esp32Network : public INetworkInterface {
public:
    Esp32Network();
    void init() override;
    void startPromiscuous(PacketCallback cb, int channel) override;
    void stopPromiscuous() override;
    void getMacAddress(uint8_t* mac) override;
    void getBssid(uint8_t* bssid) override;
    bool injectFrame(const uint8_t* frame, int length) override;

private:
    static PacketCallback currentCb;
    static void IRAM_ATTR promiscuousRxCallback(void* buf, wifi_promiscuous_pkt_type_t type);
};
