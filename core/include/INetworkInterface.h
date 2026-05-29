#pragma once
#include <stdint.h>

typedef void (*PacketCallback)(const uint8_t* buffer, int length, int rssi, int channel);

class INetworkInterface {
public:
    virtual ~INetworkInterface() = default;
    virtual void init() = 0;
    virtual void startPromiscuous(PacketCallback cb, int channel) = 0;
    virtual void stopPromiscuous() = 0;
    virtual void getMacAddress(uint8_t* mac) = 0;
    virtual void getBssid(uint8_t* bssid) = 0;
    virtual bool injectFrame(const uint8_t* frame, int length) = 0;
};
