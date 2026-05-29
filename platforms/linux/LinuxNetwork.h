#pragma once
#include "../../core/include/INetworkInterface.h"
#include <string>

class LinuxNetwork : public INetworkInterface {
public:
    LinuxNetwork(const char* interfaceName);
    ~LinuxNetwork();
    void init() override;
    void startPromiscuous(PacketCallback cb, int channel) override;
    void stopPromiscuous() override;
    void getMacAddress(uint8_t* mac) override;
    void getBssid(uint8_t* bssid) override;
    bool injectFrame(const uint8_t* frame, int length) override;

private:
    std::string iface;
    int rawSocket;
    bool sniffing;
    PacketCallback currentCb;
    uint8_t ownMac[6];

    void getMacFromIface(const char* ifname, uint8_t* mac);
    static void* snifferThread(void* arg);
    pthread_t threadId;
};
