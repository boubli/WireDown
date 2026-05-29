#pragma once
#include "ISystem.h"
#include "ITransport.h"
#include "INetworkInterface.h"
#include <string>

class Engine {
public:
    Engine(ISystem* sys, ITransport* trans, INetworkInterface* net);
    ~Engine();

    void init();
    void loop();
    void isolateDevice(const std::string& macStr);

    // This must be static or a free function to be passed as a callback if not using std::function
    static void onPacketReceived(const uint8_t* buffer, int length, int rssi, int channel);
    static void onTransportMessage(const std::string& message);

private:
    ISystem* system;
    ITransport* transport;
    INetworkInterface* network;

    static Engine* instance; // For callbacks

    unsigned long lastHeartbeat;
    unsigned long lastReconnect;

    // Detectors state
    int deauthCount;
    int disassocCount;
    unsigned long lastDeauthReset;
    uint8_t lastDeauthSrcMac[6];

    int newMacCount;
    unsigned long macFloodWindowStart;

    void processPacket(const uint8_t* buffer, int length, int rssi, int channel);
    void handleMessage(const std::string& msg);
    
    void checkTimers();
    void sendHeartbeat();
    void sendAttackAlert(const char* attack, const uint8_t* mac, const std::string& detailsJson);
    
    bool isDuplicate(const uint8_t* mac);
    bool parseMacString(const std::string& macStr, uint8_t* out);
    std::string macToString(const uint8_t* mac);
    std::string ipToString(uint32_t ip);

    // Extracted structures
    struct SeenDevice {
        uint8_t mac[6];
        unsigned long lastSeen;
    };
    static const int MAX_SEEN = 128;
    SeenDevice seenDevices[MAX_SEEN];
    int seenCount;

    struct ArpMapping {
        uint32_t ip;
        uint8_t  mac[6];
        unsigned long lastSeen;
    };
    static const int MAX_ARP_ENTRIES = 64;
    ArpMapping arpTable[MAX_ARP_ENTRIES];
    int arpTableCount;

    struct EapolTracker {
        uint8_t  clientMac[6];
        int      msg3Count;
        unsigned long windowStart;
    };
    static const int MAX_EAPOL_TRACKERS = 32;
    EapolTracker eapolTrackers[MAX_EAPOL_TRACKERS];
    int eapolTrackerCount;
};
