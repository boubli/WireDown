#include "../include/Engine.h"
#include <stdio.h>
#include <string.h>

Engine* Engine::instance = nullptr;

Engine::Engine(ISystem* sys, ITransport* trans, INetworkInterface* net)
    : system(sys), transport(trans), network(net),
      lastHeartbeat(0), lastReconnect(0), deauthCount(0), disassocCount(0),
      lastDeauthReset(0), newMacCount(0), macFloodWindowStart(0),
      seenCount(0), arpTableCount(0), eapolTrackerCount(0) {
    instance = this;
    memset(lastDeauthSrcMac, 0, 6);
}

Engine::~Engine() {
    if (instance == this) instance = nullptr;
}

void Engine::init() {
    system->print("[ENGINE] Initializing core engine...\n");
    transport->setMessageCallback(&Engine::onTransportMessage);
    network->init();
    network->startPromiscuous(&Engine::onPacketReceived, 6);
    system->print("[ENGINE] Promiscuous mode started.\n");
    transport->connect();
}

void Engine::loop() {
    transport->poll();
    unsigned long now = system->getMillis();

    if (!transport->isConnected() && (now - lastReconnect > 3000)) {
        lastReconnect = now;
        transport->connect();
    }

    if (transport->isConnected() && (now - lastHeartbeat > 5000)) {
        lastHeartbeat = now;
        sendHeartbeat();
    }

    checkTimers();
}

void Engine::checkTimers() {
    unsigned long now = system->getMillis();

    // 2. Deauth Flood Check
    if (now - lastDeauthReset >= 1000) {
        int totalDeauth = deauthCount + disassocCount;
        if (totalDeauth > 10) {
            char details[256];
            snprintf(details, sizeof(details), "{\"count_per_sec\":%d,\"type\":\"%s\"}",
                     totalDeauth, deauthCount > disassocCount ? "deauth" : "disassoc");
            sendAttackAlert("deauth_flood", lastDeauthSrcMac, details);
        }
        deauthCount = 0;
        disassocCount = 0;
        lastDeauthReset = now;
    }

    // 3. MAC Flood Check
    if (now - macFloodWindowStart >= 5000) {
        if (newMacCount > 20) {
            uint8_t zeroMac[6] = {0};
            char details[256];
            snprintf(details, sizeof(details), "{\"new_macs_in_window\":%d,\"window_sec\":5}", newMacCount);
            sendAttackAlert("mac_flood", zeroMac, details);
        }
        newMacCount = 0;
        macFloodWindowStart = now;
    }
}

void Engine::sendHeartbeat() {
    char json[256];
    snprintf(json, sizeof(json), "{\"type\":\"heartbeat\",\"uptime\":%lu,\"free_heap\":%u}",
             system->getMillis(), system->getFreeMemory());
    transport->send(json);
}

void Engine::sendAttackAlert(const char* attack, const uint8_t* mac, const std::string& detailsJson) {
    char json[512];
    snprintf(json, sizeof(json), "{\"type\":\"attack_detected\",\"attack\":\"%s\",\"mac\":\"%s\",\"details\":%s,\"ts\":%lu}",
             attack, macToString(mac).c_str(), detailsJson.c_str(), system->getMillis());
    system->print(("[ATTACK] " + std::string(attack) + " detected from " + macToString(mac) + "\n").c_str());
    transport->send(json);
}

std::string Engine::macToString(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string Engine::ipToString(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return std::string(buf);
}

bool Engine::parseMacString(const std::string& macStr, uint8_t* out) {
    if (macStr.length() != 17) return false;
    unsigned int vals[6];
    int parsed = sscanf(macStr.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                        &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]);
    if (parsed != 6) return false;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)vals[i];
    return true;
}

bool Engine::isDuplicate(const uint8_t* mac) {
    unsigned long now = system->getMillis();
    for (int i = 0; i < seenCount; i++) {
        if (memcmp(seenDevices[i].mac, mac, 6) == 0) {
            if (now - seenDevices[i].lastSeen < 10000) {
                seenDevices[i].lastSeen = now;
                return true;
            }
            seenDevices[i].lastSeen = now;
            return false;
        }
    }
    newMacCount++;
    int idx = seenCount < MAX_SEEN ? seenCount++ : (now % MAX_SEEN);
    memcpy(seenDevices[idx].mac, mac, 6);
    seenDevices[idx].lastSeen = now;
    return false;
}

void Engine::isolateDevice(const std::string& macAddress) {
    system->print(("[ISOLATION] Targeting device: " + macAddress + "\n").c_str());

    uint8_t targetMac[6];
    if (!parseMacString(macAddress, targetMac)) {
        system->print("[ISOLATION] Invalid MAC format — aborting.\n");
        return;
    }

    uint8_t bssid[6];
    network->getBssid(bssid);

    uint8_t deauthFrame[26] = {
        0xC0, 0x00, 0x00, 0x00,
        targetMac[0], targetMac[1], targetMac[2], targetMac[3], targetMac[4], targetMac[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        0x00, 0x00, 0x07, 0x00
    };

    network->stopPromiscuous();

    const int BURST_COUNT = 20;
    for (int i = 0; i < BURST_COUNT; i++) {
        network->injectFrame(deauthFrame, sizeof(deauthFrame));
        system->delayMs(1);
    }

    network->startPromiscuous(&Engine::onPacketReceived, 6);

    char ack[256];
    snprintf(ack, sizeof(ack), "{\"type\":\"isolation_complete\",\"mac\":\"%s\",\"frames\":%d}",
             macAddress.c_str(), BURST_COUNT);
    transport->send(ack);
}

void Engine::onTransportMessage(const std::string& message) {
    if (!instance) return;
    instance->handleMessage(message);
}

void Engine::handleMessage(const std::string& msg) {
    // Simple naive JSON parsing to avoid dependencies in core
    if (msg.find("\"type\":\"isolate\"") != std::string::npos || msg.find("\"type\": \"isolate\"") != std::string::npos) {
        size_t macPos = msg.find("\"mac\"");
        if (macPos != std::string::npos) {
            size_t colonPos = msg.find(":", macPos);
            size_t startQuote = msg.find("\"", colonPos);
            size_t endQuote = msg.find("\"", startQuote + 1);
            if (startQuote != std::string::npos && endQuote != std::string::npos) {
                std::string mac = msg.substr(startQuote + 1, endQuote - startQuote - 1);
                isolateDevice(mac);
            }
        }
    } else if (msg.find("\"type\":\"ping\"") != std::string::npos) {
        transport->send("{\"type\":\"pong\"}");
    }
}

typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration_id:16;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    unsigned sequence_ctrl:16;
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0];
} wifi_ieee80211_packet_t;

void Engine::onPacketReceived(const uint8_t* buffer, int length, int rssi, int channel) {
    if (!instance) return;
    instance->processPacket(buffer, length, rssi, channel);
}

void Engine::processPacket(const uint8_t* buffer, int length, int rssi, int channel) {
    if (length < sizeof(wifi_ieee80211_mac_hdr_t)) return;

    const wifi_ieee80211_packet_t* ipkt = (const wifi_ieee80211_packet_t*)buffer;
    uint16_t frame_ctrl = ipkt->hdr.frame_ctrl;
    const uint8_t* srcMac = ipkt->hdr.addr2;

    uint8_t frameType = (frame_ctrl & 0x0C) >> 2;
    uint8_t frameSubtype = (frame_ctrl & 0xF0) >> 4;

    if (frameType == 0x00) {
        if (frameSubtype == 0x0C) {
            deauthCount++;
            memcpy(lastDeauthSrcMac, srcMac, 6);
        } else if (frameSubtype == 0x0A) {
            disassocCount++;
            memcpy(lastDeauthSrcMac, srcMac, 6);
        }
    }

    if (frameType == 0x02) { // DATA
        int macHdrLen = ((frame_ctrl & 0x0080) != 0) ? 26 : 24;
        if (length > macHdrLen) {
            const uint8_t* frameData = buffer + macHdrLen;
            int remainLen = length - macHdrLen;

            if (remainLen >= 8 && frameData[0] == 0xAA && frameData[1] == 0xAA && frameData[2] == 0x03 &&
                frameData[3] == 0x00 && frameData[4] == 0x00 && frameData[5] == 0x00) {
                
                uint16_t etherType = (frameData[6] << 8) | frameData[7];
                const uint8_t* llcPayload = frameData + 8;
                int llcPayloadLen = remainLen - 8;

                if (etherType == 0x0806 && llcPayloadLen >= 28) {
                    uint16_t arpOpcode = (llcPayload[6] << 8) | llcPayload[7];
                    if (arpOpcode == 2) {
                        const uint8_t* senderMac = llcPayload + 8;
                        uint32_t senderIp;
                        memcpy(&senderIp, llcPayload + 14, 4);

                        bool found = false;
                        for (int i = 0; i < arpTableCount; i++) {
                            if (arpTable[i].ip == senderIp) {
                                found = true;
                                if (memcmp(arpTable[i].mac, senderMac, 6) != 0) {
                                    char details[256];
                                    snprintf(details, sizeof(details), "{\"ip\":\"%s\",\"original_mac\":\"%s\",\"spoofed_mac\":\"%s\"}",
                                             ipToString(senderIp).c_str(), macToString(arpTable[i].mac).c_str(), macToString(senderMac).c_str());
                                    sendAttackAlert("arp_spoof", senderMac, details);
                                    memcpy(arpTable[i].mac, senderMac, 6);
                                }
                                arpTable[i].lastSeen = system->getMillis();
                                break;
                            }
                        }
                        if (!found) {
                            int idx = arpTableCount < MAX_ARP_ENTRIES ? arpTableCount++ : (system->getMillis() % MAX_ARP_ENTRIES);
                            arpTable[idx].ip = senderIp;
                            memcpy(arpTable[idx].mac, senderMac, 6);
                            arpTable[idx].lastSeen = system->getMillis();
                        }
                    }
                }

                if (etherType == 0x888E && llcPayloadLen >= 15) {
                    uint8_t eapolType = llcPayload[1];
                    if (eapolType == 3) {
                        uint16_t keyInfo = (llcPayload[5] << 8) | llcPayload[6];
                        bool installBit = (keyInfo >> 6) & 0x01;
                        bool ackBit = (keyInfo >> 7) & 0x01;

                        if (installBit && ackBit) {
                            const uint8_t* clientMac = ipkt->hdr.addr1;
                            const uint8_t* apBssid = ipkt->hdr.addr3;
                            unsigned long now = system->getMillis();

                            int trackerIdx = -1;
                            for (int i = 0; i < eapolTrackerCount; i++) {
                                if (memcmp(eapolTrackers[i].clientMac, clientMac, 6) == 0) {
                                    trackerIdx = i;
                                    break;
                                }
                            }

                            if (trackerIdx == -1) {
                                trackerIdx = eapolTrackerCount < MAX_EAPOL_TRACKERS ? eapolTrackerCount++ : (now % MAX_EAPOL_TRACKERS);
                                memcpy(eapolTrackers[trackerIdx].clientMac, clientMac, 6);
                                eapolTrackers[trackerIdx].msg3Count = 0;
                                eapolTrackers[trackerIdx].windowStart = now;
                            }

                            EapolTracker& tracker = eapolTrackers[trackerIdx];
                            if (now - tracker.windowStart > 30000) {
                                tracker.msg3Count = 0;
                                tracker.windowStart = now;
                            }

                            tracker.msg3Count++;

                            if (tracker.msg3Count >= 3) {
                                char details[256];
                                snprintf(details, sizeof(details), "{\"msg3_count\":%d,\"window_sec\":%lu,\"ap_bssid\":\"%s\"}",
                                         tracker.msg3Count, (now - tracker.windowStart) / 1000, macToString(apBssid).c_str());
                                sendAttackAlert("krack_attack", clientMac, details);
                                tracker.msg3Count = 0;
                                tracker.windowStart = now;
                            }
                        }
                    }
                }
            }
        }
    }

    if (srcMac[0] & 0x01) return;

    uint8_t ownMac[6];
    network->getMacAddress(ownMac);
    if (memcmp(srcMac, ownMac, 6) == 0) return;

    if (isDuplicate(srcMac)) return;

    char doc[256];
    snprintf(doc, sizeof(doc), "{\"type\":\"device_discovered\",\"mac\":\"%s\",\"rssi\":%d,\"channel\":%d,\"ts\":%lu}",
             macToString(srcMac).c_str(), rssi, channel, system->getMillis());

    transport->send(doc);
}
