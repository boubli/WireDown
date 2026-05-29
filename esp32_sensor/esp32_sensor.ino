// WireDown ESP32 sensor — promiscuous WiFi sniffer + isolation
// Board: ESP32-DevKitC, Libs: ArduinoWebsockets, ArduinoJson

#include <WiFi.h>
#include <ArduinoWebsockets.h>
#include <ArduinoJson.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"

using namespace websockets;


const char* WIFI_SSID      = "HoneypotNet";
const char* WIFI_PASS      = "Tr4pN3twork!";
const char* WS_SERVER_HOST = "192.168.4.1";
const uint16_t WS_SERVER_PORT = 5000;
const char* WS_PATH        = "/ws/esp32";

const unsigned long HEARTBEAT_MS      = 5000;
const unsigned long RECONNECT_MS      = 3000;
const unsigned long DEDUP_WINDOW_MS   = 10000;
const int           SNIFF_CHANNEL     = 6;


WebsocketsClient wsClient;
bool wsConnected = false;
unsigned long lastHeartbeat  = 0;
unsigned long lastReconnect  = 0;

/* Simple ring-buffer de-duplicator for MACs */
struct SeenDevice {
    uint8_t mac[6];
    unsigned long lastSeen;
};
const int MAX_SEEN = 128;
SeenDevice seenDevices[MAX_SEEN];
int seenCount = 0;



/* 1. ARP Spoofing Detector */
struct ArpMapping {
    uint32_t ip;
    uint8_t  mac[6];
    unsigned long lastSeen;
};
const int MAX_ARP_ENTRIES = 64;
ArpMapping arpTable[MAX_ARP_ENTRIES];
int arpTableCount = 0;

/* 2. Deauth Flood Detector */
volatile int deauthCount = 0;
volatile int disassocCount = 0;
unsigned long lastDeauthReset = 0;
uint8_t lastDeauthSrcMac[6] = {0};

/* 3. MAC Flood Detector */
volatile int newMacCount = 0;
unsigned long macFloodWindowStart = 0;
const unsigned long MAC_FLOOD_WINDOW_MS = 5000;
const int MAC_FLOOD_THRESHOLD = 20;

/* 4. KRACK Detector */
struct EapolTracker {
    uint8_t  clientMac[6];
    int      msg3Count;
    unsigned long windowStart;
};
const int MAX_EAPOL_TRACKERS = 32;
EapolTracker eapolTrackers[MAX_EAPOL_TRACKERS];
int eapolTrackerCount = 0;



String macToString(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

String ipToString(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return String(buf);
}

void sendAttackAlert(const char* attack, const uint8_t* mac, JsonDocument& details) {
    StaticJsonDocument<512> alertDoc;
    alertDoc["type"]   = "attack_detected";
    alertDoc["attack"] = attack;
    alertDoc["mac"]    = macToString(mac);
    alertDoc["details"] = details;
    alertDoc["ts"]     = millis();
    String json;
    serializeJson(alertDoc, json);
    Serial.printf("[ATTACK] %s detected from %s\n", attack, macToString(mac).c_str());
    if (wsConnected) {
        wsClient.send(json);
    }
}

bool parseMacString(const String& macStr, uint8_t* out) {
    if (macStr.length() != 17) return false;
    unsigned int vals[6];
    int parsed = sscanf(macStr.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                        &vals[0], &vals[1], &vals[2],
                        &vals[3], &vals[4], &vals[5]);
    if (parsed != 6) return false;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)vals[i];
    return true;
}

bool isDuplicate(const uint8_t* mac) {
    unsigned long now = millis();
    for (int i = 0; i < seenCount; i++) {
        if (memcmp(seenDevices[i].mac, mac, 6) == 0) {
            if (now - seenDevices[i].lastSeen < DEDUP_WINDOW_MS) {
                seenDevices[i].lastSeen = now;
                return true;
            }
            seenDevices[i].lastSeen = now;
            return false;
        }
    }
    /* New MAC discovered — increment MAC flood counter */
    newMacCount++;
    int idx = seenCount < MAX_SEEN ? seenCount++ : (millis() % MAX_SEEN);
    memcpy(seenDevices[idx].mac, mac, 6);
    seenDevices[idx].lastSeen = now;
    return false;
}



void isolateDevice(String macAddress) {
    Serial.printf("[ISOLATION] Targeting device: %s\n", macAddress.c_str());

    uint8_t targetMac[6];
    if (!parseMacString(macAddress, targetMac)) {
        Serial.println("[ISOLATION] Invalid MAC format — aborting.");
        return;
    }

    /*
     * Send a burst of de-authentication frames.
     * Reason code 0x07 = "Class 3 frame received from non-associated STA"
     *
     * Frame layout (26 bytes):
     *   [0-1]   Frame Control: 0xC0, 0x00  (Deauth)
     *   [2-3]   Duration: 0x00, 0x00
     *   [4-9]   Destination (target MAC)
     *   [10-15] Source (our AP BSSID)
     *   [16-21] BSSID  (our AP BSSID)
     *   [22-23] Sequence Control: 0x00, 0x00
     *   [24-25] Reason Code: 0x07, 0x00
     */

    uint8_t bssid[6];
    esp_wifi_get_mac(WIFI_IF_AP, bssid);

    uint8_t deauthFrame[26] = {
        0xC0, 0x00,                                 /* Frame Control */
        0x00, 0x00,                                 /* Duration */
        targetMac[0], targetMac[1], targetMac[2],   /* Destination */
        targetMac[3], targetMac[4], targetMac[5],
        bssid[0], bssid[1], bssid[2],               /* Source */
        bssid[3], bssid[4], bssid[5],
        bssid[0], bssid[1], bssid[2],               /* BSSID */
        bssid[3], bssid[4], bssid[5],
        0x00, 0x00,                                 /* Seq Ctrl */
        0x07, 0x00                                  /* Reason: Class-3 */
    };

    /* Stop promiscuous mode briefly to send raw frames */
    esp_wifi_set_promiscuous(false);

    const int BURST_COUNT = 20;
    const int BURST_DELAY_US = 500;

    for (int i = 0; i < BURST_COUNT; i++) {
        esp_err_t result = esp_wifi_80211_tx(WIFI_IF_AP, deauthFrame, sizeof(deauthFrame), false);
        if (result != ESP_OK) {
            Serial.printf("[ISOLATION] TX error on frame %d: %d\n", i, result);
        }
        delayMicroseconds(BURST_DELAY_US);
    }

    /* Resume promiscuous sniffing */
    esp_wifi_set_promiscuous(true);

    Serial.printf("[ISOLATION] Sent %d deauth frames to %s\n", BURST_COUNT, macAddress.c_str());

    /* Notify backend that isolation was executed */
    StaticJsonDocument<256> ack;
    ack["type"]   = "isolation_complete";
    ack["mac"]    = macAddress;
    ack["frames"] = BURST_COUNT;
    String payload;
    serializeJson(ack, payload);
    if (wsConnected) {
        wsClient.send(payload);
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

void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const wifi_ieee80211_packet_t* ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
    uint16_t frame_ctrl = ipkt->hdr.frame_ctrl;
    int pktLen = pkt->rx_ctrl.sig_len;

    const uint8_t* srcMac = ipkt->hdr.addr2;

    /* ── 2. Deauth / Disassoc Flood Detection ─────────────── */
    uint8_t frameType    = (frame_ctrl & 0x0C) >> 2;  /* Type field (bits 2-3) */
    uint8_t frameSubtype = (frame_ctrl & 0xF0) >> 4;  /* Subtype field (bits 4-7) */

    if (frameType == 0x00) {  /* Management frame */
        if (frameSubtype == 0x0C) {  /* Deauthentication (0xC0) */
            deauthCount++;
            memcpy(lastDeauthSrcMac, srcMac, 6);
        } else if (frameSubtype == 0x0A) {  /* Disassociation (0xA0) */
            disassocCount++;
            memcpy(lastDeauthSrcMac, srcMac, 6);
        }
    }

    /* ── 1. ARP Spoofing Detection (DATA frames only) ─────── */
    if (type == WIFI_PKT_DATA) {
        /*
         * For data frames, the payload after the MAC header may contain
         * an LLC/SNAP header followed by the actual network payload.
         * We need to account for QoS data frames which add 2 bytes.
         */
        int macHdrLen = 24;  /* Standard 802.11 MAC header */
        if ((frame_ctrl & 0x0080) != 0) {  /* QoS data: subtype bit 3 set */
            macHdrLen = 26;
        }

        const uint8_t* frameData = pkt->payload + macHdrLen;
        int remainLen = pktLen - macHdrLen;

        /* Check for LLC/SNAP header: AA:AA:03:00:00:00 */
        if (remainLen >= 8) {
            if (frameData[0] == 0xAA && frameData[1] == 0xAA && frameData[2] == 0x03 &&
                frameData[3] == 0x00 && frameData[4] == 0x00 && frameData[5] == 0x00) {

                uint16_t etherType = (frameData[6] << 8) | frameData[7];
                const uint8_t* llcPayload = frameData + 8;
                int llcPayloadLen = remainLen - 8;

                /* ── ARP Detection (EtherType 0x0806) ─────── */
                if (etherType == 0x0806 && llcPayloadLen >= 28) {
                    /*
                     * ARP packet layout (after LLC/SNAP):
                     * [0-1]   Hardware type
                     * [2-3]   Protocol type
                     * [4]     Hardware size
                     * [5]     Protocol size
                     * [6-7]   Opcode (2 = reply)
                     * [8-13]  Sender MAC
                     * [14-17] Sender IP
                     * [18-23] Target MAC
                     * [24-27] Target IP
                     */
                    uint16_t arpOpcode = (llcPayload[6] << 8) | llcPayload[7];

                    if (arpOpcode == 2) {  /* ARP Reply */
                        const uint8_t* senderMac = llcPayload + 8;
                        uint32_t senderIp;
                        memcpy(&senderIp, llcPayload + 14, 4);

                        /* Look up IP in ARP table */
                        bool found = false;
                        for (int i = 0; i < arpTableCount; i++) {
                            if (arpTable[i].ip == senderIp) {
                                found = true;
                                if (memcmp(arpTable[i].mac, senderMac, 6) != 0) {
                                    /* MAC changed for known IP — ARP spoof! */
                                    StaticJsonDocument<256> details;
                                    details["ip"] = ipToString(senderIp);
                                    details["original_mac"] = macToString(arpTable[i].mac);
                                    details["spoofed_mac"]  = macToString(senderMac);
                                    sendAttackAlert("arp_spoof", senderMac, details);

                                    /* Update the stored MAC */
                                    memcpy(arpTable[i].mac, senderMac, 6);
                                }
                                arpTable[i].lastSeen = millis();
                                break;
                            }
                        }
                        if (!found) {
                            /* New IP — store the mapping */
                            int idx = arpTableCount < MAX_ARP_ENTRIES ? arpTableCount++ : (millis() % MAX_ARP_ENTRIES);
                            arpTable[idx].ip = senderIp;
                            memcpy(arpTable[idx].mac, senderMac, 6);
                            arpTable[idx].lastSeen = millis();
                        }
                    }
                }

                /* ── 4. KRACK Detection (EtherType 0x888E = EAPOL) ── */
                if (etherType == 0x888E && llcPayloadLen >= 15) {
                    /*
                     * EAPOL frame layout (after LLC/SNAP EtherType):
                     * [0]     Version
                     * [1]     Type (3 = EAPOL-Key)
                     * [2-3]   Body Length
                     * [4]     Descriptor Type
                     * [5-6]   Key Info (big-endian)
                     *
                     * Key Info bits (802.11i):
                     *   Bit 3: Pairwise (1 = pairwise)
                     *   Bit 6: Install
                     *   Bit 7: Ack
                     *   Bit 8: MIC
                     */
                    uint8_t eapolType = llcPayload[1];

                    if (eapolType == 3) {  /* EAPOL-Key */
                        uint16_t keyInfo = (llcPayload[5] << 8) | llcPayload[6];

                        bool installBit = (keyInfo >> 6) & 0x01;
                        bool ackBit     = (keyInfo >> 7) & 0x01;

                        if (installBit && ackBit) {
                            /* This is Message 3 of the 4-way handshake */
                            /* The destination (addr1) is the client */
                            const uint8_t* clientMac = ipkt->hdr.addr1;
                            /* addr3 (BSSID) is the AP */
                            const uint8_t* apBssid   = ipkt->hdr.addr3;
                            unsigned long now = millis();

                            /* Find or create tracker for this client */
                            int trackerIdx = -1;
                            for (int i = 0; i < eapolTrackerCount; i++) {
                                if (memcmp(eapolTrackers[i].clientMac, clientMac, 6) == 0) {
                                    trackerIdx = i;
                                    break;
                                }
                            }

                            if (trackerIdx == -1) {
                                /* New client — allocate tracker */
                                trackerIdx = eapolTrackerCount < MAX_EAPOL_TRACKERS
                                             ? eapolTrackerCount++
                                             : (now % MAX_EAPOL_TRACKERS);
                                memcpy(eapolTrackers[trackerIdx].clientMac, clientMac, 6);
                                eapolTrackers[trackerIdx].msg3Count   = 0;
                                eapolTrackers[trackerIdx].windowStart = now;
                            }

                            EapolTracker& tracker = eapolTrackers[trackerIdx];

                            /* Reset window if > 30 seconds */
                            if (now - tracker.windowStart > 30000) {
                                tracker.msg3Count   = 0;
                                tracker.windowStart = now;
                            }

                            tracker.msg3Count++;

                            if (tracker.msg3Count >= 3) {
                                /* KRACK attack detected! */
                                StaticJsonDocument<256> details;
                                details["msg3_count"] = tracker.msg3Count;
                                details["window_sec"] = (now - tracker.windowStart) / 1000;
                                details["ap_bssid"]   = macToString(apBssid);
                                sendAttackAlert("krack_attack", clientMac, details);

                                /* Reset tracker after alerting */
                                tracker.msg3Count   = 0;
                                tracker.windowStart = now;
                            }
                        }
                    }
                }
            }
        }
    }

    /* Skip broadcast / multicast */
    if (srcMac[0] & 0x01) return;

    /* Skip our own MAC */
    uint8_t ownMac[6];
    esp_wifi_get_mac(WIFI_IF_STA, ownMac);
    if (memcmp(srcMac, ownMac, 6) == 0) return;

    /* De-duplicate */
    if (isDuplicate(srcMac)) return;

    String macStr = macToString(srcMac);
    int rssi = pkt->rx_ctrl.rssi;

    Serial.printf("[SNIFF] New device: %s  RSSI: %d dBm\n", macStr.c_str(), rssi);

    /* Build JSON and send over WebSocket */
    StaticJsonDocument<256> doc;
    doc["type"]   = "device_discovered";
    doc["mac"]    = macStr;
    doc["rssi"]   = rssi;
    doc["channel"] = pkt->rx_ctrl.channel;
    doc["ts"]     = millis();

    String json;
    serializeJson(doc, json);

    if (wsConnected) {
        wsClient.send(json);
    }
}



void onWsMessage(WebsocketsMessage msg) {
    Serial.printf("[WS] Received: %s\n", msg.data().c_str());

    StaticJsonDocument<512> doc;
    DeserializationError err = deserializeJson(doc, msg.data());
    if (err) {
        Serial.printf("[WS] JSON parse error: %s\n", err.c_str());
        return;
    }

    const char* cmdType = doc["type"] | "";

    if (strcmp(cmdType, "isolate") == 0) {
        String mac = doc["mac"] | "";
        if (mac.length() > 0) {
            isolateDevice(mac);
        }
    } else if (strcmp(cmdType, "ping") == 0) {
        StaticJsonDocument<64> pong;
        pong["type"] = "pong";
        String out;
        serializeJson(pong, out);
        wsClient.send(out);
    }
}

void onWsEvent(WebsocketsEvent event, String data) {
    switch (event) {
        case WebsocketsEvent::ConnectionOpened:
            Serial.println("[WS] Connected to backend.");
            wsConnected = true;
            {
                StaticJsonDocument<128> hello;
                hello["type"]   = "esp32_hello";
                hello["uptime"] = millis();
                uint8_t mac[6];
                esp_wifi_get_mac(WIFI_IF_STA, mac);
                hello["sensor_mac"] = macToString(mac);
                String out;
                serializeJson(hello, out);
                wsClient.send(out);
            }
            break;
        case WebsocketsEvent::ConnectionClosed:
            Serial.println("[WS] Disconnected from backend.");
            wsConnected = false;
            break;
        case WebsocketsEvent::GotPing:
            wsClient.pong();
            break;
        default:
            break;
    }
}

void connectWebSocket() {
    String url = String("ws://") + WS_SERVER_HOST + ":" + WS_SERVER_PORT + WS_PATH;
    Serial.printf("[WS] Connecting to %s ...\n", url.c_str());
    wsClient.onMessage(onWsMessage);
    wsClient.onEvent(onWsEvent);
    wsClient.connect(url);
}



void setupWiFi() {
    Serial.println("[WIFI] Initializing...");

    WiFi.mode(WIFI_AP_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);

    Serial.print("[WIFI] Connecting to AP");
    int retries = 0;
    while (WiFi.status() != WL_CONNECTED && retries < 40) {
        delay(500);
        Serial.print(".");
        retries++;
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("\n[WIFI] Connected! IP: %s\n", WiFi.localIP().toString().c_str());
    } else {
        Serial.println("\n[WIFI] Connection failed — continuing in AP-only mode.");
    }
}

void setupSniffer() {
    Serial.println("[SNIFF] Enabling promiscuous mode...");

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;

    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(SNIFF_CHANNEL, WIFI_SECOND_CHAN_NONE);

    Serial.printf("[SNIFF] Listening on channel %d\n", SNIFF_CHANNEL);
}



void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("WireDown — ESP32 Honeypot Sensor starting...");

    setupWiFi();
    connectWebSocket();
    setupSniffer();
}

void loop() {
    wsClient.poll();
    unsigned long now = millis();

    /* Reconnect WebSocket if dropped */
    if (!wsConnected && (now - lastReconnect > RECONNECT_MS)) {
        lastReconnect = now;
        connectWebSocket();
    }

    /* Periodic heartbeat */
    if (wsConnected && (now - lastHeartbeat > HEARTBEAT_MS)) {
        lastHeartbeat = now;
        StaticJsonDocument<128> hb;
        hb["type"]   = "heartbeat";
        hb["uptime"] = now;
        hb["free_heap"] = ESP.getFreeHeap();
        String out;
        serializeJson(hb, out);
        wsClient.send(out);
    }

    /* ── 2. Deauth Flood Check (every 1 second) ─────────── */
    if (now - lastDeauthReset >= 1000) {
        int totalDeauth = deauthCount + disassocCount;
        if (totalDeauth > 10) {
            StaticJsonDocument<256> details;
            details["count_per_sec"] = totalDeauth;
            if (deauthCount > disassocCount) {
                details["type"] = "deauth";
            } else {
                details["type"] = "disassoc";
            }
            sendAttackAlert("deauth_flood", lastDeauthSrcMac, details);
        }
        deauthCount   = 0;
        disassocCount = 0;
        lastDeauthReset = now;
    }

    /* ── 3. MAC Flood Check (every 5 seconds) ───────────── */
    if (now - macFloodWindowStart >= MAC_FLOOD_WINDOW_MS) {
        if (newMacCount > MAC_FLOOD_THRESHOLD) {
            uint8_t zeroMac[6] = {0};
            StaticJsonDocument<256> details;
            details["new_macs_in_window"] = newMacCount;
            details["window_sec"] = 5;
            sendAttackAlert("mac_flood", zeroMac, details);
        }
        newMacCount = 0;
        macFloodWindowStart = now;
    }

    delay(1);
}
