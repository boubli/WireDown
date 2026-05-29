#include "Esp32Network.h"

PacketCallback Esp32Network::currentCb = nullptr;

Esp32Network::Esp32Network() {}

void Esp32Network::init() {
    // WiFi initialization is handled in setup() of main sketch
}

void IRAM_ATTR Esp32Network::promiscuousRxCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    
    if (currentCb) {
        const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
        currentCb(pkt->payload, pkt->rx_ctrl.sig_len, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);
    }
}

void Esp32Network::startPromiscuous(PacketCallback cb, int channel) {
    currentCb = cb;
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;

    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&Esp32Network::promiscuousRxCallback);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void Esp32Network::stopPromiscuous() {
    esp_wifi_set_promiscuous(false);
}

void Esp32Network::getMacAddress(uint8_t* mac) {
    esp_wifi_get_mac(WIFI_IF_STA, mac);
}

void Esp32Network::getBssid(uint8_t* bssid) {
    // Assuming BSSID for attacks/injection is the AP mac
    esp_wifi_get_mac(WIFI_IF_AP, bssid);
}

bool Esp32Network::injectFrame(const uint8_t* frame, int length) {
    esp_err_t result = esp_wifi_80211_tx(WIFI_IF_AP, (void*)frame, length, false);
    return (result == ESP_OK);
}
