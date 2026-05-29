#include <WiFi.h>
#include "Esp32System.h"
#include "Esp32Transport.h"
#include "Esp32Network.h"
#include "../../core/include/Engine.h"

const char* WIFI_SSID      = "HoneypotNet";
const char* WIFI_PASS      = "Tr4pN3twork!";
const char* WS_SERVER_HOST = "192.168.4.1";
const uint16_t WS_SERVER_PORT = 5000;
const char* WS_PATH        = "/ws/esp32";

Esp32System sys;
Esp32Transport transport(WS_SERVER_HOST, WS_SERVER_PORT, WS_PATH);
Esp32Network net;
Engine engine(&sys, &transport, &net);

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

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("WireDown — ESP32 Honeypot Sensor starting...");

    setupWiFi();
    engine.init();
}

void loop() {
    engine.loop();
    delay(1);
}
