#pragma once
#include "../../../core/include/ISystem.h"
#include <Arduino.h>

class Esp32System : public ISystem {
public:
    unsigned long getMillis() override { return millis(); }
    uint32_t getFreeMemory() override { return ESP.getFreeHeap(); }
    void delayMs(unsigned long ms) override { delay(ms); }
    void print(const char* msg) override { Serial.print(msg); }
};
