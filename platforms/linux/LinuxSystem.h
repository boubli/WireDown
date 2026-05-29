#pragma once
#include "../../core/include/ISystem.h"

class LinuxSystem : public ISystem {
public:
    LinuxSystem();
    unsigned long getMillis() override;
    uint32_t getFreeMemory() override;
    void delayMs(unsigned long ms) override;
    void print(const char* msg) override;
private:
    unsigned long startTimeMs;
};
