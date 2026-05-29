#pragma once
#include <stdint.h>

class ISystem {
public:
    virtual ~ISystem() = default;
    virtual unsigned long getMillis() = 0;
    virtual uint32_t getFreeMemory() = 0;
    virtual void delayMs(unsigned long ms) = 0;
    virtual void print(const char* msg) = 0;
};
