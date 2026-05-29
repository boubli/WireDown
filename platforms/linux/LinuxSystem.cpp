#include "LinuxSystem.h"
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <fstream>
#include <string>

LinuxSystem::LinuxSystem() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    startTimeMs = (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

unsigned long LinuxSystem::getMillis() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned long now = (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
    return now - startTimeMs;
}

uint32_t LinuxSystem::getFreeMemory() {
    // Read MemFree from /proc/meminfo
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    uint32_t freeMem = 0;
    while (std::getline(meminfo, line)) {
        if (line.compare(0, 8, "MemFree:") == 0) {
            sscanf(line.c_str(), "MemFree: %u kB", &freeMem);
            break;
        }
    }
    return freeMem * 1024; // Convert to bytes
}

void LinuxSystem::delayMs(unsigned long ms) {
    usleep(ms * 1000);
}

void LinuxSystem::print(const char* msg) {
    printf("%s", msg);
    fflush(stdout);
}
