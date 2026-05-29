#include "LinuxSystem.h"
#include "LinuxTransport.h"
#include "LinuxNetwork.h"
#include "../../core/include/Engine.h"
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

bool running = true;

void intHandler(int dummy) {
    running = false;
}

int main(int argc, char* argv[]) {
    printf("WireDown — Linux LXC/VM Sensor starting...\n");

    const char* iface = "wlan0";
    if (argc > 1) {
        iface = argv[1];
    }

    signal(SIGINT, intHandler);

    LinuxSystem sys;
    LinuxTransport transport("192.168.4.1", 5000);
    LinuxNetwork net(iface);
    Engine engine(&sys, &transport, &net);

    engine.init();

    while (running) {
        engine.loop();
        usleep(1000); // 1ms delay
    }

    printf("Exiting WireDown...\n");
    return 0;
}
