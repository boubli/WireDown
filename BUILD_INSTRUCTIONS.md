# WireDown Refactored Architecture Build Instructions

The WireDown project has been refactored into a platform-agnostic Core Engine and hardware-specific Platform Adapters (HAL). This allows the same security logic to run on an ESP32 micro-controller, a standard Linux Virtual Machine, or a Proxmox LXC container.

## 1. Directory Structure
*   `core/`: Contains the platform-agnostic `Engine` and the abstraction interfaces (`ISystem`, `INetworkInterface`, `ITransport`).
*   `platforms/esp32/`: Contains the ESP32 implementations mapping the interfaces to `esp_wifi` and `ArduinoWebsockets`.
*   `platforms/linux/`: Contains the standard Linux implementations using `AF_PACKET` raw sockets and standard POSIX sockets.

## 2. Compiling for ESP32

To compile and flash for the ESP32:
1.  Open `platforms/esp32/WireDownESP32.ino` in the Arduino IDE or PlatformIO.
2.  Ensure you have installed the required libraries (e.g. `ArduinoWebsockets`).
3.  Note: The ESP32 sketch includes the `core/` files using relative paths. Make sure your IDE can resolve `#include "../../core/include/Engine.h"`. If using the Arduino IDE, you might need to copy the `core/` folder into the `esp32/` sketch folder depending on your Arduino IDE version, or use a tool like PlatformIO which handles relative paths easily.
4.  Select your ESP32 board and click "Upload".

## 3. Compiling for Linux (LXC / VM)

To compile the standalone Linux binary, you need standard build tools (`cmake`, `g++`, `make`).
The Linux networking implementation uses `AF_PACKET` which requires root privileges or `cap_net_raw` capabilities.

**Build Steps:**
```bash
cd platforms/linux
mkdir build
cd build
cmake ..
make
```

**Running the Application:**
To run the sensor, you must provide the network interface to sniff on. For VMs, this might be `eth0` or `vmbr0`. If you have a physical WiFi card passed through, it might be `wlan0` in monitor mode.

```bash
# Run with root privileges to allow raw socket creation
sudo ./wiredown-linux wlan0
```

**LXC Container Specifics:**
If deploying inside a Proxmox LXC container, the container must be granted raw network capabilities to use `AF_PACKET`.
In your Proxmox LXC configuration file (`/etc/pve/lxc/CTID.conf`), ensure you have:
```text
lxc.cap.keep: net_raw net_admin
```
