# WireDown

WireDown is a Wi-Fi honeypot and network tarpit. It uses an ESP32 to sniff 802.11 frames and a Python backend to sinkhole DNS, fake SSH/Admin interfaces, and monitor for CVE-2024-3094. It also has a zero-gravity UI using Matter.js to visualize the network state.

## Table of Contents
- [Architecture](#architecture)
- [Features](#features)
- [Deployment](#deployment)

## Architecture

![System Architecture](Architecture.png)

1. **Hardware (ESP32)**: Sniffs raw 802.11 frames in promiscuous mode. Detects ARP spoofing, deauth floods, MAC floods, and KRACK attacks.
2. **Backend (Python/Flask)**: Runs DNS sinkhole, port scan detection, and fake services.
3. **UI (Matter.js)**: Network devices are bodies in a 2D physics space. The backend calculates vector forces to drag flagged MACs into a sink.
4. **Scoring Engine**: Composite threat scoring instead of binary flags.

## Features

### Detection
* **ARP Spoofing:** Tracks MAC-to-IP mismatches.
* **KRACK:** Monitors EAPOL handshakes for Message 3 retransmissions.
* **Floods:** Detects Deauth/Disassoc storms and MAC flooding.
* **Port Scans:** Flags probing on common ports.

### Traps
* **CVE-2024-3094 (XZ):** Fake SSH server advertising vulnerable `liblzma/xz`. Checks RSA certs for abnormal entropy.
* **Admin Panel:** Fake `NetGate Pro R4500` login portal to capture creds.

### Scoring
Threat thresholds trigger automated responses:
* **+80** XZ Backdoor Exploit
* **+60** KRACK Attack
* **+50** Deauth Flood
* **+40** ARP Spoofing
* **+30** SSH Login

### Responses
* **UI Drag:** Calculates vector forces to drag the MAC into the sinkhole UI.
* **Layer-2 Deauth:** ESP32 drops the attacker off the network.
* **Throttle:** Bandwidth drops from 100% to 1% over time.
* **Captive Portal:** Fake forensic extraction timer.

![UI Lifecycle](AI%20Agent%20Lifecycle.png)

## Deployment

Proxmox helper scripts:

**LXC Container (Debian 12)**
```bash
bash -c "$(wget -qO - https://raw.githubusercontent.com/boubli/WireDown/master/proxmox-lxc.sh)"
```

**Virtual Machine (Ubuntu 22.04)**
```bash
bash -c "$(wget -qO - https://raw.githubusercontent.com/boubli/WireDown/master/proxmox-vm.sh)"
```

**Update Existing LXC**
```bash
bash -c "$(wget -qO - https://raw.githubusercontent.com/boubli/WireDown/master/proxmox-update.sh)"
```

**Docker Compose**
```bash
git clone https://github.com/boubli/WireDown.git
cd WireDown
docker compose up -d
```

### Hardware setup
Flash `esp32_sensor/esp32_sensor.ino` to an ESP32. Set your WiFi credentials and backend IP.

## Disclaimer
Only run on networks you own. Active response modules are illegal to run on public networks. I'm not responsible for what you do with this.
