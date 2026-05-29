#include "LinuxNetwork.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <pthread.h>

LinuxNetwork::LinuxNetwork(const char* interfaceName) 
    : iface(interfaceName), rawSocket(-1), sniffing(false), currentCb(nullptr) {
    memset(ownMac, 0, 6);
}

LinuxNetwork::~LinuxNetwork() {
    stopPromiscuous();
}

void LinuxNetwork::getMacFromIface(const char* ifname, uint8_t* mac) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    }
    close(s);
}

void LinuxNetwork::init() {
    getMacFromIface(iface.c_str(), ownMac);
    printf("[NETWORK] Initialized on %s (MAC: %02X:%02X:%02X:%02X:%02X:%02X)\n", 
           iface.c_str(), ownMac[0], ownMac[1], ownMac[2], ownMac[3], ownMac[4], ownMac[5]);
}

void* LinuxNetwork::snifferThread(void* arg) {
    LinuxNetwork* net = (LinuxNetwork*)arg;
    uint8_t buffer[65536];
    
    while (net->sniffing) {
        int length = recvfrom(net->rawSocket, buffer, sizeof(buffer), 0, NULL, NULL);
        if (length > 0 && net->currentCb) {
            // Note: In a real LXC/VM with 802.11 monitor mode, the buffer contains Radiotap + 802.11 MAC.
            // If it's a standard ethernet interface, it contains Ethernet headers.
            // The Engine expects 802.11 frames. We pass it through directly.
            net->currentCb(buffer, length, 0, 0);
        }
    }
    return nullptr;
}

void LinuxNetwork::startPromiscuous(PacketCallback cb, int channel) {
    if (sniffing) return;
    currentCb = cb;
    
    rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rawSocket < 0) {
        printf("[NETWORK] Error: Cannot create raw socket. Need root or cap_net_raw.\n");
        return;
    }

    // Bind to interface
    struct sockaddr_ll sll;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
    if (ioctl(rawSocket, SIOCGIFINDEX, &ifr) < 0) {
        close(rawSocket);
        return;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(rawSocket, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        close(rawSocket);
        return;
    }

    // Set Promiscuous mode
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(rawSocket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    sniffing = true;
    pthread_create(&threadId, nullptr, LinuxNetwork::snifferThread, this);
    printf("[NETWORK] Started promiscuous capture on channel %d\n", channel);
}

void LinuxNetwork::stopPromiscuous() {
    if (!sniffing) return;
    sniffing = false;
    // Thread will exit on next packet or we can close the socket
    if (rawSocket >= 0) {
        close(rawSocket);
        rawSocket = -1;
    }
    pthread_join(threadId, nullptr);
}

void LinuxNetwork::getMacAddress(uint8_t* mac) {
    memcpy(mac, ownMac, 6);
}

void LinuxNetwork::getBssid(uint8_t* bssid) {
    // Return dummy BSSID or bridge mac for Linux
    memcpy(bssid, ownMac, 6);
}

bool LinuxNetwork::injectFrame(const uint8_t* frame, int length) {
    if (rawSocket < 0) return false;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
    ioctl(rawSocket, SIOCGIFINDEX, &ifr);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    
    int bytes = sendto(rawSocket, frame, length, 0, (struct sockaddr*)&sll, sizeof(sll));
    return bytes == length;
}
