#include "LinuxTransport.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>

LinuxTransport::LinuxTransport(const char* host, uint16_t port) 
    : host(host), port(port), sockfd(-1), connected(false), msgCb(nullptr) {}

LinuxTransport::~LinuxTransport() {
    disconnect();
}

void LinuxTransport::connect() {
    if (connected) return;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return;

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0) {
        close(sockfd);
        return;
    }

    if (::connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sockfd);
        sockfd = -1;
        return;
    }

    // Set non-blocking
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    connected = true;
    printf("[TRANSPORT] Connected to %s:%d\n", host.c_str(), port);

    // Simulated hello
    char hello[256];
    snprintf(hello, sizeof(hello), "{\"type\":\"linux_hello\"}\n");
    send(std::string(hello));
}

void LinuxTransport::disconnect() {
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
    connected = false;
}

bool LinuxTransport::isConnected() {
    return connected;
}

void LinuxTransport::send(const std::string& payload) {
    if (!connected || sockfd < 0) return;
    std::string msg = payload + "\n"; // Basic framing
    ::send(sockfd, msg.c_str(), msg.length(), 0);
}

void LinuxTransport::poll() {
    if (!connected || sockfd < 0) return;
    
    char buffer[1024];
    int n = ::recv(sockfd, buffer, sizeof(buffer)-1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        if (msgCb) msgCb(std::string(buffer));
    } else if (n == 0) {
        disconnect(); // Server closed
    }
}

void LinuxTransport::setMessageCallback(MessageCallback cb) {
    msgCb = cb;
}
