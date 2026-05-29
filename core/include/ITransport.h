#pragma once
#include <string>

// Simple callback for when transport receives a message (like "isolate")
typedef void (*MessageCallback)(const std::string& message);

class ITransport {
public:
    virtual ~ITransport() = default;
    virtual void connect() = 0;
    virtual void disconnect() = 0;
    virtual bool isConnected() = 0;
    virtual void send(const std::string& payload) = 0;
    virtual void poll() = 0;
    virtual void setMessageCallback(MessageCallback cb) = 0;
};
