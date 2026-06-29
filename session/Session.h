#pragma once
#include <winsock2.h>
#include <string>
#include <queue>
#include <mutex>
#include <atomic>
#include <cstdint>
#include "../protocol/Packet.h"
#include"./datastructure/Mpsc.h"

class IOCPManager; // Forward declaration

class Session
{
public:
    std::string userId;
    SOCKET socket;
    bool recievingFile = false; // set it false when user send disconnect packet and set true when user send sownload request 
    IOCPManager* iocp = nullptr; // Set when session is created, used by sendPacket
    size_t id;

    // --- Auth hot-path cache (written once at login, read per-packet) ---
    std::atomic<int> auth_state{0};         // AuthSessionState enum value
    uint8_t cached_user_id[16]{};           // Copied from UserRecord on login
    std::atomic<uint64_t> cached_expiry{0};  // Unix timestamp, atomic for lock-free read
   
public:
    Session();
    ~Session();
    Session(Session&& other) noexcept;
    Session& operator=(Session&& other) noexcept;
     bool sendPacket(Packet* p);
    void setSocket(SOCKET s);
    // Close the socket
    void close();
};