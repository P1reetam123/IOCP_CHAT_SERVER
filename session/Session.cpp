
 #pragma once
#include "Session.h"
#include "../network/IOCPManager.h"
#include <cstring>

Session::Session()
    
{
}
Session::~Session()
{
    close();
}

Session::Session(Session&& other) noexcept
{
    userId = std::move(other.userId);
    socket = other.socket;
    recievingFile = other.recievingFile;
    iocp = other.iocp;
    id = other.id;
    auth_state.store(other.auth_state.load(std::memory_order_relaxed), std::memory_order_relaxed);
    std::memcpy(cached_user_id, other.cached_user_id, 16);
    cached_expiry.store(other.cached_expiry.load(std::memory_order_relaxed), std::memory_order_relaxed);

    other.socket = INVALID_SOCKET;
    other.iocp = nullptr;
    other.auth_state.store(0, std::memory_order_relaxed);
    other.cached_expiry.store(0, std::memory_order_relaxed);
}

Session& Session::operator=(Session&& other) noexcept
{
    if (this != &other) {
        close();
        userId = std::move(other.userId);
        socket = other.socket;
        recievingFile = other.recievingFile;
        iocp = other.iocp;
        id = other.id;
        auth_state.store(other.auth_state.load(std::memory_order_relaxed), std::memory_order_relaxed);
        std::memcpy(cached_user_id, other.cached_user_id, 16);
        cached_expiry.store(other.cached_expiry.load(std::memory_order_relaxed), std::memory_order_relaxed);

        other.socket = INVALID_SOCKET;
        other.iocp = nullptr;
        other.auth_state.store(0, std::memory_order_relaxed);
        other.cached_expiry.store(0, std::memory_order_relaxed);
    }
    return *this;
}

void Session::close()
{
    if (socket != INVALID_SOCKET) {
        closesocket(socket);
        socket = INVALID_SOCKET;
    }
    
   
}

bool Session::sendPacket(Packet* p){
    // Kick off IOCP send if we have a reference
    if (iocp) {
        iocp->queueSend(this->socket, p);
    }
    return true;
}
 void Session::setSocket(SOCKET s){
    socket =s;
 }