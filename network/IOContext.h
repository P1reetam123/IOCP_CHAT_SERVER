#pragma once
#include <winsock2.h>
#include <windows.h>

class Packet; // Forward declaration

// Per            IO operation data used with IOCP overlapped I/O
struct PER_IO_OPERATION_DATA
{
    OVERLAPPED overlapped;
    WSABUF buffer;
    char data[16384];//16kb
    int operationType; // 0 = send, 1 = recv
    Packet* packet = nullptr;  // The Packet being sent (for status tracking)
    int totalToSend = 0;       // Total bytes to send for this packet
    int bytesSent = 0;         // Bytes confirmed sent so far
    size_t id;
};