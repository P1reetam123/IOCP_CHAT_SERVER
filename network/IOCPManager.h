#pragma once
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <thread>
#include <unordered_set>
#include"./protocol/Packet.h"
// note as multiple thread working on same port and for same buffer we need to add thread synchronization 
// Forward declarations to avoid circular includes
class SessionManager;
class MessageRouter;
class ManageOffline;
class Session;
//class Packet;

class IOCPManager

{
private:
    HANDLE iocpHandle;
    SOCKET listenSocket;
    std::vector<std::thread> workerThreads;

    // Injected dependencies
    SessionManager* sessionManager;
    MessageRouter* messageRouter;
    ManageOffline* offlineManager;
    int numWorkerThreads;
    std::mutex mtx;
    static std::mutex socketBuffersMutex;

    //  One-shot disconnect guard — prevents closesocket() from running
    // multiple times on the same SOCKET when multiple overlapped operations
    // fail concurrently for a dying socket.
    std::unordered_set<SOCKET> disconnectedSockets;
    std::mutex disconnectMtx;

public:
    IOCPManager();
    ~IOCPManager();
    std::atomic<int>totalPacketRecieved{0};
   // std::atomic<int>totalPacketsent{0};

    // Initialize Winsock, bind/listen, create IOCP, launch worker threads
    bool initialize(int port, SessionManager* sm, MessageRouter* mr,ManageOffline* mf);

    // Main accept loop — call this after initialize (blocks)
    void acceptLoop();

    // Stop the server
    void shutdown();

    // Public send entry point: dequeues packet from session, kicks off IOCP send
    void queueSend(SOCKET s, Packet* p);

    // Post an async send on a socket
    bool initiateSend(SOCKET socket, Packet* p);
void handleDisconnect(SOCKET socket);
private:
    // Worker thread function: processes IOCP completions
    void workerThread();

    // Post an async receive on a socket
    bool postRecv(SOCKET socket);

    // Handle a disconnected client
    
};