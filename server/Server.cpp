#include "Server.h"
#include "../utils/Logger.h"
#include <ws2tcpip.h>
#include"./pool/PacketPool.h"
Server::Server()
    : router(&sessionManager, &groupManager)
{
    mf.setRouter(&router);
    mf.setIOCP(&iocp);
    router.setOfflineManager(&mf);
    router.setFileManager(&fileTransfer);
    router.setSignUpManager(&signUpManager);
    router.setAuthManager(&authManager);
    authManager.SetRouter(&router);
    signUpManager.setRouter(&router);
    signUpManager.setAuthManager(&authManager);
    fileTransfer.setRouter(&router);
    fileTransfer.setOfflineManager(&mf);
    fileTransfer.setSessionManager(&sessionManager);
    fileTransfer.start();

    // Synchronize persistent database records to AuthManager cache on startup
    authManager.LoadUsersFromDatabase(signUpManager.getDatabase());
}

bool Server::start(int port)
{
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        Logger::error("WSAStartup failed with error: " + std::to_string(result));
        return false;
    }
    wsaInitialized = true;
    Logger::info("Winsock initialized");

    // Initialize IOCP with dependencies
    if (!iocp.initialize(port, &sessionManager, &router,&mf)) {
        Logger::error("Failed to initialize IOCP server");
        stop();
        return false;
    }

    Logger::info("Chat server starting on port " + std::to_string(port));

    // Enter the accept loop (this blocks until shutdown)
    // primary thread waits on this 
    
    iocp.acceptLoop();

    return true;
}

void Server::stop()
{
//     Logger::info("Stopping server...");
//    Logger::info("total packet sent from server "+std::to_string(router.counter));
//    Logger::info("total packet recieved by server "+std::to_string(iocp.totalPacketRecieved));
//     Logger::info("total  complete packet received by server "+std::to_string(mf.TotalReceivedCompletePacktet));
//      Logger::info("total  complete packet sent by server "+std::to_string(mf.TotalsentCompletePacktet));
  Logger::info("peak packet used from packet pool is "+std::to_string(PacketPool::Instance().returnPeak()));
  
    iocp.shutdown();

    if (wsaInitialized) {
        WSACleanup();
        wsaInitialized = false;
    }

    Logger::info("Server stopped");
}