#pragma once
#include "../network/IOCPManager.h"
#include "../session/SessionManager.h"
#include "../chat/MessageRouter.h"
#include "../chat/GroupManager.h"
#include "../filetransfer/FileTransferManager.h"
#include"../offlineManager/ManageOffline.h"
#include"../authentication/SignUp.h"
#include"../authentication/AuthManager.h"

class Server
{
private:
    IOCPManager iocp;
    SessionManager sessionManager;
    GroupManager groupManager;
    MessageRouter router;
    FileTransferManager fileTransfer;
    ManageOffline mf;
    SignUp signUpManager;
    AuthManager authManager;
    bool wsaInitialized = false;

public:
    Server();

    // Initialize WSA, IOCP, and start accepting connections (blocks)
    bool start(int port);

    // Gracefully shut down the server
    void stop();
};