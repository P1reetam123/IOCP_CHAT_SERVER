#pragma once
#include "../session/SessionManager.h"
#include "GroupManager.h"
 #include "../protocol/Packet.h"
#include"../offlineManager/ManageOffline.h"
#include"../filetransfer/FileTransferManager.h"
#include<atomic>
class SignUp;
class AuthManager;

class MessageRouter
{
private:
    SessionManager* sessionManager;
    GroupManager* groupManager;
    ManageOffline* offManager;
    FileTransferManager *filemanager=nullptr;
    SignUp *signUpManager = nullptr;
    AuthManager* authManager = nullptr;

public:
std::atomic<int>counter{0};
std::atomic<int>receivedPrivateMsg{0};
    MessageRouter(SessionManager* sm, GroupManager* gm);
    void setOfflineManager(ManageOffline* om) { offManager = om; }
    void setFileManager(FileTransferManager* fm) { filemanager = fm; }
    void setSignUpManager(SignUp* su) { signUpManager = su; }
    void setAuthManager(AuthManager* am) { authManager = am; }

    // Route a private 1-to-1 message to the target user
    bool routePacket(Packet* packet,const std::string recvId);

    // Route a group message to all members of the group
    void routeGroupMessage( Packet* packet);

    // Main dispatch method: inspect packet type and route accordingly
 bool handlePacket(Packet*  packet, Session* sender);
};