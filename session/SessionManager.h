#pragma once
#include <unordered_map>
#include <string>
#include <mutex>
#include <winsock2.h>
#include "Session.h"

class SessionManager
{
private:
    std::unordered_map<std::string, Session*> sessions;       // userId -> Session*
    std::unordered_map<SOCKET, std::string> socketToUserId;   // socket -> userId
    std::mutex mtx;

public:
    void addSession(const std::string& id, Session* session);
    void removeSession(const std::string& id);
    void removeBySocket(SOCKET s);

    Session* findSession(const std::string& id);
    Session* findBySocket(SOCKET s);
    std::string getUserIdBySocket(SOCKET s);
    bool checkReciever(const std:: string recId);
    void setRecievingFileTrue(const std:: string recId); // cal when reciever send download request
     void setRecievingFileFalse(const std:: string recId); // cal when reciever send disconnect  request

    
};