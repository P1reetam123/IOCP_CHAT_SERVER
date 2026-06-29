#include "SessionManager.h"
#include "../utils/Logger.h"
#include "./network/IOCPManager.h"
#include "./pool/SessionPool.h"

void SessionManager::updateNewId(const std::string &id, Session *s)
{

    std::lock_guard<std::mutex> lock(mtx);
    auto it = sessions.find(id); // temporary id
    if (it != sessions.end())
        sessions.erase(it);
    socketToUserId[s->socket] = s->userId; // overwrite old temp id to new id

    { // removing duplicate user if connected sice they will have same id and different socket
        std::string id = s->userId;
        auto it = sessions.find(id);
        if (it != sessions.end())
        {                                          // we got the old session
            SOCKET oldSocket = it->second->socket; /// got the socket of old user
            sessions.erase(it);                    // erase the old session
            SessionPool::Instance().returnSession(it->second);
            socketToUserId.erase(oldSocket); // erase the old socket
            s->iocp->handleDisconnect(oldSocket) ; // cleanup the socket
        }
    }

    sessions[s->userId] = s; // add current session on new id
}
void SessionManager::addSession(const std::string &id, Session *session)
{
    std::lock_guard<std::mutex> lock(mtx);
    sessions[id] = session;
    socketToUserId[session->socket] = id;
}

void SessionManager::removeSession(const std::string &id)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = sessions.find(id);
    if (it != sessions.end())
    {
        socketToUserId.erase(it->second->socket);
        // delete it->second;
        SessionPool::Instance().returnSession(it->second);
        sessions.erase(it);
    }
}

void SessionManager::removeBySocket(SOCKET s)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = socketToUserId.find(s);
    if (it != socketToUserId.end())
    {
        std::string userId = it->second;
        socketToUserId.erase(it);
        auto sit = sessions.find(userId);
        if (sit != sessions.end())
        {
            // delete sit->second;
            SessionPool::Instance().returnSession(sit->second);
            sessions.erase(sit);
        }
    }
}

Session *SessionManager::findSession(const std::string &id)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = sessions.find(id);
    if (it != sessions.end())
        return it->second;
    return nullptr;
}

Session *SessionManager::findBySocket(SOCKET s)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = socketToUserId.find(s);
    if (it != socketToUserId.end())
    {
        return sessions[it->second];
    }
    return nullptr;
}

std::string SessionManager::getUserIdBySocket(SOCKET s)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = socketToUserId.find(s);
    if (it != socketToUserId.end())
        return it->second;
    return "";
}
bool SessionManager::checkReciever(const std::string recId)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = sessions.find(recId);
    if (it != sessions.end() && it->second->recievingFile)
        return true;
    return false;
}
void SessionManager::setRecievingFileFalse(const std::string recId)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = sessions.find(recId);
    if (it == sessions.end())
    {
        Logger::error(" current reciever is not in the session ");
        return;
    }
    it->second->recievingFile = false;
}
void SessionManager::setRecievingFileTrue(const std::string recId)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = sessions.find(recId);
    if (it == sessions.end())
    {
        Logger::error(" current reciever is not in the session ");
        return;
    }
    it->second->recievingFile = true;
}