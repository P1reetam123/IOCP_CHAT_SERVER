#include "SessionManager.h"
#include "../utils/Logger.h"
#include "./network/IOCPManager.h"
#include "./pool/SessionPool.h"

void SessionManager::updateNewId(const std::string &id, Session *s)
{
    std::lock_guard<std::mutex> lock(mtx); // this lock  for whole update process so it ensuure no deadlock
    // once login ---> socket -->mainid, mainId->>previous session
    // this to update old id to new id ,

    std::string newid = s->userId; // new id and currently not updated sesstions for this
    auto newit = sessions.find(newid);
    // to check whether there is any previous session on current id
    if (newit != sessions.end())
    {                                             // we got the old session
        SOCKET oldSocket = newit->second->socket; /// got the socket of old user

        s->iocp->HandleDisconnectWithoutLock(oldSocket);
        socketToUserId.erase(oldSocket);
        SessionPool::Instance().returnSession(newit->second); // return the session
        sessions.erase(newit);                                // this erase the session on new id , means old login
    }

    // to delete temporary id
    auto it = sessions.find(id); // temporary id
    if (it != sessions.end())
    {
        sessions.erase(it); // erase the old id
    }
    // to update new id
    socketToUserId[s->socket] = s->userId;
    sessions[s->userId] = s; // add current session on new id // overwrite old temp id to new id
}
void SessionManager::addSession(const std::string &id, Session *session)
{
    std::lock_guard<std::mutex> lock(mtx);
    sessions[id] = session;               ////// old id ----> session
    socketToUserId[session->socket] = id; // current socket --> old id
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