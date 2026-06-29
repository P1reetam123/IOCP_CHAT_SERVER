#include<iostream>
#include<vector>
#include<queue>
#include"./session/Session.h"

class SessionPool{
    private:
    std::vector<Session>pool;
    std::queue<size_t>freeIndices;
    std::mutex fmx;
    size_t maxSize ;// keep 10k active users in one server
    public:
    SessionPool();
       SessionPool(const Session&) = delete;
   SessionPool& operator=(const Session&) = delete;

    // The Singleton Accessor
    static SessionPool& Instance();
    Session *borrowSession(SOCKET s);
    void returnSession(Session *s);




};