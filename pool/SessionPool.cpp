
#include<iostream>
#include <cstring>
#include"SessionPool.h"
#include"./utils/Logger.h"

SessionPool::SessionPool(){
    maxSize =10000;
    pool.resize(maxSize);
    for(size_t i=0;i<maxSize;i++){
        freeIndices.push(i);
    }
}
SessionPool& SessionPool::Instance() {
    // Created on first call, thread-safe in C++11+, persists for program lifetime
    static SessionPool instance; 
    return instance;
}
 Session* SessionPool::borrowSession(SOCKET s){

 size_t idx;
 {
       std::lock_guard<std::mutex> lk(fmx);
       if(freeIndices.empty()){
    throw std::runtime_error("No packet available"); // instead of throwing error 
}
    idx=freeIndices.front(); freeIndices.pop();
 }

 if(idx>pool.size()){
    //
 }
 Session * se=&(pool[idx]);
 se->id=idx;
 se->setSocket(s);
 //Logger::info(" borrowed a session of id : "+std::to_string(se->id));
  return se;
}
void SessionPool::returnSession(Session *s){

       if (s == nullptr) return;

    size_t id = s->id;
 //   Logger::info(" returned a session of id : "+std::to_string(id));
if (id >= maxSize) {
        throw std::runtime_error("Invalid packet index on return");
    }
    s->recievingFile=false;
    //s->socket=NULL;
    s->userId.clear();
    s->auth_state.store(0, std::memory_order_relaxed);
    std::memset(s->cached_user_id, 0, 16);
    s->cached_expiry.store(0, std::memory_order_relaxed);
   
    {
        
        std::lock_guard<std::mutex>lk(fmx);
        freeIndices.push(id);

    }
    return;

}