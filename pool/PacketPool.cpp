#include"PacketPool.h"
#include<string.h>
#include <stdexcept>
#include"./utils/Logger.h"

PacketPool::PacketPool(){
    pool.resize(currentSize);
    inUse.resize(currentSize);
    for(int i=0;i<currentSize;i++){
        availableIdx.push(i);
        inUse[i]=0;//initlalise all available initially 
    }
}

  // implement in use flag also
  PacketPool& PacketPool::Instance() {
    // Created on first call, thread-safe in C++11+, persists for program lifetime
    static PacketPool instance; 
    return instance;
}

  
  Packet* PacketPool::borrowPacket(){
   
    size_t id;
  {
        std::lock_guard<std::mutex> lk(amx);
        if(availableIdx.empty()) {
          Logger::debug(" no more packet left in the pool current packet in use" + std:: to_string(currentPacketUse));
          return nullptr;
            // throw std::runtime_error("No packet available");
        }
      while(true){
          id = availableIdx.front(); 
        availableIdx.pop();
        if(inUse[id]==0){
                break;
        }
        Logger::info("this packet is already in use ");
      }
       if(id >= currentSize) {
        throw std::runtime_error("Invalid packet index");
    }
       inUse[id]=1;
    } 
   
   // Logger::info(" borrowed a packet of id : "+std::to_string(id));
    pool[id].id=id;

    size_t newCount = currentPacketUse.fetch_add(1, std::memory_order_relaxed) + 1;
    size_t prevPeak = peak.load(std::memory_order_relaxed);
    while (newCount > prevPeak &&
           !peak.compare_exchange_weak(prevPeak, newCount, std::memory_order_relaxed)) {
        // prevPeak is refreshed by compare_exchange_weak on failure; loop retries with latest value
    }
    return &pool[id];
  }



  void PacketPool::returnPacket(  Packet* p){
   if (p == nullptr) return;

    size_t id = p->id;

  //  Logger::info(" returned  a packet of id : "+std::to_string(id));
if (id >= currentSize) {
     //   throw std::runtime_error("Invalid packet index on return");
        return ;
    }

    p->clearInPointer();
    memset(p->data, 0, 4096);

    {
        std::lock_guard<std::mutex> lk(amx);
        if(inUse[id]==0){// means already not in use so don't push in the queue 
 Logger::info("this packet is already returned  "+std::to_string(id));
        return ;

    }
        availableIdx.push(id);
        inUse[id]=0;
    }

    currentPacketUse--; // only decrement once we've confirmed a real, successful return
  }
 
int PacketPool::returnPeak(){
  return peak;
}
// datastructure/fixedQueue.h
