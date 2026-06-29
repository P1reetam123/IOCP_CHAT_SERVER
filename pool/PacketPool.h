#include<vector>
#include<queue>
#include"./protocol/packet.h"
#include<mutex>
#include<atomic>
class PacketPool
{

    std::vector<Packet>pool;// 100mb
     std::queue<size_t>availableIdx;
     std::vector<uint8_t>inUse;
     std::atomic<size_t>currentPacketUse{0};
     std::atomic<size_t>peak{0};
     //std::mutex pmx;
      std::mutex amx;
      size_t idx=0;
    const size_t currentSize=25000;
     PacketPool();
public:
      PacketPool(const PacketPool&) = delete;
    PacketPool& operator=(const PacketPool&) = delete;

    // The Singleton Accessor
    static PacketPool& Instance();

     Packet* borrowPacket();
     void returnPacket(Packet *p);
    
   int returnPeak();
   

};

