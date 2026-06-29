#pragma once
#include<winsock2.h>
#include<queue>
#include<unordered_map>
#include<string>
#include<iostream>
#include<mutex>
#include "../protocol/Packet.h"
#include"./datastructure/Mpsc.h"
#include<set>

class MessageRouter; // Forward declaration
class IOCPManager;   // Forward declaration

class ManageOffline
{
private:
    /* data */
    MessageRouter* router = nullptr;
    IOCPManager* iocp = nullptr;

    // Protects queue_per_client map against concurrent rehash.
    // The MpscQueue inside each entry is itself lock-free, but
    // unordered_map::operator[] can rehash and is NOT thread-safe.
    std::mutex mapMutex;

public:
struct WorkItem {
    std::string recId;
    Packet* packet;
};
struct clientQueue{
    MpscQueue<WorkItem> queue;
    std::atomic<bool>flag{false};// true means a packet is in-flight
};
    std::unordered_map<std::string,clientQueue>queue_per_client; // only keep online client
    std::unordered_map<std::string,Packet*>offData;// sender is offline 
    std::atomic<int>TotalReceivedCompletePacktet{0};
    std::atomic<int>TotalsentCompletePacktet{0};
   
    ManageOffline(/* args */);
    ~ManageOffline();
    void setRouter(MessageRouter* r) { router = r; }
    void setIOCP(IOCPManager* i) { iocp = i; }
    void ManageOffPacket(Packet *p);
    void ManageCompletePacket(Packet *p,std:: string recvId);
    bool mergePacket(std::string id,Packet* p);

    // Called by the IOCP send-completion handler after a packet has been
    // fully sent (or failed). Pops the completed front item, and if the
    // queue has more items, initiates the next send. Otherwise clears the
    // in-flight flag so future ManageCompletePacket calls will kick off a
    // new send.
    //
    // @param recvId  The receiver whose queue to drain
    // @param socket  The socket to send the next packet on
    void drainNext(const std::string& recvId, SOCKET socket);

    // Clear the in-flight flag for a receiver (e.g. when a send fails
    // due to disconnect and the packet should be retried later).
    void clearFlag(const std::string& recvId);
};
