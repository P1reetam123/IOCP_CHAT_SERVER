#include "ManageOffline.h"
#include "../chat/MessageRouter.h"
#include "../utils/Logger.h"
#include "../network/IOCPManager.h"
#include <iostream>
#include"./pool/PacketPool.h"

ManageOffline::ManageOffline() {
}
ManageOffline::~ManageOffline() {
}

void ManageOffline::ManageCompletePacket(Packet *p,std::string recvId){

    WorkItem item; 
    item.recId=recvId;
    item.packet=p;

    clientQueue* cq = nullptr;
    {
       // lock only for lookup
        std::lock_guard<std::mutex> lock(mapMutex);
        cq = &queue_per_client[recvId];
    }

    cq->queue.push(item); // lock-free push

    // If no packet is currently in-flight for this receiver, we need to
    // kick off the send for the front item we just pushed.
    // compare_exchange: expected=false → set to true 
    bool expected = false;
    if(cq->flag.compare_exchange_strong(expected, true, 
            std::memory_order_acq_rel, std::memory_order_acquire)) {
        // We set flag false→true, so we own the send slot.
        WorkItem front = cq->queue.front();
        bool routed = router->routePacket(front.packet, recvId);
        if(!routed) {
            // routePacket failed (receiver offline) — clear the flag so
            // the next ManageCompletePacket call will retry.
            // The packet stays at the front of the queue.
            cq->flag.store(false, std::memory_order_release);
        }
    }
    // else: a packet is already in-flight; when it completes,
    // drainNext() will pick up our newly-pushed item.

    TotalReceivedCompletePacktet++;
}

void ManageOffline::drainNext(const std::string& recvId, SOCKET socket){
    clientQueue* cq = nullptr;
    {
        std::lock_guard<std::mutex> lock(mapMutex);
        auto it = queue_per_client.find(recvId);
        if(it == queue_per_client.end()) return;
        cq = &it->second;
    }

    // Pop the completed front item
    cq->queue.pop();

    // Check if there are more packets to send
    if(!cq->queue.empty()){
        WorkItem next = cq->queue.front();
        bool sent = iocp->initiateSend(socket, next.packet);
        if(!sent){
            // initiateSend failed immediately — clear flag so the next
            // ManageCompletePacket will retry the front item.
            cq->flag.store(false, std::memory_order_release);
        }
        // If sent==true, the flag stays true; the next IOCP completion
        // will call drainNext again.
    } else {
        // Queue drained — clear the in-flight flag
        cq->flag.store(false, std::memory_order_release);
    }
}

void ManageOffline::clearFlag(const std::string& recvId){
    std::lock_guard<std::mutex> lock(mapMutex);
    auto it = queue_per_client.find(recvId);
    if(it != queue_per_client.end()){
        it->second.flag.store(false, std::memory_order_release);
    }
}
