#pragma once
#include <string>
#include <unordered_map>
#include <fstream>
#include"../protocol/Packet.h"
#include <mutex>
#include<vector>
#include<thread>
#include<condition_variable>
#include"./protocol/Packet.h"
#include"../offlineManager/ManageOffline.h"
#include <queue>
#include <vector>

class MessageRouter;
class SessionManager;

class FileTransferManager
{
public:
    struct TransferTask {
        std::string fileName;
        std::string receiverId;
        std::string upId;
        size_t startBytes;
    };

    struct TransferState {
        std::string senderId;
        std::string receiverId;
        std::string fileName;
        std::string filePath;
        std::ofstream fileStream;
        size_t round = 0;
       size_t totalLength;
       size_t totalChunks;
       std:: string timestamp;
       std::string uploadId;
       size_t totalChunksRecieved=0;// in whole file recieving 
       size_t chunkRecieved=0; // chunk recieved in one go
       uint32_t checkSum;
       std::vector<bool> chunkReceived;
    };
    struct TransferSession
{
    uint32_t round;
    std::vector<std::vector<char>> buffer;
    std::queue<int> missingChunks;
    size_t bytes_remaining;
    

};

     // this need to maintain resume for receiver and multiple uploads same file to differen users 
     struct ChunkHeader {
    uint32_t uploadIdHash;
    uint16_t chunkIdx;
    uint16_t dataLen;
};
    
private:
    MessageRouter *route=nullptr;
    ManageOffline *off=nullptr;
    SessionManager *se=nullptr;
    // Key = senderId (one active transfer per sender) // later manage concurrent handling
    std::unordered_map<std::string, TransferState*> activeTransfers; // no need of this active transfer 
    std::unordered_map<std::string,TransferState*>uploadIdToTranserState;
    std::unordered_map<uint32_t, TransferState*> uploadIdHashMap;
    std::unordered_map<std::string,TransferState*>downloadableFiles; // clear this after 48 hours or 24
    std::queue<TransferState*>completedUpload;
    std::mutex mtx;
    std::string saveDirectory = "./uploads/";
     struct AckPayload { uint32_t round; std::vector<uint32_t> missing; };
    std::unordered_map<std::string, AckPayload> pendingAcks;
    std::mutex                                  ackMtx;
    std::condition_variable                     ackCv;
    std::thread downloadThread;
    std::condition_variable downloadCv;
    std::mutex downloadMtx;
    bool stopLoop = false;
    std::mutex downloadableFilesMtx;

    // Transfer Thread Pool
    std::queue<TransferTask> transferQueue_;
    std::vector<std::thread> transferWorkers_;
    std::mutex transferMtx_;
    std::condition_variable transferCv_;
    bool stopTransferPool_ = false;
    static constexpr size_t TRANSFER_POOL_SIZE = 4;
    void transferWorkerLoop();

public:
    FileTransferManager();
    ~FileTransferManager();
    void setRouter(MessageRouter* r) { route = r; }
    void setOfflineManager(ManageOffline* o) { off = o; }
    void setSessionManager(SessionManager* s) { se = s; }
    void start();
    void handleStart(Packet *p);
    bool startTransfer(const std::string& sender,
                       const std::string& receiver,
                       const std::string& fileName);

    bool transferChunk(const std::string& sender, const char* data, int size);
    bool finishTransfer(const std::string& sender);
    void handleChunks(Packet *p);
    void handleEnd(Packet *p);
    void requestChunk(Packet *p);
  //  void copyChunks(std::array<std::array<char, 4096>, 1024>& store,const std::string &raw,int pos,int chunkIdx);
   void acknowledgment(Packet *p);
   bool isResumable(TransferState *s){
        return s->totalChunksRecieved <  s->totalChunks;
   }
   void SendAck(const std::string upId,PacketType,const std::string chunkIdx);// this tells missing chunks idx
   void SendAck(const std::string upId,PacketType);// empty string means sequences of chunks have been recieved 
   void HandleDisconnect(Packet *p);
   void HandleResume(Packet *p);
   void sendDownloadLinkLoop();
   bool checkGrp(const  std:: string& Id);
   void HandleDownloadRequest(Packet *p);
   void HandleFileTransfer(const std:: string& fileName, const std:: string &receiverID, const std::string& upId,const size_t startBytes);
   void SendStartAck( const std:: string& sendId, const std:: string &recId, const std::string& upId ,const std:: string &payload);
   void HandleDisconnectRequest(Packet *p);
   // this need to be added as if user want to discontinue to download then this is useful 
 //  void SendDisconnectAck(std:: string recId,std::string upId);
//void SendResumeAck(std::string recId,std::string upId);
   void SendEndAck(
                                     const std::string& recId,
                                     const std::string& upId,
                                     uint32_t           checksum);
   void SendRoundAck(std:: string recId,std::string upId);

   void onAckReceived(Packet *p);
    std::vector<uint32_t> waitForAck(const std::string& upId,
                                     uint32_t            round,
                                     int                 timeoutMs = 5000);   
                                                                      void SendRoundEnd(const std::string&          receiverId,
                                       const std::string&          upId,
                                       uint32_t                    round,
                                       const size_t roundLastIdx);
     void SendErrorPacket(const std::string& recId,
                                          const std::string& upId,
                                          const std::string& reason);           
                     void startResponse(const std::string& upId);      
};