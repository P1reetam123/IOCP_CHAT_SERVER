#pragma once
#include <string>
#include <unordered_map>
#include <fstream>
#include "../protocol/Packet.h"
#include "../protocol/FileTransferConstants.h"
#include <mutex>
#include <vector>
#include <thread>
#include <condition_variable>
#include "../offlineManager/ManageOffline.h"
#include <queue>

class MessageRouter;
class SessionManager;

struct TransferState {
    std::string senderId;
    std::string receiverId;
    std::string uploadId;
    std::string fileName;
    std::string tempPath;
    std::string timestamp;
    uint64_t totalSize = 0;
    uint64_t receivedOffset = 0;
    uint32_t currentRound = 0;
    uint32_t roundReceivedCount = 0;
    uint32_t finalCrc = 0;

      std::mutex ackMtx;
        std::condition_variable ackCv;
bool ackReceived=false;
    std::vector<std::vector<uint8_t>> roundBuffer;
     std::vector<uint64_t> roundOffsets;
      std::vector<uint32_t> missingChunks;
    std::ofstream fileStream;
    std::mutex mtx;
    TransferState(){
        roundBuffer.assign(MAX_CHUNKS_PER_ROUND, {});
roundOffsets.assign(MAX_CHUNKS_PER_ROUND, 0);
missingChunks.clear();
    }
};

class FileTransferManager
{
public:
    FileTransferManager();
    ~FileTransferManager();
    void stopAllTransfers();
    void setRouter(MessageRouter* r) { route = r; }
    void setOfflineManager(ManageOffline* o) { off = o; }
    void setSessionManager(SessionManager* s) { se = s; }
    void start();

    void handleFileStart(Packet* p, const std::string& senderId);
    void handleFileChunk(Packet* p);
    void handleRoundEnd(Packet* p);
    void handleFileEnd(Packet* p);

    void sendDownloadLinkLoop();
    bool checkGrp(const std::string& Id);
    void HandleDownloadRequest(Packet* p);
    void HandleFileTransfer(const std::string& fileName,
                            const std::string& receiverID,
                            const std::string& upId,
                            size_t startBytes);

    void onAckReceived(Packet* p);
    std::vector<uint32_t> waitForAck(const std::string& upId,
                                     uint32_t round,
                                     int timeoutMs = 5000);
    void SendErrorPacket(const std::string& recId,
                         const std::string& upId,
                         const std::string& reason);
    void HandleDisconnectRequest(Packet* p);

    void writeRoundToDisk(TransferState* state);
    TransferState* getTransferState(const std::string& uploadId);
    void cleanupTransfer(const std::string& uploadId);
    uint32_t computeFileCRC(const std::string& filepath);
    void sendAck(const std::string& uploadId, uint32_t roundId,
                 const std::vector<uint32_t>& missingChunks,
                 const std::string& recId);
    void sendFileStatus(const std::string& uploadId, bool success,
                        const std::string& recId);

private:
    MessageRouter* route = nullptr;
    ManageOffline* off = nullptr;
    SessionManager* se = nullptr;

    std::unordered_map<std::string, TransferState*> activeTransfers;
    std::unordered_map<std::string, TransferState*> uploadIdToTransferState;
    std::unordered_map<std::string, TransferState*> downloadableFiles;
    std::queue<TransferState*> completedUpload;
    std::mutex mtx;

    struct AckPayload { uint32_t round; std::vector<uint32_t> missing; };
    std::unordered_map<std::string, AckPayload> pendingAcks;
    std::mutex ackMtx;
    std::condition_variable ackCv;

    std::thread downloadThread;
    std::condition_variable downloadCv;
    std::mutex downloadMtx;
    bool stopLoop = false;
    std::mutex downloadableFilesMtx;
        std::string sanitize(const std::string& name);
    std::string saveDirectory = "./uploads/";
};
