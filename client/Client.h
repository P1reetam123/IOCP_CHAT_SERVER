#pragma once
#include <winsock2.h>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <unordered_map>
#include <fstream>
#include <queue>
#include <condition_variable>
#include <memory>
#include <vector>
#include "../protocol/Packet.h"
#include "../protocol/FileTransferConstants.h"

class Client
{
private:
    SOCKET clientSocket;
    std::string userId;
    std::thread recvThread;
    std::mutex sendMtx;

public:
    Client();
    ~Client();

    bool connectToServer(const std::string &ip, int port);
    void disconnect();
    bool reconnectWithToken();

    std::atomic<bool> isConnected{false};
    std::atomic<int> messagesReceived{0};
    std::vector<char> buffer;
    std::vector<char> streamBuffer;
    std::function<void()> onMessageReceived;

    void setUserId(const std::string &id) { userId = id; }
    std::string getUserId() const { return userId; }
    bool connected() const { return isConnected.load(); }

    bool requestOtp(const std::string &email);
    bool verifyOtp(const std::string &email, const std::string &otp);
    bool signup(const std::string &email, const std::string &number,
                const std::string &username, const std::string &password);
    bool login(const std::string &identifier, const std::string &password);

    bool sendPrivateMessage(const std::string &receiver, const std::string &message);
    bool sendGroupMessage(const std::string &groupId, const std::string &message);
    bool createGroup(const std::string &groupId);
    bool joinGroup(const std::string &groupId);
    bool leaveGroup(const std::string &groupId);

    bool sendFile(const std::string &receiver, const std::string &filepath);
    bool downloadFile(const std::string &uploadId);

private:
    struct UploadState {
        std::string uploadId;
        std::string filepath;
        std::string receiver;
        uint64_t totalSize = 0;
        uint32_t currentRound = 0;
        uint64_t bytesSent = 0;
        uint32_t finalCrc = 0;

        std::vector<std::vector<uint8_t>> roundBuffer;
        std::vector<uint64_t> roundOffsets;

        std::mutex bytesAck;
        std::condition_variable bytesCv;
        bool bytesWritten = false;
        uint64_t startBytes = 0;

        std::mutex ackMtx;
        std::condition_variable ackCv;
        bool ackReceived = false;
        std::vector<uint32_t> missingChunks;

        std::jthread uploadThread;
        
    };

    struct DownloadState {
        std::string uploadId;
        std::string fileName;
        uint64_t totalSize = 0;
        uint64_t receivedOffset = 0;
        uint32_t currentRound = 0;
        uint32_t roundReceivedCount = 0;
        uint32_t finalCrc = 0;

        std::vector<std::vector<uint8_t>> roundBuffer;
        std::ofstream fileStream;
        std::mutex mtx;
    };

    std::unordered_map<std::string, std::shared_ptr<UploadState>> activeUploads;
    std::mutex uploadsMtx;

    std::unordered_map<std::string, std::shared_ptr<DownloadState>> activeDownloads;
    std::mutex downloadsMtx;

    std::vector<uint8_t> accessToken;
    std::vector<uint8_t> refreshToken;

    void receiveLoop();
    void handleIncomingPacket(Packet &p);
    bool sendRawPacket(Packet &p);

    void uploadWorker(std::shared_ptr<UploadState> state);

    void handleDownloadLink(Packet &p);
    void handleFileStart(Packet &p);
    void handleFileChunk(Packet &p);
    void handleRoundEnd(Packet &p);
    void handleFileEnd(Packet &p);

    void writeRoundToDisk(std::shared_ptr<DownloadState> state);
    void sendRoundAck(const std::string& uploadId, uint32_t roundId,
                     const std::vector<uint32_t>& missing = {});

    void HandleFileStartResponse(Packet &p);
    void handleFileAck(Packet &p);
    void HandleFileStatus(Packet &p);
    void HandlePacketAck(Packet &p);

    void handleUserIdPacket(Packet &p);
    void handleTokenGranted(Packet &p);
    void handleAuthFail(Packet &p);
  std::string sanitize(const std::string& name);
    uint32_t computeFileCRC(const std::string& filepath);
};
