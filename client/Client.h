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
#include "../protocol/Packet.h"

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
    bool reconnectWithToken();
    std::vector<char> streamBuffer;
    std::atomic<bool> isConnected;
    std::vector<char> buffer;
    std::function<void()> onMessageReceived; 
    bool connectToServer(const std::string &ip, int port);
    std::atomic<int> messagesReceived{0};
    void disconnect();

    // Set the registered user id
    void setUserId(const std::string &id) { userId = id; }
    std::string getUserId() const { return userId; }
    bool connected() const { return isConnected.load(); }

    // Handlers
    bool requestOtp(const std::string &email);
    bool verifyOtp(const std::string &email, const std::string &otp);
    bool signup(const std::string &email, const std::string &number, const std::string &username, const std::string &password);
    bool login(const std::string &identifier, const std::string &password);
    bool sendPrivateMessage(const std::string &receiver, const std::string &message);
    bool sendGroupMessage(const std::string &groupId, const std::string &message);
    bool createGroup(const std::string &groupId);
    bool joinGroup(const std::string &groupId);
    bool leaveGroup(const std::string &groupId);

    // File Transfer Methods
    bool sendFile(const std::string &receiver, const std::string &filepath);
    bool downloadFile(const std::string &uploadId);

private:
    struct UploadState
    {
        std::string uploadId;
        size_t startBytes;
        std::string filepath;
        std::string receiver;
        size_t totalSize;
        size_t totalChunks;
        uint32_t currentRound;
        std::queue<uint32_t> missingChunks;
        std::mutex ackMtx;
        std::condition_variable ackCv;
        bool ackReceived = false;
        bool isFinished = false;
        bool isError = false;
        std::mutex bytesAck;
        bool bytesWritten = false;
        std::condition_variable bytesCv;
        std::thread uploadThread;
        ~UploadState()
        {
            if (uploadThread.joinable())
                uploadThread.join();
        }
    };

    struct DownloadState
    {
        std::string uploadId;
        std::string fileName;
        size_t totalSize;
        size_t totalChunks;
        std::ofstream fileStream;
        size_t bytesReceived = 0;
        uint32_t currentRound = 0;
        int chunkRecieved;
        size_t round;
        // std::unordered_map<std::string, std::vector<char>> //chunkBuffer; // round local buffer
    };
    std::unordered_map<std::string, std::vector<std::string>> chunkBuffer;
    std::unordered_map<std::string, std::shared_ptr<UploadState>> activeUploads;
    std::mutex uploadsMtx;

    std::unordered_map<std::string, std::shared_ptr<DownloadState>> activeDownloads;
    std::mutex downloadsMtx;

    // File transfer hash map mapping (uploadIdHash -> uploadId)
    std::unordered_map<uint32_t, std::string> uploadIdHashMap;
    std::mutex hashMtx;

    // Authentication Tokens
    std::vector<uint8_t> accessToken;
    std::vector<uint8_t> refreshToken;

    void uploadThreadFunc(std::shared_ptr<UploadState> state);

    void receiveLoop();
    void handleIncomingPacket(Packet &p);
    bool sendRawPacket(Packet &p);

    // File Transfer Packet Handlers
    void handleDownloadLink(Packet &p);
    void handleFileStart(Packet &p);
    void handleFileChunk(Packet &p);
    void handleRoundEnd(Packet &p);
    void handleRoundStatus(Packet &p);
    void handleFileEnd(Packet &p);
    void HandleFileStatus(Packet &p);
    void HandleFileStartResponse(Packet &p);
    void HandlePacketAck(Packet &p);
    void handleTokenGranted(Packet &p);
    void handleAuthFail(Packet &p);
    void SendAck(const std::string upId, PacketType P);
    void SendAck(const std::string upId, PacketType P, const std::string chunkIdx);
};
