
#include "Client.h"
#include <iostream>
#include <ws2tcpip.h>
#include <cstring>
#include <filesystem>
#include <chrono>
#include <sstream>
#include "../authentication/auth_types.h"
#include <cstddef>
#include <type_traits>
#include <cassert>
#include "./protocol/CRC32C.h"

static_assert(std::is_trivially_copyable<AccessToken>::value,
              "AccessToken must be trivially copyable to go over the wire");
static_assert(std::is_trivially_copyable<RefreshToken>::value,
              "RefreshToken must be trivially copyable to go over the wire");

constexpr std::size_t kAccessTokenSize = sizeof(AccessToken);
constexpr std::size_t kRefreshTokenSize = sizeof(RefreshToken);
constexpr std::size_t kTokenGrantedPayloadLen = kAccessTokenSize + kRefreshTokenSize;

Client::Client()
    : clientSocket(INVALID_SOCKET), isConnected(false)
{
    buffer.resize(16384);
    accessToken.resize(sizeof(AccessToken));
    refreshToken.resize(sizeof(RefreshToken));
}

Client::~Client()
{
    disconnect();
}

bool Client::connectToServer(const std::string &ip, int port)
{
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET)
    {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Connect failed: " << WSAGetLastError() << "\n";
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
        return false;
    }

    isConnected = true;
    recvThread = std::thread(&Client::receiveLoop, this);
    return true;
}

void Client::disconnect()
{
    isConnected = false;

    {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        for (auto& [id, state] : activeUploads) {
            if (state->uploadThread.joinable())
                state->uploadThread.join();
        }
        activeUploads.clear();
    }

    if (clientSocket != INVALID_SOCKET)
    {
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
    }
    if (recvThread.joinable())
    {
        recvThread.join();
    }
}

// ====================== AUTHENTICATION ======================
bool Client::requestOtp(const std::string &email)
{
    Packet p;
    p.serialize(PKT_OTP_REQ, email, "", email);
    return sendRawPacket(p);
}

bool Client::verifyOtp(const std::string &email, const std::string &otp)
{
    Packet p;
    std::string payload = email + " " + otp;
    p.serialize(PKT_OTP_VERIFY, "", "", payload);
    return sendRawPacket(p);
}

bool Client::signup(const std::string &email, const std::string &number, const std::string &username, const std::string &password)
{
    Packet p;
    std::string payload = email + " " + number + " " + username + " " + password;
    p.serialize(PKT_SIGN_UP, "", "", payload);
    return sendRawPacket(p);
}

bool Client::login(const std::string &identifier, const std::string &password)
{
    Packet p;
    std::string payload = identifier + " " + password;
    p.serialize(PKT_LOGIN, identifier, "", payload);
    return sendRawPacket(p);
}

bool Client::reconnectWithToken()
{
    if (accessToken.size() != kAccessTokenSize)
    {
        std::cerr << "[Auth] Refusing to reconnect\n";
        return false;
    }

    Packet p;
    std::string binary_payload(reinterpret_cast<const char*>(accessToken.data()), accessToken.size());
    p.serialize(PKT_TOKEN, "", "", binary_payload);
    return sendRawPacket(p);
}

// ====================== MESSAGING ======================
bool Client::sendPrivateMessage(const std::string &receiver, const std::string &message)
{
    Packet p;
    p.serialize(PKT_PRIVATE_MESSAGE, userId, receiver, message);
    return sendRawPacket(p);
}

bool Client::sendGroupMessage(const std::string &groupId, const std::string &message)
{
    Packet p;
    p.serialize(PKT_GROUP_MESSAGE, userId, groupId, message);
    return sendRawPacket(p);
}

bool Client::createGroup(const std::string &groupId)
{
    Packet p;
    p.serialize(PKT_CREATE_GROUP, userId, groupId, "");
    return sendRawPacket(p);
}

bool Client::joinGroup(const std::string &groupId)
{
    Packet p;
    p.serialize(PKT_JOIN_GROUP, userId, groupId, "");
    return sendRawPacket(p);
}

bool Client::leaveGroup(const std::string &groupId)
{
    Packet p;
    p.serialize(PKT_LEAVE_GROUP, userId, groupId, "");
    return sendRawPacket(p);
}

// ====================== RECEIVE LOOP ======================
void Client::receiveLoop()
{
    while (isConnected)
    {
        int bytesRead = recv(clientSocket, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (bytesRead <= 0)
        {
            std::cout << "Disconnected from server.\n";
            isConnected = false;
            break;
        }

        streamBuffer.insert(streamBuffer.end(), buffer.data(), buffer.data() + bytesRead);
        std::fill(buffer.begin(), buffer.end(), 0);

        while (true)
        {
            if (streamBuffer.size() < HEADER_SIZE) break;

            uint32_t packetSize = ntohl(*reinterpret_cast<uint32_t*>(streamBuffer.data()));
            if (streamBuffer.size() < packetSize || packetSize>sizeof(Packet::data)){
                    std::cout<<" pacekt overflow\n";
                     streamBuffer.erase(streamBuffer.begin(), streamBuffer.begin() + packetSize); // erase that much data
                    break;
            } 

            Packet p;
            std::memcpy(p.data, streamBuffer.data(), packetSize);
            p.in = p.data + packetSize;
            p.parseHeader();

            streamBuffer.erase(streamBuffer.begin(), streamBuffer.begin() + packetSize);

            handleIncomingPacket(p);
            p.parsedHeader = false;
            p.parsedData = false;
        }
    }
}

void Client::handleIncomingPacket(Packet &p)
{
    switch (p.header.type)
    {
        case PKT_USER_ID:           handleUserIdPacket(p); break;
        case PKT_PRIVATE_MESSAGE:
            std::cout << "\n[Private] " << p.senderId << ": " << p.payload << "\n> ";
            if (onMessageReceived) onMessageReceived();
            messagesReceived++;
            break;
        case PKT_GROUP_MESSAGE:
            std::cout << "\n[Group " << p.receiverId << "] " << p.senderId << ": " << p.payload << "\n> ";
            break;
        case DOWNLOAD_LINK:         handleDownloadLink(p); break;
        case PKT_FILE_START:        handleFileStart(p); break;
        case PKT_FILE_CHUNK:        handleFileChunk(p); break;
        case PKT_ROUND_END:         handleRoundEnd(p); break;
        case PKT_FILE_END:          handleFileEnd(p); break;
        case PKT_FILE_ACK:          handleFileAck(p); break;
        case PKT_FILE_STATUS:       HandleFileStatus(p); break;
        case FILE_START_RESPONSE:   HandleFileStartResponse(p); break;
        case PKT_ACKNOWLEDGMENT:
            p.parseData();
            if (p.payload.find("OTP Verified") != std::string::npos)
                std::cout << "\n[Auth] OTP Verified successfully!\n> ";
            else
                HandlePacketAck(p);
            break;
        case PKT_TOKEN_GRANTED:     handleTokenGranted(p); break;
        case PKT_AUTH_FAIL:
        case PKT_SIGNUP_ERROR:      handleAuthFail(p); break;
        case PKT_FILE_ERROR : p.parseData(); std::cout<<p.payload<<std::endl; break;
        default:
            std::cout << "[WARN] Unknown packet type: " << static_cast<int>(p.header.type) << "\n";
            break;
    }
}

bool Client::sendRawPacket(Packet &p)
{
    std::lock_guard<std::mutex> lock(sendMtx);
    if (!isConnected) return false;

    int totalSize = p.header.size;
    int totalSent = 0;

    while (totalSent < totalSize)
    {
        int sent = send(clientSocket, p.data + totalSent, totalSize - totalSent, 0);
        if (sent <= 0) return false;
        totalSent += sent;
    }
    return true;
}

// ====================== AUTH CALLBACKS ======================
void Client::handleUserIdPacket(Packet &p)
{
    p.parseData();
    setUserId(p.payload);
    std::cout << "user id updated successfully: " << p.payload << std::endl;
}

void Client::handleTokenGranted(Packet &p) { 


 p.parseData();

    // Use ONE source for both pointer and length (don't mix data+HEADER_SIZE with payload.size()).
    const uint8_t *payload = reinterpret_cast<const uint8_t *>(p.payload.data());
    const size_t payloadLen = p.payload.size();

    // Validate BEFORE touching memory. No tautological "resize then compare".
    if (payloadLen < kTokenGrantedPayloadLen)
    {
        std::cerr << "[Auth] Token payload too small: got " << payloadLen
                  << ", need " << kTokenGrantedPayloadLen << ". Dropping.\n";
        accessToken.clear();
        refreshToken.clear();
        return;
    }

    accessToken.assign(payload, payload + kAccessTokenSize);
    refreshToken.assign(payload + kAccessTokenSize,
                        payload + kAccessTokenSize + kRefreshTokenSize);

    // Postcondition: the invariant the reconnect path depends on.
    std::cout<<payload<<std::endl;
    assert(accessToken.size() == kAccessTokenSize);
    assert(refreshToken.size() == kRefreshTokenSize);

    std::cout << "\n[Auth] Authentication successful! Tokens received.\n> ";
    return;


 }
void Client::handleAuthFail(Packet &p) { p.parseData(); std::cout << "[Auth] Failed: " << p.payload << "\n"; }

// ====================== FILE TRANSFER ======================
std::string generateUploadId()
{
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return "up_" + std::to_string(now);
}

uint32_t Client::computeFileCRC(const std::string& filepath)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return 0;

    std::vector<uint8_t> buf(1024 * 1024);
    uint32_t crc = 0;
    while (file) {
        file.read(reinterpret_cast<char*>(buf.data()), buf.size());
        size_t read = file.gcount();
        if (read > 0) crc = CRC32C::compute(buf.data(), read, crc);
    }
    return crc;
}

// ====================== UPLOAD ======================
bool Client::sendFile(const std::string &receiver, const std::string &filepath)
{
    if (!isConnected || !std::filesystem::exists(filepath)) return false;

    auto state = std::make_shared<UploadState>();
    state->uploadId = generateUploadId();
    state->filepath = filepath;
    state->receiver = receiver;
    state->totalSize = std::filesystem::file_size(filepath);
    state->finalCrc = computeFileCRC(filepath);
    state->roundBuffer.resize(MAX_CHUNKS_PER_ROUND);
    state->roundOffsets.resize(MAX_CHUNKS_PER_ROUND);

    {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        activeUploads[state->uploadId] = state;
    }
    state->uploadThread = std::jthread(&Client::uploadWorker, this, state);
// first launch the thread then send the packet 
    Packet p;
    p.serializeFileStart(state->receiver,state->uploadId,std::filesystem::path(filepath).filename().string(),
                         state->totalSize,
                         state->finalCrc);
    sendRawPacket(p);

    return true;
}

void Client::uploadWorker(std::shared_ptr<UploadState> state)
{
    std::ifstream file(state->filepath, std::ios::binary);
    if (!file.is_open()) return;

    {
        std::unique_lock<std::mutex> lc(state->bytesAck);
        if (!state->bytesCv.wait_for(lc, std::chrono::seconds(10),
                                     [&](){ return state->bytesWritten; })) {
            std::cerr << "Upload resume timeout\n";
            return;
        }
    }

    file.seekg(static_cast<std::streamoff>(state->startBytes), std::ios::beg);
    uint64_t bytesSent = state->startBytes;
    state->currentRound = static_cast<uint32_t>(
        bytesSent / (static_cast<uint64_t>(MAX_CHUNK_SIZE) * MAX_CHUNKS_PER_ROUND));

    while (bytesSent < state->totalSize)
    {
        uint64_t roundBase = bytesSent;
        uint32_t chunksThisRound = 0;
        state->roundBuffer.assign(MAX_CHUNKS_PER_ROUND, {});

        while (chunksThisRound < MAX_CHUNKS_PER_ROUND && bytesSent < state->totalSize)
        {
            size_t remaining = static_cast<size_t>(state->totalSize - bytesSent);
            size_t chunkSize = std::min(static_cast<size_t>(MAX_CHUNK_SIZE), remaining);

            std::vector<uint8_t> chunk(chunkSize);
            file.read(reinterpret_cast<char*>(chunk.data()), chunkSize);
            size_t read = file.gcount();
            if (read == 0) break;

            chunk.resize(read);
            uint64_t offset = roundBase;
            roundBase += read;
            bytesSent += read;

            state->roundOffsets[chunksThisRound] = offset;
            state->roundBuffer[chunksThisRound] = std::move(chunk);
            chunksThisRound++;
        }

        if (chunksThisRound == 0) break;

        for (uint32_t i = 0; i < chunksThisRound; ++i)
        {
            Packet p;
            p.serializeFileChunk(state->uploadId, state->roundOffsets[i], state->roundBuffer[i]);
            sendRawPacket(p);
        }

        bool roundDone = false;
        while (!roundDone)
        {
            Packet roundP;
            roundP.serializeRoundEnd(state->uploadId, state->currentRound, chunksThisRound);
            sendRawPacket(roundP);

            {
                std::unique_lock<std::mutex> lk(state->ackMtx);
                state->ackReceived = false;
                if (!state->ackCv.wait_for(lk, std::chrono::seconds(15),
                                           [&](){ return state->ackReceived; })) {
                    std::cerr << "Upload ACK timeout\n";
                    return;
                }
            }

            if (state->missingChunks.empty()) {
                roundDone = true;
                state->currentRound++;
            } else {
                for (uint32_t idx : state->missingChunks) {
                    if (idx >= chunksThisRound) continue;
                    Packet p;
                    p.serializeFileChunk(state->uploadId, state->roundOffsets[idx],
                                         state->roundBuffer[idx]);
                    sendRawPacket(p);
                }
            }
        }
    }

    Packet endP;
    endP.serializeFileEnd(state->uploadId, state->finalCrc);
    sendRawPacket(endP);

   
    std::cout << "Upload completed: " << state->filepath << std::endl;
}

std::string Client::sanitize(const std::string& name){
    std::string result = std::filesystem::path(name).filename().string();
    if (result.empty() || result == "." || result == "..") 
        return "unnamed_" + std::to_string(std::time(nullptr));
    return result;
}
// ====================== DOWNLOAD ======================
void Client::handleFileStart(Packet &p)
{
    size_t pos = HEADER_SIZE;
    uint64_t totalSize = p.readUint64(pos);
    std::string senderId=p.readString(pos);
    std::string fileName =sanitize( p.readString(pos));
    std::string uploadId = p.readString(pos);
    uint32_t finalCrc = (pos + 4 <= p.header.size) ? p.readUint32(pos) : 0;

    auto state = std::make_shared<DownloadState>();
    state->uploadId = uploadId;
    state->fileName = fileName;
    state->totalSize = totalSize;
    state->finalCrc = finalCrc;
    state->roundBuffer.resize(MAX_CHUNKS_PER_ROUND);

    std::filesystem::create_directories("./downloads");
    state->fileStream.open("./downloads/" + fileName, std::ios::binary | std::ios::out | std::ios::app);

    if (state->fileStream.is_open()) {
        std::string path = "./downloads/" + fileName;
        if (std::filesystem::exists(path))
            state->receivedOffset = std::filesystem::file_size(path);
        state->currentRound = static_cast<uint32_t>(
            state->receivedOffset / (static_cast<uint64_t>(MAX_CHUNK_SIZE) * MAX_CHUNKS_PER_ROUND));
    }

    {
        std::lock_guard<std::mutex> lock(downloadsMtx);
        activeDownloads[uploadId] = state;
    }

    std::cout << "Downloading: " << fileName << "\n";
}

void Client::handleFileChunk(Packet &p)
{
    size_t pos = HEADER_SIZE;
    std::string uploadId = p.readString(pos);
    uint64_t byteOffset = p.readUint64(pos);
    uint32_t chunkSize = p.readUint32(pos);
    uint32_t crcReceived = p.readUint32(pos);
    std::vector<uint8_t> chunkData = p.readBytes(pos, chunkSize);

    std::shared_ptr<DownloadState> state;
    {
        std::lock_guard<std::mutex> lock(downloadsMtx);
        auto it = activeDownloads.find(uploadId);
        if (it != activeDownloads.end()) state = it->second;
    }
    if (!state) return;

    if (CRC32C::compute(chunkData) != crcReceived) return;

    size_t chunkIndex = (byteOffset / MAX_CHUNK_SIZE) % MAX_CHUNKS_PER_ROUND;

    std::lock_guard<std::mutex> lock(state->mtx);
    if (chunkIndex >= state->roundBuffer.size()) return;
    if (!state->roundBuffer[chunkIndex].empty()) return;

    state->roundBuffer[chunkIndex] = std::move(chunkData);
    state->roundReceivedCount++;
}

void Client::handleRoundEnd(Packet &p)
{
    
    size_t pos = HEADER_SIZE;
    std::string uploadId = p.readString(pos);
   // std::cout<<uploadId<<std::endl;
    uint32_t roundId = p.readUint32(pos);
   //  std::cout<<roundId<<std::endl;
    uint32_t expectedChunkCount = p.readUint32(pos);
 //    std::cout<<expectedChunkCount<<std::endl;

    std::shared_ptr<DownloadState> state;
    {
        std::lock_guard<std::mutex> lock(downloadsMtx);
        auto it = activeDownloads.find(uploadId);
        if (it != activeDownloads.end()) state = it->second;
    }
    if (!state) return;

    std::vector<uint32_t> missing;
    {
        std::lock_guard<std::mutex> lock(state->mtx);
        if (roundId != state->currentRound) {
            sendRoundAck(uploadId, state->currentRound, {});
            return;
        }

        for (uint32_t i = 0; i < expectedChunkCount; ++i) {
            if (state->roundBuffer[i].empty())
                missing.push_back(i);
        }

        if (missing.empty()) {
            writeRoundToDisk(state);
            state->roundReceivedCount = 0;
            state->roundBuffer.assign(MAX_CHUNKS_PER_ROUND, {});
            state->currentRound++;
        }
    }

    sendRoundAck(uploadId, roundId, missing);
}

void Client::writeRoundToDisk(std::shared_ptr<DownloadState> state)
{
    for (auto& chunk : state->roundBuffer) {
        if (!chunk.empty()) {
            state->fileStream.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            state->receivedOffset += chunk.size();
        }
    }
    state->fileStream.flush();
}

void Client::sendRoundAck(const std::string& uploadId, uint32_t roundId,
                          const std::vector<uint32_t>& missing)
{
    Packet p;
    p.serializeFileAck(uploadId, roundId, missing);
    std::cout<<"sending round end  with upload id :- "<<uploadId<<std::endl;
    sendRawPacket(p);
}

void Client::handleFileEnd(Packet &p)
{
    size_t pos = HEADER_SIZE;
    std::string uploadId = p.readString(pos);
    uint32_t finalCrc = p.readUint32(pos);

    std::shared_ptr<DownloadState> state;
    {
        std::lock_guard<std::mutex> lock(downloadsMtx);
        auto it = activeDownloads.find(uploadId);
        if (it != activeDownloads.end()) {
            state = it->second;
            activeDownloads.erase(it);
        }
    }

    if (!state) return;

    if (state->fileStream.is_open())
        state->fileStream.close();

    bool success = (state->receivedOffset == state->totalSize);
    if (success && finalCrc != 0) {
        std::string path = "./downloads/" + state->fileName;
        success = (computeFileCRC(path) == finalCrc);
    }

    if (success)
        std::cout << "\nDownload completed: " << state->fileName << std::endl;
    else
        std::cerr << "\nDownload failed: " << state->fileName << std::endl;
}

void Client::HandleFileStartResponse(Packet &p)
{
    size_t pos = HEADER_SIZE;
    std::string upId = p.readString(pos);
    uint64_t resumeOffset = p.readUint64(pos);

    std::shared_ptr<UploadState> state;
    {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        auto it = activeUploads.find(upId);
        if (it == activeUploads.end()) return;
        state = it->second;
    }

    {
        std::lock_guard<std::mutex> l(state->bytesAck);
        state->startBytes = resumeOffset;
        state->bytesWritten = true;
    }
    state->bytesCv.notify_one();
}

void Client::handleFileAck(Packet &p)
{
    std::cout<<" got the file end ack\n";
    size_t pos = HEADER_SIZE;
    std::string upId = p.readString(pos);
    uint32_t roundId = p.readUint32(pos);
    uint32_t missingCount = p.readUint32(pos);

    std::vector<uint32_t> missing;
    for (uint32_t i = 0; i < missingCount; ++i)
        missing.push_back(p.readUint32(pos));

    std::shared_ptr<UploadState> state;
    {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        auto it = activeUploads.find(upId);
        if (it == activeUploads.end()) return;
        state = it->second;
    }

    if (roundId != state->currentRound) return;

    {
        std::lock_guard<std::mutex> lk(state->ackMtx);
        state->missingChunks = std::move(missing);
        state->ackReceived = true;
    }
    state->ackCv.notify_one();
}

bool Client::downloadFile(const std::string &uploadId)
{
    std::cout<<"enter into download request\n";
    if (!isConnected) return false;

    std::streampos fileSize = 0;
    // {
    //     std::filesystem::create_directory("downloads");
    //     std::string dir = "./downloads/" + 
    //     std::ifstream file(dir, std::ios::ate);
    //     if (file.is_open()) fileSize = file.tellg();
    // }
// recid||updi||bytes ||
    Packet p;
    p.serializeDownloadReq(userId,uploadId,(static_cast<uint32_t>(fileSize)));
    return sendRawPacket(p);
}

void Client::handleDownloadLink(Packet &p)
{
    // Existing logic
    std::string senderid, upId,filename,timestamp;
    uint32_t totalsize;
  size_t pos=HEADER_SIZE;
  senderid=p.readString(pos);
  upId=p.readString(pos);
  filename=p.readString(pos);
  totalsize=p.readUint32(pos);
  timestamp=p.readString(pos);
   
    std::cout << "\n[File Transfer] User " << senderid << " sent: " << filename<<" of size : "<<totalsize<<" at time : "<<timestamp<<" with upload id : - "<<upId << "\n";
}

void Client::HandleFileStatus(Packet &p)
{   p.parseHeader();
    p.parseData();
     {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        activeUploads.erase(p.receiverId); // it contains upload id 
    }

    std::cout << "[File Status] " << p.payload << std::endl;
}

void Client::HandlePacketAck(Packet &p)
{
    p.parseData();
    // Legacy ACK handling
}