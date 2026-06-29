#pragma once
#include "Client.h"
#include <iostream>
#include <ws2tcpip.h>
#include <cstring>
#include <filesystem>
#include <chrono>
#include <sstream>
#include "../authentication/auth_types.h"
// token_wire.h

#include <cstddef>
#include <type_traits>
#include <cassert>

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
    // FIX #4: WSAStartup/WSACleanup removed from here.
    // Call WSAStartup once in main() before creating any Client,
    // and WSACleanup once in main() after all Clients are destroyed.

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
    if (clientSocket != INVALID_SOCKET)
    {
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
    }
    if (recvThread.joinable())
    {
        recvThread.join();
    }
    // FIX #4: WSACleanup removed from here. Call it once in main().
}

bool Client::requestOtp(const std::string &email)
{
    Packet p;
    // Server expects email as senderId
    p.serialize(PKT_OTP_REQ, email, "", email);
    return sendRawPacket(p);
}

bool Client::verifyOtp(const std::string &email, const std::string &otp)
{
    Packet p;
    std::string payload=email+" "+otp;
    p.serialize(PKT_OTP_VERIFY, "", "", payload);
    return sendRawPacket(p);
}

bool Client::signup(const std::string &email, const std::string &number, const std::string &username, const std::string &password)
{
    userId = username;
    Packet p;
    std::string payload = email + " " + number + " " + username + " " + password;
    p.serialize(PKT_SIGN_UP, "", "", payload);
    return sendRawPacket(p);
}

bool Client::login(const std::string &identifier, const std::string &password)
{
    userId = identifier;
    Packet p;
    std::string payload= identifier+" "+password;
    p.serialize(PKT_LOGIN, identifier, "",payload);
    return sendRawPacket(p);
}

bool Client::reconnectWithToken()
{
    // Enforce the wire contract loudly instead of trusting it silently.
    if (accessToken.size() != kAccessTokenSize)
    {
        std::cerr << "[Auth] Refusing to reconnect: access token is "
                  << accessToken.size() << " bytes, expected "
                  << kAccessTokenSize << ". Call login() again.\n";
        return false;
    }

    Packet p;
    // Drive length off the vector's real size (now guaranteed == kAccessTokenSize).
    std::string binary_payload(
        reinterpret_cast<const char *>(accessToken.data()),
        accessToken.size());
std::cout<<binary_payload<<std::endl;

    p.serialize(PKT_TOKEN, "", "", binary_payload);
    return sendRawPacket(p);
}

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

void Client::receiveLoop()
{
    while (isConnected)
    {
        // FIX #1: was sizeof(buffer) which returns sizeof(std::vector) ~24 bytes,
        // not the allocated capacity. Use buffer.size() to pass the correct 4096.
        int bytesRead = recv(clientSocket, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (bytesRead <= 0)
        {
            std::cout << "Disconnected from server.\n";
            isConnected = false;
            break;
        }

        // Feed data into stream buffer
        streamBuffer.insert(streamBuffer.end(), buffer.data(), buffer.data() + bytesRead);
        std::fill(buffer.begin(), buffer.end(), 0);

        while (true)
        {
            // Need at least header
            if (streamBuffer.size() < HEADER_SIZE)
                break;

            uint32_t packetSize =
                ntohl(*reinterpret_cast<uint32_t *>(streamBuffer.data()));

            // Full packet not yet received
            if (streamBuffer.size() < packetSize)
                break;

            // Build packet from stream buffer
            Packet p;
            std::memcpy(
                p.data,
                streamBuffer.data(),
                packetSize);

            p.in = p.data + packetSize;
            p.parseHeader();

            // Remove consumed packet bytes
            streamBuffer.erase(
                streamBuffer.begin(),
                streamBuffer.begin() + packetSize);

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
    case PKT_PRIVATE_MESSAGE:
        std::cout << "\n[Private] " << p.senderId << ": " << p.payload << "\n> ";
        if (onMessageReceived)
            onMessageReceived();
        messagesReceived++;
        break;
    case PKT_GROUP_MESSAGE:
        std::cout << "\n[Group " << p.receiverId << "] " << p.senderId << ": " << p.payload << "\n> ";
        break;
    case DOWNLOAD_LINK:
        handleDownloadLink(p);
        break;
    case PKT_FILE_START:
        handleFileStart(p);
        break;
    case PKT_FILE_CHUNK:
        handleFileChunk(p);
        break;
    case ROUND_STATUS:
        handleRoundStatus(p);
        std::cout << " round status is arrived " << std::endl;
        break;
    case PKT_FILE_END:
        handleFileEnd(p);
        break;
    case FILE_STATUS:
        HandleFileStatus(p);
        break;
    case FILE_START_RESPONSE:
        HandleFileStartResponse(p);
        break;
    case PKT_ACKNOWLEDGMENT:
        p.parseData();
        if (p.payload.find("OTP Verified") != std::string ::npos)
        {
            std::cout << "\n[Auth] OTP Verified successfully! You can now /register.\n> ";
        }
        else
        {
            HandlePacketAck(p);
        }
        break;
    case PKT_ROUND_END:
        HandlePacketAck(p);
        break;
    case PKT_FILE_ERROR:
        std::cout << "\n[File Error] " << p.payload << "\n> ";
        break;
    case PKT_TOKEN_GRANTED:
        handleTokenGranted(p);
        break;
    case PKT_AUTH_FAIL:
        handleAuthFail(p);
        break;
    default:
        std::cout << "[WARN] Unknown packet type: "
                  << static_cast<int>(p.header.type) << "\n";
        break;
    }
}

bool Client::sendRawPacket(Packet &p)
{
    std::lock_guard<std::mutex> lock(sendMtx);
    if (!isConnected)
        return false;

    int totalSize = p.header.size;
    int totalSent = 0;

    // FIX #3: replaced stale `sent` variable check after loop exit.
    // Now returns false immediately on any send error, true only when
    // all bytes are confirmed sent.
    while (totalSent < totalSize)
    {
        int sent = send(
            clientSocket,
            p.data + totalSent,
            totalSize - totalSent,
            0);

        if (sent <= 0)
            return false;

        totalSent += sent;
    }
    return true;
}

// Authentication Callbacks

void Client::handleTokenGranted(Packet &p)
{ // return bool so caller knows
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

void Client::handleAuthFail(Packet &p)
{
    p.parseData();
    std::cout << "\n[Auth] Authentication failed: " << p.payload << "\n> ";
}

// File Transfer Implementation

std::string generateUploadId()
{
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return "up_" + std::to_string(now);
}

bool Client::sendFile(const std::string &receiver, const std::string &filepath)
{
    if (!isConnected)
        return false;
    if (!std::filesystem::exists(filepath))
    {
        std::cout << "File does not exist: " << filepath << "\n";
        return false;
    }

    size_t totalSize = std::filesystem::file_size(filepath);
    size_t totalChunks = (totalSize + 3999) / 4000;
    std::string fileName = std::filesystem::path(filepath).filename().string();
    std::string uploadId = generateUploadId();

    auto state = std::make_shared<UploadState>();
    state->uploadId = uploadId;
    state->filepath = filepath;
    state->receiver = receiver;
    state->totalSize = totalSize;
    state->totalChunks = totalChunks;
    state->currentRound = 0;

    {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        activeUploads[uploadId] = state;
    }

    std::string timestamp = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    std::string payload = std::to_string(totalSize) + " " + fileName + " " + uploadId + " " + std::to_string(totalChunks) + " " + timestamp + " " + std::to_string(totalSize);

    Packet p;
    p.serialize(PKT_FILE_START, userId, receiver, payload);
    state->uploadThread = std::thread(&Client::uploadThreadFunc, this, state);
    std::cout << "\nUpload started for " << fileName << " (ID: " << uploadId << ")\n> ";
    sendRawPacket(p);

    return true;
}

void Client::uploadThreadFunc(std::shared_ptr<UploadState> state)
{
    {
        std::unique_lock<std::mutex> lc(state->bytesAck);
        if (!state->bytesCv.wait_for(lc, std::chrono::seconds(10), [state]
                                     { return state->bytesWritten; }))
        {
            std::cout << "did not recieve the start response " << std::endl;
            return;
        }
    }

    std::ifstream file(state->filepath, std::ios::binary);
    if (!file.is_open())
    {
        std::cout << "\nFailed to open file for upload: " << state->filepath << "\n> ";
        return;
    }

    size_t bytesSent = state->startBytes;
    file.seekg(state->startBytes, std::ios::beg);
    while (bytesSent < state->totalSize)
    {
        size_t bytesRemaining = state->totalSize - bytesSent;
        size_t chunksThisRound = 0;
        std::vector<std::vector<char>> roundBuffer;
        size_t bytesthisRound = 0;

        while (bytesRemaining > 0 && chunksThisRound < 1024)
        {
            size_t chunkSize = std::min(static_cast<size_t>(4000), bytesRemaining);
            std::vector<char> block(chunkSize);
            file.read(block.data(), chunkSize);
            bytesthisRound += chunkSize;
            roundBuffer.push_back(block);
            bytesRemaining = chunkSize;
            chunksThisRound++;
        }

        for (uint32_t i = 0; i < chunksThisRound; i++)
        {
            state->missingChunks.push(i);
        }

        bool retryRound = true;
        while (retryRound && isConnected)
        {
            while (!state->missingChunks.empty())
            {
                uint32_t idx = state->missingChunks.front();
                state->missingChunks.pop();

                // Compute FNV            1a hash of uploadId for binary chunk serialization
                uint32_t uploadIdHash = 2166136261u;
                for (char c : state->uploadId)
                {
                    uploadIdHash ^= static_cast<uint8_t>(c);
                    uploadIdHash *= 16777619u;
                }

                Packet p;
                p.serializeChunkBinary(uploadIdHash, static_cast<uint16_t>(idx), roundBuffer[idx].data(), static_cast<uint16_t>(roundBuffer[idx].size()));
                sendRawPacket(p);
            }

            Packet ackP;
            ackP.serialize(PKT_ACKNOWLEDGMENT, state->uploadId, std::to_string(chunksThisRound), "");
            sendRawPacket(ackP);

            std::unique_lock<std::mutex> lk(state->ackMtx);
            if (state->ackCv.wait_for(lk, std::chrono::seconds(10), [state]
                                      { return state->ackReceived; }))
            {
                state->ackReceived = false;
                if (state->missingChunks.empty())
                {
                    retryRound = false;
                }
            }
            else
            {
                std::cout << "\n[Upload] ACK timeout, resending round...\n> ";
                for (uint32_t i = 0; i < chunksThisRound; i++)
                    state->missingChunks.push(i);
            }
        }

        bytesSent += bytesthisRound;
        state->currentRound++;
    }

    Packet endP;
    endP.serialize(PKT_FILE_END, state->uploadId, "0", "");
    sendRawPacket(endP);

    std::cout << "\nUpload complete: " << state->filepath << "\n> ";
}

void Client::HandleFileStartResponse(Packet &p)
{
    std::cout << " handle file function " << std::endl;
    char *st = p.data + HEADER_SIZE;
    size_t len = p.header.size - HEADER_SIZE;
    std::string raw(st, len);
    std::string upId, recId, bytes;
    std::istringstream iss(raw);
    if (!(iss >> upId >> recId >> bytes))
    {
        std::cout << " returned without working " << std::endl;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        auto it = activeUploads.find(upId);
        if (it == activeUploads.end())
        {
            std::cout << " upload is not found " << std::endl;
            return;
        }

        auto state = it->second;
        {
            std::lock_guard<std::mutex> l(state->bytesAck);
            state->startBytes = std::stoll(bytes);
            state->bytesWritten = true;
        }
        state->bytesCv.notify_one();
    }
}

bool Client::downloadFile(const std::string &uploadId)
{
    if (!isConnected)
        return false;

    std::streampos fileSize;
    {
        std::lock_guard<std::mutex> lk(downloadsMtx);
        auto it = activeDownloads.find(uploadId);
        if (it == activeDownloads.end())
        {
            std::cout << " no active downloads for this id " << std::endl;
            return false;
        }
        auto state = it->second;
        std::filesystem::create_directory("downloads");

        {
            const std::string dir = "./downloads/" + state->fileName;
            std::ifstream file(dir, std::ios::ate);
            fileSize = file.tellg();
            if (fileSize == std::streampos(1))
            {
                std::cout << " error in finding the file size\n";
                return false;
            }
        }
    }

    Packet p;
    p.serialize(DOWNLOAD_REQUEST, userId, uploadId, std::to_string(static_cast<std::streamoff>(fileSize)));
    std::cout << " download request sent \n";
    return sendRawPacket(p);
}

void Client::handleDownloadLink(Packet &p)
{
    char *st = p.data + HEADER_SIZE;
    size_t len = p.header.size - HEADER_SIZE;
    std::string raw(st, len);
    std::stringstream ss(raw);
    std::string sendId, recId, upId, fileName, length, timestamp;
    ss >> sendId >> recId >> upId >> fileName >> length >> timestamp;

    std::cout << "\n[File Transfer] User " << sendId << " sent a file: " << fileName
              << " (" << length << " bytes). Type '/download " << upId << std::endl;

    auto state = std::make_shared<DownloadState>();
    state->uploadId = upId;
    state->fileName = fileName;

    std::cout << " before the stoll\n";
    state->totalSize = std::stoll(length);
    std::cout << " after the stoll\n";
    state->bytesReceived = 0;

    {
        std::lock_guard<std::mutex> lk(downloadsMtx);
        activeDownloads[upId] = state;
        std::cout << " pushed into active download \n";
    }

    {
        uint32_t hash = 2166136261u;
        for (char c : upId)
        {
            hash ^= static_cast<uint8_t>(c);
            hash *= 16777619u;
        }
        std::lock_guard<std::mutex> lk(hashMtx);
        uploadIdHashMap[hash] = upId;
    }
}

void Client::handleFileStart(Packet &p)
{
    p.parseData();
    std::stringstream ss(p.payload);
    std::string sender, receiver, fileSize, fileName, upId, totalChunks, timestamp, length;
    ss >> sender >> receiver >> fileSize >> fileName >> upId >> totalChunks >> timestamp >> length;

    chunkBuffer[upId].resize(1024);

    {
        uint32_t hash = 2166136261u;
        for (char c : upId)
        {
            hash ^= static_cast<uint8_t>(c);
            hash *= 16777619u;
        }
        std::lock_guard<std::mutex> lk(hashMtx);
        uploadIdHashMap[hash] = upId;
    }

    std::cout << "\nDownloading " << fileName << "...\n> ";
}

void Client::handleFileChunk(Packet &p)
{
    // Packet is already parsed as binary ChunkHeader
    if (p.header.size < HEADER_SIZE + sizeof(ChunkHeader))
        return;

    const char *chunkStart = p.data + HEADER_SIZE;
    const ChunkHeader *ch = reinterpret_cast<const ChunkHeader *>(chunkStart);

    uint32_t hash = ch->uploadIdHash;
    int chunkIdx = ch->chunkIdx;

    std::string upId;
    {
        std::lock_guard<std::mutex> lk(hashMtx);
        auto it = uploadIdHashMap.find(hash);
        if (it == uploadIdHashMap.end())
            return;
        upId = it->second;
    }

    std::shared_ptr<DownloadState> state;
    {
        std::lock_guard<std::mutex> lock(downloadsMtx);
        if (activeDownloads.count(upId))
        {
            state = activeDownloads[upId];
        }
    }
    if (!state)
        return;

    const char *dataStart = chunkStart + sizeof(ChunkHeader);
    std::string chunkData(dataStart, ch->dataLen);

    auto &arr = chunkBuffer[upId];
    if (chunkIdx >= 0 && chunkIdx < 1024 && arr[chunkIdx].empty())
    {
        arr[chunkIdx] = chunkData;
        state->chunkRecieved += 1;
    }
}

void Client::handleRoundStatus(Packet &p)
{
    std::string upId;
    std::string missingData;

    char *st = p.data + HEADER_SIZE;
    size_t len = p.header.size - HEADER_SIZE;
    std::string raw(st, len);
    size_t pos = 0;
    while (pos < raw.size() && raw[pos] != ' ')
    {
        upId.push_back(raw[pos++]);
    }
    pos++;
    while (pos < raw.size() && raw[pos] != ' ')
        pos++;
    pos++; // skip recid
    while (pos < raw.size() && raw[pos] != ' ')
        missingData.push_back(raw[pos++]);

    // Upload side: server is ACKing a round we sent
    {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        if (activeUploads.count(upId))
        {
            auto state = activeUploads[upId];
            std::lock_guard<std::mutex> lk(state->ackMtx);

            std::stringstream ss(missingData);
            std::string idx;
            while (ss >> idx)
            {
                state->missingChunks.push(std::stoul(idx));
            }
            state->ackReceived = true;
            state->ackCv.notify_one();
            return;
        }
    }
}

void Client::handleFileEnd(Packet &p)
{
    std::cout << " handling file end packet \n";
    char *st = p.data + HEADER_SIZE;
    size_t len = p.header.size - HEADER_SIZE;
    std::string raw(st, len);
    std::stringstream ss(raw);
    std::string upId;
    ss >> upId;

    std::shared_ptr<DownloadState> state;
    {
        std::lock_guard<std::mutex> lock(downloadsMtx);
        if (activeDownloads.count(upId))
        {
            state = activeDownloads[upId];
            activeDownloads.erase(upId);
        }
        else
        {
            std::cout << " state not found \n";
        }
    }
    if (!state)
        return;

    state->fileStream.close();
    std::cout << "\nDownload complete: " << state->fileName << " (Saved in ./downloads/)\n> ";
}

void Client::HandleFileStatus(Packet &p)
{
    std::string upId;
    std::string message;

    char *st = p.data + HEADER_SIZE;
    size_t len = p.header.size - HEADER_SIZE;
    std::string raw(st, len);
    size_t pos = 0;
    while (pos < raw.size() && raw[pos] != ' ')
    {
        upId.push_back(raw[pos++]);
    }
    pos++;
    while (pos < raw.size() && raw[pos] != ' ')
        pos++;
    pos++; // skip recid
    while (pos < raw.size() && raw[pos] != ' ')
        message.push_back(raw[pos++]);

    if (message.empty())
    {
        std::cout << " upload for id : " << upId << " is completed successfully" << std::endl;
    }
    else
    {
        std::cout << message << std::endl;
    }
}

// FIX #5: activeDownloads accessed without holding downloadsMtx — fixed by
// taking the lock, retrieving the shared_ptr under the lock, then releasing
// it before doing any further work with the state.
void Client::HandlePacketAck(Packet &p)
{
    std::cout << " got the server asking for ack \n";
    char *st = p.data + HEADER_SIZE;
    int len = p.header.size - HEADER_SIZE;
    std::string raw(st, len);
    size_t pos = 0;
    std::string upId;
    std::string tc; // total chunks sent in this round
    while (pos < raw.size() && raw[pos] != ' ')
        upId.push_back(raw[pos++]);
    pos++;
    while (pos < raw.size() && raw[pos] != ' ')
        tc.push_back(raw[pos++]);

    std::cout << " upID : " << upId << " last chunkIdx : " << tc << std::endl;

    // FIX #5: acquire lock before touching activeDownloads
    std::shared_ptr<DownloadState> state;
    {
        std::lock_guard<std::mutex> lock(downloadsMtx);
        auto it = activeDownloads.find(upId);
        if (it == activeDownloads.end())
        {
            std::cout << " no transfer state\n";
            return;
        }
        state = it->second;
    }

    int tcInt;
    try
    {
        tcInt = std::stoi(tc);
    }
    catch (...)
    {
        std::cout << " problem in stoi \n";
        return;
    }

    std::cout << " total incoming chunk is : " << tcInt
              << " total stored chunk in buffer " << state->chunkRecieved << std::endl;

    if (tcInt == state->chunkRecieved)
    {
        state->chunkRecieved = 0;

        std::string dir = "./downloads/" + state->fileName;
        std::cout << state->fileName << std::endl;
        {
            std::ofstream in(dir, std::ios::binary | std::ios::app);
            if (!in)
            {
                std::cout << " unable to open the file \n";
                return;
            }
            auto &chunkStore = chunkBuffer[upId];
            for (size_t i = 0; i < static_cast<size_t>(tcInt); i++)
            {
                in.write(chunkStore[i].data(), chunkStore[i].length());
                if (!in)
                {
                    std::cout << " Error writing chunk " << i << ". Disk full?\n";
                    in.close();
                    return;
                }
                chunkStore[i].clear();
            }
            in.flush();
            in.close();
        }

        SendAck(upId, ROUND_STATUS);
        state->round += 1;
        std::cout << " round ack sent with successful message \n";
    }
    else
    {
        std::string missingChunksIdx;
        auto &missingStore = chunkBuffer[upId];
        for (size_t i = 0; i < static_cast<size_t>(tcInt); i++)
        {
            if (missingStore[i].empty())
            {
                missingChunksIdx += std::to_string(i);
                missingChunksIdx.push_back(' ');
            }
        }
        if (!missingChunksIdx.empty())
            missingChunksIdx.pop_back(); // remove trailing space
        SendAck(upId, ROUND_STATUS, missingChunksIdx);
        std::cout << " round ack sent along with missing chunks \n";
    }
}

void Client::SendAck(const std::string upId, PacketType P)
{
    // FIX #5: lock before accessing activeDownloads
    std::shared_ptr<DownloadState> state;
    {
        std::lock_guard<std::mutex> lock(downloadsMtx);
        auto it = activeDownloads.find(upId);
        if (it == activeDownloads.end())
            return;
        state = it->second;
    }
    Packet p;
    p.receiverId = userId;
    p.serialize(P, upId, std::to_string(state->round), "");
    sendRawPacket(p);
}

void Client::SendAck(const std::string upId, PacketType P, const std::string chunkIdx)
{
    // FIX #5: lock before accessing activeDownloads
    std::shared_ptr<DownloadState> state;
    {
        std::lock_guard<std::mutex> lock(downloadsMtx);
        auto it = activeDownloads.find(upId);
        if (it == activeDownloads.end())
            return;
        state = it->second;
    }
    Packet p;
    p.receiverId = userId;
    p.serialize(P, upId, std::to_string(state->round), chunkIdx);
    sendRawPacket(p);
}