
#include "Client.h"
#include <random>
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
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif
static std::string bytesToHex(const uint8_t* bytes, size_t len = 16) {
    std::string hex;
    hex.reserve(len * 2);
    static const char hexChars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        hex.push_back(hexChars[bytes[i] >> 4]);
        hex.push_back(hexChars[bytes[i] & 0x0F]);
    }
    return hex;
}

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
   p.serializeOtpRequest(email);
    return sendRawPacket(p);
}

bool Client::verifyOtp(const std::string &email, const std::string &otp)
{
    Packet p;
    p.serializeOtpVerification(email,otp);
    return sendRawPacket(p);
}

bool Client::signup(const std::string &email, const std::string &number, const std::string &username, const std::string &password)
{
    Packet p;
    p.serializeSignup(email,number,username,password);
    return sendRawPacket(p);
}

bool Client::login(const std::string &identifier, const std::string &password)
{
    Packet p;
    p.serializeLogin(identifier,password);
    return sendRawPacket(p);
}
bool Client::reconnectWithToken()
{
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    // Try Access Token first
    if (isAccessTokenValid(now))
    {
        Packet p;
        std::string payload(reinterpret_cast<const char*>(&access), sizeof(AccessToken));
        p.serializeRaw(PKT_TOKEN, payload);
        
        if (sendRawPacket(p)) {
            std::cout << "[Auth] Reconnected using access token\n";
            return true;
        }
    }

    // Try Refresh Token
    if (isRefreshTokenValid(now))
    {
        Packet p;
        std::string payload(reinterpret_cast<const char*>(&refresh), sizeof(RefreshToken));
        p.serializeRaw(PKT_REFRESH, payload);
        
        if (sendRawPacket(p)) {
            std::cout << "[Auth] Reconnected using refresh token\n";
            return true;
        }
    }

    std::cout << "[Auth] Tokens expired or invalid - login required\n";
    return false;
}

// Add these helper methods
bool Client::isAccessTokenValid(uint64_t now) const
{
    return accessValid && access.payload.expiry > now;
}

bool Client::isRefreshTokenValid(uint64_t now) const
{
    return refreshValid && refresh.payload.expiry > now;
}
// Helper to parse hex strings to 16-byte array, or fallback to direct copy for non-hex IDs
static void hexToBytes(const std::string& str, uint8_t* outBytes) {
    std::memset(outBytes, 0, 16);
    if (str.length() == 32) {
        bool isHex = true;
        for (char c : str) {
            if (!std::isxdigit(c)) { isHex = false; break; }
        }
        if (isHex) {
            for (size_t i = 0; i < 16; ++i) {
                std::string byteStr = str.substr(i * 2, 2);
                outBytes[i] = static_cast<uint8_t>(strtol(byteStr.c_str(), nullptr, 16));
            }
            return;
        }
    }
    size_t copyLen = std::min(str.length(), static_cast<size_t>(16));
    std::memcpy(outBytes, str.c_str(), copyLen);
}

// ====================== MESSAGING ======================
bool Client::sendPrivateMessage(const std::string &receiver, const std::string &message)
{
    uint8_t senderBin[16];
    uint8_t receiverBin[16];
    hexToBytes(userId, senderBin);
    hexToBytes(receiver, receiverBin);
    
    Packet p;
    p.serialize(PKT_PRIVATE_MESSAGE, senderBin, receiverBin, nullptr, "", message);
    return sendRawPacket(p);
}

bool Client::sendGroupMessage(const std::string &groupId, const std::string &message)
{
    uint8_t senderBin[16];
    uint8_t groupBin[16];
    hexToBytes(userId, senderBin);
    hexToBytes(groupId, groupBin);

    Packet p;
    p.serialize(PKT_GROUP_MESSAGE, senderBin, groupBin, nullptr, "", message);
    return sendRawPacket(p);
}

bool Client::createGroup(const std::string &groupId)
{
    uint8_t senderBin[16];
    uint8_t groupBin[16];
    hexToBytes(userId, senderBin);
    hexToBytes(groupId, groupBin);

    Packet p;
    p.serialize(PKT_CREATE_GROUP, senderBin, groupBin, nullptr, "", "");
    return sendRawPacket(p);
}

bool Client::joinGroup(const std::string &groupId)
{
    uint8_t senderBin[16];
    uint8_t groupBin[16];
    hexToBytes(userId, senderBin);
    hexToBytes(groupId, groupBin);

    Packet p;
    p.serialize(PKT_JOIN_GROUP, senderBin, groupBin, nullptr, "", "");
    return sendRawPacket(p);
}

bool Client::leaveGroup(const std::string &groupId)
{
    uint8_t senderBin[16];
    uint8_t groupBin[16];
    hexToBytes(userId, senderBin);
    hexToBytes(groupId, groupBin);

    Packet p;
    p.serialize(PKT_LEAVE_GROUP, senderBin, groupBin, nullptr, "", "");
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
            
            PacketHeader* hdr = reinterpret_cast<PacketHeader*>(streamBuffer.data());
            if (hdr->magic != START_BYTE) {
                std::cout << "Invalid magic byte\n";
                streamBuffer.erase(streamBuffer.begin(), streamBuffer.begin() + 1); // skip bad byte
                continue;
            }
            
            uint32_t payloadSize = ntohl(hdr->payload_length);
            uint32_t packetSize = HEADER_SIZE + payloadSize;
            
            if (streamBuffer.size() < packetSize || packetSize > sizeof(Packet::data)) {
                if (packetSize > sizeof(Packet::data)) {
                    std::cout << "packet overflow\n";
                    streamBuffer.erase(streamBuffer.begin(), streamBuffer.begin() + HEADER_SIZE); // erase header and retry
                }
                break;
            }
            
            Packet p;
            std::memcpy(p.data, streamBuffer.data(), packetSize);
            p.in = p.data + packetSize;

            if (!p.parseHeader() || !p.parseData()) {
                std::cout << "corrupted data or parsing failed\n";
                streamBuffer.erase(streamBuffer.begin(), streamBuffer.begin() + packetSize);
                continue;
            }

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
        case PKT_PRIVATE_MESSAGE: {
            const ChatMessagePayload* payload = p.getPayload<ChatMessagePayload>();
            std::string sender = bytesToHex(payload->sender_id);
            uint16_t txtLen = ntohs(payload->text_len);
            const char* txtPtr = reinterpret_cast<const char*>(payload + 1) + ntohs(payload->username_len);
            std::string text(txtPtr, txtLen);
            std::cout << "\n[Private] " << sender << ": " << text << "\n> ";
            if (onMessageReceived) onMessageReceived();
            messagesReceived++;
            break;
        }
        case PKT_GROUP_MESSAGE: {
            const ChatMessagePayload* payload = p.getPayload<ChatMessagePayload>();
            std::string sender = bytesToHex(payload->sender_id);
            std::string receiver = bytesToHex(payload->receiver_id);
            uint16_t txtLen = ntohs(payload->text_len);
            const char* txtPtr = reinterpret_cast<const char*>(payload + 1) + ntohs(payload->username_len);
            std::string text(txtPtr, txtLen);
            std::cout << "\n[Group " << receiver << "] " << sender << ": " << text << "\n> ";
            break;
        }
        case DOWNLOAD_LINK:         handleDownloadLink(p); break;
        case PKT_FILE_START:        handleFileStart(p); break;
        case PKT_FILE_CHUNK:        handleFileChunk(p); break;
        case PKT_ROUND_END:         handleRoundEnd(p); break;
        case PKT_FILE_END:          handleFileEnd(p); break;
        case PKT_FILE_ACK:          handleFileAck(p); break;
        case PKT_FILE_STATUS:       HandleFileStatus(p); break;
        case FILE_START_RESPONSE:   HandleFileStartResponse(p); break;
        case PKT_ACKNOWLEDGMENT: {
            const StringPayload* payload = p.getPayload<StringPayload>();
            uint16_t msgLen = ntohs(payload->str_len);
            const char* strData = reinterpret_cast<const char*>(payload + 1);
            std::string msg(strData, msgLen);
            if (msg.find("OTP Verified") != std::string::npos)
                std::cout << "\n[Auth] OTP Verified successfully!\n> ";
            else
                HandlePacketAck(p);
            break;
        }
        case PKT_TOKEN_GRANTED:     handleTokenGranted(p); break;
        case PKT_AUTH_FAIL:
        case PKT_SIGNUP_ERROR:      handleAuthFail(p); break;
        case PKT_FILE_ERROR : {
            const StringPayload* payload = p.getPayload<StringPayload>();
            uint16_t msgLen = ntohs(payload->str_len);
            const char* strData = reinterpret_cast<const char*>(payload + 1);
            std::string msg(strData, msgLen);
            std::cout<<msg<<std::endl; 
            break;
        }
        default:
            std::cout << "[WARN] Unknown packet type: " << static_cast<int>(p.header.type) << "\n";
            break;
    }
}

bool Client::sendRawPacket(Packet &p)
{
    std::lock_guard<std::mutex> lock(sendMtx);
    if (!isConnected) return false;

    int totalSize = p.header.payload_length + HEADER_SIZE;
    int totalSent = 0;

    while (totalSent < totalSize)
    {
        int sent = send(clientSocket, reinterpret_cast<const char*>(p.data + totalSent), totalSize - totalSent, 0);
        if (sent <= 0) return false;
        totalSent += sent;
    }
    return true;
}bool Client::tokenBuildOnStartUp() {
    const std::string userfile = "userID.bin";
    const std::string accessfile = "accessToken.bin";
    const std::string refreshfile = "refreshToken.bin";

    // Helper lambda for safe binary read
    auto safeRead = [](auto& stream, void* data, std::size_t size) -> bool {
        stream.read(static_cast<char*>(data), size);
        return stream.gcount() == static_cast<std::streamsize>(size) && stream;
    };

    // Check user ID
    {
        std::ifstream uf(userfile, std::ios::binary);
        if (!uf || !std::filesystem::exists(userfile) ||
            std::filesystem::file_size(userfile) != UUID_SIZE) {
            return false;
        }

        if (!safeRead(uf, userId.data(), UUID_SIZE)) {
            return false;
        }
    }

    // Access token is optional
    {
        std::ifstream acf(accessfile, std::ios::binary);
        if (acf && std::filesystem::file_size(accessfile) >= sizeof(AccessToken)) {
           if( safeRead(acf, &access, sizeof(AccessToken)))accessValid=true;  // ignore failure, it's optional
        }
    }

    // Refresh token is required
    {
        std::ifstream ref(refreshfile, std::ios::binary);
        if (!ref || !std::filesystem::exists(refreshfile) ||
            std::filesystem::file_size(refreshfile) != sizeof(RefreshToken)) {
            return false;
        }

        if (!safeRead(ref, &refresh, sizeof(RefreshToken))) {
            return false;
        }
        else{
            refreshValid=true;
        }
    }

    return true;
}

// ====================== AUTH CALLBACKS ======================
void Client::handleUserIdPacket(Packet &p)
{
    size_t pos=HEADER_SIZE;
    std::memcpy(serverId, p.data+pos, UUID_SIZE);
    pos+=UUID_SIZE;
    userId.assign(reinterpret_cast<const char*>(p.data+pos), UUID_SIZE);
    std::ofstream userFile("userID.bin",std::ios::trunc);
    if(userFile.is_open()){
userFile.write(reinterpret_cast<char*>(&userId),UUID_SIZE);
        userFile.close();
    }
    std::cout << "user id updated successfully: " << std::endl;
}

void Client::handleTokenGranted(Packet &p) { 


 p.parseData();

    const TokenGrantedPayload* payload = p.getPayload<TokenGrantedPayload>();
    uint16_t accessLen = ntohs(payload->access_token_len);
    uint16_t refreshLen = ntohs(payload->refresh_token_len);
    const uint8_t *payloadPtr = reinterpret_cast<const uint8_t *>(payload + 1);
  
    if (accessLen != sizeof(AccessToken) || refreshLen != sizeof(RefreshToken)) {
        std::cerr << "[Client] Received invalid token lengths.\n";
        return;
    }
    std::memcpy(accessToken.data(), payloadPtr, accessLen);
    std::memcpy(refreshToken.data(), payloadPtr + accessLen, refreshLen);
    std::ofstream accesFile("accessToken.bin",std::ios::trunc|std::ios::binary);
    if(accesFile.is_open()){
        accesFile.write(reinterpret_cast<char*>(accessToken.data()),accessLen);
        accesFile.close();
    }

    std::ofstream refreshFile("refreshToken.bin",std::ios::trunc|std::ios::binary);
    if(refreshFile.is_open()){
        refreshFile.write(reinterpret_cast<char*>(refreshToken.data()),refreshLen);
        refreshFile.close();
    }
      std::memcpy(&access,accessToken.data(),accessLen);
      std::memcpy(&refresh,refreshToken.data(),refreshLen);
    std::cout << "\n[Auth] Authentication successful! Tokens received.\n> ";
    refreshValid=true;
    accessValid=true;
    return;


 }
void Client::handleAuthFail(Packet &p) { 
    const StringPayload* payload = p.getPayload<StringPayload>();
    std::string msg(reinterpret_cast<const char*>(payload + 1), ntohs(payload->str_len));
    std::cout << "[Auth] Failed: " << msg << "\n"; 
}

// ====================== FILE TRANSFER ======================
std::string generateUploadId()
{
    uint8_t bytes[UUID_SIZE] = {};  // Zero-initialized

    bool success = false;

#ifdef _WIN32
    // Windows: Use CryptGenRandom (strong randomness)
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        success = CryptGenRandom(hProv, UUID_SIZE, bytes);
        CryptReleaseContext(hProv, 0);
    }
#else
    // Linux / Unix: Use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        ssize_t n = read(fd, bytes, UUID_SIZE);
        close(fd);
        success = (n == UUID_SIZE);
    }
#endif

    // Fallback to std::random_device + Mersenne Twister if secure RNG failed
    if (!success)
    {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        for (size_t i = 0; i < UUID_SIZE / sizeof(uint64_t); ++i) {
            uint64_t val = gen();
            std::memcpy(bytes + i * sizeof(uint64_t), &val, sizeof(uint64_t));
        }
        // Fill any remaining bytes if UUID_SIZE is not multiple of 8
        if (UUID_SIZE % sizeof(uint64_t) != 0) {
            uint64_t val = gen();
            std::memcpy(bytes + (UUID_SIZE / sizeof(uint64_t)) * sizeof(uint64_t),
                        &val, UUID_SIZE % sizeof(uint64_t));
        }
    }

    return bytesToHex(bytes, UUID_SIZE);
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

// first launch the thread then send the packet 
    Packet p;
    uint8_t receiverBin[16], uploadBin[16];
    hexToBytes(state->receiver, receiverBin);
    hexToBytes(state->uploadId, uploadBin);
    p.serializeFileStart(receiverBin, uploadBin, std::filesystem::path(filepath).filename().string(),
                         state->totalSize, state->finalCrc);
    sendRawPacket(p);

    return true;
}

void Client::uploadWorker(std::shared_ptr<UploadState> state)
{
    std::cout<<" upload thread sarted\n";
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
            uint8_t uploadBin[16];
            hexToBytes(state->uploadId, uploadBin);
            p.serializeFileChunk(uploadBin, state->roundOffsets[i], state->roundBuffer[i]);
            sendRawPacket(p);
        }

        bool roundDone = false;
        while (!roundDone)
        {
            Packet roundP;
            uint8_t uploadBin[16];
            hexToBytes(state->uploadId, uploadBin);
            roundP.serializeRoundEnd(uploadBin, state->currentRound, chunksThisRound);
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
                    uint8_t uploadBin[16];
                    hexToBytes(state->uploadId, uploadBin);
                    p.serializeFileChunk(uploadBin, state->roundOffsets[idx],
                                         state->roundBuffer[idx]);
                    sendRawPacket(p);
                }
            }
        }
    }

    Packet endP;
    uint8_t uploadBin[16];
    hexToBytes(state->uploadId, uploadBin);
    endP.serializeFileEnd(uploadBin, state->finalCrc);
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
    const FileStartPayload* payload = p.getPayload<FileStartPayload>();
    uint64_t totalSize = ntohll(payload->total_size);
    uint32_t finalCrc = ntohl(payload->final_crc);
    uint16_t filenameLen = ntohs(payload->filename_len);
    std::string senderId = bytesToHex(payload->receiver_id); // receiver_id in the payload represents the sender from the perspective of the server sending it to the client? wait, FileStartPayload has receiver_id and upload_id. It might be sender_id in the payload but it's called receiver_id in struct.
    std::string uploadId = bytesToHex(payload->upload_id);
    const char* strData = reinterpret_cast<const char*>(payload + 1);
    std::string fileName = sanitize(std::string(strData, filenameLen));

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
    const FileChunkPayload* payload = p.getPayload<FileChunkPayload>();
    std::string uploadId = bytesToHex(payload->upload_id);
    uint64_t byteOffset = ntohll(payload->byte_offset);
    uint32_t chunkSize = ntohl(payload->chunk_size);
    uint32_t crcReceived = ntohl(payload->chunk_crc);
    const uint8_t* chunkPtr = reinterpret_cast<const uint8_t*>(payload + 1);
    std::vector<uint8_t> chunkData(chunkPtr, chunkPtr + chunkSize);

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
    const RoundEndPayload* payload = p.getPayload<RoundEndPayload>();
    std::string uploadId = bytesToHex(payload->upload_id);
    uint32_t roundId = ntohl(payload->round_id);
    uint32_t expectedChunkCount = ntohl(payload->chunk_count);

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

void Client::sendRoundAck(const std::string &uploadId, uint32_t roundId, const std::vector<uint32_t> &missing)
{
    Packet p;
    uint8_t upBin[16];
    hexToBytes(uploadId, upBin);
    p.serializeFileAck(upBin, roundId, missing);
    sendRawPacket(p);
}

void Client::handleFileEnd(Packet &p)
{
    const FileEndPayload* payload = p.getPayload<FileEndPayload>();
    std::string uploadId = bytesToHex(payload->upload_id);
    uint32_t finalCrc = ntohl(payload->final_crc);

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
    std::cout<<" got the file response \n";
    const FileStartResponsePayload* payload = p.getPayload<FileStartResponsePayload>();
    std::string upId = bytesToHex(payload->upload_id);
    uint64_t resumeOffset = ntohll(payload->resume_offset);

    std::shared_ptr<UploadState> state;
    {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        auto it = activeUploads.find(upId);
        std::cout<<" searching for file response \n";
        if (it == activeUploads.end()) return;
        std::cout<<" got the state proceedding next\n";
        state = it->second;
    }

    {
        std::lock_guard<std::mutex> l(state->bytesAck);
        state->startBytes = resumeOffset;
        state->bytesWritten = true;
    }
       state->uploadThread = std::jthread(&Client::uploadWorker, this, state);
   // state->bytesCv.notify_one();
}

void Client::handleFileAck(Packet &p)
{
    std::cout<<" got the file end ack\n";
    const FileAckPayload* payload = p.getPayload<FileAckPayload>();
    std::string upId = bytesToHex(payload->upload_id);
    uint32_t roundId = ntohl(payload->round_id);
    uint32_t missingCount = ntohl(payload->missing_count);

    std::vector<uint32_t> missing;
    const uint32_t* missingArr = reinterpret_cast<const uint32_t*>(payload + 1);
    for (uint32_t i = 0; i < missingCount; ++i)
        missing.push_back(ntohl(missingArr[i]));

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
    Packet p;
    uint8_t userBin[16], uploadBin[16];
    hexToBytes(userId, userBin);
    hexToBytes(uploadId, uploadBin);
    p.serializeDownloadReq(userBin, uploadBin, (static_cast<uint32_t>(fileSize)));
    return sendRawPacket(p);
}

void Client::handleDownloadLink(Packet &p)
{
    // Existing logic
    const DownloadLinkPayload* payload = p.getPayload<DownloadLinkPayload>();
    std::string senderid = bytesToHex(payload->sender_id);
    std::string upId = bytesToHex(payload->upload_id);
    uint32_t totalsize = ntohl(payload->total_size);
    uint16_t filenameLen = ntohs(payload->filename_len);
    uint16_t timeLen = ntohs(payload->timestamp_len);
    const char* strData = reinterpret_cast<const char*>(payload + 1);
    std::string filename(strData, filenameLen);
    std::string timestamp(strData + filenameLen, timeLen);
   
    std::cout << "\n[File Transfer] User " << senderid << " sent: " << filename<<" of size : "<<totalsize<<" at time : "<<timestamp<<" with upload id : - "<<upId << "\n";
}

void Client::HandleFileStatus(Packet &p)
{   
    const StringPayload* payload = p.getPayload<StringPayload>();
    uint16_t msgLen = ntohs(payload->str_len);
    const char* strData = reinterpret_cast<const char*>(payload + 1);
    std::string msg(strData, msgLen);
    
     {
        std::lock_guard<std::mutex> lock(uploadsMtx);
        // We'll just extract the upload ID from the message if possible,
        // since receiverId is no longer on the packet.
    }

    std::cout << "[File Status] " << msg << std::endl;
}

void Client::HandlePacketAck(Packet &p)
{
    p.parseData();
    // Legacy ACK handling
}