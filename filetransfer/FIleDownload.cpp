#include "FileTransferManager.h"
#include "../authentication/auth_types.h"

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
#include "../utils/Logger.h"
#include <windows.h>
#include <cstring>
#include <fstream>
#include "../chat/MessageRouter.h"
#include <filesystem>
#include <algorithm>
#include "../pool/PacketPool.h"
#include "../protocol/CRC32C.h"
#include <chrono>

bool FileTransferManager::checkGrp(const std::string &id)
{
    return id.size() >= 3 && id.substr(0, 3) == "GRP";
}

void FileTransferManager::start()
{
    downloadThread = std::thread(&FileTransferManager::sendDownloadLinkLoop, this);
}

void FileTransferManager::sendDownloadLinkLoop()
{
    while (true)
    {
        {
            std::unique_lock<std::mutex> lk(downloadMtx);
            downloadCv.wait(lk, [this]
                            { return stopLoop || !completedUpload.empty(); });
        }
        if (stopLoop && completedUpload.empty())
            break;

        while (!completedUpload.empty())
        {
            TransferState *state = completedUpload.front();
            completedUpload.pop();

            if (nullptr == state)
                continue;
            Packet *p = PacketPool::Instance().borrowPacket();

            // upid||filename||totalsize||timestamp
            //;
            uint8_t senderBin[16], uploadBin[16];
            hexToBytes(state->senderId, senderBin);
            hexToBytes(state->uploadId, uploadBin);
            p->serializeLink(senderBin, uploadBin, state->fileName, state->totalSize, state->timestamp);
            {
                std::lock_guard<std::mutex> mapLk(downloadableFilesMtx);
                downloadableFiles[state->uploadId] = state;
            }

            if (checkGrp(state->receiverId))
                route->routeGroupMessage(p);
            else
                off->ManageCompletePacket(p, state->receiverId);
        }
    }
}

void FileTransferManager::HandleDownloadRequest(Packet *p)
{
    const DownloadReqPayload* payload = p->getPayload<DownloadReqPayload>();
    std::string receiverId = bytesToHex(payload->user_id);
    std::string upId = bytesToHex(payload->upload_id);
    uint32_t startBytes = ntohl(payload->bytes_requested);
    PacketPool::Instance().returnPacket(p);

    if (receiverId.empty() || upId.empty())
    {
        Logger::error("HandleDownloadRequest: parse failed");
        return;
    }

    TransferState *state = nullptr;
    {
        std::lock_guard<std::mutex> mapLk(downloadableFilesMtx);
        auto it = downloadableFiles.find(upId);
        if (it != downloadableFiles.end())
            state = it->second;
    }

    if (!state)
    {
        SendErrorPacket(receiverId, upId, "File not found");
        return;
    }

    se->setRecievingFileTrue(receiverId);
    state->roundBuffer.resize(MAX_CHUNKS_PER_ROUND);
    state->roundOffsets.resize(MAX_CHUNKS_PER_ROUND);
    Packet *startP = PacketPool::Instance().borrowPacket();
    uint8_t senderBin[16], uploadBin[16];
    hexToBytes(state->senderId, senderBin);
    hexToBytes(state->uploadId, uploadBin);
    startP->serializeFileStart(senderBin, uploadBin, state->fileName, state->totalSize, state->finalCrc);
    off->ManageCompletePacket(startP, receiverId);

    std::thread(&FileTransferManager::HandleFileTransfer, this,
                state->fileName, receiverId, upId, startBytes)
        .detach();
    std::cout << "file sending started \n";
}

void FileTransferManager::HandleFileTransfer(const std::string &fileName,
                                             const std::string &receiverId,
                                             const std::string &upId,
                                             size_t startBytes)
{
    TransferState *state = nullptr;
    {
        std::lock_guard<std::mutex> mapLk(downloadableFilesMtx);
        auto it = downloadableFiles.find(upId);
        if (it != downloadableFiles.end())
            state = it->second;
    }

    if (!state)
    {
        SendErrorPacket(receiverId, upId, "State lost");
        se->setRecievingFileFalse(receiverId);
        return;
    }

    const std::string dir = state->tempPath;
    std::ifstream file(dir, std::ios::binary);
    if (!file.is_open())
    {
        SendErrorPacket(receiverId, upId, "Cannot open file");
        se->setRecievingFileFalse(receiverId);
        return;
    }

    file.seekg(static_cast<std::streamoff>(startBytes));

    uint64_t bytesSent = startBytes;
    uint32_t currentRound = static_cast<uint32_t>(
        startBytes / (static_cast<uint64_t>(MAX_CHUNK_SIZE) * MAX_CHUNKS_PER_ROUND));

    while (bytesSent < state->totalSize)
    {
        uint64_t roundBase = bytesSent;
        uint32_t chunksThisRound = 0;
        state->roundBuffer.assign(MAX_CHUNKS_PER_ROUND, {});

        while (chunksThisRound < MAX_CHUNKS_PER_ROUND && bytesSent < state->totalSize)
        {
            size_t remaining = static_cast<size_t>(state->totalSize - bytesSent);
            size_t toRead = std::min(static_cast<size_t>(MAX_CHUNK_SIZE), remaining);

            std::vector<uint8_t> block(toRead);
            file.read(reinterpret_cast<char *>(block.data()), toRead);
            size_t read = file.gcount();
            if (read == 0)
                break;

            block.resize(read);
            uint64_t chunkOffset = roundBase;
            roundBase += read;
            bytesSent += read;

            state->roundOffsets[chunksThisRound] = chunkOffset;
            state->roundBuffer[chunksThisRound] = std::move(block);

            chunksThisRound++;
        }

        if (chunksThisRound == 0)
            break;
        for (size_t i = 0; i < chunksThisRound; i++)
        {
            Packet *chunkP = PacketPool::Instance().borrowPacket();
            uint8_t upBin[16];
            hexToBytes(upId, upBin);
            chunkP->serializeFileChunk(upBin, state->roundOffsets[i], state->roundBuffer[i]);
            off->ManageCompletePacket(chunkP, receiverId);
        }

        bool roundDone = false;
        while (!roundDone)
        {
            Packet *roundP = PacketPool::Instance().borrowPacket();
            Logger::debug(" asking for ack on up id "+upId);
            uint8_t upBin[16];
            hexToBytes(upId, upBin);
            roundP->serializeRoundEnd(upBin, currentRound, chunksThisRound);
            off->ManageCompletePacket(roundP, receiverId);

            {
                std::unique_lock<std::mutex> lk(state->ackMtx);
                state->ackReceived = false;
                if (!state->ackCv.wait_for(lk, std::chrono::seconds(15),
                                           [&]()
                                           { return state->ackReceived; }))
                {
                    std::cerr << "download ACK timeout\n";
                    return;
                }
            }

            if (state->missingChunks.size() == 1 && state->missingChunks[0] == static_cast<uint32_t>(-1))
            {
                Logger::error("ACK timeout for round " + std::to_string(currentRound));
                se->setRecievingFileFalse(receiverId);
                file.close();
                return;
            }

            if (state->missingChunks.empty())
            {
                roundDone = true;
                currentRound++;
            }
            else
            {
                for (uint32_t idx : state->missingChunks)
                {
                    if (idx >= chunksThisRound)
                        continue;
                    Packet *chunkP = PacketPool::Instance().borrowPacket();
                    uint8_t upBin[16];
                    hexToBytes(upId, upBin);
                    chunkP->serializeFileChunk(upBin, state->roundOffsets[idx], state->roundBuffer[idx]);
                    off->ManageCompletePacket(chunkP, receiverId);
                }
            }
        }
    }

    uint32_t fileCrc = state->finalCrc;
    Packet *endP = PacketPool::Instance().borrowPacket();
    uint8_t upBin[16];
    hexToBytes(upId, upBin);
    endP->serializeFileEnd(upBin, fileCrc);
    off->ManageCompletePacket(endP, receiverId);

    se->setRecievingFileFalse(receiverId);
    file.close();
}

void FileTransferManager::onAckReceived(Packet *p)
{
    std::cout << " got the file end ack\n";
    const FileAckPayload* payload = p->getPayload<FileAckPayload>();
    std::string upId = bytesToHex(payload->upload_id);
    uint32_t roundId = ntohl(payload->round_id);
    uint32_t missingCount = ntohl(payload->missing_count);

    std::vector<uint32_t> missing;
    const uint32_t* missingArr = reinterpret_cast<const uint32_t*>(payload + 1);
    for (uint32_t i = 0; i < missingCount; ++i)
        missing.push_back(ntohl(missingArr[i]));
    PacketPool::Instance().returnPacket(p);
    TransferState *state = nullptr;
    {
        Logger::info(" entering into the lock donmtx");
        std::unique_lock<std::mutex> lock(downloadableFilesMtx);
        Logger::info(" entered into the mtx");
        auto it = downloadableFiles.find(upId);
        if (it == downloadableFiles.end()){
            Logger::debug("no state for upload id "+upId);
            return ;
        }
        state = it->second;
    }

    if (roundId != state->currentRound)
        return;

    {
        std::cout << " waiting for lock to open\n";
        std::unique_lock<std::mutex> lk(state->ackMtx);
        state->missingChunks = std::move(missing);
        state->ackReceived = true;
        std::cout << "lock opened \n";
    }
    state->ackCv.notify_one();
}

void FileTransferManager::SendErrorPacket(const std::string &recId,
                                          const std::string &upId,
                                          const std::string &reason)
{
    Packet *p = PacketPool::Instance().borrowPacket();
    p->serializeString(PKT_FILE_ERROR, upId + " " + reason);
    off->ManageCompletePacket(p, recId);
}

void FileTransferManager::HandleDisconnectRequest(Packet *p)
{
    if (p->header.payload_length + HEADER_SIZE < HEADER_SIZE)
        return;

    const char *st = reinterpret_cast<const char*>(p->data + HEADER_SIZE);
    const size_t len = p->header.payload_length;
    const std::string raw(st, len);
    PacketPool::Instance().returnPacket(p);

    std::string recId;
    for (size_t pos = 0; pos < raw.size() && raw[pos] != ' '; ++pos)
        recId.push_back(raw[pos]);

    if (!recId.empty())
        se->setRecievingFileFalse(recId);
}
