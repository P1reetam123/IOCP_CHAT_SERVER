#include "FileTransferManager.h"
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

bool FileTransferManager::checkGrp(const std::string& id)
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
        std::unique_lock<std::mutex> lk(downloadMtx);
        downloadCv.wait(lk, [this]{ return stopLoop || !completedUpload.empty(); });
        if (stopLoop && completedUpload.empty()) break;

        while (!completedUpload.empty())
        {
            TransferState* state = completedUpload.front();
            completedUpload.pop();
            lk.unlock();

            Packet* p = PacketPool::Instance().borrowPacket();
            std::string payload = state->uploadId + " " + state->fileName + " " +
                                 std::to_string(state->totalSize) + " " + state->timestamp;
            p->serialize(DOWNLOAD_LINK, state->senderId, state->receiverId, payload);

            {
                std::lock_guard<std::mutex> mapLk(downloadableFilesMtx);
                downloadableFiles[state->uploadId] = state;
            }

            if (checkGrp(state->receiverId))
                route->routeGroupMessage(p);
            else
                off->ManageCompletePacket(p, state->senderId);

            lk.lock();
        }
    }
}

void FileTransferManager::HandleDownloadRequest(Packet* p)
{
    std::string upId, receiverId, bytes;
    char* st = p->data + HEADER_SIZE;
    size_t len = p->header.size - HEADER_SIZE;
    std::string raw(st, len);
    PacketPool::Instance().returnPacket(p);

    size_t pos = 0;
    while (pos < len && raw[pos] != ' ') receiverId.push_back(raw[pos++]);
    pos++;
    while (pos < len && raw[pos] != ' ') upId.push_back(raw[pos++]);
    pos++;
    while (pos < len && raw[pos] != ' ') bytes.push_back(raw[pos++]);

    if (receiverId.empty() || upId.empty()) {
        Logger::error("HandleDownloadRequest: parse failed");
        return;
    }

    TransferState* state = nullptr;
    {
        std::lock_guard<std::mutex> mapLk(downloadableFilesMtx);
        auto it = downloadableFiles.find(upId);
        if (it != downloadableFiles.end())
            state = it->second;
    }

    if (!state) {
        SendErrorPacket(receiverId, upId, "File not found");
        return;
    }

    size_t startBytes = 0;
    try {
        startBytes = static_cast<size_t>(std::stoul(bytes));
    } catch (...) {
        Logger::error("Invalid bytes in download request");
        SendErrorPacket(receiverId, upId, "Invalid request");
        return;
    }

    se->setRecievingFileTrue(receiverId);

    Packet* startP = PacketPool::Instance().borrowPacket();
    startP->serializeFileStart(state->uploadId, state->fileName, state->totalSize, state->finalCrc);
    off->ManageCompletePacket(startP, receiverId);

    std::thread(&FileTransferManager::HandleFileTransfer, this,
                state->fileName, receiverId, upId, startBytes).detach();
}

void FileTransferManager::HandleFileTransfer(const std::string& fileName,
                                            const std::string& receiverId,
                                            const std::string& upId,
                                            size_t startBytes)
{
    TransferState* state = nullptr;
    {
        std::lock_guard<std::mutex> mapLk(downloadableFilesMtx);
        auto it = downloadableFiles.find(upId);
        if (it != downloadableFiles.end()) state = it->second;
    }

    if (!state) {
        SendErrorPacket(receiverId, upId, "State lost");
        se->setRecievingFileFalse(receiverId);
        return;
    }

    const std::string dir = saveDirectory + fileName;
    std::ifstream file(dir, std::ios::binary);
    if (!file.is_open()) {
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
        std::vector<std::vector<uint8_t>> roundBuffer(MAX_CHUNKS_PER_ROUND);
        std::vector<uint64_t> roundOffsets(MAX_CHUNKS_PER_ROUND);

        while (chunksThisRound < MAX_CHUNKS_PER_ROUND && bytesSent < state->totalSize)
        {
            size_t remaining = static_cast<size_t>(state->totalSize - bytesSent);
            size_t toRead = std::min(static_cast<size_t>(MAX_CHUNK_SIZE), remaining);

            std::vector<uint8_t> block(toRead);
            file.read(reinterpret_cast<char*>(block.data()), toRead);
            size_t read = file.gcount();
            if (read == 0) break;

            block.resize(read);
            uint64_t chunkOffset = roundBase;
            roundBase += read;
            bytesSent += read;

            roundOffsets[chunksThisRound] = chunkOffset;
            roundBuffer[chunksThisRound] = std::move(block);

            Packet* chunkP = PacketPool::Instance().borrowPacket();
            chunkP->serializeFileChunk(upId, chunkOffset, roundBuffer[chunksThisRound]);
            off->ManageCompletePacket(chunkP, receiverId);
            chunksThisRound++;
        }

        if (chunksThisRound == 0) break;

        bool roundDone = false;
        while (!roundDone)
        {
            Packet* roundP = PacketPool::Instance().borrowPacket();
            roundP->serializeRoundEnd(upId, currentRound, chunksThisRound);
            off->ManageCompletePacket(roundP, receiverId);

            std::vector<uint32_t> missing = waitForAck(upId, currentRound, 15000);

            if (missing.size() == 1 && missing[0] == static_cast<uint32_t>(-1)) {
                Logger::error("ACK timeout for round " + std::to_string(currentRound));
                se->setRecievingFileFalse(receiverId);
                file.close();
                return;
            }

            if (missing.empty()) {
                roundDone = true;
                currentRound++;
            } else {
                for (uint32_t idx : missing) {
                    if (idx >= chunksThisRound) continue;
                    Packet* chunkP = PacketPool::Instance().borrowPacket();
                    chunkP->serializeFileChunk(upId, roundOffsets[idx], roundBuffer[idx]);
                    off->ManageCompletePacket(chunkP, receiverId);
                }
            }
        }
    }

    uint32_t fileCrc = state->finalCrc ? state->finalCrc : computeFileCRC(dir);
    Packet* endP = PacketPool::Instance().borrowPacket();
    endP->serializeFileEnd(upId, fileCrc);
    off->ManageCompletePacket(endP, receiverId);

    se->setRecievingFileFalse(receiverId);
    file.close();
}

void FileTransferManager::onAckReceived(Packet* p)
{
    size_t pos = HEADER_SIZE;
    std::string uploadId = p->readString(pos);
    uint32_t roundId = p->readUint32(pos);
    uint32_t missingCount = p->readUint32(pos);

    std::vector<uint32_t> missing;
    for (uint32_t i = 0; i < missingCount; ++i) {
        missing.push_back(p->readUint32(pos));
    }
    PacketPool::Instance().returnPacket(p);

    std::lock_guard<std::mutex> lock(ackMtx);
    pendingAcks[uploadId] = {roundId, missing};
    ackCv.notify_all();
}

std::vector<uint32_t> FileTransferManager::waitForAck(const std::string& upId,
                                                    uint32_t round,
                                                    int timeoutMs)
{
    std::unique_lock<std::mutex> lock(ackMtx);
    bool got = ackCv.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&] {
        auto it = pendingAcks.find(upId);
        return it != pendingAcks.end() && it->second.round == round;
    });

    if (!got) return {static_cast<uint32_t>(-1)};

    auto it = pendingAcks.find(upId);
    std::vector<uint32_t> missing = it->second.missing;
    pendingAcks.erase(it);
    return missing;
}

void FileTransferManager::SendErrorPacket(const std::string& recId,
                                          const std::string& upId,
                                          const std::string& reason)
{
    Packet* p = PacketPool::Instance().borrowPacket();
    p->serialize(PKT_FILE_ERROR, "", recId, upId + " " + reason);
    off->ManageCompletePacket(p, recId);
}

void FileTransferManager::HandleDisconnectRequest(Packet* p)
{
    if (p->header.size < HEADER_SIZE) return;

    const char* st = p->data + HEADER_SIZE;
    const size_t len = p->header.size - HEADER_SIZE;
    const std::string raw(st, len);
    PacketPool::Instance().returnPacket(p);

    std::string recId;
    for (size_t pos = 0; pos < raw.size() && raw[pos] != ' '; ++pos)
        recId.push_back(raw[pos]);

    if (!recId.empty())
        se->setRecievingFileFalse(recId);
}
