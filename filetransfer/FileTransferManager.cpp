#include "FileTransferManager.h"
#include "../utils/Logger.h"
#include <windows.h>
#include <fstream>
#include <filesystem>
#include "../chat/MessageRouter.h"
#include "../pool/PacketPool.h"
#include "../protocol/CRC32C.h"
#include <chrono>

namespace fs = std::filesystem;

FileTransferManager::FileTransferManager()
{
    CreateDirectoryA(saveDirectory.c_str(), NULL);
}

FileTransferManager::~FileTransferManager()
{
    stopAllTransfers();
}

void FileTransferManager::stopAllTransfers()
{
    {
        std::lock_guard<std::mutex> lk(downloadMtx);
        stopLoop = true;
    }
    downloadCv.notify_all();
    if (downloadThread.joinable()) downloadThread.join();


    std::lock_guard<std::mutex> lock(mtx);
    for (auto& pair : activeTransfers) {
        if (pair.second && pair.second->fileStream.is_open()) {
            pair.second->fileStream.close();
        }
        delete pair.second;
    }
    activeTransfers.clear();
    uploadIdToTransferState.clear();
}
std::string FileTransferManager::sanitize(const std::string& name) {
    std::string result = std::filesystem::path(name).filename().string();
    if (result.empty() || result == "." || result == "..") 
        return "unnamed_" + std::to_string(std::time(nullptr));
    return result;
}

void FileTransferManager::handleFileStart(Packet* p, const std::string& senderId)
{
    size_t pos = HEADER_SIZE;
    uint64_t totalSize = p->readUint64(pos);
    std::string recId=p->readString(pos);
    std::string fileName = sanitize(p->readString(pos));
    std::string uploadId = p->readString(pos);
    uint32_t finalCrc = (pos + 4 <= p->header.size) ? p->readUint32(pos) : 0;

    PacketPool::Instance().returnPacket(p);
    if(totalSize>1024*1024*5){
        SendErrorPacket(recId,uploadId," file is too big ");
        return;
    }
    // store only . partial formate 
    TransferState* state = new TransferState();
    state->senderId = senderId;
    state->receiverId=recId;
    state->uploadId = uploadId;
    state->fileName = fileName;
    state->totalSize = totalSize;
    state->finalCrc = finalCrc;
    state->tempPath = saveDirectory + fileName + ".partial";
    state->roundBuffer.resize(MAX_CHUNKS_PER_ROUND);

    state->fileStream.open(state->tempPath, std::ios::binary | std::ios::out | std::ios::app);
    if (!state->fileStream.is_open()) {
        Logger::error("Failed to create partial file: " + state->tempPath);
        delete state;
        return;
    }

    uint64_t resumeOffset = 0;
    if (fs::exists(state->tempPath)) {
        resumeOffset = fs::file_size(state->tempPath);
    }
    state->receivedOffset = resumeOffset;
    state->currentRound = static_cast<uint32_t>(resumeOffset / (static_cast<uint64_t>(MAX_CHUNK_SIZE) * MAX_CHUNKS_PER_ROUND));

    {
        std::lock_guard<std::mutex> lock(mtx);
        activeTransfers[uploadId] = state;
        uploadIdToTransferState[uploadId] = state;
    }

    Logger::info("File transfer started: " + fileName + " resumeOffset=" + std::to_string(resumeOffset));

    Packet* resp = PacketPool::Instance().borrowPacket();
    resp->serializeFileStartResponse(uploadId, resumeOffset);
    off->ManageCompletePacket(resp, senderId);
}

void FileTransferManager::handleFileChunk(Packet* p)
{
    size_t pos = HEADER_SIZE;
    std::string uploadId = p->readString(pos);
    uint64_t byteOffset = p->readUint64(pos);
    uint32_t chunkSize = p->readUint32(pos);
    uint32_t crcReceived = p->readUint32(pos);
    std::vector<uint8_t> chunkData = p->readBytes(pos, chunkSize);
    PacketPool::Instance().returnPacket(p);

    TransferState* state = getTransferState(uploadId);
    if (!state) return;

    if (CRC32C::compute(chunkData) != crcReceived) {
        Logger::warn("CRC mismatch at offset " + std::to_string(byteOffset));
        return;
    }

    size_t chunkIndex = (byteOffset / MAX_CHUNK_SIZE) % MAX_CHUNKS_PER_ROUND;

    std::lock_guard<std::mutex> lock(state->mtx);
    if (chunkIndex >= state->roundBuffer.size()) return;
    if (!state->roundBuffer[chunkIndex].empty()) return;

    state->roundBuffer[chunkIndex] = std::move(chunkData);
    state->roundReceivedCount++;
}

void FileTransferManager::handleRoundEnd(Packet* p)
{
    size_t pos = HEADER_SIZE;
    std::string uploadId = p->readString(pos);
    uint32_t roundId = p->readUint32(pos);
    uint32_t expectedChunkCount = p->readUint32(pos);
    PacketPool::Instance().returnPacket(p);

    TransferState* state = getTransferState(uploadId);
    if (!state) return;

    std::vector<uint32_t> missing;
    bool roundComplete = false;

    {
        std::lock_guard<std::mutex> lock(state->mtx);
        if (roundId != state->currentRound) {
            Logger::warn("Round mismatch: expected " + std::to_string(state->currentRound) +
                         " got " + std::to_string(roundId));
            sendAck(uploadId, state->currentRound, {}, state->senderId);
            return;
        }

        for (uint32_t i = 0; i < expectedChunkCount; ++i) {
            if (state->roundBuffer[i].empty()) {
                missing.push_back(i);
            }
        }

        roundComplete = missing.empty();
        if (roundComplete) {
            writeRoundToDisk(state);
            state->roundReceivedCount = 0;
            state->roundBuffer.assign(state->roundBuffer.size(), std::vector<uint8_t>{});
            state->currentRound++;
        }
    }

    sendAck(uploadId, roundId, missing, state->senderId);
}

void FileTransferManager::handleFileEnd(Packet* p)
{
    size_t pos = HEADER_SIZE;
    std::string uploadId = p->readString(pos);
    uint32_t finalCrc = p->readUint32(pos);
    PacketPool::Instance().returnPacket(p);

    TransferState* state = getTransferState(uploadId);
    if (!state) return;
std::string senderid=state->senderId;
    bool success = (state->receivedOffset == state->totalSize);
    // skip crc server side 
    // if (success) {
    //     uint32_t computed = computeFileCRC(state->tempPath);
    //     success = (computed == finalCrc);
    //     if (!success) {
    //         Logger::error("CRC mismatch for " + state->fileName +
    //                       " expected=" + std::to_string(finalCrc) +
    //                       " got=" + std::to_string(computed));
    //     }
    // }

    if (success) {
        std::string finalPath = saveDirectory + state->fileName;
        state->fileStream.close();
        fs::rename(state->tempPath, finalPath);
        Logger::info("File saved: " + state->fileName);

        auto now = std::chrono::system_clock::now();
        state->timestamp = std::to_string(
            std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());

        {
            std::lock_guard<std::mutex> lk(downloadMtx);
            completedUpload.push(state);
        }// note cleanup is not done also 
        downloadCv.notify_one();
    } else {
        Logger::error("File transfer failed: " + state->fileName);
        if (state->fileStream.is_open()) state->fileStream.close();
        cleanupTransfer(uploadId);
    }

    sendFileStatus(uploadId, success, senderid);
    if (!success) return;

    {
        std::lock_guard<std::mutex> lock(mtx);
        uploadIdToTransferState.erase(uploadId);
        activeTransfers.erase(uploadId);
    }
}

void FileTransferManager::writeRoundToDisk(TransferState* state)
{
    for (const auto& chunk : state->roundBuffer) {
        if (!chunk.empty()) {
            state->fileStream.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            state->receivedOffset += chunk.size();
        }
    }
    state->fileStream.flush();
}

void FileTransferManager::sendAck(const std::string& uploadId, uint32_t roundId,
                                  const std::vector<uint32_t>& missingChunks,
                                  const std::string& recId)
{
    Packet* p = PacketPool::Instance().borrowPacket();
    p->serializeFileAck(uploadId, roundId, missingChunks);
    std::cout<<" sendign round ack to :- "<<recId<<std::endl;
    off->ManageCompletePacket(p, recId);
}

void FileTransferManager::sendFileStatus(const std::string& uploadId, bool success,
                                         const std::string& recId)
{
    Packet* p = PacketPool::Instance().borrowPacket();
    p->serialize(PKT_FILE_STATUS, "SERVER", uploadId, success ? "SUCCESS" : "FAILED");
    off->ManageCompletePacket(p, recId);
}

TransferState* FileTransferManager::getTransferState(const std::string& uploadId)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = uploadIdToTransferState.find(uploadId);
    return (it != uploadIdToTransferState.end()) ? it->second : nullptr;
}

void FileTransferManager::cleanupTransfer(const std::string& uploadId)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = uploadIdToTransferState.find(uploadId);
    if (it != uploadIdToTransferState.end()) {
        if (it->second->fileStream.is_open()) it->second->fileStream.close();
        delete it->second;
        uploadIdToTransferState.erase(it);
        activeTransfers.erase(uploadId);
    }
}

uint32_t FileTransferManager::computeFileCRC(const std::string& filepath)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return 0;

    std::vector<uint8_t> buffer(1024 * 1024);
    uint32_t crc = 0;
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        size_t read = file.gcount();
        if (read > 0) crc = CRC32C::compute(buffer.data(), read, crc);
    }
    return crc;
}
