#pragma once
#include "FileTransferManager.h"
#include "../utils/Logger.h"
#include <windows.h>
#include<cstring>
#include<fstream>
#include"../chat/MessageRouter.h"
#include<filesystem>
#include"./pool/PacketPool.h"
#include"./protocol/Packet.h"

#pragma pack(push, 1)

#pragma pack(pop)

//activeTransfers
FileTransferManager::FileTransferManager()
{
    // Ensure upload directory exists
    CreateDirectoryA(saveDirectory.c_str(), NULL);
}

FileTransferManager::~FileTransferManager()
{
    {
        std::lock_guard<std::mutex> lk(downloadMtx);
        stopLoop = true;
    }
    downloadCv.notify_all();
    if (downloadThread.joinable()) downloadThread.join();

    {
        std::lock_guard<std::mutex> lk(transferMtx_);
        stopTransferPool_ = true;
    }
    transferCv_.notify_all();
    for (auto& t : transferWorkers_) {
        if (t.joinable()) t.join();
    }

    std::lock_guard<std::mutex> lock(mtx);
    for (auto& pair : activeTransfers) {
        if (pair.second->fileStream.is_open()) {
            pair.second->fileStream.close();
        }
        delete pair.second;
    }
    activeTransfers.clear();
    uploadIdToTranserState.clear();
    uploadIdHashMap.clear();
}


// FOR START PACKET 
// packet layout that server expect
//------------------------------------------
// length ||pkt||senderId|| receiverid||filesize||filename||uplaodId||totalChunks||timstamp|| length
//--------------------------------------------
// send ack in response for start packet to tell from which bytes you need to send 
void FileTransferManager::handleStart(Packet *p){
// extract the all info from this packet
char* st=p->data;
std::string sender,receiver,fileSize,fileName,uploadId,totalChunks,timestamp,length;
st=st+HEADER_SIZE;
int len=p->header.size-HEADER_SIZE;
std::string raw(st,len);
 PacketPool::Instance().returnPacket(p);

    size_t pos=0;
    while(pos<raw.size()&&raw[pos]!=' ') sender.push_back(raw[pos++]);
    pos++;
     while(pos<raw.size()&&raw[pos]!=' ') receiver.push_back(raw[pos++]);
     pos++;
      while(pos<raw.size()&&raw[pos]!=' ') fileSize.push_back(raw[pos++]);
      pos++;
       while(pos<raw.size()&&raw[pos]!=' ') fileName.push_back(raw[pos++]);
       pos++;
        while(pos<raw.size()&&raw[pos]!=' ') uploadId.push_back(raw[pos++]);
        pos++;
        while(pos<raw.size()&&raw[pos]!=' ') totalChunks.push_back(raw[pos++]);
      pos++;
       while(pos<raw.size()&&raw[pos]!=' ') timestamp.push_back(raw[pos++]);
       pos++;
       while(pos<raw.size()&&raw[pos]!=' ') length.push_back(raw[pos++]);
    
            
    TransferState *state=new TransferState();
    state->senderId=sender;
    state->receiverId=receiver;
    state->fileName=fileName;
    try {
        state->totalChunks=std::stoul(totalChunks);
        state->totalLength=std::stoull(length);
    } catch (...) {
        Logger::error("Invalid numeric field in handleStart");
        delete state;

        return;
    }
    state->timestamp=timestamp;
    state->uploadId=uploadId;

    std::lock_guard<std::mutex> lk(mtx);

    state->filePath = saveDirectory + state->fileName;
    // Open immediately for random-access binary write
    state->fileStream.open(state->filePath, std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);
    if (!state->fileStream.is_open()) {
        // Fallback if file creation fails, try simple out
        state->fileStream.open(state->filePath, std::ios::binary | std::ios::out);
    }
    
    // Allocate chunk tracker bitset
    if (state->totalChunks > 0) {
        state->chunkReceived.resize(state->totalChunks, false);
    }

    uploadIdToTranserState[uploadId]=state;
    activeTransfers[uploadId]=state;

    // FNV-1a Hash for binary chunk lookup
    uint32_t hash = 2166136261u;
    for (char c : state->uploadId) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 16777619u;
    }
    uploadIdHashMap[hash] = state;

    startResponse(state->uploadId); 
}
// chunk layout 
//---------------------------------------
//length||p kt||upId|| cidx|| payload
//----------------------------------------
// TO HANDLE CHUNK PACKET
void FileTransferManager::handleChunks(Packet *p) {
    if (p->header.size < HEADER_SIZE + sizeof(ChunkHeader)) {
        PacketPool::Instance().returnPacket(p);
        return;
    }

    ChunkHeader* ch = reinterpret_cast<ChunkHeader*>(p->data + HEADER_SIZE);
    uint32_t hash = ch->uploadIdHash;
    uint16_t chunkIdx = ch->chunkIdx;
    uint16_t dataLen = ch->dataLen;
    const char* chunkData = p->data + HEADER_SIZE + sizeof(ChunkHeader);

    // Validate bounds
    if (HEADER_SIZE + sizeof(ChunkHeader) + dataLen > p->header.size) {
        PacketPool::Instance().returnPacket(p);
        return;
    }

    std::lock_guard<std::mutex> lk(mtx);
    auto it = uploadIdHashMap.find(hash);
    if (it == uploadIdHashMap.end()) {
        PacketPool::Instance().returnPacket(p);
        return;
    }

    TransferState* state = it->second;
    if (chunkIdx < state->chunkReceived.size() && !state->chunkReceived[chunkIdx]) {
        // Direct-to-disk write at correct offset
        // Assuming chunk size is 4000 bytes max based on download path
        size_t offset = static_cast<size_t>(chunkIdx) * 4000ULL;
        if (state->fileStream.is_open()) {
            state->fileStream.seekp(offset, std::ios::beg);
            state->fileStream.write(chunkData, dataLen);
            state->chunkReceived[chunkIdx] = true;
            state->chunkRecieved += 1;
            state->totalChunksRecieved += 1;
        }
    }
    
    PacketPool::Instance().returnPacket(p);
}

// after sending one buffer receiver ask for acknowledgment
// acknowledgment layout 
//-------------------------------------
//length|| pkt||upID|| lastRoundIdx||
//------------------------------
void FileTransferManager::acknowledgment(Packet *p) {
    char *st = p->data + HEADER_SIZE;
    int len = p->header.size - HEADER_SIZE;
    std::string raw(st, len);
    PacketPool::Instance().returnPacket(p);

    size_t pos = 0;
    std::string upId;
    std::string tc; // totalChunk sent by one go
    while (pos < raw.size() && raw[pos] != ' ') upId.push_back(raw[pos++]);
    pos++;
    while (pos < raw.size() && raw[pos] != ' ') tc.push_back(raw[pos++]);
    
    int tcInt;
    try { tcInt = std::stoi(tc); } 
    catch (...) { return; }

    std::lock_guard<std::mutex> lk(mtx);
    auto it = uploadIdToTranserState.find(upId);
    if (it == uploadIdToTranserState.end()) return;
    
    TransferState* state = it->second;

    if (tcInt == state->chunkRecieved) {
        state->chunkRecieved = 0;
        // Data is already on disk. Just flush if necessary.
        if (state->fileStream.is_open()) {
            state->fileStream.flush();
        }
        state->round += 1;
        SendAck(upId, ROUND_STATUS);
    } else {
        std::string missingChunksIdx;
        // Find which chunks in this round's expected range are missing
        // round * 1024 is the start index.
        size_t startIdx = state->round * 1024;
        for (size_t i = 0; i < static_cast<size_t>(tcInt) && (startIdx + i) < state->chunkReceived.size(); i++) {
            if (!state->chunkReceived[startIdx + i]) {
                missingChunksIdx += std::to_string(i); // Relies on client wanting relative idx or absolute. The protocol sends 0..1023
                missingChunksIdx.push_back(' ');
            }
        }
        if (!missingChunksIdx.empty()) missingChunksIdx.pop_back();
        SendAck(upId, ROUND_STATUS, missingChunksIdx);
    }
}
 // round ack layou
 //------------------------------------
 // length||pkt|| uid|| chunkIdx seprated by sapce 
 //-------------------------------------
// acknowledgmet for correct buffer
// acknowledgmet for correct buffer
void FileTransferManager::SendAck(const std::string upId, PacketType P) {
    Packet* p = PacketPool::Instance().borrowPacket();
    std::string recId;
    {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = uploadIdToTranserState.find(upId);  
        if (it != uploadIdToTranserState.end()) recId = it->second->senderId;
    }
    if(recId.empty()) { PacketPool::Instance().returnPacket(p); return; }
    p->receiverId = recId;
    p->serialize(P, upId, recId, "");
    off->ManageCompletePacket(p, recId);
}

// acknowledgment for buffer 
void FileTransferManager::SendAck(const std::string upId, PacketType P, const std::string chunkIdx) {
    Packet* p = PacketPool::Instance().borrowPacket();
    std::string recId;
    {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = uploadIdToTranserState.find(upId);  
        if (it != uploadIdToTranserState.end()) recId = it->second->senderId;
    }
    if(recId.empty()) { PacketPool::Instance().returnPacket(p); return; }
    p->receiverId = recId;
    p->serialize(P, upId, recId, chunkIdx);
    off->ManageCompletePacket(p, recId);
}

 // to hanlde disconnect pkt 
 // for disconnect remove user from active transfer
 void FileTransferManager::HandleDisconnect(Packet *p){
    char *st=p->data+HEADER_SIZE;
    int len=p->header.size-HEADER_SIZE;
    std::string raw(st,len);
    PacketPool::Instance().returnPacket(p);

    size_t pos=0;
    std::string upId;
    while(pos<raw.size()&&raw[pos]!=' ')upId.push_back(raw[pos++]);

    std::lock_guard<std::mutex> lk(mtx);
    auto it = activeTransfers.find(upId);
    if (it == activeTransfers.end()) return;
    
    TransferState *state = it->second;
    state->totalChunksRecieved -= state->chunkRecieved;
    state->chunkRecieved = 0;
    activeTransfers.erase(upId);
 }
 // handle resume
 void FileTransferManager::HandleResume(Packet *p){
    char *st=p->data+HEADER_SIZE;
    std::string upId;
    int l = p->header.size - HEADER_SIZE;
    std::string raw(st, l);
    PacketPool::Instance().returnPacket(p);

    size_t pos = 0;
    while (pos < l && raw[pos] != ' ') upId.push_back(raw[pos++]);
    pos++;
    std::string lsRound;
    while (pos < l && raw[pos] != ' ') lsRound.push_back(raw[pos++]);
    int round = 0;
    try { round = std::stoi(lsRound); } 
    catch (...) { return; }

    std::lock_guard<std::mutex> lk(mtx);
    auto it = uploadIdToTranserState.find(upId);
    if (it == uploadIdToTranserState.end()) return;
    
    activeTransfers[upId] = it->second;

    if (it->second->round == static_cast<size_t>(round)) {
        SendAck(upId, ROUND_STATUS);
    } else {
        SendAck(upId, ROUND_STATUS, std::to_string(it->second->round + 1));
    }
 }
 // handle end of file
 // end packet layout 
//--------------------------------------
//  upId || checksum
//------------------------------------
  void FileTransferManager::handleEnd(Packet *p) {
    char *st = p->data + HEADER_SIZE;
    int len = p->header.size - HEADER_SIZE;
    std::string raw(st, len);
    PacketPool::Instance().returnPacket(p);

    std::string upId;
    std::string finalCheckSum;
    size_t pos = 0;
    while (pos < len && raw[pos] != ' ') upId.push_back(raw[pos++]);
    pos++;
    while (pos < len && raw[pos] != ' ') finalCheckSum.push_back(raw[pos++]);

    std::lock_guard<std::mutex> lk(mtx);
    auto it = uploadIdToTranserState.find(upId);
    if (it == uploadIdToTranserState.end()) return;
    
    TransferState *state = it->second;
    
    // Store checksum to pass to downloaders
    try { state->checkSum = static_cast<uint32_t>(std::stoul(finalCheckSum)); }
    catch (...) { state->checkSum = 0; }

    if (state->fileStream.is_open()) {
        state->fileStream.close();
    }

    bool fileIsCorrect = (state->totalChunksRecieved == state->totalChunks);

    if (fileIsCorrect) {
        SendAck(upId, FILE_STATUS, "");
        {
            std::lock_guard<std::mutex> dlk(downloadMtx);
            completedUpload.push(state);
        }
        downloadCv.notify_one();
    } else {
        SendAck(upId, FILE_STATUS, "SENT FAILED");
    }

    activeTransfers.erase(upId);
    uploadIdToTranserState.erase(upId);
    // Hash removal
    uint32_t hash = 2166136261u;
    for (char c : upId) { hash ^= static_cast<uint8_t>(c); hash *= 16777619u; }
    uploadIdHashMap.erase(hash);
  }
 // this will tell the sender to send from which bytes of file 
void FileTransferManager::startResponse(const std::string& upId) {
    // No lock needed here as it's called synchronously from handleStart which already holds mtx
    auto it = uploadIdToTranserState.find(upId);
    if (it == uploadIdToTranserState.end()) return;

    TransferState* state = it->second;
    std::streampos fileSize = 0; // Fresh file
    
    Packet* p = PacketPool::Instance().borrowPacket();
    p->serialize(FILE_START_RESPONSE, upId, state->senderId, 
                std::to_string(static_cast<std::streamoff>(fileSize)));
    
    off->ManageCompletePacket(p, state->senderId); 
}