#include "Packet.h"
#include <cstring>
#include <winsock2.h>
#include <limits>

void Packet::clearInPointer()
{
    in = data;
    header.size = 0;
    header.type = 0;
    senderId.clear();
    receiverId.clear();
    payload.clear();
    parsedHeader = false;
    parsedData = false;
    isSent = false;
    isSending = false;
    isSentFail = false;
}

int Packet::bytesReceived() const
{
    return static_cast<int>(in - data);
}
bool Packet::isComplete() const
{
     return bytesReceived() >= static_cast<int>(header.size);
}
bool Packet::isHeaderComplete() const
{
    return bytesReceived() >= HEADER_SIZE;
}

bool Packet::parseData() {
    size_t received = static_cast<size_t>(bytesReceived());
    if (received < header.size) return false;

    size_t bodyLen = header.size - HEADER_SIZE;
    if (bodyLen == 0) {
        parsedData = true;
        return true;
    }

    const uint8_t* body = reinterpret_cast<const uint8_t*>(data + HEADER_SIZE);
    
    // Find first space
    const uint8_t* sp1 = static_cast<const uint8_t*>(memchr(body, ' ', bodyLen));
    if (!sp1) return false;
    
    // Calculate remaining length after first space
    size_t remaining = bodyLen - (sp1 - body) - 1;
    if (remaining == 0) return false;
    
    // Find second space in remaining portion
    const uint8_t* sp2 = static_cast<const uint8_t*>(memchr(sp1 + 1, ' ', remaining));
    if (!sp2) return false;
    
    const uint8_t* payloadStart = sp2 + 1;
    size_t clen = bodyLen - (payloadStart - body);
    
    if (clen == 0) {
        parsedData = true;
        return true;
    }
    
    payload.assign(payloadStart, payloadStart + clen);
    parsedData = true;
    return true;
}   
bool Packet::parseHeader()
{
    int received = bytesReceived();
    if (received < HEADER_SIZE) return false;

    // Extract header fields (network byte order)
    header.size = ntohl(*(uint32_t*)data);
    header.type = *(uint8_t*)(data + 4);
   
    if (received < static_cast<int>(header.size)) return false;
    
    // Parse payload: "senderId receiverId actual_payload"
    const char* payloadStart = data + HEADER_SIZE;
    int payloadLen = header.size - HEADER_SIZE;
    if (payloadLen <= 0) return true;
    std::string raw(payloadStart, payloadLen);
    senderId.clear();
    receiverId.clear();
    size_t pos = 0;
    // Extract senderId
    while (pos < raw.size() && raw[pos] != ' ')
        senderId.push_back(raw[pos++]);
    pos++; // skip space
    // Extract receiverId
    while (pos < raw.size() && raw[pos] != ' ')
        receiverId.push_back(raw[pos++]);
    pos++; // skip space
// we can skip payload in serevr because we need only need header
    // Rest is payload
    if (pos < raw.size()) {
        payload = raw.substr(pos);
    }
    parsedHeader = true;
    return true;
}
int Packet::serialize(PacketType type,
                      const std::string& sender,
                      const std::string& receiver,
                      const std::string& payloadData)
{
    const size_t senderSize   = sender.size();
    const size_t receiverSize = receiver.size();
    const size_t payloadSize  = payloadData.size();

    const size_t total = HEADER_SIZE + senderSize + 1 + receiverSize + 1 + payloadSize;

    // Guard BOTH the buffer capacity and the uint32_t range before any write.
    if (total > 4096 || total > std::numeric_limits<uint32_t>::max()) {
        return -1;
    }
    const uint32_t totalSize = static_cast<uint32_t>(total);

    uint32_t netSize = htonl(totalSize);
    std::memcpy(data, &netSize, 4);
    data[4] = static_cast<uint8_t>(type);

    uint8_t* ptr = reinterpret_cast<uint8_t*>(data + HEADER_SIZE);
    if (senderSize)  { std::memcpy(ptr, sender.data(),   senderSize);   ptr += senderSize; }
    *ptr++ = ' ';
    if (receiverSize){ std::memcpy(ptr, receiver.data(), receiverSize); ptr += receiverSize; }
    *ptr++ = ' ';
    if (payloadSize) { std::memcpy(ptr, payloadData.data(), payloadSize); }

    header.size = totalSize;
    header.type = static_cast<uint8_t>(type);
    in = data + totalSize;
    return static_cast<int>(totalSize);
}
void Packet::serializeChunk(const std::string& upId, const std::string& chunkIdx, const std::vector<char>& memeblock) {
    // 1. Calculate sizes
    size_t idSize = upId.size();
    size_t idxSize = chunkIdx.size();
    size_t blockSize = memeblock.size();
    
    // Total payload = id + space + idx + space + block
    size_t payloadSize = idSize + 1 + idxSize + 1 + blockSize;
    uint32_t totalSize = HEADER_SIZE + static_cast<uint32_t>(payloadSize);

    
    uint32_t netSize = htonl(totalSize);
    std::memcpy(data, &netSize, 4);
    data[4] = static_cast<uint8_t>(PKT_FILE_CHUNK);

  
  // Correct: Explicitly tell the compiler to treat this address as uint8_t*

  // this reads bytes by bytes
uint8_t* ptr = reinterpret_cast<uint8_t*>(data + HEADER_SIZE); 

   
    if (idSize > 0) {
        std::memcpy(ptr, upId.c_str(), idSize);
    }
    ptr += idSize;
    
   
    *ptr++ = ' ';

    // Copy chunkIdx
    if (idxSize > 0) {
        std::memcpy(ptr, chunkIdx.c_str(), idxSize);
    }
    ptr += idxSize;

    // Add space
    *ptr++ = ' ';

    if (blockSize > 0) {
        std::memcpy(ptr, memeblock.data(), blockSize);
    }

    // 4. Update State
    header.size = totalSize;
    header.type = static_cast<uint8_t>(PKT_FILE_CHUNK);
    in = data + totalSize;
}

void Packet::serializeChunkBinary(uint32_t uploadIdHash, uint16_t chunkIdx, const char* chunkData, uint16_t dataLen) {
    // Total size = Header + ChunkHeader + dataLen
    // ChunkHeader is 8 bytes
    uint32_t totalSize = HEADER_SIZE + sizeof(ChunkHeader) + dataLen;

    uint32_t netSize = htonl(totalSize);
    std::memcpy(data, &netSize, 4);
    data[4] = static_cast<uint8_t>(PKT_FILE_CHUNK);

    ChunkHeader chunkHeader;
    chunkHeader.uploadIdHash = uploadIdHash; // Stored in little-endian/native is fine if client matches, but usually htonl/htons should be used.
    // For now keeping it native endian as assuming same architecture for simplicity, or we can use htonl/htons
    chunkHeader.chunkIdx = chunkIdx;
    chunkHeader.dataLen = dataLen;

    uint8_t* ptr = reinterpret_cast<uint8_t*>(data + HEADER_SIZE);
    std::memcpy(ptr, &chunkHeader, sizeof(ChunkHeader));
    ptr += sizeof(ChunkHeader);

    if (dataLen > 0) {
        std::memcpy(ptr, chunkData, dataLen);
    }

    header.size = totalSize;
    header.type = static_cast<uint8_t>(PKT_FILE_CHUNK);
    in = data + totalSize;
}