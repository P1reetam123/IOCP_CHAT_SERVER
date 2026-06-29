#pragma once
#include <string>
#include <vector>
#include "PacketHeader.h"
#include "PacketTypes.h"

#pragma pack(push, 1)
struct ChunkHeader {
    uint32_t uploadIdHash;  // FNV-1a hash of upload ID for O(1) lookup
    uint16_t chunkIdx;      // Max 1024 chunks per round
    uint16_t dataLen;       // Actual chunk data length
};
#pragma pack(pop)

class Packet
{
public:
    PacketHeader header;
    char data[4096];
    char* in = data;
    size_t id;
    // Parsed fields (populated after parseHeader)
    std::string senderId;
    std::string receiverId;
    // for server side we do need payload we need only sender and reciever id
    std::string payload;
    bool parsedHeader=false;
    bool parsedData=false;
    bool isSent=false; // to check whether data is sent or not
    bool isSending =false;
    bool isSentFail=false;
    
    // Reset the write pointer back to the start of the buffer
    void clearInPointer();
    // Parse the raw buffer to extract senderId, receiverId, payload
    // Wire payload format: "senderId receiverId payload_data"
    bool parseHeader();
    bool parseData();
    // Build a complete packet from fields into the data buffer
    // Returns the total size written
    int serialize(PacketType type,
                  const std::string& sender,
                  const std::string& receiver,
                  const std::string& payloadData);

    // Get the total number of bytes received so far
    int bytesReceived() const;

    // Check if a complete packet has been received
    bool isHeaderComplete() const;
    bool isComplete() const;
    void serializeChunk(const std::string &upId, const std::string &chunkIdx,const std::vector<char>&memeblock);
    void serializeChunkBinary(uint32_t uploadIdHash, uint16_t chunkIdx, const char* chunkData, uint16_t dataLen);
};