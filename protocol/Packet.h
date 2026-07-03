#pragma once
#include <string>
#include <vector>
#include "PacketHeader.h"
#include "PacketTypes.h"

class Packet
{
public:
    PacketHeader header;
    char data[4096];
    char* in = data;
    size_t id;
    std::string tempSessionId;
    std::string user_name;
    std::string senderId;
    std::string receiverId;
    std::string payload;
    bool parsedHeader=false;
    bool parsedData=false;
    bool isSent=false;
    bool isSending =false;
    bool isSentFail=false;

    void clearInPointer();
    bool parseHeader();
    bool parseData();
    int serialize(PacketType type,
                  const std::string& sender,
                  const std::string& receiver,
                  const std::string& payloadData);

    int bytesReceived() const;
    bool isHeaderComplete() const;
    bool isComplete() const;

    void serializeFileStart(const std::string& uploadId,
                           const std::string& fileName,
                           uint64_t totalSize,
                           uint32_t finalCrc = 0);

    void serializeFileStartResponse(const std::string& uploadId,
                                   uint64_t resumeOffset);

    void serializeFileChunk(const std::string& uploadId,
                           uint64_t byteOffset,
                           const std::vector<uint8_t>& chunkData);

    void serializeRoundEnd(const std::string& uploadId,
                          uint32_t roundId,
                          uint32_t chunkCount);

    void serializeFileAck(const std::string& uploadId,
                         uint32_t roundId,
                         const std::vector<uint32_t>& missingChunks = {});

    void serializeFileEnd(const std::string& uploadId, uint32_t finalCrc);

    void writeUint8(uint8_t v);
    void writeUint32(uint32_t v);
    void writeUint64(uint64_t v);
    void writeString(const std::string& str);
    void writeBytes(const uint8_t* data, uint32_t len);

    uint8_t readUint8(size_t& pos) const;
    uint32_t readUint32(size_t& pos) const;
    uint64_t readUint64(size_t& pos) const;
    std::string readString(size_t& pos) const;
    std::vector<uint8_t> readBytes(size_t& pos, uint32_t len) const;

private:
    size_t writePos = HEADER_SIZE;
    void resetWritePos();
    void finalizeBinaryPacket(PacketType type);
};
