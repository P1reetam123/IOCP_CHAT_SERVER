#pragma once
#include <string>
#include <vector>
#include "PacketHeader.h"
#include "PacketTypes.h"
#include "ProtocolStructs.h"

class Packet
{
public:
    PacketHeader header;
    uint8_t data[4096];
    uint8_t* in = data;
    
    // Legacy fields removed: std::string senderId, etc.
    // Instead we interact with the raw byte buffer directly.

    size_t writePos = HEADER_SIZE;
    
    bool parsedHeader = false;
    bool parsedData = false;
    bool isSent = false;
    bool isSending = false;
    bool isSentFail = false;
    bool bypassQueue = false;

    size_t id = 0; // Needed by PacketPool

    void clearInPointer();
    
    bool parseHeader();
    bool parseData(); // Kept for backwards compatibility structure, but simplified

    // Direct payload access
    template<typename T>
    const T* getPayload() const {
        return reinterpret_cast<const T*>(data + HEADER_SIZE);
    }
    
    template<typename T>
    T* getPayload() {
        return reinterpret_cast<T*>(data + HEADER_SIZE);
    }

    const uint8_t* getPayloadRaw() const {
        return data + HEADER_SIZE;
    }

    int bytesReceived() const;
    bool isHeaderComplete() const;
    bool isComplete() const;
    bool checkPacketVersion();

    // Serializers
    bool serialize(PacketType type,
                   const uint8_t *sender,
                   const uint8_t *receiver,
                   const uint8_t *number,
                   const std::string &username,
                   const std::string& payloadData);

    bool serializeFileStart(const uint8_t* recid, const uint8_t* uploadId,
                            const std::string& fileName,
                            uint64_t totalSize,
                            uint32_t finalCrc = 0);

    bool serializeFileStartResponse(const uint8_t* uploadId,
                                    uint64_t resumeOffset);

    bool serializeFileChunk(const uint8_t* uploadId,
                            uint64_t byteOffset,
                            const std::vector<uint8_t>& chunkData);

    bool serializeRoundEnd(const uint8_t* uploadId,
                           uint32_t roundId,
                           uint32_t chunkCount);

    bool serializeFileAck(const uint8_t* uploadId,
                          uint32_t roundId,
                          const std::vector<uint32_t>& missingChunks = {});

    bool serializeFileEnd(const uint8_t* uploadId, uint32_t finalCrc);

    bool serializeLink(const uint8_t* senderId, const uint8_t* uploadId, 
                       const std::string& filename, uint32_t totalsize, const std::string& timestamp);
                       
    bool serializeDownloadReq(const uint8_t* userId, const uint8_t* upId, uint32_t bytes);
    
    bool serializeLogin(const std::string &identifier, const std::string &password);
    bool serializeOtpRequest(const std::string &email);
    bool serializeOtpVerification(const std::string &email, const std::string &otp);
    bool serializeSignup(const std::string &email, const std::string &number, 
                         const std::string &username, const std::string &password);
    bool serializeUserId(const uint8_t *userId, const uint8_t* serverTempId);
    
    // For Token passing
    bool serializeToken(PacketType type, const std::vector<uint8_t>& accessToken, const std::vector<uint8_t>& refreshToken);
    bool serializeString(PacketType type, const std::string& str);
    bool serializeRaw(PacketType type, const std::string& rawPayload);

private:
    void resetWritePos();
    bool finalizePacket(PacketType type); // computes length and crc, sets header
};
