#include "Packet.h"
#include <cstring>
#include <winsock2.h>
#include <limits>
#include <stdexcept>
#include "CRC32C.h"

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
    writePos = HEADER_SIZE;
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

bool Packet::parseData()
{
    size_t received = static_cast<size_t>(bytesReceived());
    if (received < header.size) return false;

    size_t bodyLen = header.size - HEADER_SIZE;
    if (bodyLen == 0) {
        parsedData = true;
        return true;
    }

    const uint8_t* body = reinterpret_cast<const uint8_t*>(data + HEADER_SIZE);

    const uint8_t* sp1 = static_cast<const uint8_t*>(memchr(body, ' ', bodyLen));
    if (!sp1) return false;

    size_t remaining = bodyLen - (sp1 - body) - 1;
    if (remaining == 0) return false;

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

    header.size = ntohl(*(uint32_t*)data);
    header.type = *(uint8_t*)(data + 4);

    if (received < static_cast<int>(header.size)) return false;

    const char* payloadStart = data + HEADER_SIZE;
    int payloadLen = header.size - HEADER_SIZE;
    if (payloadLen <= 0) return true;

    std::string raw(payloadStart, payloadLen);
    senderId.clear();
    receiverId.clear();
    size_t pos = 0;
    while (pos < raw.size() && raw[pos] != ' ')
        senderId.push_back(raw[pos++]);
    pos++;
    while (pos < raw.size() && raw[pos] != ' ')
        receiverId.push_back(raw[pos++]);
    pos++;
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

void Packet::resetWritePos()
{
    writePos = HEADER_SIZE;
}

void Packet::finalizeBinaryPacket(PacketType type)
{
    uint32_t netSize = htonl(static_cast<uint32_t>(writePos));
    std::memcpy(data, &netSize, 4);
    data[4] = static_cast<uint8_t>(type);
    header.size = static_cast<uint32_t>(writePos);
    header.type = static_cast<uint8_t>(type);
    in = data + writePos;
}

void Packet::writeUint8(uint8_t v)
{
    if (writePos + 1 > sizeof(data)) return;
    std::memcpy(data + writePos, &v, 1);
    writePos += 1;
}

void Packet::writeUint32(uint32_t v)
{
    if (writePos + 4 > sizeof(data)) return;
    uint32_t net = htonl(v);
    std::memcpy(data + writePos, &net, 4);
    writePos += 4;
}

void Packet::writeUint64(uint64_t v)
{
    if (writePos + 8 > sizeof(data)) return;
    uint64_t net = htonll(v);
    std::memcpy(data + writePos, &net, 8);
    writePos += 8;
}

void Packet::writeString(const std::string& str)
{
    uint32_t len = static_cast<uint32_t>(str.length());
    writeUint32(len);
    if (writePos + len > sizeof(data)) return;
    std::memcpy(data + writePos, str.data(), len);
    writePos += len;
}

void Packet::writeBytes(const uint8_t* bytes, uint32_t len)
{
    if (writePos + len > sizeof(data)) return;
    std::memcpy(data + writePos, bytes, len);
    writePos += len;
}

void Packet::serializeFileStart(const std::string& uploadId,
                               const std::string& fileName,
                               uint64_t totalSize,
                               uint32_t finalCrc)
{
    resetWritePos();
    writeUint64(totalSize);
    writeString(fileName);
    writeString(uploadId);
    writeUint32(finalCrc);
    finalizeBinaryPacket(PKT_FILE_START);
}

void Packet::serializeFileStartResponse(const std::string& uploadId,
                                       uint64_t resumeOffset)
{
    resetWritePos();
    writeString(uploadId);
    writeUint64(resumeOffset);
    finalizeBinaryPacket(FILE_START_RESPONSE);
}

void Packet::serializeFileChunk(const std::string& uploadId,
                               uint64_t byteOffset,
                               const std::vector<uint8_t>& chunkData)
{
    resetWritePos();

    uint32_t chunkSize = static_cast<uint32_t>(chunkData.size());
    uint32_t crc = CRC32C::compute(chunkData);

    writeString(uploadId);
    writeUint64(byteOffset);
    writeUint32(chunkSize);
    writeUint32(crc);
    writeBytes(chunkData.data(), chunkSize);

    finalizeBinaryPacket(PKT_FILE_CHUNK);
}

void Packet::serializeRoundEnd(const std::string& uploadId,
                              uint32_t roundId,
                              uint32_t chunkCount)
{
    resetWritePos();
    writeString(uploadId);
    writeUint32(roundId);
    writeUint32(chunkCount);
    finalizeBinaryPacket(PKT_ROUND_END);
}

void Packet::serializeFileAck(const std::string& uploadId,
                             uint32_t roundId,
                             const std::vector<uint32_t>& missingChunks)
{
    resetWritePos();
    writeString(uploadId);
    writeUint32(roundId);
    writeUint32(static_cast<uint32_t>(missingChunks.size()));
    for (uint32_t idx : missingChunks) {
        writeUint32(idx);
    }
    finalizeBinaryPacket(PKT_FILE_ACK);
}

void Packet::serializeFileEnd(const std::string& uploadId, uint32_t finalCrc)
{
    resetWritePos();
    writeString(uploadId);
    writeUint32(finalCrc);
    finalizeBinaryPacket(PKT_FILE_END);
}

uint8_t Packet::readUint8(size_t& pos) const
{
    if (pos + 1 > header.size) throw std::runtime_error("readUint8 bounds");
    uint8_t v;
    std::memcpy(&v, data + pos, 1);
    pos += 1;
    return v;
}

uint32_t Packet::readUint32(size_t& pos) const
{
    if (pos + 4 > header.size) throw std::runtime_error("readUint32 bounds");
    uint32_t net;
    std::memcpy(&net, data + pos, 4);
    pos += 4;
    return ntohl(net);
}

uint64_t Packet::readUint64(size_t& pos) const
{
    if (pos + 8 > header.size) throw std::runtime_error("readUint64 bounds");
    uint64_t net;
    std::memcpy(&net, data + pos, 8);
    pos += 8;
    return ntohll(net);
}

std::string Packet::readString(size_t& pos) const
{
    uint32_t len = readUint32(pos);
    if (pos + len > header.size) throw std::runtime_error("readString bounds");
    std::string str(reinterpret_cast<const char*>(data + pos), len);
    pos += len;
    return str;
}

std::vector<uint8_t> Packet::readBytes(size_t& pos, uint32_t len) const
{
    if (pos + len > header.size) throw std::runtime_error("readBytes bounds");
    std::vector<uint8_t> result(len);
    std::memcpy(result.data(), data + pos, len);
    pos += len;
    return result;
}
