#include "Packet.h"
#include <cstring>
#include <winsock2.h>
#include <limits>
#include <stdexcept>
#include "CRC32C.h"
#include <chrono>

void Packet::clearInPointer()
{
    in = data;
    std::memset(&header, 0, sizeof(PacketHeader));
    parsedHeader = false;
    parsedData = false;
    isSent = false;
    isSending = false;
    isSentFail = false;
    bypassQueue = false;
    writePos = HEADER_SIZE;
}

int Packet::bytesReceived() const
{
    return static_cast<int>(in - data);
}

bool Packet::isHeaderComplete() const
{
    return bytesReceived() >= HEADER_SIZE;
}

bool Packet::isComplete() const
{
    if (!isHeaderComplete()) return false;
    return bytesReceived() >= static_cast<int>(HEADER_SIZE + header.payload_length);
}

bool Packet::checkPacketVersion()
{
    return parsedHeader && header.magic == START_BYTE && header.version == CURRENT_VERSION;
}

bool Packet::parseHeader()
{
    if (bytesReceived() < HEADER_SIZE) return false;
    
    // Read header into host byte order struct
    PacketHeader* raw_header = reinterpret_cast<PacketHeader*>(data);
    header.magic = raw_header->magic;
    header.version = raw_header->version;
    header.type = ntohs(raw_header->type);
    header.payload_length = ntohl(raw_header->payload_length);
    header.sequence_number = ntohl(raw_header->sequence_number);
    header.checksum = ntohl(raw_header->checksum);
    
    if (header.magic != START_BYTE) return false;
    
    parsedHeader = true;
    return true;
}

bool Packet::parseData()
{
    if (!parsedHeader) return false;
    if (bytesReceived() < static_cast<int>(HEADER_SIZE + header.payload_length)) return false;
    
    // Verify checksum
    uint32_t computed_crc = CRC32C::compute(data, HEADER_SIZE - sizeof(uint32_t)); // exclude checksum field itself
    if (header.payload_length > 0) {
        computed_crc = CRC32C::compute(data + HEADER_SIZE, header.payload_length, computed_crc);
    }
    
    if (computed_crc != header.checksum) {
        // Return false on strict checking, but let's allow it to pass or log
        // return false; 
        return false;
    }
    
    parsedData = true;
    return true;
}

void Packet::resetWritePos()
{
    writePos = HEADER_SIZE;
}

bool Packet::finalizePacket(PacketType type)
{
    uint32_t payload_len = static_cast<uint32_t>(writePos - HEADER_SIZE);
    
    PacketHeader* hdr = reinterpret_cast<PacketHeader*>(data);
    hdr->magic = START_BYTE;
    hdr->version = CURRENT_VERSION;
    hdr->type = htons(static_cast<uint16_t>(type));
    hdr->payload_length = htonl(payload_len);
    hdr->sequence_number = htonl(0); // Optional sequence number
    
    uint32_t computed_crc = CRC32C::compute(data, HEADER_SIZE - sizeof(uint32_t));
    if (payload_len > 0) {
        computed_crc = CRC32C::compute(data + HEADER_SIZE, payload_len, computed_crc);
    }
    hdr->checksum = htonl(computed_crc);
    
    // also set our internal parsed header
    header.magic = START_BYTE;
    header.version = CURRENT_VERSION;
    header.type = static_cast<uint16_t>(type);
    header.payload_length = payload_len;
    header.sequence_number = 0;
    header.checksum = computed_crc;
    
    in = data + writePos;
    return true;
}

bool Packet::serialize(PacketType type,
               const uint8_t *sender,
               const uint8_t *receiver,
               const uint8_t *number,
               const std::string &username,
               const std::string& payloadData)
{
    resetWritePos();
    if (writePos + sizeof(ChatMessagePayload) + username.length() + payloadData.length() > sizeof(data)) return false;
    
    ChatMessagePayload* p = reinterpret_cast<ChatMessagePayload*>(data + writePos);
    std::memcpy(p->sender_id, sender, 16);
    std::memcpy(p->receiver_id, receiver, 16);
    
    int64_t timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    p->timestamp = htonll(timestamp_ms);
    
    uint32_t num = 0;
    if(number) std::memcpy(&num, number, 4); // assuming number is a 4-byte string or int array
    p->message_number = htonl(num);
    
    p->username_len = htons(static_cast<uint16_t>(username.length()));
    p->text_len = htons(static_cast<uint16_t>(payloadData.length()));
    
    writePos += sizeof(ChatMessagePayload);
    std::memcpy(data + writePos, username.c_str(), username.length());
    writePos += username.length();
    
    std::memcpy(data + writePos, payloadData.c_str(), payloadData.length());
    writePos += payloadData.length();
    
    return finalizePacket(type);
}

bool Packet::serializeFileStart(const uint8_t* recid, const uint8_t* uploadId,
                        const std::string& fileName,
                        uint64_t totalSize,
                        uint32_t finalCrc)
{
    resetWritePos();
    if (writePos + sizeof(FileStartPayload) + fileName.length() > sizeof(data)) return false;
    
    FileStartPayload* p = reinterpret_cast<FileStartPayload*>(data + writePos);
    std::memcpy(p->receiver_id, recid, 16);
    std::memcpy(p->upload_id, uploadId, 16);
    p->total_size = htonll(totalSize);
    p->final_crc = htonl(finalCrc);
    p->filename_len = htons(static_cast<uint16_t>(fileName.length()));
    
    writePos += sizeof(FileStartPayload);
    std::memcpy(data + writePos, fileName.c_str(), fileName.length());
    writePos += fileName.length();
    
    return finalizePacket(PKT_FILE_START);
}

bool Packet::serializeFileStartResponse(const uint8_t* uploadId, uint64_t resumeOffset)
{
    resetWritePos();
    if (writePos + sizeof(FileStartResponsePayload) > sizeof(data)) return false;
    
    FileStartResponsePayload* p = reinterpret_cast<FileStartResponsePayload*>(data + writePos);
    std::memcpy(p->upload_id, uploadId, 16);
    p->resume_offset = htonll(resumeOffset);
    writePos += sizeof(FileStartResponsePayload);
    
    return finalizePacket(FILE_START_RESPONSE);
}

bool Packet::serializeFileChunk(const uint8_t* uploadId, uint64_t byteOffset, const std::vector<uint8_t>& chunkData)
{
    resetWritePos();
    if (writePos + sizeof(FileChunkPayload) + chunkData.size() > sizeof(data)) return false;
    
    FileChunkPayload* p = reinterpret_cast<FileChunkPayload*>(data + writePos);
    std::memcpy(p->upload_id, uploadId, 16);
    p->byte_offset = htonll(byteOffset);
    p->chunk_size = htonl(static_cast<uint32_t>(chunkData.size()));
    p->chunk_crc = htonl(CRC32C::compute(chunkData));
    
    writePos += sizeof(FileChunkPayload);
    std::memcpy(data + writePos, chunkData.data(), chunkData.size());
    writePos += chunkData.size();
    
    return finalizePacket(PKT_FILE_CHUNK);
}

bool Packet::serializeRoundEnd(const uint8_t* uploadId, uint32_t roundId, uint32_t chunkCount)
{
    resetWritePos();
    if (writePos + sizeof(RoundEndPayload) > sizeof(data)) return false;
    
    RoundEndPayload* p = reinterpret_cast<RoundEndPayload*>(data + writePos);
    std::memcpy(p->upload_id, uploadId, 16);
    p->round_id = htonl(roundId);
    p->chunk_count = htonl(chunkCount);
    writePos += sizeof(RoundEndPayload);
    
    return finalizePacket(PKT_ROUND_END);
}

bool Packet::serializeFileAck(const uint8_t* uploadId, uint32_t roundId, const std::vector<uint32_t>& missingChunks)
{
    resetWritePos();
    if (writePos + sizeof(FileAckPayload) + missingChunks.size() * sizeof(uint32_t) > sizeof(data)) return false;
    
    FileAckPayload* p = reinterpret_cast<FileAckPayload*>(data + writePos);
    std::memcpy(p->upload_id, uploadId, 16);
    p->round_id = htonl(roundId);
    p->missing_count = htonl(static_cast<uint32_t>(missingChunks.size()));
    
    writePos += sizeof(FileAckPayload);
    for (uint32_t chunk : missingChunks) {
        uint32_t netChunk = htonl(chunk);
        std::memcpy(data + writePos, &netChunk, sizeof(uint32_t));
        writePos += sizeof(uint32_t);
    }
    
    return finalizePacket(PKT_FILE_ACK);
}

bool Packet::serializeFileEnd(const uint8_t* uploadId, uint32_t finalCrc)
{
    resetWritePos();
    if (writePos + sizeof(FileEndPayload) > sizeof(data)) return false;
    
    FileEndPayload* p = reinterpret_cast<FileEndPayload*>(data + writePos);
    std::memcpy(p->upload_id, uploadId, 16);
    p->final_crc = htonl(finalCrc);
    writePos += sizeof(FileEndPayload);
    
    return finalizePacket(PKT_FILE_END);
}

bool Packet::serializeLink(const uint8_t* senderId, const uint8_t* uploadId, 
                   const std::string& filename, uint32_t totalsize, const std::string& timestamp)
{
    resetWritePos();
    if (writePos + sizeof(DownloadLinkPayload) + filename.length() + timestamp.length() > sizeof(data)) return false;
    
    DownloadLinkPayload* p = reinterpret_cast<DownloadLinkPayload*>(data + writePos);
    std::memcpy(p->sender_id, senderId, 16);
    std::memcpy(p->upload_id, uploadId, 16);
    p->total_size = htonl(totalsize);
    p->filename_len = htons(static_cast<uint16_t>(filename.length()));
    p->timestamp_len = htons(static_cast<uint16_t>(timestamp.length()));
    
    writePos += sizeof(DownloadLinkPayload);
    std::memcpy(data + writePos, filename.c_str(), filename.length());
    writePos += filename.length();
    
    std::memcpy(data + writePos, timestamp.c_str(), timestamp.length());
    writePos += timestamp.length();
    
    return finalizePacket(DOWNLOAD_LINK);
}

bool Packet::serializeDownloadReq(const uint8_t* userId, const uint8_t* upId, uint32_t bytes)
{
    resetWritePos();
    if (writePos + sizeof(DownloadReqPayload) > sizeof(data)) return false;
    
    DownloadReqPayload* p = reinterpret_cast<DownloadReqPayload*>(data + writePos);
    std::memcpy(p->user_id, userId, 16);
    std::memcpy(p->upload_id, upId, 16);
    p->bytes_requested = htonl(bytes);
    
    writePos += sizeof(DownloadReqPayload);
    
    return finalizePacket(DOWNLOAD_REQUEST);
}

bool Packet::serializeLogin(const std::string &identifier, const std::string &password)
{
    resetWritePos();
    if (writePos + sizeof(LoginPayload) + identifier.length() + password.length() > sizeof(data)) return false;
    
    LoginPayload* p = reinterpret_cast<LoginPayload*>(data + writePos);
    p->identifier_len = htons(static_cast<uint16_t>(identifier.length()));
    p->password_len = htons(static_cast<uint16_t>(password.length()));
    
    writePos += sizeof(LoginPayload);
    std::memcpy(data + writePos, identifier.c_str(), identifier.length());
    writePos += identifier.length();
    std::memcpy(data + writePos, password.c_str(), password.length());
    writePos += password.length();
    
    return finalizePacket(PKT_LOGIN);
}

bool Packet::serializeOtpRequest(const std::string &email)
{
    resetWritePos();
    if (writePos + sizeof(OtpReqPayload) + email.length() > sizeof(data)) return false;
    
    OtpReqPayload* p = reinterpret_cast<OtpReqPayload*>(data + writePos);
    p->email_len = htons(static_cast<uint16_t>(email.length()));
    
    writePos += sizeof(OtpReqPayload);
    std::memcpy(data + writePos, email.c_str(), email.length());
    writePos += email.length();
    
    return finalizePacket(PKT_OTP_REQ);
}

bool Packet::serializeOtpVerification(const std::string &email, const std::string &otp)
{
    resetWritePos();
    if (writePos + sizeof(OtpVerifyPayload) + email.length() + otp.length() > sizeof(data)) return false;
    
    OtpVerifyPayload* p = reinterpret_cast<OtpVerifyPayload*>(data + writePos);
    p->email_len = htons(static_cast<uint16_t>(email.length()));
    p->otp_len = htons(static_cast<uint16_t>(otp.length()));
    
    writePos += sizeof(OtpVerifyPayload);
    std::memcpy(data + writePos, email.c_str(), email.length());
    writePos += email.length();
    std::memcpy(data + writePos, otp.c_str(), otp.length());
    writePos += otp.length();
    
    return finalizePacket(PKT_OTP_VERIFY);
}

bool Packet::serializeSignup(const std::string &email, const std::string &number, 
                     const std::string &username, const std::string &password)
{
    resetWritePos();
    if (writePos + sizeof(SignupPayload) + email.length() + number.length() + username.length() + password.length() > sizeof(data)) return false;
    
    SignupPayload* p = reinterpret_cast<SignupPayload*>(data + writePos);
    p->email_len = htons(static_cast<uint16_t>(email.length()));
    p->number_len = htons(static_cast<uint16_t>(number.length()));
    p->username_len = htons(static_cast<uint16_t>(username.length()));
    p->password_len = htons(static_cast<uint16_t>(password.length()));
    
    writePos += sizeof(SignupPayload);
    std::memcpy(data + writePos, email.c_str(), email.length());
    writePos += email.length();
    std::memcpy(data + writePos, number.c_str(), number.length());
    writePos += number.length();
    std::memcpy(data + writePos, username.c_str(), username.length());
    writePos += username.length();
    std::memcpy(data + writePos, password.c_str(), password.length());
    writePos += password.length();
    
    return finalizePacket(PKT_SIGN_UP);
}

bool Packet::serializeUserId(const uint8_t *userId, const uint8_t* serverTempId)
{
    resetWritePos();
    if (writePos + sizeof(UserIdPayload) > sizeof(data)) return false;
    
    UserIdPayload* p = reinterpret_cast<UserIdPayload*>(data + writePos);
    std::memcpy(p->server_temp_id, serverTempId, 16);
    std::memcpy(p->user_id, userId, 16);
    writePos += sizeof(UserIdPayload);
    
    return finalizePacket(PKT_USER_ID);
}

bool Packet::serializeToken(PacketType type, const std::vector<uint8_t>& accessToken, const std::vector<uint8_t>& refreshToken)
{
    resetWritePos();
    if (writePos + sizeof(TokenGrantedPayload) + accessToken.size() + refreshToken.size() > sizeof(data)) return false;
    
    TokenGrantedPayload* p = reinterpret_cast<TokenGrantedPayload*>(data + writePos);
    p->access_token_len = htons(static_cast<uint16_t>(accessToken.size()));
    p->refresh_token_len = htons(static_cast<uint16_t>(refreshToken.size()));
    
    writePos += sizeof(TokenGrantedPayload);
    std::memcpy(data + writePos, accessToken.data(), accessToken.size());
    writePos += accessToken.size();
    
    std::memcpy(data + writePos, refreshToken.data(), refreshToken.size());
    writePos += refreshToken.size();
    
    return finalizePacket(type);
}

bool Packet::serializeString(PacketType type, const std::string& str)
{
    resetWritePos();
    if (writePos + sizeof(StringPayload) + str.length() > sizeof(data)) return false;
    
    StringPayload* p = reinterpret_cast<StringPayload*>(data + writePos);
    p->str_len = htons(static_cast<uint16_t>(str.length()));
    
    writePos += sizeof(StringPayload);
    std::memcpy(data + writePos, str.c_str(), str.length());
    writePos += str.length();
    
    return finalizePacket(type);
}

bool Packet::serializeRaw(PacketType type, const std::string& rawPayload) {
    resetWritePos();
    if (writePos + rawPayload.size() > sizeof(data)) return false;
    std::memcpy(data + writePos, rawPayload.data(), rawPayload.size());
    writePos += rawPayload.size();
    return finalizePacket(type);
}
