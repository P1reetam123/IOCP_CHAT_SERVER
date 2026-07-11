#pragma once
#include <cstdint>

#pragma pack(push, 1)
struct PacketHeader
{
    uint8_t magic;           // 0xD5
    uint8_t version;         // 0x01
    uint16_t type;           // PacketType (network byte order)
    uint32_t payload_length; // Size of payload (network byte order)
    uint32_t sequence_number;// Sequence (network byte order)
    uint32_t checksum;       // CRC32C of header + payload (network byte order)
};
#pragma pack(pop)

constexpr int HEADER_SIZE = 16;
constexpr uint8_t START_BYTE = 0xD5;
constexpr uint8_t CURRENT_VERSION = 0x01;
constexpr int UUID_SIZE = 16;
constexpr int NUMBER_SIZE = 4;
constexpr int TIME_STAMP_SIZE = 8;
constexpr int CHECK_SUM_SIZE = 4;