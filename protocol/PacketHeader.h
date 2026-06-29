#pragma once
#include <cstdint>

#pragma pack(push, 1)
struct PacketHeader
{
    uint32_t size = 0;
    uint8_t type = 0;
};
#pragma pack(pop)

// Wire format: [4 bytes size][1 byte type][payload...]
// size = total packet length including header (5 bytes) + payload
constexpr int HEADER_SIZE = 5;