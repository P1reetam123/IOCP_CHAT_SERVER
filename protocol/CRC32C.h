#pragma once
#include<string>
#include <cstdint>
#include <vector>

class CRC32C {
public:
    // Compute CRC32C for a buffer
    static uint32_t compute(const void* data, size_t length, uint32_t crc = 0);

    // For std::vector<uint8_t>
    static uint32_t compute(const std::vector<uint8_t>& data, uint32_t crc = 0);

    // For string (metadata)
    static uint32_t compute(const std::string& str, uint32_t crc = 0);

private:
    static const uint32_t kCrc32cTable[256];
    
    // Hardware accelerated version (SSE4.2) if available
    static uint32_t computeHardware(const void* data, size_t length, uint32_t crc);
    static bool supportsHardwareAcceleration();
};