
// ./token/userInfo.h
#pragma once
#include <cstdint>

struct userInfo {
    uint8_t user_id[16];
    char username[32];
    uint8_t password_hash[128];  // increased size for Argon2id hash compatibility
    char email[64];
    bool email_verified;
    uint8_t phone_hash[32];
    bool phone_discoverable;
    bool is_deleted = false;     // ← Soft delete flag
    uint32_t checksum = 0;       // checksum at the end
};