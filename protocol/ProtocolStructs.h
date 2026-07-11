#pragma once
#include <cstdint>
#include "PacketHeader.h"
#include "PacketTypes.h"

#pragma pack(push, 1)

struct ChatMessagePayload {
    uint8_t sender_id[16];
    uint8_t receiver_id[16];
    uint64_t timestamp;
    uint32_t message_number;
    uint16_t username_len;
    uint16_t text_len;
    // followed by username_len bytes of username
    // followed by text_len bytes of text
};

struct FileStartPayload {
    uint8_t receiver_id[16];
    uint8_t upload_id[16];
    uint64_t total_size;
    uint32_t final_crc;
    uint16_t filename_len;
    // followed by filename_len bytes
};

struct FileStartResponsePayload {
    uint8_t upload_id[16];
    uint64_t resume_offset;
};

struct FileChunkPayload {
    uint8_t upload_id[16];
    uint64_t byte_offset;
    uint32_t chunk_size;
    uint32_t chunk_crc;
    // followed by chunk_size bytes
};

struct RoundEndPayload {
    uint8_t upload_id[16];
    uint32_t round_id;
    uint32_t chunk_count;
};

struct FileAckPayload {
    uint8_t upload_id[16];
    uint32_t round_id;
    uint32_t missing_count;
    // followed by missing_count * sizeof(uint32_t)
};

struct FileEndPayload {
    uint8_t upload_id[16];
    uint32_t final_crc;
};

struct LoginPayload {
    uint16_t identifier_len;
    uint16_t password_len;
    // followed by identifier_len + password_len bytes
};

struct SignupPayload {
    uint16_t email_len;
    uint16_t number_len;
    uint16_t username_len;
    uint16_t password_len;
    // followed by the string bytes in order
};

struct OtpReqPayload {
    uint16_t email_len;
    // followed by email
};

struct OtpVerifyPayload {
    uint16_t email_len;
    uint16_t otp_len;
    // followed by email, then otp
};

struct UserIdPayload {
    uint8_t server_temp_id[16];
    uint8_t user_id[16];
};

struct DownloadLinkPayload {
    uint8_t sender_id[16];
    uint8_t upload_id[16];
    uint32_t total_size;
    uint16_t filename_len;
    uint16_t timestamp_len;
    // followed by filename, then timestamp
};

struct DownloadReqPayload {
    uint8_t user_id[16];
    uint8_t upload_id[16];
    uint32_t bytes_requested;
};

struct StringPayload {
    uint16_t str_len;
    // followed by str_len bytes
};

struct TokenGrantedPayload {
    uint16_t access_token_len;
    uint16_t refresh_token_len;
    // followed by access token bytes, then refresh token bytes
};

#pragma pack(pop)
