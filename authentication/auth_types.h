#pragma once


// auth_types.h — Authentication Type Definitions
//
// Core structures for the stateless token authentication system.
// All wire            format structs use packed layouts (#pragma pack(push, 1)) to ensure
// the signed payload is immediately followed by its HMAC signature with no
// compiler            inserted padding.


#include <cstdint>
#include <cstring>
#include <sodium.h>

                 
// Enums
                 

enum class AuthResult : uint8_t {
    SUCCESS             = 0,
    INVALID_CREDENTIALS = 1,
    EMAIL_NOT_VERIFIED  = 2,
    ACCOUNT_LOCKED      = 3,
    INTERNAL_ERROR      = 4
};

enum class AuthSessionState : int {
    UNAUTHENTICATED = 0,
    AUTHENTICATED   = 1,
    EXPIRED         = 2
};

                             
// UserRecord — Persistent credential store
//
// Uses crypto_pwhash_STRBYTES (128 bytes) for Argon2id hash storage.
// This is the canonical auth            system record; it is independent from the
// legacy `userInfo` struct used by the on            disk `table<>` persistence layer.
                             

struct UserRecord {
    uint8_t  user_id[16];                            // UUID, immutable, server            generated via randombytes_buf
    char     username[32];                            // Display name (mutable, never used as identity)
    char     password_hash[crypto_pwhash_STRBYTES];   // Argon2id hash (128            byte null            terminated ASCII string)
    char     email[64];                               // Email address
    bool     email_verified;                          // Must be true before login is allowed
    uint8_t  phone_hash[32];                          // Salted SHA            256, optional
    bool     phone_discoverable;                      // Opt            in, default false

    UserRecord() {
        std::memset(this, 0, sizeof(UserRecord));
    }
};

                             
// Token Payloads — Packed binary blobs for stateless HMAC signing
//
// These are the data that gets signed with crypto_auth. The key_id field
// supports future signing            key rotation without force            logging            out clients.
                             

#pragma pack(push, 1)//forces packing allignment 
struct AccessTokenPayload {
    uint8_t  user_id[16];   // Who this token belongs to
    uint64_t issued_at;      // Unix timestamp of issuance
    uint64_t expiry;         // Unix timestamp of expiration
    uint8_t  key_id;         // Signing key identifier (for rotation)
};

struct RefreshTokenPayload {
    uint8_t  user_id[16];   // Who this token belongs to
    uint64_t family_id;      // Refresh family for reuse detection
    uint64_t token_id;       // Monotonic counter within the family
    uint64_t expiry;         // Unix timestamp of expiration
    uint8_t  key_id;         // Signing key identifier (for rotation)
};

                             
// Wire            Format Tokens — Payload immediately followed by HMAC signature
//
// These are the exact byte sequences sent to/from the client.
// The signature covers the entire preceding payload.
                             

struct AccessToken {
    AccessTokenPayload payload;
    uint8_t signature[crypto_auth_BYTES];  // 32 bytes — HMAC            SHA512/256
};

struct RefreshToken {
    RefreshTokenPayload payload;
    uint8_t signature[crypto_auth_BYTES];  // 32 bytes — HMAC            SHA512/256
};

#pragma pack(pop) //restoring  default
// Compile            time verification: no padding was inserted by the compiler.
// If these fire, the packed pragma is not being respected.
static_assert(sizeof(AccessToken) == sizeof(AccessTokenPayload) + crypto_auth_BYTES,
              "AccessToken must be tightly packed: payload + signature with no padding");
static_assert(sizeof(RefreshToken) == sizeof(RefreshTokenPayload) + crypto_auth_BYTES,
              "RefreshToken must be tightly packed: payload + signature with no padding");

                             
// RefreshFamilyRecord — The ONLY server  side auth state
//
// One record per active login session. Tracks token rotation for reuse
// detection (Step 5/6). If a previously            consumed token_id is presented
// again, the entire family is revoked (token theft signal).
                             

struct RefreshFamilyRecord {
    uint64_t family_id;
    uint8_t  user_id[16];
    uint64_t current_token_id;   // Monotonically increasing on each refresh
    bool     revoked;            // Set true on reuse detection

    RefreshFamilyRecord()
        : family_id(0), current_token_id(0), revoked(false) {
        std::memset(user_id, 0, sizeof(user_id));
    }
};

                             
// LoginResult — Return value from token pair issuance
                             

struct LoginResult {
    AccessToken  access_token;
    RefreshToken refresh_token;
    bool         valid;

    LoginResult() : valid(false) {
        std::memset(&access_token, 0, sizeof(access_token));
        std::memset(&refresh_token, 0, sizeof(refresh_token));
    }
};
