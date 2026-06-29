#pragma once
#include "AuthManager.h"
#include "../protocol/Packet.h"
#include "../protocol/PacketTypes.h"
#include "../chat/MessageRouter.h"
#include "../pool/PacketPool.h"
#include "../utils/Logger.h"
#include <cstring>
#include <ctime>
#include <sstream>
#include <sodium.h>
#include "../datastructure/table.h"
#include "../token/userInfo.h"

#include <cstddef>
#include <type_traits>

static_assert(std::is_trivially_copyable<AccessToken>::value,
              "AccessToken must be trivially copyable to go over the wire");
static_assert(std::is_trivially_copyable<RefreshToken>::value,
              "RefreshToken must be trivially copyable to go over the wire");

constexpr std::size_t kAccessTokenSize        = sizeof(AccessToken);
constexpr std::size_t kRefreshTokenSize       = sizeof(RefreshToken);
constexpr std::size_t kTokenGrantedPayloadLen = kAccessTokenSize + kRefreshTokenSize;
// ============================================================================
// Constructor / Destructor
// ============================================================================

AuthManager::AuthManager() {
    // Initialize Libsodium (idempotent — safe to call multiple times).
    // Returns 0 on success, 1 if already initialized, -1 on failure.
    if (sodium_init() < 0) {
        Logger::error("[AUTH] FATAL: Libsodium initialization failed");
    }

    // Generate the HMAC signing key for token authentication.
    // This key is held in memory for the lifetime of the server process.
    // In a production deployment, this would be loaded from a secure key
    // store (e.g., HSM, vault) and support rotation via the key_id field.
    crypto_auth_keygen(signing_key_);
    Logger::info("[AUTH] HMAC signing key generated (key_id=0)");

    // -----------------------------------------------------------------------
    // Timing Attack Mitigation — Pre-compute a dummy Argon2id hash
    //
    // When a login attempt targets a non-existent user, we MUST still execute
    // a full Argon2id verification cycle against a valid hash. Without this,
    // an attacker could enumerate valid usernames/emails by measuring the
    // response time difference between "user not found" (fast) and "wrong
    // password" (slow due to Argon2id).
    //
    // By verifying against this pre-computed dummy hash for missing users,
    // both code paths take approximately the same wall-clock time.
    // -----------------------------------------------------------------------
    const char* dummy_password = "timing_attack_mitigation_dummy_v1";
    if (crypto_pwhash_str(
            dummy_hash_,
            dummy_password,
            strlen(dummy_password),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        Logger::error("[AUTH] FATAL: Failed to generate dummy Argon2id hash "
                      "(out of memory for Argon2id arena?)");
        std::memset(dummy_hash_, 0, sizeof(dummy_hash_));
    }
    Logger::info("[AUTH] Timing-attack mitigation hash pre-computed");
    Logger::info("[AUTH] AuthManager initialized successfully");
}

AuthManager::~AuthManager() {
    // Securely wipe all key material from memory.
    // sodium_memzero is guaranteed not to be optimized away by the compiler.
    sodium_memzero(signing_key_, sizeof(signing_key_));
    sodium_memzero(dummy_hash_, sizeof(dummy_hash_));
    Logger::info("[AUTH] Key material securely wiped from memory");
}

// ============================================================================
// Packet Handlers — Called from MessageRouter dispatch
// ============================================================================

void AuthManager::HandleLoginPacket(Packet* packet, Session* sender) {
    // Parse the packet payload.
    // Wire format: "senderId receiverId email password"
    // After parseHeader() (called during network read), payload contains "email password"
 packet->parseData();
    std::istringstream iss(packet->payload);
    std::string identifier, password;
    iss >> identifier >> password;

    // Return the packet to the pool immediately — we've extracted what we need.
    // This minimizes pool pressure under load.
    PacketPool::Instance().returnPacket(packet);

    // Validate input presence
    if (identifier.empty() || password.empty()) {
        Logger::debug("[AUTH] Login rejected: missing credentials");
        SendAuthFailure(sender, "Missing credentials");
        return;
    }

    // Execute the full login pipeline (timing-safe, with dummy hash on miss)
    AuthResult result = ProcessLogin(identifier, password, sender);

    // ProcessLogin already sent the appropriate response packet
    // (PKT_TOKEN_GRANTED on success, PKT_AUTH_FAIL on any failure).
    // The result is used here only for logging at the call site if needed.
    (void)result;
}

void AuthManager::HandleTokenPacket(Packet* packet, Session* sender) {
    // PKT_TOKEN: Client reconnecting with a saved access token.
    // The payload contains the raw binary AccessToken bytes.
//  packet->parseData();
    const uint8_t* token_data =
        reinterpret_cast<const uint8_t*>(packet->data+HEADER_SIZE);
    size_t token_len = packet->header.size - HEADER_SIZE;

    AccessTokenPayload verified_payload;
    bool valid = ValidateAccessToken(token_data, token_len, verified_payload);

    PacketPool::Instance().returnPacket(packet);

    if (!valid) {
        SendAuthFailure(sender, "Invalid or expired access token");
        return;
    }

    // Token signature and expiry verified — cache the auth state on the session.
    CacheAuthOnSession(sender, verified_payload.user_id, verified_payload.expiry);

    // Set the session userId for SessionManager routing compatibility.
    sender->userId = UserIdToHexString(verified_payload.user_id);

    Logger::info("[AUTH] Token reconnect successful for user " + sender->userId);

    // Issue a fresh token pair for the reconnecting client.
    LoginResult tokens = IssueTokenPair(verified_payload.user_id);
    if (tokens.valid) {
        SendTokenGranted(sender, tokens);
    } else {
        SendAuthFailure(sender, "Token generation failed");
    }
}

void AuthManager::HandleRefreshPacket(Packet* packet, Session* sender) {
    // PKT_REFRESH: Client requesting new tokens using their refresh token.
    // This is the primary integration point for Step 5 (rotation + reuse detection).
 packet->parseData();
    const uint8_t* token_data =
        reinterpret_cast<const uint8_t*>(packet->payload.data());
    size_t token_len = packet->payload.size();

    RefreshTokenPayload verified_payload;
    bool valid = ValidateRefreshToken(token_data, token_len, verified_payload);

    PacketPool::Instance().returnPacket(packet);

    if (!valid) {
        SendAuthFailure(sender, "Invalid or expired refresh token");
        return;
    }

    // Verify the family record and atomically advance the token counter.
    // If the presented token_id doesn't match the stored current_token_id,
    // this indicates token theft (reuse detection) and the family is revoked.
    bool family_valid = family_store_.AdvanceTokenId(
        verified_payload.family_id, verified_payload.token_id);

    if (!family_valid) {
        Logger::warn("[AUTH] Refresh token reuse detected for family " +
                     std::to_string(verified_payload.family_id) +
                     " — revoking and forcing re-login");

        // Invalidate the session immediately
        sender->auth_state.store(
            static_cast<int>(AuthSessionState::UNAUTHENTICATED),
            std::memory_order_release);
        sender->cached_expiry.store(0, std::memory_order_release);

        SendAuthFailure(sender, "Refresh token revoked — re-login required");
        return;
    }

    // Valid rotation — issue a fresh token pair
    LoginResult tokens = IssueTokenPair(verified_payload.user_id);
    if (!tokens.valid) {
        SendAuthFailure(sender, "Token generation failed");
        return;
    }

    // Update the session cache with the new access token's expiry
    CacheAuthOnSession(sender, verified_payload.user_id,
                       tokens.access_token.payload.expiry);

    sender->userId = UserIdToHexString(verified_payload.user_id);

    Logger::info("[AUTH] Token refresh successful for user " + sender->userId);
    SendTokenGranted(sender, tokens);
}

// ============================================================================
// User Registration
// ============================================================================

AuthResult AuthManager::RegisterUser(const std::string& username,
                                     const std::string& password,
                                     const std::string& email) {
    UserRecord record;

    // Generate a cryptographically random 16-byte UUID for the user_id.
    // randombytes_buf uses the OS CSPRNG (CryptGenRandom on Windows).
    randombytes_buf(record.user_id, sizeof(record.user_id));

    // Copy username (safe truncation)
    size_t uname_len = std::min(username.size(), sizeof(record.username) - 1);
    std::memcpy(record.username, username.c_str(), uname_len);
    record.username[uname_len] = '\0';

    // Copy email (safe truncation)
    size_t email_len = std::min(email.size(), sizeof(record.email) - 1);
    std::memcpy(record.email, email.c_str(), email_len);
    record.email[email_len] = '\0';

    // Hash the password with Argon2id via Libsodium.
    // OPSLIMIT_INTERACTIVE and MEMLIMIT_INTERACTIVE provide a reasonable
    // balance of security and latency for interactive login flows.
    // The result is a 128-byte null-terminated ASCII string stored directly
    // in the UserRecord's password_hash field.
    if (crypto_pwhash_str(
            record.password_hash,
            password.c_str(),
            password.size(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        Logger::error("[AUTH] Argon2id hashing failed for registration "
                      "(out of memory for Argon2id arena?)");
        return AuthResult::INTERNAL_ERROR;
    }

    // New accounts require email verification before login
    record.email_verified = false;
    record.phone_discoverable = false;
    std::memset(record.phone_hash, 0, sizeof(record.phone_hash));

    // Attempt insertion (checks for duplicate email/username)
    if (!user_store_.Insert(record)) {
        Logger::warn("[AUTH] Registration rejected: duplicate email or username "
                     "(email=" + email + ", username=" + username + ")");
        return AuthResult::INVALID_CREDENTIALS;
    }

    // Securely wipe the plaintext password from the record's stack frame
    sodium_memzero(record.password_hash, sizeof(record.password_hash));

    Logger::info("[AUTH] User registered: " + username + " (" + email + ")");
    return AuthResult::SUCCESS;
}

bool AuthManager::VerifyUserEmail(const uint8_t* user_id) {
    return user_store_.SetEmailVerified(user_id);
}


// Core Login Pipeline


AuthResult AuthManager::ProcessLogin(const std::string& identifier,
                                     const std::string& password,
                                     Session* session) {
   
    // Step 1: Look up the user by email 
           //      If not found by email, try username as a fallback.
    
    std::optional<UserRecord> record_opt = user_store_.FindByEmail(identifier);

    if (!record_opt.has_value()) {
        record_opt = user_store_.FindByUsername(identifier);
    }

 
    // Step 2: Timing Attack Mitigation
    //
    // If the user doesn't exist, we MUST still execute a full Argon2id
    // verification cycle against our pre-computed dummy hash. This ensures
    // the response time is statistically indistinguishable from a failed
    // password attempt on a real account.
    //
    // Without this, an attacker could enumerate valid usernames/emails by
    // measuring response latencies:
    //   - "User not found" → fast response (no Argon2id)
    //   - "Wrong password" → slow response (Argon2id verification)
    
    if (!record_opt.has_value()) {
        // Execute the dummy verification cycle (result is always failure,
        // but the timing matches a real verification)
        int dummy_res = crypto_pwhash_str_verify(
            dummy_hash_,
            password.c_str(),
            password.size());
        (void)dummy_res;

        Logger::debug("[AUTH] Login failed: user not found "
                      "(identifier=" + identifier + ", timing-mitigated)");
        SendAuthFailure(session, "Invalid credentials");
        return AuthResult::INVALID_CREDENTIALS;
    }

    const UserRecord& record = record_opt.value();

   
    // Step 3: Check email verification status
   
    if (!record.email_verified) {
        // Still need to run a dummy verify to prevent timing leakage
        // that distinguishes "unverified" from "wrong password"
        int dummy_res = crypto_pwhash_str_verify(
            dummy_hash_,
            password.c_str(),
            password.size());
        (void)dummy_res;

        Logger::debug("[AUTH] Login rejected: email not verified "
                      "(identifier=" + identifier + ")");
        SendAuthFailure(session, "Email not verified");
        return AuthResult::EMAIL_NOT_VERIFIED;
    }

    // Step 4: Verify the password against the stored Argon2id hash
   
    if (crypto_pwhash_str_verify(
            record.password_hash,
            password.c_str(),
            password.size()) != 0) {
        Logger::debug("[AUTH] Login failed: wrong password "
                      "(identifier=" + identifier + ")");
        SendAuthFailure(session, "Invalid credentials");
        return AuthResult::INVALID_CREDENTIALS;
    }

 
    // Step 5: Password verified — issue the token pair
    
    LoginResult tokens = IssueTokenPair(record.user_id);
    if (!tokens.valid) {
        Logger::error("[AUTH] Token issuance failed for user "
                      "(identifier=" + identifier + ")");
        SendAuthFailure(session, "Internal error");
        return AuthResult::INTERNAL_ERROR;
    }

    // Step 6: Create a refresh family record for reuse detection
    
    RefreshFamilyRecord family;
    family.family_id = tokens.refresh_token.payload.family_id;
    std::memcpy(family.user_id, record.user_id, 16);
    family.current_token_id = 1;
    family.revoked = false;
    family_store_.Insert(family);

  
    // Step 7: Cache auth state on the IOCP session (zero-lock hot path)
    //
    // After this point, every subsequent packet on this session will be
    // validated by ValidateSessionHotPath — a pure integer compare with
    // no locks, no crypto, and no database lookups.
  
    CacheAuthOnSession(session, record.user_id,
                       tokens.access_token.payload.expiry);


    // Step 8: Set session userId for SessionManager routing compatibility
    //
    // The existing SessionManager uses string-keyed maps. We convert the
    // 16-byte UUID to a 32-character hex string for compatibility.
   
    session->userId = UserIdToHexString(record.user_id);

    Logger::info("[AUTH] Login successful: " + session->userId +
                 " (identifier=" + identifier + ")");


    // Step 9: Send the token pair to the client
    
    SendTokenGranted(session, tokens);

    return AuthResult::SUCCESS;
}


// Token Issuance — Stateless Signed Binary Blobs


LoginResult AuthManager::IssueTokenPair(const uint8_t* user_id) {
    LoginResult result;

    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    // --- Access Token ---
    AccessTokenPayload& ap = result.access_token.payload;
    std::memcpy(ap.user_id, user_id, 16);
    ap.issued_at = now;
    ap.expiry    = now + ACCESS_TOKEN_LIFETIME;
    ap.key_id    = 0; // Current signing key

    // Sign the access token payload with HMAC-SHA512/256.
    // crypto_auth produces a crypto_auth_BYTES (32-byte) tag that
    // authenticates the payload under our symmetric signing key.
    if (crypto_auth(
            result.access_token.signature,
            reinterpret_cast<const unsigned char*>(&ap),
            sizeof(AccessTokenPayload),
            signing_key_) != 0) {
        Logger::error("[AUTH] crypto_auth failed for access token");
        result.valid = false;
        return result;
    }

    // --- Refresh Token ---
    uint64_t family_id =
        next_family_id_.fetch_add(1, std::memory_order_relaxed);

    RefreshTokenPayload& rp = result.refresh_token.payload;
    std::memcpy(rp.user_id, user_id, 16);
    rp.family_id = family_id;
    rp.token_id  = 1; // First token in the family
    rp.expiry    = now + REFRESH_TOKEN_LIFETIME;
    rp.key_id    = 0; // Current signing key

    // Sign the refresh token payload
    if (crypto_auth(
            result.refresh_token.signature,
            reinterpret_cast<const unsigned char*>(&rp),
            sizeof(RefreshTokenPayload),
            signing_key_) != 0) {
        Logger::error("[AUTH] crypto_auth failed for refresh token");
        result.valid = false;
        return result;
    }

    result.valid = true;
    return result;
}


// Token Validation — Cryptographic Signature + Expiry Verification


bool AuthManager::ValidateAccessToken(const uint8_t* token_data, size_t len,
                                      AccessTokenPayload& out_payload) {
    // Verify exact size match (no truncation or padding)
    if (len != sizeof(AccessToken)) {
        Logger::debug("[AUTH] Access token size mismatch: expected=" +
                      std::to_string(sizeof(AccessToken)) +
                      " got=" + std::to_string(len));
        return false;
    }

    const AccessToken* token =
        reinterpret_cast<const AccessToken*>(token_data);

    // Verify the HMAC signature (constant-time comparison internally).
    // crypto_auth_verify returns 0 on success, -1 on failure.
    if (crypto_auth_verify(
            token->signature,
            reinterpret_cast<const unsigned char*>(&token->payload),
            sizeof(AccessTokenPayload),
            signing_key_) != 0) {
        Logger::debug("[AUTH] Access token signature verification failed");
        return false;
    }

    // Verify the token hasn't expired
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    if (now >= token->payload.expiry) {
        Logger::debug("[AUTH] Access token expired (now=" +
                      std::to_string(now) + " expiry=" +
                      std::to_string(token->payload.expiry) + ")");
        return false;
    }

    // Verify key_id matches our current signing key
    if (token->payload.key_id != 0) {
        Logger::debug("[AUTH] Access token key_id mismatch: " +
                      std::to_string(token->payload.key_id));
        return false;
    }

    out_payload = token->payload;
    return true;
}

bool AuthManager::ValidateRefreshToken(const uint8_t* token_data, size_t len,
                                       RefreshTokenPayload& out_payload) {
    // Verify exact size match
    if (len != sizeof(RefreshToken)) {
        Logger::debug("[AUTH] Refresh token size mismatch: expected=" +
                      std::to_string(sizeof(RefreshToken)) +
                      " got=" + std::to_string(len));
        return false;
    }

    const RefreshToken* token =
        reinterpret_cast<const RefreshToken*>(token_data);

    // Verify the HMAC signature (constant-time comparison internally)
    if (crypto_auth_verify(
            token->signature,
            reinterpret_cast<const unsigned char*>(&token->payload),
            sizeof(RefreshTokenPayload),
            signing_key_) != 0) {
        Logger::debug("[AUTH] Refresh token signature verification failed");
        return false;
    }

    // Verify the token hasn't expired
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    if (now >= token->payload.expiry) {
        Logger::debug("[AUTH] Refresh token expired (now=" +
                      std::to_string(now) + " expiry=" +
                      std::to_string(token->payload.expiry) + ")");
        return false;
    }

    // Verify key_id
    if (token->payload.key_id != 0) {
        Logger::debug("[AUTH] Refresh token key_id mismatch: " +
                      std::to_string(token->payload.key_id));
        return false;
    }

    out_payload = token->payload;
    return true;
}


// Session Cache — Write auth state onto the IOCP session context


void AuthManager::CacheAuthOnSession(Session* session,
                                     const uint8_t* user_id,
                                     uint64_t expiry) {
    // Copy the 16-byte user_id to the session's cache.
    // This is a non-atomic write, but it happens BEFORE the release-store
    // to auth_state, so any thread that reads auth_state == AUTHENTICATED
    // (with acquire ordering) is guaranteed to see this value.
    std::memcpy(session->cached_user_id, user_id, 16);

    // Store the expiry timestamp (atomic).
    // relaxed ordering is acceptable because the release-store to auth_state
    // below provides the necessary visibility guarantee.
    session->cached_expiry.store(expiry, std::memory_order_relaxed);

    // Set the auth state LAST with release ordering.
    // This is the publication barrier: it ensures that cached_user_id and
    // cached_expiry are fully visible to any thread that subsequently reads
    // auth_state == AUTHENTICATED with acquire ordering (which is exactly
    // what ValidateSessionHotPath does).
    session->auth_state.store(
        static_cast<int>(AuthSessionState::AUTHENTICATED),
        std::memory_order_release);
}


// Response Packet Builders


void AuthManager::SendAuthFailure(Session* sender, const std::string& reason) {
    if (!sender || !sender->iocp) {
        Logger::error("[AUTH] Cannot send auth failure: null session or IOCP");
        return;
    }

    Packet* response = PacketPool::Instance().borrowPacket();
    if (!response) {
        Logger::error("[AUTH] Failed to borrow packet for PKT_AUTH_FAIL");
        return;
    }

    // Use the session's current userId (may be empty for unauthenticated sessions)
    std::string receiver_id = sender->userId.empty() ? "PENDING" : sender->userId;

    response->serialize(
        PKT_AUTH_FAIL,
        "SERVER",
        receiver_id,
        reason);

    sender->sendPacket(response);
}

void AuthManager::SendTokenGranted(Session* sender, const LoginResult& tokens) {
    if (!sender || !sender->iocp) {
        Logger::error("[AUTH] Cannot send token granted: null session or IOCP");
        return;
    }

    Packet* response = PacketPool::Instance().borrowPacket();
    if (!response) {
        Logger::error("[AUTH] Failed to borrow packet for PKT_TOKEN_GRANTED");
        return;
    }

    // Build the binary payload: [AccessToken bytes][RefreshToken bytes]
    // Both are packed structs with compile-time-known sizes, so the client
    // can split them deterministically.
    std::string binary_payload;
    binary_payload.resize(sizeof(AccessToken) + sizeof(RefreshToken));

    std::memcpy(&binary_payload[0],
                &tokens.access_token,
                sizeof(AccessToken));

    std::memcpy(&binary_payload[sizeof(AccessToken)],
                &tokens.refresh_token,
                sizeof(RefreshToken));
// send the acces token and refresh token
    response->serialize(
        PKT_TOKEN_GRANTED,
        "",
        "",
        binary_payload);

    sender->sendPacket(response); // it is boolfunction  so check whether it has been sent or not 
}

//utility

std::string AuthManager::UserIdToHexString(const uint8_t* user_id) {
    return UserStore::ToHex(user_id, 16);
}

void AuthManager::LoadUsersFromDatabase(table<userInfo>& db) {
    std::vector<userInfo> dbRecords = db.getAllRecords();
    size_t loadedCount = 0;
    for (const auto& u : dbRecords) {
        UserRecord ur;
        std::memcpy(ur.user_id, u.user_id, 16);
        std::memcpy(ur.username, u.username, sizeof(ur.username));
        // Use min to prevent buffer overrun and ensure null termination if password_hash in db doesn't fill the buffer
        std::memcpy(ur.password_hash, u.password_hash, std::min(sizeof(ur.password_hash), sizeof(u.password_hash)));
        ur.password_hash[sizeof(ur.password_hash) - 1] = '\0';
        std::memcpy(ur.email, u.email, sizeof(ur.email));
        ur.email_verified = u.email_verified;
        std::memcpy(ur.phone_hash, u.phone_hash, sizeof(ur.phone_hash));
        ur.phone_discoverable = u.phone_discoverable;

        if (user_store_.Insert(ur)) {
            loadedCount++;
        }
    }
    Logger::info("[AUTH] Loaded " + std::to_string(loadedCount) + " persistent users from disk database");
}

bool AuthManager::AddUserRecord(const UserRecord& record) {
    return user_store_.Insert(record);
}
