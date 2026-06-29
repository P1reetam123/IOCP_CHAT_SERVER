#pragma once

// ============================================================================
// AuthManager.h — Core Authentication State Engine
//
// Owns the HMAC signing keys, user store, and refresh family store.
// Processes login packets, issues stateless signed tokens, and provides
// the zero-lock hot-path session validator for per-packet auth checks.
//
// Thread Safety:
//   - All data stores use std::shared_mutex (read-heavy optimization).
//   - The signing key is write-once at construction, read-only thereafter.
//   - The hot-path validator uses only atomic loads (no locks at all).
// ============================================================================

#include "auth_types.h"
#include "auth_store.h"
#include "../session/Session.h"
#include <atomic>
#include <cstdint>
#include <ctime>

class Packet;
class MessageRouter;
template <typename T> class table;
struct userInfo;

class AuthManager {
private:
    // HMAC signing key for token authentication (crypto_auth).
    // Generated once at construction via crypto_auth_keygen.
    // Wiped from memory on destruction via sodium_memzero.
    uint8_t signing_key_[crypto_auth_KEYBYTES];

    // Pre-computed valid Argon2id hash for timing attack mitigation.
    // When a user lookup fails, we verify the supplied password against this
    // dummy hash so the response time is indistinguishable from a real
    // password check. This prevents username/email enumeration.
    char dummy_hash_[crypto_pwhash_STRBYTES];

    // Thread-safe data stores
    UserStore user_store_;
    RefreshFamilyStore family_store_;

    // Monotonic family ID generator (atomic for thread-safe increment)
    std::atomic<uint64_t> next_family_id_{1};

    // Token lifetimes (seconds)
    static constexpr uint64_t ACCESS_TOKEN_LIFETIME  = 900;      // 15 minutes
    static constexpr uint64_t REFRESH_TOKEN_LIFETIME = 2592000;  // 30 days

    // Router for sending response packets back to the client
    MessageRouter* router_ = nullptr;

public:
    AuthManager();
    ~AuthManager();

    // Non-copyable, non-movable (holds raw cryptographic key material)
    AuthManager(const AuthManager&) = delete;
    AuthManager& operator=(const AuthManager&) = delete;

    // Dependency injection
    void SetRouter(MessageRouter* router) { router_ = router; }

    // -------------------------------------------------------------------
    // Packet handlers — called from MessageRouter dispatch
    // -------------------------------------------------------------------

    // Handle PKT_LOGIN: email/username + password → verify → issue tokens
    void HandleLoginPacket(Packet* packet, Session* sender);

    // Handle PKT_TOKEN: reconnect with a saved access token
    void HandleTokenPacket(Packet* packet, Session* sender);

    // Handle PKT_REFRESH: refresh token rotation (Step 5 integration point)
    void HandleRefreshPacket(Packet* packet, Session* sender);

    // -------------------------------------------------------------------
    // User registration — called from the signup flow
    // -------------------------------------------------------------------

    // Register a new user with Argon2id password hashing.
    AuthResult RegisterUser(const std::string& username,
                            const std::string& password,
                            const std::string& email);

    // Mark a user's email as verified (called after OTP confirmation).
    bool VerifyUserEmail(const uint8_t* user_id);

    // Synchronize and load persistent users from the disk database
    void LoadUsersFromDatabase(table<userInfo>& db);

    // Directly insert a UserRecord into the in-memory store
    bool AddUserRecord(const UserRecord& record);

    // -------------------------------------------------------------------
    // Build and send a PKT_AUTH_FAIL response packet
    void SendAuthFailure(Session* sender, const std::string& reason);

    // Build and send a PKT_TOKEN_GRANTED response packet with both tokens
    void SendTokenGranted(Session* sender, const LoginResult& tokens);

    // Zero-Lock Hot-Path Validator (declaration)
    // -------------------------------------------------------------------
    //
    // Full implementation is below, outside the class body, to allow
    // force-inlining with platform-specific attributes.
    //
    // This is the ONLY auth check that runs on every inbound packet after
    // the initial login. It performs:
    //   1. Atomic load of auth_state   → integer compare
    //   2. Atomic load of cached_expiry → integer compare against time()
    //
    // NO cryptographic operations. NO mutex locks. NO heap allocations.
    // NO database lookups. Pure register-level integer arithmetic.
    // -------------------------------------------------------------------
    static bool ValidateSessionHotPath(const Session* session);

    // Utility: convert 16-byte UUID to hex string
    static std::string UserIdToHexString(const uint8_t* user_id);

private:
    // Core login pipeline: verify credentials, issue tokens, cache on session
    AuthResult ProcessLogin(const std::string& identifier,
                            const std::string& password,
                            Session* session);

    // Generate a signed access + refresh token pair for the given user_id
    LoginResult IssueTokenPair(const uint8_t* user_id);

    // Cryptographically verify an access token's signature and check expiry
    bool ValidateAccessToken(const uint8_t* token_data, size_t len,
                             AccessTokenPayload& out_payload);

    // Cryptographically verify a refresh token's signature and check expiry
    bool ValidateRefreshToken(const uint8_t* token_data, size_t len,
                              RefreshTokenPayload& out_payload);

    // Cache authentication state directly onto the IOCP session context.
    // Uses acquire/release ordering to ensure cached_user_id and cached_expiry
    // are visible to any thread that subsequently reads auth_state == AUTHENTICATED.
    void CacheAuthOnSession(Session* session, const uint8_t* user_id,
                            uint64_t expiry);
};


// ===========================================================================
// Inline Implementation — ValidateSessionHotPath
//
// Force-inlined so the compiler can embed this directly into the IOCP
// worker thread's packet-processing loop. On x86-64 this compiles to
// approximately 3-5 instructions (two atomic loads + two integer compares
// + one time() call).
// ===========================================================================

#ifdef _MSC_VER
  __forceinline
#else
  inline __attribute__((always_inline))
#endif
bool AuthManager::ValidateSessionHotPath(const Session* session) {
    // Step 1: Check if the session has been authenticated.
    // acquire ordering guarantees we see the cached_user_id and cached_expiry
    // that were written before auth_state was set to AUTHENTICATED.
    int state = session->auth_state.load(std::memory_order_acquire);
    if (state != static_cast<int>(AuthSessionState::AUTHENTICATED)) {
        return false;
    }

    // Step 2: Check if the cached access token expiry has not elapsed.
    // relaxed ordering is sufficient here — the value is monotonic and
    // the worst case is a single stale read that causes one extra crypto
    // validation cycle (harmless).
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    uint64_t expiry = session->cached_expiry.load(std::memory_order_relaxed);

    return now < expiry;
}
