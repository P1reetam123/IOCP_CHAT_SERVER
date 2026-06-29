#pragma once

// ============================================================================
// auth_store.h — Thread-Safe In-Memory Authentication Stores
//
// UserStore:          Read-heavy concurrent access via std::shared_mutex.
//                     Lookups by email or username return a COPY to avoid
//                     dangling references after the lock is released.
//
// RefreshFamilyStore: Manages refresh token families for rotation and
//                     reuse detection (Step 5/6 integration).
// ============================================================================

#include "auth_types.h"
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <string>
#include <optional>
#include <cstring>
#include <sodium.h>

// ---------------------------------------------------------------------------
// UserStore — Thread-safe credential repository
// ---------------------------------------------------------------------------

class UserStore {
private:
    mutable std::shared_mutex mutex_;

    // Primary storage: hex(user_id) → UserRecord
    std::unordered_map<std::string, UserRecord> records_;

    // Secondary indexes for O(1) lookup by alternate keys
    std::unordered_map<std::string, std::string> email_to_uid_;     // email → hex(user_id)
    std::unordered_map<std::string, std::string> username_to_uid_;  // username → hex(user_id)

public:
    // Insert a new user record.
    // Returns false if the email or username already exists (duplicate check).
    bool Insert(const UserRecord& record) {
        std::unique_lock lock(mutex_);

        std::string uid_hex = ToHex(record.user_id, 16);
        std::string email_key(record.email, strnlen(record.email, sizeof(record.email)));
        std::string uname_key(record.username, strnlen(record.username, sizeof(record.username)));

        // Reject duplicate email
        if (email_to_uid_.count(email_key) > 0) {
            return false;
        }

        // Reject duplicate username (if non-empty)
        if (!uname_key.empty() && username_to_uid_.count(uname_key) > 0) {
            return false;
        }

        records_[uid_hex] = record;
        email_to_uid_[email_key] = uid_hex;
        if (!uname_key.empty()) {
            username_to_uid_[uname_key] = uid_hex;
        }

        return true;
    }

    // Look up by email address. Returns a copy for thread safety.
    std::optional<UserRecord> FindByEmail(const std::string& email) const {
        std::shared_lock lock(mutex_);

        auto it = email_to_uid_.find(email);
        if (it == email_to_uid_.end()) return std::nullopt;

        auto rec_it = records_.find(it->second);
        if (rec_it == records_.end()) return std::nullopt;

        return rec_it->second;
    }

    // Look up by username. Returns a copy for thread safety.
    std::optional<UserRecord> FindByUsername(const std::string& username) const {
        std::shared_lock lock(mutex_);

        auto it = username_to_uid_.find(username);
        if (it == username_to_uid_.end()) return std::nullopt;

        auto rec_it = records_.find(it->second);
        if (rec_it == records_.end()) return std::nullopt;

        return rec_it->second;
    }

    // Look up by 16-byte UUID. Returns a copy for thread safety.
    std::optional<UserRecord> FindByUserId(const uint8_t* user_id) const {
        std::shared_lock lock(mutex_);

        std::string uid_hex = ToHex(user_id, 16);
        auto it = records_.find(uid_hex);
        if (it == records_.end()) return std::nullopt;

        return it->second;
    }

    // Mark a user's email as verified. Returns false if user not found.
    bool SetEmailVerified(const uint8_t* user_id) {
        std::unique_lock lock(mutex_);

        std::string uid_hex = ToHex(user_id, 16);
        auto it = records_.find(uid_hex);
        if (it == records_.end()) return false;

        it->second.email_verified = true;
        return true;
    }

    // Utility: convert a byte array to a lowercase hex string.
    // Uses Libsodium's sodium_bin2hex for constant-time safety.
    static std::string ToHex(const uint8_t* data, size_t len) {
        std::string hex(len * 2, '\0');
        sodium_bin2hex(&hex[0], hex.size() + 1, data, len);
        return hex;
    }
};

// ---------------------------------------------------------------------------
// RefreshFamilyStore — Thread-safe refresh token family tracking
// ---------------------------------------------------------------------------

class RefreshFamilyStore {
private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t, RefreshFamilyRecord> families_;

public:
    // Insert a new family record.
    void Insert(const RefreshFamilyRecord& record) {
        std::unique_lock lock(mutex_);
        families_[record.family_id] = record;
    }

    // Look up a family record by family_id. Returns a copy.
    std::optional<RefreshFamilyRecord> Find(uint64_t family_id) const {
        std::shared_lock lock(mutex_);

        auto it = families_.find(family_id);
        if (it == families_.end()) return std::nullopt;

        return it->second;
    }

    // Atomically advance the token_id for a family.
    //
    // Returns true if the presented token_id matched the stored current_token_id
    // (valid rotation — the counter is incremented).
    //
    // Returns false if:
    //   - Family not found
    //   - Family already revoked
    //   - token_id mismatch (REUSE DETECTED — family is revoked)
    bool AdvanceTokenId(uint64_t family_id, uint64_t presented_token_id) {
        std::unique_lock lock(mutex_);

        auto it = families_.find(family_id);
        if (it == families_.end()) return false;

        RefreshFamilyRecord& fam = it->second;

        // Already revoked — reject
        if (fam.revoked) return false;

        // Token reuse detection: if the presented ID doesn't match,
        // an old token was replayed — revoke the entire family.
        if (fam.current_token_id != presented_token_id) {
            fam.revoked = true;
            return false;
        }

        // Valid rotation: advance the monotonic counter
        fam.current_token_id++;
        return true;
    }

    // Revoke a family (e.g., on logout or suspicious activity).
    void Revoke(uint64_t family_id) {
        std::unique_lock lock(mutex_);

        auto it = families_.find(family_id);
        if (it != families_.end()) {
            it->second.revoked = true;
        }
    }

    // Remove a family record entirely.
    void Remove(uint64_t family_id) {
        std::unique_lock lock(mutex_);
        families_.erase(family_id);
    }
};
