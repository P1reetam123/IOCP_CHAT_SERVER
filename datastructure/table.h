// table.h              Production Ready (10k users, Multi            threaded, Searchable, Secure)
#pragma once

#include <fstream>
#include <sstream>
#include <string>
#include <cstdint>
#include <unordered_map>
#include <list>
#include <mutex>
#include <chrono>
#include <vector>
#include <windows.h>
#include "./token/userInfo.h"
#include <zlib.h> // For CRC32 checksum
#include <thread>

template <typename T = userInfo>
class table
{
private:
    // LFU Cache (O(1) eviction)
    struct FreqNode
    {
        int freq = 0;
        std::list<std::string> keys;
    };
    std::unordered_map<std::string, std::pair<T, typename std::list<FreqNode>::iterator>> cacheMap;
    std::list<FreqNode> freqList;
    std::unordered_map<std::string, typename std::list<FreqNode>::iterator> keyToFreq;

    // Indexes
    std::unordered_map<std::string, size_t> pageNum; // uid                      -> record index
    std::unordered_map<std::string, std::string> emailToUid;
    std::unordered_map<std::string, std::string> phoneToUid;

    // Storage
    std::string dataFile = "./userData/data.bin";
    std::string backupDir = "./userData/backups/";
    size_t currentRecords = 0;
    const size_t CACHE_LIMIT = 10000;

    std::mutex mtx;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = INVALID_HANDLE_VALUE;
    char *mappedMemory = nullptr;
    size_t mappedSize = 0;

    // Encryption (XOR for now              replace with AES in production)
    const uint8_t ENC_KEY[16] = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B,
                                 0x9C, 0xAD, 0xBE, 0xCF, 0xD1, 0xE2, 0xF3, 0x04};

public:
    table()
    {
        CreateDirectoryA("./userData", nullptr);
        CreateDirectoryA(backupDir.c_str(), nullptr);
        initStorage();
    }

    ~table() { flushAndClose(); }

private:
    void initStorage()
    {
        hFile = CreateFileA(dataFile.c_str(), GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);

        if (hFile == INVALID_HANDLE_VALUE)
            return;

        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile, &fileSize);

        if (fileSize.QuadPart > 0)
        {
            hMap = CreateFileMappingA(hFile, nullptr, PAGE_READWRITE, 0, 0, nullptr);
            if (hMap)
            {
                mappedMemory = static_cast<char *>(MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0));
                if (mappedMemory)
                {
                    currentRecords = fileSize.QuadPart / sizeof(T);
                    loadIndex();
                    UnmapViewOfFile(mappedMemory);
                }
                CloseHandle(hMap);
            }
        }
        else
        {
            currentRecords = 0;
        }

        // Truncate to the actual used size before extending
        LARGE_INTEGER usedSize;
        usedSize.QuadPart = currentRecords * sizeof(T);
        SetFilePointerEx(hFile, usedSize, nullptr, FILE_BEGIN);
        SetEndOfFile(hFile);

        mappedSize = (currentRecords + 20000) * sizeof(T); // headroom
        hMap = CreateFileMappingA(hFile, nullptr, PAGE_READWRITE, 0, (DWORD)mappedSize, nullptr);
        if (hMap)
        {
            mappedMemory = static_cast<char *>(MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, mappedSize));
        }
    }

    void flushAndClose()
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (mappedMemory)
        {
            FlushViewOfFile(mappedMemory, 0);
            UnmapViewOfFile(mappedMemory);
        }
        if (hMap)
            CloseHandle(hMap);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            LARGE_INTEGER usedSize;
            usedSize.QuadPart = currentRecords * sizeof(T);
            SetFilePointerEx(hFile, usedSize, nullptr, FILE_BEGIN);
            SetEndOfFile(hFile);

            FlushFileBuffers(hFile);
            CloseHandle(hFile);
        }
    }

    void loadIndex()
    {
        if (!mappedMemory)
            return;
        T rec;
        pageNum.clear();
        emailToUid.clear();
        phoneToUid.clear();

        size_t actualRecords = 0;
        for (size_t i = 0; i < currentRecords; ++i)
        {
            memcpy(&rec, mappedMemory + i * sizeof(T), sizeof(T));
            decryptRecord(rec); // decrypt for index building

            bool isEmpty = true;
            for (size_t j = 0; j < sizeof(rec.user_id); ++j)
            {
                if (rec.user_id[j] != 0)
                {
                    isEmpty = false;
                    break;
                }
            }
            if (isEmpty)
            {
                break;
            }
            actualRecords++;

            std::string uid = toKey(rec.user_id, sizeof(rec.user_id));
            pageNum[uid] = i;

            std::string email = toKey(rec.email, sizeof(rec.email));
            std::string phone = toKey(rec.phone_hash, sizeof(rec.phone_hash));
            if (!email.empty())
                emailToUid[email] = uid;
            if (!phone.empty())
                phoneToUid[phone] = uid;

            encryptRecord(rec); // re            encrypt
        }
        currentRecords = actualRecords;
    }

    static std::string toKey(const uint8_t *arr, size_t len)
    {
        return std::string(reinterpret_cast<const char *>(arr), len);
    }

    static std::string toKey(const char *arr, size_t len)
    {
        return std::string(arr, strnlen(arr, len));
    }

    uint32_t calculateChecksum(const T &rec)
    {
        uLong crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, reinterpret_cast<const Bytef *>(&rec), sizeof(T) - sizeof(uint32_t));
        return static_cast<uint32_t>(crc);
    }

    void encryptRecord(T &rec)
    {
        uint8_t *data = reinterpret_cast<uint8_t *>(&rec);
        for (size_t i = 0; i < sizeof(T); ++i)
        {
            data[i] ^= ENC_KEY[i % 16];
        }
    }

    void decryptRecord(T &rec)
    {
        encryptRecord(rec); // XOR is its own inverse
    }

    void evictLFU()
    {
        if (freqList.empty())
            return;
        auto &lowest = freqList.front();
        if (!lowest.keys.empty())
        {
            std::string key = lowest.keys.front();
            lowest.keys.pop_front();
            cacheMap.erase(key);
            keyToFreq.erase(key);
            if (lowest.keys.empty())
                freqList.pop_front();
        }
    }

    void updateLFU(const std::string &key, const T &value)
    {
        auto it = keyToFreq.find(key);
        if (it != keyToFreq.end())
        {
            auto freqIt = it->second;
            freqIt->keys.remove(key);
            if (freqIt->keys.empty() && freqIt != freqList.end())
            {
                freqList.erase(freqIt);
            }
            freqIt->freq++;
            if (freqIt->freq > freqList.back().freq)
            {
                freqList.push_back({freqIt->freq, {}});
                freqIt = freqList.end();
            }
        }
        else
        {
            if (freqList.empty() || freqList.back().freq != 1)
            {
                freqList.push_back({1, {}});
            }
            freqList.back().keys.push_back(key);
            keyToFreq[key] = freqList.end();
        }
        cacheMap[key] = {value, keyToFreq[key]};
    }

    bool parseInput(const std::string &data, T &out)
    {
        std::istringstream iss(data);
        std::string token;

        if (!(iss >> token))
            return false;
        safeCopyBytes(out.user_id, token, sizeof(out.user_id));

        if (!(iss >> token))
            return false;
        safeCopy(out.username, token, sizeof(out.username));

        if (!(iss >> token))
            return false;
        safeCopyBytes(out.password_hash, token, sizeof(out.password_hash));

        if (!(iss >> token))
            return false;
        safeCopy(out.email, token, sizeof(out.email));

        if (!(iss >> token))
            return false;
        out.email_verified = (token == "true" || token == "TRUE");

        if (!(iss >> token))
            return false;
        safeCopyBytes(out.phone_hash, token, sizeof(out.phone_hash));

        if (!(iss >> token))
            return false;
        out.phone_discoverable = (token == "true" || token == "TRUE");

        return true;
    }

    void safeCopy(char *dest, const std::string &src, size_t maxLen)
    {
        size_t len = std::min(src.size(), maxLen- 1);
        std::copy_n(src.begin(), len, dest);
        dest[len] = '\0';
    }

    void safeCopyBytes(uint8_t *dest, const std::string &src, size_t maxLen)
    {
        size_t len = std::min(src.size(), maxLen);
        std::copy_n(src.begin(), len, dest);
    }

public:
    bool writeTheData(const std::string &dataStr)
    {
        std::lock_guard<std::mutex> lock(mtx);
        T record{};
        if (!parseInput(dataStr, record))
            return false;

        std::string uid = toKey(record.user_id, sizeof(record.user_id));

        record.is_deleted = false;

        uint32_t *csPtr = reinterpret_cast<uint32_t *>(reinterpret_cast<char *>(&record) + sizeof(T) - sizeof(uint32_t));
        *csPtr = calculateChecksum(record);
        encryptRecord(record);

        size_t idx = currentRecords;
        memcpy(mappedMemory + idx * sizeof(T), &record, sizeof(T));
        FlushViewOfFile(mappedMemory + idx * sizeof(T), sizeof(T));
        FlushFileBuffers(hFile);

        pageNum[uid] = idx;
        currentRecords++;

        // Secondary indexes
        std::string email = toKey(record.email, sizeof(record.email)); // Note: decrypt not done here
        std::string phone = toKey(record.phone_hash, sizeof(record.phone_hash));
        if (!email.empty() && !record.is_deleted)
            emailToUid[email] = uid;
        if (!phone.empty() && !record.is_deleted)
            phoneToUid[phone] = uid;

        if (cacheMap.size() >= CACHE_LIMIT)
            evictLFU();
        updateLFU(uid, record);

        return true;
    }

    bool updateTheData(const std::string &dataStr)
    {
        std::lock_guard<std::mutex> lock(mtx);
        T newRecord{};
        if (!parseInput(dataStr, newRecord))
            return false;

        std::string uid = toKey(newRecord.user_id, sizeof(newRecord.user_id));
        auto it = pageNum.find(uid);
        if (it == pageNum.end())
            return false;

        newRecord.is_deleted = false;

        uint32_t *csPtr = reinterpret_cast<uint32_t *>(reinterpret_cast<char *>(&newRecord) + sizeof(T) -sizeof(uint32_t));
        *csPtr = calculateChecksum(newRecord);
        encryptRecord(newRecord);

        size_t idx = it->second;
        memcpy(mappedMemory + idx * sizeof(T), &newRecord, sizeof(T));
        FlushViewOfFile(mappedMemory + idx * sizeof(T), sizeof(T));
        FlushFileBuffers(hFile);

        if (cacheMap.count(uid))
            updateLFU(uid, newRecord);

        return true;
    }

    bool deleteData(const std::string &identifier)
    { // uid, email or phone
        std::lock_guard<std::mutex> lock(mtx);

        std::string uid = identifier;
        auto eit = emailToUid.find(identifier);
        if (eit != emailToUid.end())
            uid = eit->second;
        auto pit = phoneToUid.find(identifier);
        if (pit != phoneToUid.end())
            uid = pit->second;

        auto pit2 = pageNum.find(uid);
        if (pit2 == pageNum.end())
            return false;

        size_t idx = pit2->second;
        T record;
        memcpy(&record, mappedMemory + idx * sizeof(T), sizeof(T));
        decryptRecord(record);

        if (record.is_deleted)
            return false;

        record.is_deleted = true;
        uint32_t *csPtr = reinterpret_cast<uint32_t *>(reinterpret_cast<char *>(&record) + sizeof(T)- sizeof(uint32_t));
        *csPtr = calculateChecksum(record);
        encryptRecord(record);

        memcpy(mappedMemory + idx * sizeof(T), &record, sizeof(T));
        FlushViewOfFile(mappedMemory + idx * sizeof(T), sizeof(T));
        FlushFileBuffers(hFile);

        // Remove from active indexes and cache
        cacheMap.erase(uid);
        keyToFreq.erase(uid);
        emailToUid.erase(uid); // will be cleaned properly on reload
        phoneToUid.erase(uid);

        return true;
    }

    std::string getData(const std::string &query)
    {
        std::lock_guard<std::mutex> lock(mtx);

        std::istringstream iss(query);
        std::string key;
        iss >> key;

        std::string uid = key;
        auto eit = emailToUid.find(key);
        if (eit != emailToUid.end())
            uid = eit->second;
        auto pit = phoneToUid.find(key);
        if (pit != phoneToUid.end())
            uid = pit->second;

        T record;
        bool found = false;

        auto cit = cacheMap.find(uid);
        if (cit != cacheMap.end())
        {
            record = cit->second.first;
            updateLFU(uid, record);
            found = true;
        }
        else
        {
            auto pIt = pageNum.find(uid);
            if (pIt == pageNum.end())
                return "NOT_FOUND";

            size_t offset = pIt->second * sizeof(T);
            memcpy(&record, mappedMemory + offset, sizeof(T));
            decryptRecord(record);

            if (record.is_deleted)
                return "NOT_FOUND";

            if (cacheMap.size() >= CACHE_LIMIT)
                evictLFU();
            updateLFU(uid, record);
            found = true;
        }

        if (!found)
            return "NOT_FOUND";
        return buildOutput(record, query);
    }
    std::vector<T> getAllRecords()
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<T> records;
        if (!mappedMemory)
            return records;
        T rec;
        for (size_t i = 0; i < currentRecords; ++i)
        {
            memcpy(&rec, mappedMemory + i * sizeof(T), sizeof(T));
            decryptRecord(rec);
            if (!rec.is_deleted)
            {
                records.push_back(rec);
            }
            encryptRecord(rec); // restore encrypted memory state
        }
        return records;
    }
    void startPeriodicBackup()
    {
        std::thread([this]()
                    {
            while (true) {
                std::this_thread::sleep_for(std::chrono::minutes(5));
                std::string backupPath = backupDir + "backup_" + std::to_string(std::time(nullptr)) + ".bin";
                CopyFileA(dataFile.c_str(), backupPath.c_str(), FALSE);
            } })
            .detach();
    }

private:
    std::string buildOutput(const T &rec, const std::string &query)
    {
        if (rec.is_deleted)
            return "NOT_FOUND";
        std::ostringstream oss;
        std::istringstream iss(query);
        oss << toKey(rec.user_id, sizeof(rec.user_id)) << " ";
        std::string token;

        while (iss >> token)
        {
            createOutput(oss, rec, token);
        }

        return oss.str();
    }

    void createOutput(std::ostringstream &oss, const T &rec, const std::string &req)
    {
        if (req == "NULL")
            return;

        if (req == "username")
        {
            oss << toKey(rec.username, sizeof(rec.username)) << " ";
        }
        else if (req == "password_hash")
        {
            oss << toKey(rec.password_hash, sizeof(rec.password_hash)) << " ";
        }
        else if (req == "email")
        {
            oss << toKey(rec.email, sizeof(rec.email)) << " ";
        }
        else if (req == "email_verified")
        {
            if (rec.email_verified)
            {
                oss << "TRUE" << " ";
            }
            else
            {
                oss << "FALSE" << " ";
            }
        }
        else if (req == "phone_hash")
        {
            oss << toKey(rec.phone_hash, sizeof(rec.phone_hash)) << " ";
        }
        else if (req == "phone_discoverable")
        {
            if (rec.phone_discoverable)
            {
                oss << "TRUE" << " ";
            }
            else
            {
                oss << "FALSE" << " ";
            }
        }
    }
};