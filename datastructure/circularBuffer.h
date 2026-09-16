#pragma once
#include <cstdint>
#include <cstring>
#include <winsock2.h>

constexpr size_t capacity = 16384;
constexpr size_t mask = capacity - 1;

class CircularBuffer {
    uint8_t buffer[capacity];
    size_t stidx = 0;   // grows unbounded — mask only when indexing into buffer[]
    size_t endidx = 0;  // grows unbounded — mask only when indexing into buffer[]

public:
    // Unsigned subtraction handles wrap-around naturally.
    // Empty: endidx == stidx → 0.  Full: endidx - stidx == capacity.
    // No ambiguity because indices are never clamped.
    size_t size() const {
        return endidx - stidx;
    }

    size_t freeSpace() const {
        return capacity - size();
    }

    bool insert(size_t length, const uint8_t* startPtr) {
        if (length > freeSpace()) return false;

        for (size_t i = 0; i < length; ++i) {
            buffer[(endidx + i) & mask] = startPtr[i];
        }
        endidx += length;
        return true;
    }

    bool erase(size_t length) {
        if (length > size()) return false;
        stidx += length;
        return true;
    }

    bool copy(uint8_t* dest, size_t length) const {
        if (size() < length) return false;

        for (size_t i = 0; i < length; ++i) {
            dest[i] = buffer[(stidx + i) & mask];
        }
        return true;
    }

    // Copies data out AND advances the read pointer in one call.
    // Replaces the copy() + erase() pattern to avoid double traversal.
    bool consume(uint8_t* dest, size_t length) {
        if (size() < length) return false;

        for (size_t i = 0; i < length; ++i) {
            dest[i] = buffer[(stidx + i) & mask];
        }
        stidx += length;
        return true;
    }

    // Populates an array of WSABUF with the physical memory locations of free space.
    // Returns the number of buffers populated (0, 1, or 2).
    int getWriteBuffers(WSABUF* bufs) {
        size_t free = freeSpace();
        if (free == 0) return 0;

        size_t wPhys = endidx & mask;  // physical write position
        size_t rPhys = stidx & mask;   // physical read position

        if (wPhys >= rPhys) {
            // Data is contiguous [rPhys, wPhys).
            // Free space: [wPhys, capacity) then [0, rPhys).
            size_t tailSpace = capacity - wPhys;
            bufs[0].buf = (char*)&buffer[wPhys];
            bufs[0].len = (ULONG)tailSpace;

            if (rPhys > 0) {
                bufs[1].buf = (char*)&buffer[0];
                bufs[1].len = (ULONG)rPhys;
                return 2;
            }
            return 1;
        } else {
            // Data wraps around. Free space is contiguous [wPhys, rPhys).
            bufs[0].buf = (char*)&buffer[wPhys];
            bufs[0].len = (ULONG)(rPhys - wPhys);
            return 1;
        }
    }

    // Call this after WSARecv successfully reads bytes to commit them.
    void commitWrite(size_t length) {
        if (length > freeSpace()) return; // Safety check
        endidx += length;
    }
};