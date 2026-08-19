#include <iostream>
#include <stdint.h>
#include <cstring>

constexpr size_t capacity = 16384;
constexpr size_t mask = capacity - 1;

class CircularBuffer {
    uint8_t buffer[capacity];
    size_t stidx = 0; 
    size_t endidx = 0;

public:
    size_t size() const {
        return (endidx - stidx + capacity) & mask;
    }

    size_t freeSpace() const {
      
        return capacity - 1 - size();
    }

    bool insert(int length, const uint8_t* startPtr) {
        if (length > freeSpace()) return false;

        for (int i = 0; i < length; ++i) {
            buffer[endidx & mask] = startPtr[i];
            endidx++;
         
        }
        
        if (endidx >= capacity) {
            endidx &= mask;
            stidx &= mask;
        }
        return true;
    }

    bool erase(size_t length) {
        if (length > size()) return false;
        stidx += length;
       
        if (stidx >= capacity) {
            stidx &= mask;
            endidx &= mask;
        }
        return true;
    }

    bool copy(uint8_t* dest, size_t length) const {
        if (size() < length) return false;
        
        size_t current = stidx;
        for (size_t i = 0; i < length; ++i) {
            dest[i] = buffer[current & mask]; 
            current++;
        }
        return true;
    }
};   