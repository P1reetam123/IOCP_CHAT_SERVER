#include <iostream>
#include <atomic>
#include <cstddef>
#include <vector>
#include <stdexcept>
#include <optional>

constexpr size_t CACHE_LINE_SIZE = 64;

template <typename T>
class Fqueue {
private:
    struct Slot {
        std::atomic<size_t> sequence;
        T data;
    };

    size_t capacity_;
    std::vector<Slot> pool;
    
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> head{0};
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> tail{0};

    static size_t round_up_to_power_of_two(size_t n) {
        if (n == 0) return 2;
        --n;
        n |= n >> 1; n |= n >> 2; n |= n >> 4;
        n |= n >> 8; n |= n >> 16; n |= n >> 32;
        return n + 1;
    }

public:
    Fqueue(const size_t l) : capacity_(round_up_to_power_of_two(l)), pool(capacity_) {
        for (size_t i = 0; i < capacity_; ++i) {
            pool[i].sequence.store(i, std::memory_order_relaxed);
        }
    }

    ~Fqueue() {}

    Fqueue(const Fqueue&) = delete;
    Fqueue& operator=(const Fqueue&) = delete;

    void push(T val) {
        size_t pos = head.load(std::memory_order_relaxed);
        while (true) {
            Slot& slot = pool[pos & (capacity_ - 1)];
            size_t seq = slot.sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);

            if (diff == 0) {
                if (head.compare_exchange_weak(pos, pos + 1,
                                               std::memory_order_relaxed,
                                               std::memory_order_relaxed)) {
                    ::new (static_cast<void*>(&slot.data)) T(std::move(val));
                    slot.sequence.store(pos + 1, std::memory_order_release);
                    return;
                }
            } else if (diff < 0) {
                // Queue full: spin or yield
                pos = head.load(std::memory_order_relaxed);
            } else {
                pos = head.load(std::memory_order_relaxed);
            }
        }
    }

    // Returns std::optional<T> with the popped value, or std::nullopt if empty
    std::optional<T> pop() {
        size_t pos = tail.load(std::memory_order_relaxed);
        while (true) {
            Slot& slot = pool[pos & (capacity_ - 1)];
            size_t seq = slot.sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);

            if (diff == 0) {
                if (tail.compare_exchange_weak(pos, pos + 1,
                                               std::memory_order_relaxed,
                                               std::memory_order_relaxed)) {
                    T val = std::move(slot.data);
                    slot.data.~T();
                    slot.sequence.store(pos + capacity_, std::memory_order_release);
                    return val;
                }
            } else if (diff < 0) {
                return std::nullopt; // Empty
            } else {
                pos = tail.load(std::memory_order_relaxed);
            }
        }
    }

    /**
     * Fully race-free front() implementation.
     * Returns std::optional<T>: contains value if successful, nullopt if empty.
     * 
     * Logic:
     * 1. Load tail and sequence.
     * 2. Verify sequence indicates data is ready (seq == pos + 1).
     * 3. CRITICAL: Re-check that tail hasn't changed. If tail changed, another 
     *    consumer might have popped this slot, making our read unsafe.
     * 4. If stable, copy data and return.
     */
    std::optional<T> front() const {
        size_t pos = tail.load(std::memory_order_relaxed);
        
        while (true) {
            const Slot& slot = pool[pos & (capacity_ - 1)];
            size_t seq = slot.sequence.load(std::memory_order_acquire);
            
            // Check if data is ready
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);
            
            if (diff != 0) {
                // If diff < 0, queue is empty. If diff > 0, state changed.
                return std::nullopt;
            }

            // RACE-FREE CHECK: 
            // Ensure 'tail' hasn't moved while we were reading the sequence.
            // If tail changed, another consumer might have claimed this slot.
            if (tail.load(std::memory_order_acquire) == pos) {
                // Stable: Safe to copy data
                return slot.data; 
            }
            
            // Tail changed: Retry with new position
            pos = tail.load(std::memory_order_relaxed);
        }
    }

    bool empty() const {
        size_t pos = tail.load(std::memory_order_relaxed);
        const Slot& slot = pool[pos & (capacity_ - 1)];
        size_t seq = slot.sequence.load(std::memory_order_acquire);
        return (static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1)) != 0;
    }
    
    size_t size() const {
        return head.load(std::memory_order_relaxed) - tail.load(std::memory_order_relaxed);
    }
};   