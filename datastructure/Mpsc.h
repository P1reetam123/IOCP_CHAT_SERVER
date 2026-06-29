#pragma once
#include <atomic>
#include <thread>
#include <utility>  // for std::move

template <typename T>
class MpscQueue {
private:
    struct Node {
        T* data = nullptr;
        std::atomic<Node*> next{nullptr};

        Node() = default;
        explicit Node(T* ptr) : data(ptr) {}
    };

    std::atomic<Node*> head{nullptr};
    std::atomic<Node*> tail{nullptr};
   std::atomic<size_t>s;

public:
    MpscQueue();
    ~MpscQueue();
   

    // Push by value (moves when possible)
    void push(T value);

    // Returns true if an element was popped
    bool pop();

    // Returns a copy of the front element without removing it
    // Returns default-constructed T if queue is empty
    T front() const;

    // Check if queue has any ready elements
    bool empty() const;
    size_t size();
};

// implementation

template <typename T>
MpscQueue<T>::MpscQueue()
{
    s.store(0,std::memory_order_relaxed);
    Node* stub = new Node();
    head.store(stub, std::memory_order_relaxed);
    tail.store(stub, std::memory_order_relaxed);
}

template <typename T>
MpscQueue<T>::~MpscQueue()
{
    while (pop()) {}
    delete tail.load(std::memory_order_relaxed);
}

template <typename T>
void MpscQueue<T>::push(T value)
{
    // Allocate data on heap and wrap in Node
    T* data_ptr = new T(std::move(value));
    Node* new_node = new Node(data_ptr);

    // Swap head and link previous node to new one
    Node* prev = head.exchange(new_node, std::memory_order_acq_rel);
    prev->next.store(new_node, std::memory_order_release);
   s++;
}

template <typename T>
bool MpscQueue<T>::pop()
{
    Node* tail_ = tail.load(std::memory_order_relaxed);
    Node* next_ = tail_->next.load(std::memory_order_acquire);

    if (next_ == nullptr) {
        // Check if really empty
        if (tail_ == head.load(std::memory_order_acquire)) {
            return false;
        }
        // Producer is in the middle of push - wait
        while ((next_ = tail_->next.load(std::memory_order_acquire)) == nullptr) {
            std::this_thread::yield();
        }
    }

    // Advance tail
    tail.store(next_, std::memory_order_release);

    // Clean up old stub
    delete tail_->data;   // Free the stored object
    delete tail_;         // Free the old node
s--;
    return true;
}

template <typename T>
T MpscQueue<T>::front() const
{
    Node* tail_ = tail.load(std::memory_order_relaxed);
    Node* next_ = tail_->next.load(std::memory_order_acquire);

    if (next_ == nullptr) {
        if (tail_ == head.load(std::memory_order_acquire)) {
            return T{}; // Return default-constructed T when empty
        }
        // Wait for producer to finish linking
        while ((next_ = tail_->next.load(std::memory_order_acquire)) == nullptr) {
            std::this_thread::yield();
        }
    }

    return *(next_->data);  // Return copy
}

template <typename T>
bool MpscQueue<T>::empty() const
{
    Node* tail_ = tail.load(std::memory_order_relaxed);
    Node* next_ = tail_->next.load(std::memory_order_acquire);
    return next_ == nullptr;
}


template <typename T>
size_t MpscQueue<T>::size(){
    return s;
}