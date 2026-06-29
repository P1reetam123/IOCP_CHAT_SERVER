#include"./network/IOContext.h"
#include<array>
#include"./datastructure/fixedQueue.h"
class IOContextPool
{
private:
size_t maxSize=20000;// 
    /* data */
    std::array<PER_IO_OPERATION_DATA,20000>pool;
    Fqueue<int> freeIndices{20000};
     std::atomic<size_t>currentPacketUse{0};
     std::atomic<size_t>peak{0};
    // implement in use also 
public:
    IOContextPool(/* args */);
    ~IOContextPool();
    PER_IO_OPERATION_DATA* borrowIOPdata();
    void returnIOPdata(PER_IO_OPERATION_DATA* pio);
    int returnPeak();
};

IOContextPool::IOContextPool(/* args */)
{
    for(size_t i=0;i<20000;i++){
        freeIndices.push(i);
        pool[i].id=i;
    }
}

IOContextPool::~IOContextPool()
{
}

 PER_IO_OPERATION_DATA* IOContextPool::borrowIOPdata(){
std::optional<size_t> id;
     id=freeIndices.pop();
     if(!id.has_value()) return nullptr;
      size_t idx= id.value();
    if(idx>=maxSize){
        return nullptr;
    }
   
    size_t newCount = currentPacketUse.fetch_add(1, std::memory_order_relaxed) + 1;
    size_t prevPeak = peak.load(std::memory_order_relaxed);
    while (newCount > prevPeak &&
           !peak.compare_exchange_weak(prevPeak, newCount, std::memory_order_relaxed)) {
        // prevPeak is refreshed by compare_exchange_weak on failure; loop retries with latest value
    }
   
    return &(pool[idx]);

}
void IOContextPool::returnIOPdata(PER_IO_OPERATION_DATA* pio){

if(pio==nullptr)return;
size_t idx=pio->id;
if(idx>=maxSize)return;
memset(pio->data,0,16384);
pio->packet=nullptr;
pio->totalToSend=0;
pio->bytesSent=0;
freeIndices.push(idx);
currentPacketUse--;
return ;

}
int IOContextPool::returnPeak(){
  return peak;
}