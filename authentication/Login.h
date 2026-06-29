#include"./datastructure/Mpsc.h"
#include<thread>
#include<condition_variable>
#include<mutex>
class Packet;
class Login{
private:
std::thread loginThread;
std::condition_variable lv;
std::mutex lmtx;
bool stopThread;

 public:
 Login();
 ~Login();
 // email +password , or number +password
 void handleLoginPacket(Packet *p);
 MpscQueue<Packet*>loginRequestQueue;
void HandleLoginQueue();
};