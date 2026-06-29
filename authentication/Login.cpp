#include"Login.h"

Login::Login(){
   loginThread=std::thread(&Login::HandleLoginQueue,this); 
   stopThread=false;
}
Login::~Login(){
    stopThread=true;
    lv.notify_all();
    if(loginThread.joinable())loginThread.join();
    
}
void Login::handleLoginPacket(Packet *p){
  loginRequestQueue.push(p); // push into the reques queue;
  lv.notify_one();// wake the thread
}

void Login::HandleLoginQueue(){
    while(true){
      {
          std::unique_lock<std::mutex>lk(lmtx);
        lv.wait(lk,[this]{return stopThread ||!loginRequestQueue.empty();});
      }


    }
}