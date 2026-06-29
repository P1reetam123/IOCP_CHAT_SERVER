#include"SignUp.h"
#include<regex>
#include <random>
#include <curl/curl.h>
#include"../pool/PacketPool.h"
#include"../chat/MessageRouter.h"
#include"AuthManager.h"
#include <sodium.h>
#include <sstream>

SignUp::SignUp(){
  stopThread=false;
  otpThread=std::thread(&SignUp::otpSenderLoop,this);
  signUpthread=std::thread(&SignUp::signupManager,this);
}

SignUp::~SignUp(){
    stopThread = true;
    ov.notify_all();
    cv.notify_all();
    if(otpThread.joinable()) otpThread.join();
    if(signUpthread.joinable()) signUpthread.join();
}

std::string SignUp::hashStr(const std::string& input) {
    std::hash<std::string> hasher;
    return std::to_string(hasher(input));
}

std::string SignUp::generateUserId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(100000000ULL, 999999999ULL);
    return std::to_string(dis(gen));
}

bool SignUp::sendMail(const std::string& message, const std::string &emailAddress) {
    // Basic mock for email sending, since configuring libcurl for SMTP is complex 
    // and depends on an actual SMTP server credentials.
    std::cout << "[EMAIL MOCK] To: " << emailAddress << " Message: " << message << std::endl;
    return true;
}
 bool SignUp::isValidE164Phone(const std::string num){
    const std::regex pattern(R"(^\+[1-9]\D{1,14}$)");
    return std::regex_match(num,pattern);
 }
 bool SignUp::isValidEmail(const std::string email){ 

  size_t  pos=email.find('@');
  if(pos==std::string:: npos)return false;
   std::string localPart = email.substr(0, pos);
    std::string domainPart = email.substr(pos + 1);

    if (localPart.empty() || domainPart.empty()) return false;
    if (domainPart.find('.') == std::string::npos) return false;

     for (char c : email) {
        if (!std::isalnum(c) && c != '@' && c != '.' && c != '_' && c != '-') {
            return false;
        }
    }
    return true;

 }
// number formate wiil be also checked on client side
void SignUp::otpRequestHandler(Packet *p){
  p->parseHeader(); 
  std::string email=p->senderId;
  PacketPool::Instance().returnPacket(p);

  if(!isValidEmail(email)){
    return;
  }

  std::lock_guard<std::mutex> lock(omutex);
  otpQueue.push(email);
  ov.notify_one();
}

// this thread will keep the message into a signup queue
void SignUp::otpSenderLoop(){

    while(true){
      {
        std::unique_lock<std::mutex>lk(omutex);
        ov.wait(lk,[this]{ return stopThread ||!otpQueue.empty();});

      }
      if(stopThread && otpQueue.empty()) break;
      if(otpQueue.empty()) continue;

       std::string email=otpQueue.front();
       otpQueue.pop();
       // even though connection or sent failed  ,client will ask for resent otp after certain time 
       std::string otp=otpGenerator();
       time_t exp=timestamp(300); // 5 min delay
       std::string message="OTP for login into Chat Application is : "+ otp +" this otp is only valid for 2 minutes ";

       bool sent=  sendMail(message,email);
       if(!sent){
        //send something wrong mssage 
       }
       otpData otpd;
       otpd.otp=otp;
       otpd.expiry=exp;
        otpChecker[email].otp = hashStr(otp);
        otpChecker[email].expiry = exp;
        otpChecker[email].count = 0;
        requestCounter[email] = 0; 
    }
}

std::string SignUp::otpGenerator(){
  std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    return std::to_string(dis(gen));
}
// email  ||number ||usrername || password 
void SignUp::signUpRequestHandler(Packet *p){
     p->parseData();
  std::istringstream iss(p->payload);
  std::string email,number,username,password;
  iss>>email>>number>>username>>password;
  
  std::string sessionId = p->senderId;
  PacketPool::Instance().returnPacket(p);

  bool verified = isVerified(email);
  if(!verified){
    if (router) {
        Packet* errPacket = PacketPool::Instance().borrowPacket();
        errPacket->serialize(PKT_FILE_ERROR, "SERVER", sessionId, "Signup Failed: Email not verified");
        std::cout<<"email not verified \n";
        router->routePacket(errPacket, sessionId);
    }
    return ;
  }

  signupState state;
  state.email = email;
  state.number = number;
  state.username = username;
  state.password = password;

  std::lock_guard<std::mutex> lock(cmutex);
  signUpQueue.push(state);
  std::cout<<"pushed into the queue \n";
  cv.notify_one();
}
bool SignUp::isVerified(const std::string email){
auto it =emailVerified.find(email);
if(it==emailVerified.end()) return false;
return it->second;
}
// email || otp 
void SignUp::onOtpVerificationRequest(Packet* p){
   p->parseData();
  std::istringstream iss(p->payload);
  std::string email, otp;
  iss>>email>>otp;
  std::string sessionId = p->senderId;
  PacketPool::Instance().returnPacket(p);
  
  std::string hashedOtp = hashStr(otp);

  auto it = otpChecker.find(email);
  if(it == otpChecker.end()){
    if (router) {
        Packet* errPacket = PacketPool::Instance().borrowPacket();
         std::cout<<" otp not generated \n";
        errPacket->serialize(PKT_FILE_ERROR, "SERVER", sessionId, "OTP not generated");
        router->routePacket(errPacket, sessionId);
    }
    return ;
  }

  if(it->second.count > 5 || it->second.expiry < timestamp(0)){
    if (router) {
        Packet* errPacket = PacketPool::Instance().borrowPacket();
         std::cout<<" otp verified failed \n";
        errPacket->serialize(PKT_FILE_ERROR, "SERVER", sessionId, "OTP expired or limit reached");
        router->routePacket(errPacket, sessionId);
    }
    return ;
  }
  it->second.count++;

  if(it->second.otp == hashedOtp){
    emailVerified[email] = true;
    if (router) {
        Packet* okPacket = PacketPool::Instance().borrowPacket();
        std::cout<<" otp verified \n";
        okPacket->serialize(PKT_ACKNOWLEDGMENT, "SERVER", sessionId, "OTP Verified");
        router->routePacket(okPacket, sessionId);
    }
    return ;
  }
  emailVerified[email] = false;
}

void SignUp::signupManager() {
    while(true) {
        signupState state;
        {
            std::unique_lock<std::mutex> lk(cmutex);
            cv.wait(lk, [this]{ return stopThread || !signUpQueue.empty(); });
            if (stopThread && signUpQueue.empty()) break;
            if (signUpQueue.empty()) continue;
            state = signUpQueue.front();
            signUpQueue.pop();
        }

        std::string userID = generateUserId();
        
        char hashed_password[crypto_pwhash_STRBYTES]{};
        if (crypto_pwhash_str(
                hashed_password,
                state.password.c_str(),
                state.password.size(),
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
            std::cerr << "[SIGNUP] Argon2id hashing failed for " << state.email << std::endl;
            continue;
        }

        std::ostringstream dbData;
        dbData << userID << " " << state.username << " " << hashed_password << " " 
               << state.email << " " << "TRUE" << " " << hashStr(state.number) << " " << "TRUE";
               
        if (db.writeTheData(dbData.str())) {
            std::cout << "[SIGNUP] Registered user " << state.email << " with ID " << userID << std::endl;
            if (authManager) {
                UserRecord ur;
                std::memset(ur.user_id, 0, 16);
                std::memcpy(ur.user_id, userID.c_str(), std::min(userID.size(), size_t(16)));
                std::memset(ur.username, 0, sizeof(ur.username));
                std::memcpy(ur.username, state.username.c_str(), std::min(state.username.size(), sizeof(ur.username) - 1));
                std::memcpy(ur.password_hash, hashed_password, sizeof(ur.password_hash));
                std::memset(ur.email, 0, sizeof(ur.email));
                std::memcpy(ur.email, state.email.c_str(), std::min(state.email.size(), sizeof(ur.email) - 1));
                ur.email_verified = true;
                std::string p_hash = hashStr(state.number);
                std::memset(ur.phone_hash, 0, sizeof(ur.phone_hash));
                std::memcpy(ur.phone_hash, p_hash.c_str(), std::min(p_hash.size(), size_t(32)));
                ur.phone_discoverable = true;

                authManager->AddUserRecord(ur);
            }
        } else {
            std::cout << "[SIGNUP] DB Write failed for " << state.email << std::endl;
        }
    }
}
