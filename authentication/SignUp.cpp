#include "SignUp.h"
#include <regex>
#include <random>
#include <curl/curl.h>
#include "../pool/PacketPool.h"
#include "../chat/MessageRouter.h"
#include "AuthManager.h"
#include <sodium.h>
#include <sstream>

SignUp::SignUp()
{
  stopThread = false;
  otpThread = std::thread(&SignUp::otpSenderLoop, this);
  signUpthread = std::thread(&SignUp::signupManager, this);
}

SignUp::~SignUp()
{
  stopThread = true;
  ov.notify_all();
  cv.notify_all();
  if (otpThread.joinable())
    otpThread.join();
  if (signUpthread.joinable())
    signUpthread.join();
}

std::string SignUp::hashStr(const std::string &input)
{
  std::hash<std::string> hasher;
  return std::to_string(hasher(input));
}

std::string SignUp::generateUserId()
{
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> dis(100000000ULL, 999999999ULL);
  return std::to_string(dis(gen));
}

bool SignUp::sendMail(const std::string &message, const std::string &emailAddress)
{
  // Basic mock for email sending, since configuring libcurl for SMTP is complex
  // and depends on an actual SMTP server credentials.
  std::cout << "[EMAIL MOCK] To: " << emailAddress << " Message: " << message << std::endl;
  return true;
}
bool SignUp::isValidE164Phone(const std::string num)
{
  const std::regex pattern(R"(^\+[1-9]\d{1,14}$)");
  return std::regex_match(num, pattern);
}
bool SignUp::isValidEmail(const std::string email)
{

  size_t pos = email.find('@');
  if (pos == std::string::npos)
    return false;
  std::string localPart = email.substr(0, pos);
  std::string domainPart = email.substr(pos + 1);

  if (localPart.empty() || domainPart.empty())
    return false;
  if (domainPart.find('.') == std::string::npos)
    return false;

  for (char c : email)
  {
    if (!std::isalnum(c) && c != '@' && c != '.' && c != '_' && c != '-')
    {
      return false;
    }
  }
  return true;
}
// number formate wiil be also checked on client side
void SignUp::otpRequestHandler(Packet *p)
{
 bool parsed= p->parseHeader();
 if(!parsed){
  std::cout<<" failed to parse the header\n";
  return ;
 }
  std::string email = p->senderId;
  PacketPool::Instance().returnPacket(p);

  if (!isValidEmail(email))
  {
    return;
  }
  if (!isAlreadySignup(email))
  {

    // std::lock_guard<std::mutex> lock(omutex);
    otpQueue.push(email);
    ov.notify_one();
    return;
  }
  // already singed
  if (router)
  {
    Packet *errPacket = PacketPool::Instance().borrowPacket();
    errPacket->bypassQueue =true;
    errPacket->serialize(PKT_SIGNUP_ERROR, "SERVER", p->tempSessionId, "already signed !/ login ");
  std::cout<<"signup(101) routing to id :- "<<p->tempSessionId<<std::endl;
   bool routed= router->routePacket(errPacket, p->tempSessionId);
   if(!routed) PacketPool::Instance().returnPacket(errPacket);
  }

  return;
}

// this thread will keep the message into a signup queue
void SignUp::otpSenderLoop()
{

  while (true)
  {
    {
      std::unique_lock<std::mutex> lk(omutex);
      ov.wait(lk, [this]
              { return stopThread || !otpQueue.empty(); });
    }
    if (stopThread && otpQueue.empty())
      break;
    if (otpQueue.empty())
      continue;

    std::string email = otpQueue.front();
    otpQueue.pop();
    // even though connection or sent failed  ,client will ask for resent otp after certain time
    std::string otp = otpGenerator();
    time_t exp = timestamp(300); // 5 min delay
    std::string message = "OTP for login into Chat Application is : " + otp + " this otp is only valid for 2 minutes ";

    bool sent = sendMail(message, email);
    if (!sent)
    {
      // send something wrong mssage
    }
    otpData otpd;
    otpd.otp = otp;
    otpd.expiry = exp;
    otpChecker[email].otp = hashStr(otp);
    otpChecker[email].expiry = exp;
    otpChecker[email].count = 0;
    requestCounter[email] = 0;
  }
}

std::string SignUp::otpGenerator()
{
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(1000, 9999);
  return std::to_string(dis(gen));
}
// email  ||number ||usrername || password
void SignUp::signUpRequestHandler(Packet *p)
{
  p->parseData();
  std::istringstream iss(p->payload);
  std::string email, number, username, password;
  iss >> email >> number >> username >> password;

  std::string sessionId = p->tempSessionId;
  PacketPool::Instance().returnPacket(p);

  bool verified = isVerified(email);
  if (!verified)
  {
    if (router)
    {
      Packet *errPacket = PacketPool::Instance().borrowPacket();
      errPacket->bypassQueue=true;
      errPacket->serialize(PKT_SIGNUP_ERROR, "SERVER", sessionId, "Signup Failed: Email not verified");
        std::cout<<"signup(172) routing to id :- "<<sessionId<<std::endl;
    bool routed =  router->routePacket(errPacket, sessionId);
       if(!routed) PacketPool::Instance().returnPacket(errPacket);
     
    }
    std::cout << "returning without pushign into the queue\n";
    return;
  }

  signupState state;
  state.email = email;
  state.number = number;
  state.username = username;
  state.password = password;
  state.sessionId = sessionId;

  std::lock_guard<std::mutex> lock(cmutex);
  std::cout << " state pushed into the quwu\n";
  signUpQueue.push(state);
  cv.notify_one();
}
bool SignUp::isVerified(const std::string email)
{
  std::lock_guard<std::mutex> lk(emtx);
  auto it = emailVerified.find(email);
  std::cout << "verifying the email\n";
  if (it == emailVerified.end())
    return false;
  std::cout << "email verified\n";
  return it->second;
}
// email || otp
void SignUp::onOtpVerificationRequest(Packet *p)
{
 p->parseData();
std::istringstream iss(p->payload);
std::string email, otp;
iss >> email >> otp;
std::string sessionId = p->tempSessionId;
PacketPool::Instance().returnPacket(p);

std::string hashedOtp = hashStr(otp);
bool found = false;
otpData otCopy; // Store a copy to avoid dangling pointers and reduce lock time
std::string key;

{
    std::unique_lock<std::mutex> lk(otmtx);
    auto it = otpChecker.find(email);
    if (it != otpChecker.end())
    {
        found = true;
        key = it->first;
        otCopy = it->second; // Copy data safely inside the lock
        it->second.count++;
    }
}

// Logic Fix: Error if NOT found
if (!found)
{
    if (router)
    {
        Packet *errPacket = PacketPool::Instance().borrowPacket();
        errPacket->bypassQueue=true;
        std::cout << " otp not generated \n";
        errPacket->serialize(PKT_SIGNUP_ERROR, "SERVER", sessionId, "OTP not generated");
         std::cout<<"signup(236) routing to id :- "<<sessionId<<std::endl;
      bool routed =  router->routePacket(errPacket, sessionId);
       if(!routed) PacketPool::Instance().returnPacket(errPacket);
        
    }
    return;
}

// Check limits using the local copy
if (otCopy.count >= 5 || otCopy.expiry < timestamp(0))
{
    if (router)
    {
        Packet *errPacket = PacketPool::Instance().borrowPacket();
        errPacket->bypassQueue=true;
        std::cout << " otp verified failed \n";
        errPacket->serialize(PKT_SIGNUP_ERROR, "SERVER", sessionId, "OTP expired or limit reached");
        
        // Erase inside a new lock scope
        std::lock_guard<std::mutex> lk(otmtx);
        otpChecker.erase(key);
          std::cout<<"signup(254) routing to id :- "<<sessionId<<std::endl;
      bool routed=  router->routePacket(errPacket, sessionId);
       if(!routed) PacketPool::Instance().returnPacket(errPacket);
       
    }
    return;
}

if (otCopy.otp == hashedOtp)
{
    // Success
    {
        std::lock_guard<std::mutex> lk(emtx);
        emailVerified[email] = true;
    }

    if (router)
    {
        Packet *okPacket = PacketPool::Instance().borrowPacket();
        okPacket->bypassQueue=true;
        std::cout << " otp verified \n";
        okPacket->serialize(PKT_ACKNOWLEDGMENT, "SERVER", sessionId, "OTP Verified");
        
        // Erase immediately after success
        {
            std::lock_guard<std::mutex> lk(otmtx);
            otpChecker.erase(key);
        }
   std::cout<<"signup (280) routing to id :- "<<sessionId<<std::endl;
        bool routed = router->routePacket(okPacket, sessionId);
     
        if (!routed)
        {
           if(!routed) PacketPool::Instance().returnPacket(okPacket);
            std::lock_guard<std::mutex> lk(emtx);
            emailVerified[email] = false;

        }
    }
    return;
}

{
    std::lock_guard<std::mutex> lk(emtx);
    emailVerified[email] = false;
}   
}

void SignUp::signupManager()
{
  while (true)
  {
    signupState state;
    {
      std::cout << "got the state\n";
      std::unique_lock<std::mutex> lk(cmutex);
      cv.wait(lk, [this]
              { return stopThread || !signUpQueue.empty(); });
      if (stopThread && signUpQueue.empty())
        break;
      if (signUpQueue.empty())
        continue;
      state = signUpQueue.front();
      signUpQueue.pop();
    }
    // use libsodium for random generation
    std::string userID = generateUserId();

    char hashed_password[crypto_pwhash_STRBYTES]{};
    if (crypto_pwhash_str(
            hashed_password,
            state.password.c_str(),
            state.password.size(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
      std::cerr << "[SIGNUP] Argon2id hashing failed for " << state.email << std::endl;
      continue;
    }

    std::ostringstream dbData;
    dbData << userID << " " << state.username << " " << hashed_password << " "
           << state.email << " " << "TRUE" << " " << hashStr(state.number) << " " << "TRUE";

    if (db.writeTheData(dbData.str()))
    {
      std::cout << "[SIGNUP] Registered user " << state.email << " with ID " << userID << std::endl;
      if (authManager)
      {
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
    }
    else
    {
      std::cout << "[SIGNUP] DB Write failed for " << state.email << std::endl;
    }
  }
}
bool SignUp::isAlreadySignup(const std::string email)
{
  auto it = db.emailToUid.find(email);
  if (it == db.emailToUid.end())
    return false;
  return true;
}