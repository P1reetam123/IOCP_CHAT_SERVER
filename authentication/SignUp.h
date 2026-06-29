
#include<string>
#include<unordered_map>
#include"../protocol/Packet.h"
#include"../datastructure/Mpsc.h"
#include"../datastructure/table.h"
#include<condition_variable>
#include<mutex>
#include<thread>

class MessageRouter;
class AuthManager;

class SignUp{
 private:
 struct otpData
 {
   std::string otp; // hash
   time_t expiry;
   size_t count=0;
 };
 
 struct signupState
 {
    std::string email;
    std::string number;
    std::string username;
    std::string password;
 };
 bool stopThread;
MpscQueue<std::string>otpQueue;
MpscQueue<signupState>signUpQueue;
std::thread otpThread;
std::condition_variable ov;
std::mutex omutex;// mutex for ov
std::thread signUpthread;
std::mutex cmutex; // mutex for cv

std::condition_variable cv;
std::unordered_map<std::string,otpData >otpChecker;// to check the otp  by number

std::unordered_map<std::string ,bool>emailVerified;
std::unordered_map<std::string, size_t> requestCounter;

table<userInfo> db;
MessageRouter* router = nullptr;
AuthManager* authManager = nullptr;

public:
SignUp();
~SignUp();
void setRouter(MessageRouter* r) { router = r; }
void setAuthManager(AuthManager* am) { authManager = am; }
table<userInfo>& getDatabase() { return db; }
std::string otpGenerator();
void otpRequestHandler(Packet *p);
void signUpRequestHandler(Packet *p);
void otpSenderLoop();
bool SignupVerification(const std::string num,const size_t otp );
void signupManager();
bool isValidEmail(const std::string email);
bool isValidE164Phone(const std::string num);
bool sendMail(const std::string& message,const std::string &emailAddress);
bool isVerified(const std::string email);
void onOtpVerificationRequest(Packet *p);
std::string generateUserId();
std::string hashStr(const std::string& input);
 static time_t timestamp(time_t delay)
    {
        time_t now = time(nullptr);
        now+=delay;
        char buf[32] = {};
        struct tm timeinfo;

#ifdef _WIN32
        localtime_s(&timeinfo, &now);        // Thread-safe on Windows
#else
        localtime_r(&now, &timeinfo);        // Thread-safe on Linux/macOS
#endif

        return now;
    }
};