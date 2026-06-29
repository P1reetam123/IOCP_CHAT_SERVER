#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include "Client.h"
#include <thread>
#include <atomic>
#include <chrono>

void printHelp() {
    std::cout << "\nCommands:\n";
    std::cout << "  /signup <email>                  (Step 1: Request OTP)\n";
    std::cout << "  /verify <email> <otp>            (Step 2: Verify OTP)\n";
    std::cout << "  /register <email> <number> <username> <password> (Step 3: Complete Signup)\n";
    std::cout << "  /login <email_or_username> <password>\n";
    std::cout<<"/connect\n";
    std::cout << "  /msg <receiver> <message>\n";
    std::cout << "  /gmsg <groupId> <message>\n";
    std::cout << "  /create <groupId>\n";
    std::cout << "  /join <groupId>\n";
    std::cout << "  /leave <groupId>\n";
    std::cout << "  /sendfile <receiver> <filepath>\n";
    std::cout << "  /download <uploadId>\n";
    std::cout << "  /quit\n";
    std::cout << "  /help\n";
}

int main() {
    // Initialize Winsock exactly once for the application
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    Client client;
    std::string ip = "127.0.0.1";
    int port = 8080;

    std::cout << "Connecting to server at " << ip << ":" << port << "...\n";
    if (!client.connectToServer(ip, port)) {
        std::cerr << "Failed to connect to server.\n";
        WSACleanup();
        return 1;
    }
    
    std::cout << "Connected!\n";
    printHelp();

    std::string line;
    while (true) {
        std::cout << "> ";
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string cmd;
        ss >> cmd;

        if (cmd == "/quit") {
            break;
        } else if (cmd == "/help") {
            printHelp();
        } else if (cmd == "/signup") {
            std::string email;
            ss >> email;
            if (!email.empty()) {
                client.requestOtp(email);
                std::cout << "OTP requested for " << email << ".\n";
            } else {
                std::cout << "Usage: /signup <email>\n";
            }
        } else if (cmd == "/verify") {
            std::string email, otp;
            ss >> email >> otp;
            if (!email.empty() && !otp.empty()) {
                client.verifyOtp(email, otp);
            } else {
                std::cout << "Usage: /verify <email> <otp>\n";
            }
        } else if (cmd == "/register") {
            std::string email, number, user, password;
            ss >> email >> number >> user >> password;
            if (!email.empty() && !number.empty() && !user.empty() && !password.empty()) {
                client.signup(email, number, user, password);
            } else {
                std::cout << "Usage: /register <email> <number> <username> <password>\n";
            }
        } else if (cmd == "/login") {
            std::string identifier, password;
            ss >> identifier >> password;
            if (!identifier.empty() && !password.empty()) {
                client.login(identifier, password);
            } else {
                std::cout << "Usage: /login <identifier> <password>\n";
            }
        } 
        else if(cmd=="/connect"){
            client.reconnectWithToken();
        }
        else if (cmd == "/msg") {
            std::string receiver, msg;
            ss >> receiver;
            std::getline(ss, msg);
            if (!receiver.empty() && !msg.empty()) {
                if (msg[0] == ' ') msg.erase(0, 1);
                client.sendPrivateMessage(receiver, msg);
            }
        } else if (cmd == "/gmsg") {
            std::string groupId, msg;
            ss >> groupId;
            std::getline(ss, msg);
            if (!groupId.empty() && !msg.empty()) {
                if (msg[0] == ' ') msg.erase(0, 1);
                client.sendGroupMessage(groupId, msg);
            }
        } else if (cmd == "/create") {
            std::string g;
            ss >> g;
            if (!g.empty()) client.createGroup(g);
        } else if (cmd == "/join") {
            std::string g;
            ss >> g;
            if (!g.empty()) client.joinGroup(g);
        } else if (cmd == "/leave") {
            std::string g;
            ss >> g;
            if (!g.empty()) client.leaveGroup(g);
        } else if (cmd == "/sendfile") {
            std::string receiver, filepath;
            ss >> receiver;
            std::getline(ss, filepath);
            if (!receiver.empty() && !filepath.empty()) {
                if (filepath[0] == ' ') filepath.erase(0, 1);
                client.sendFile(receiver, filepath);
            }
        } else if (cmd == "/download") {
            std::string uploadId;
            ss >> uploadId;
            if (!uploadId.empty()) client.downloadFile(uploadId);
        } else {
            std::cout << "Unknown command. Type /help for help.\n";
        }
    }

    client.disconnect();
    WSACleanup();
    return 0;
}