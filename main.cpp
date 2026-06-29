#include <iostream>
#include <csignal>
#include "server/Server.h"
#include "utils/Logger.h"

// Global server pointer for signal handling
Server* g_server = nullptr;

void signalHandler(int signum)
{
    Logger::info("Interrupt signal (" + std::to_string(signum) + ") received");
    if (g_server) {
        g_server->stop();
    }
    exit(signum);
}

int main()
{
    const int PORT = 8080;

    Server server;
    g_server = &server;

    // Register signal handler for clean shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    Logger::info("=================================");
    Logger::info("   IOCP Chat Server v1.0");
    Logger::info("=================================");

    if (!server.start(PORT)) {
        Logger::error("Server failed to start");
        return 1;
    }

    server.stop();
    return 0;
}