#pragma once
#include <string>
#include <iostream>
#include <ctime>
#include <mutex>
#include <shared_mutex>  // if you want shared locking (optional)

class Logger
{
private:
    // Single mutex is sufficient and simplest for logging
    static inline std::mutex mtx;

    // Optional: Use shared_mutex if you want many readers (rarely needed for logging)
    // static inline std::shared_mutex mtx;

    static std::string timestamp()
    {
        time_t now = time(nullptr);
        char buf[32] = {};
        struct tm timeinfo;

#ifdef _WIN32
        localtime_s(&timeinfo, &now);        // Thread-safe on Windows
#else
        localtime_r(&now, &timeinfo);        // Thread-safe on Linux/macOS
#endif

        strftime(buf, sizeof(buf), "%H:%M:%S", &timeinfo);
        return std::string(buf);
    }

public:
    static void info(const std::string& msg)
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::cout << "[INFO  " << timestamp() << "] " << msg << std::endl;
    }

    static void warn(const std::string& msg)
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::cout << "[WARN  " << timestamp() << "] " << msg << std::endl;
    }

    static void error(const std::string& msg)
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::cerr << "[ERROR " << timestamp() << "] " << msg << std::endl;
    }

    // Optional: Debug level
    static void debug(const std::string& msg)
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::cout << "[DEBUG " << timestamp() << "] " << msg << std::endl;
    }
};