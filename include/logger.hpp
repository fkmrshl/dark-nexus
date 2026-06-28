#pragma once

#include <string>
#include <mutex>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>

enum class LogLevel { DEBUG, INFO, WARN, ERROR };

class Logger {
public:
    static Logger& get() { static Logger l; return l; }

    void init(const std::string& path, LogLevel min = LogLevel::INFO) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }

        fd_ = ::open(path.c_str(),
                     O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                     0600);
        min_ = min;
    }

    void log(LogLevel lv, const std::string& mod, const std::string& msg) {
        if (lv < min_ || fd_ < 0) return;
        std::lock_guard<std::mutex> lk(mtx_);

        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", localtime(&t));

        char buf[2048];
        int n = snprintf(buf, sizeof(buf),
                         "{\"t\":\"%s\",\"lv\":\"%s\",\"mod\":\"%s\",\"msg\":\"%s\"}\n",
                         ts, lvstr(lv), mod.c_str(), esc(msg).c_str());

        if (n > 0 && n < (int)sizeof(buf)) {
            const char* data_ptr = buf;
            size_t bytes_left = static_cast<size_t>(n);

            while (bytes_left > 0) {
                ssize_t written = ::write(fd_, data_ptr, bytes_left);

                if (written < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    break;
                }

                data_ptr += written;
                bytes_left -= written;
            }
        }
    }

private:
    Logger() = default;
    int      fd_  = -1;
    std::mutex mtx_;
    LogLevel min_ = LogLevel::INFO;

    static const char* lvstr(LogLevel l) {
        switch(l) {
            case LogLevel::DEBUG: return "DBG";
            case LogLevel::INFO:  return "INF";
            case LogLevel::WARN:  return "WRN";
            case LogLevel::ERROR: return "ERR";
        }
        return "?";
    }

    static std::string esc(const std::string& s) {
        std::string o;
        o.reserve(s.size());
        for (char c : s) {
            if      (c == '"')  o += "\\\"";
            else if (c == '\\') o += "\\\\";
            else if (c == '\n') o += "\\n";
            else if (c == '\r') o += "\\r";
            else                o += c;
        }
        return o;
    }
};

#define LOG_INFO(mod,msg)  Logger::get().log(LogLevel::INFO,  mod, msg)
#define LOG_WARN(mod,msg)  Logger::get().log(LogLevel::WARN,  mod, msg)
#define LOG_ERR(mod,msg)   Logger::get().log(LogLevel::ERROR, mod, msg)
