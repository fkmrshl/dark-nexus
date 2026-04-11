#pragma once

#include <fstream>
#include <mutex>
#include <string>
#include <chrono>
#include <ctime>

enum class LogLevel { DEBUG, INFO, WARN, ERROR };

class Logger {
public:
    static Logger& get() { static Logger l; return l; }

    void init(const std::string& path, LogLevel min = LogLevel::INFO) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (file_.is_open()) file_.close();
        file_.open(path, std::ios::app);
        min_ = min;
    }

    void log(LogLevel lv, const std::string& mod, const std::string& msg) {
        if (lv < min_) return;
        std::lock_guard<std::mutex> lk(mtx_);
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", localtime(&t));
        if (file_.is_open())
            file_ << "{\"t\":\"" << ts << "\",\"lv\":\"" << lvstr(lv)
                  << "\",\"mod\":\"" << mod << "\",\"msg\":\""
                  << esc(msg) << "\"}\n";
    }

private:
    Logger() = default;
    std::ofstream file_;
    std::mutex mtx_;
    LogLevel min_ = LogLevel::INFO;

    static const char* lvstr(LogLevel l) {
        switch(l){ case LogLevel::DEBUG: return "DBG";
                   case LogLevel::INFO:  return "INF";
                   case LogLevel::WARN:  return "WRN";
                   case LogLevel::ERROR: return "ERR"; }
        return "?";
    }
    static std::string esc(const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '"') o += "\\\"";
            else if (c == '\\') o += "\\\\";
            else if (c == 10) o += "\\n";
            else o += c;
        }
        return o;
    }
};

#define LOG_INFO(mod,msg)  Logger::get().log(LogLevel::INFO,  mod, msg)
#define LOG_WARN(mod,msg)  Logger::get().log(LogLevel::WARN,  mod, msg)
#define LOG_ERR(mod,msg)   Logger::get().log(LogLevel::ERROR, mod, msg)
