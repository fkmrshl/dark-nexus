#pragma once
#ifndef DARK_NEXUS_LOGGER_H
#define DARK_NEXUS_LOGGER_H

#include <string>

enum class LogLevel { DEBUG, INFO, WARN, ERROR };

class Logger {
public:
    static Logger& get();
    void init(const std::string& path, LogLevel min = LogLevel::INFO);
    void log(LogLevel lv, const std::string& mod, const std::string& msg);
private:
    Logger() = default;
};

#define LOG_INFO(mod,msg)  Logger::get().log(LogLevel::INFO,  mod, msg)
#define LOG_WARN(mod,msg)  Logger::get().log(LogLevel::WARN,  mod, msg)
#define LOG_ERR(mod,msg)   Logger::get().log(LogLevel::ERROR, mod, msg)

#endif
