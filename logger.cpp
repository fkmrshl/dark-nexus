#include "modules.hpp"

void Logger::init(const std::string& path, LogLevel min) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (file_.is_open()) file_.close();
    file_.open(path, std::ios::app);
    min_ = min;
}

void Logger::log(LogLevel lv, const std::string& mod, const std::string& msg) {
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

const char* Logger::lvstr(LogLevel l) {
    switch(l){ 
        case LogLevel::DEBUG: return "DBG";
        case LogLevel::INFO:  return "INF";
        case LogLevel::WARN:  return "WRN";
        case LogLevel::ERROR: return "ERR"; 
    }
    return "?";
}

std::string Logger::esc(const std::string& s) {
    std::string o; 
    for(char c : s) { 
        if(c=='"') o+="\\\""; 
        else if(c=='\\') o+="\\\\"; 
        else if(c==10) o+="\\n"; 
        else o+=c; 
    } 
    return o;
}
