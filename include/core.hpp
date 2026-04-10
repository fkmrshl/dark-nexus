#ifndef CORE_HPP
#define CORE_HPP

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <future>
#include <queue>
#include <condition_variable>
#include <functional>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <map>
#include <set>
#include <algorithm>
#include <regex>
#include <chrono>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"
#define WHITE   "\033[97m"
#define BOLD    "\033[1m"
#define GRAY    "\033[90m"
#define DIM     "\033[2m"

extern std::mutex g_print_mtx;

struct ScanResult {
    std::string target, timestamp;
    std::vector<std::pair<int, std::string>> open_ports;
    std::vector<std::string> subdomains, osint_hits;
    std::string geo_country, geo_city, geo_isp, geo_as, os_guess;
    bool proxy = false, hosting = false;
};

extern ScanResult g_result;

class ThreadPool {
public:
    explicit ThreadPool(size_t n = std::thread::hardware_concurrency());
    ~ThreadPool();
    template<class F, class... Args>
    auto submit(F&& f, Args&&... args) -> std::future<typename std::invoke_result<F, Args...>::type> {
        using R = typename std::invoke_result<F, Args...>::type;
        auto task = std::make_shared<std::packaged_task<R()>>(std::bind(std::forward<F>(f), std::forward<Args>(args)...));
        auto fut = task->get_future();
        { std::lock_guard<std::mutex> lk(mtx_); tasks_.emplace([task] { (*task)(); }); }
        cv_.notify_one();
        return fut;
    }
    void wait();
private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mtx_;
    std::condition_variable cv_, done_cv_;
    std::atomic<bool> stop_;
    std::atomic<int> active_{0};
};

enum class LogLevel { DEBUG, INFO, WARN, ERROR };
class Logger {
public:
    static Logger& get() { static Logger l; return l; }
    void init(const std::string& path, LogLevel min = LogLevel::INFO);
    void log(LogLevel lv, const std::string& mod, const std::string& msg);
private:
    Logger() = default;
    std::ofstream file_;
    std::mutex mtx_;
    LogLevel min_ = LogLevel::INFO;
};

#define LOG_INFO(mod,msg) Logger::get().log(LogLevel::INFO, mod, msg)

#endif
