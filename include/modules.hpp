#ifndef MODULES_HPP
#define MODULES_HPP

#include "core.hpp"

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
    static const char* lvstr(LogLevel l);
    static std::string esc(const std::string& s);
};

#define LOG_INFO(mod,msg)  Logger::get().log(LogLevel::INFO,  mod, msg)
#define LOG_WARN(mod,msg)  Logger::get().log(LogLevel::WARN,  mod, msg)
#define LOG_ERR(mod,msg)   Logger::get().log(LogLevel::ERROR, mod, msg)

class ThreadPool {
public:
    explicit ThreadPool(size_t n = std::thread::hardware_concurrency())
        : stop_(false)
    {
        if (n == 0) n = 4;
        for (size_t i = 0; i < n; ++i) {
            workers_.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lk(mtx_);
                        cv_.wait(lk, [this]{ return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    active_++;
                    task();
                    active_--;
                    done_cv_.notify_all();
                }
            });
        }
    }

    template<class F, class... Args>
    auto submit(F&& f, Args&&... args)
        -> std::future<typename std::invoke_result<F,Args...>::type>
    {
        using R = typename std::invoke_result<F,Args...>::type;
        auto task = std::make_shared<std::packaged_task<R()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...));
        auto fut = task->get_future();
        { std::lock_guard<std::mutex> lk(mtx_); tasks_.emplace([task]{ (*task)(); }); }
        cv_.notify_one();
        return fut;
    }

    void wait() {
        std::unique_lock<std::mutex> lk(mtx_);
        done_cv_.wait(lk, [this]{ return tasks_.empty() && active_ == 0; });
    }

    ~ThreadPool() {
        { std::unique_lock<std::mutex> lk(mtx_); stop_ = true; }
        cv_.notify_all();
        for (auto& w : workers_) w.join();
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex mtx_;
    std::condition_variable cv_, done_cv_;
    std::atomic<bool> stop_;
    std::atomic<int>  active_{0};
};

void port_scan(const std::string& ip, int start, int end);
void net_scan(const std::string& subnet);
void os_detect(const std::string& ip);
void ip_intel(const std::string& ip);
void dns_lookup(const std::string& ip);
void whois_lookup(const std::string& target);
void osint_scan(const std::string& username);
void traceroute(const std::string& target);
void subdomain_scan(const std::string& domain);
void full_recon(const std::string& target);

std::string safe_exec(const std::vector<std::string>& args, int t = 8);
std::string safe_curl(const std::string& url, int t = 8);
std::string resolve(const std::string& host);
std::string sanitize(const std::string& s);
void draw_progress(int done, int total, const std::string& label);
void print_header(const std::string& title);
void print_row(const std::string& label, const std::string& val);

#endif
