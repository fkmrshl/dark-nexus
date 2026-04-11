#pragma once

#include <thread>
#include <mutex>
#include <atomic>
#include <future>
#include <queue>
#include <condition_variable>
#include <functional>
#include <vector>

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
