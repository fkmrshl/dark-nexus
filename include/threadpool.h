#pragma once
#ifndef DARK_NEXUS_THREADPOOL_H
#define DARK_NEXUS_THREADPOOL_H

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>

class ThreadPool {
public:
    explicit ThreadPool(size_t n = std::thread::hardware_concurrency());
    template<class F, class... Args>
    auto submit(F&& f, Args&&... args) -> std::future<typename std::invoke_result<F,Args...>::type>;
    void wait();
    ~ThreadPool();
private:
};

#endif
