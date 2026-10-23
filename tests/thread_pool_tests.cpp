#include "thread_pool.hpp"
#include <iostream>
#include <stdexcept>

int main() {
    ThreadPool pool(4);
    for (int pass = 0; pass < 200; ++pass) {
        std::atomic<int> finished{0};
        for (int i = 0; i < 50; ++i) pool.submit([&finished] { ++finished; });
        pool.wait();
        if (finished != 50) { std::cerr << "wait returned before all tasks finished\n"; return 1; }
    }
    auto failure = pool.submit([]() -> int { throw std::runtime_error("expected"); });
    pool.wait();
    try { failure.get(); return 1; } catch (const std::runtime_error&) {}
    std::cout << "thread pool completion and exception checks passed\n";
}
