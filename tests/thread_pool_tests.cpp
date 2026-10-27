#include "thread_pool.hpp"
#include <iostream>
#include <stdexcept>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    const pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        const rlimit limit{256 * 1024 * 1024, 256 * 1024 * 1024};
        if (setrlimit(RLIMIT_AS, &limit) != 0) _exit(2);
        try { ThreadPool excessive(512); }
        catch (const std::exception&) { _exit(0); }
        _exit(3);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::cerr << "thread pool construction failure did not clean up workers\n";
        return 1;
    }
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
