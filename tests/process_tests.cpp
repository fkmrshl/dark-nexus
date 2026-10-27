#include "process.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace {
int failures = 0, checks = 0;
void check(bool value, const char* description) {
    ++checks;
    if (!value) { ++failures; std::cerr << "FAIL: " << description << '\n'; }
}

int helper(int argc, char** argv) {
    const std::string mode = argv[1];
    if (mode == "normal") { std::cout << "output"; std::cerr << "diagnostic"; return 7; }
    if (mode == "argument") { std::cout << argv[2]; return 0; }
    if (mode == "stdin") { char c; return read(0, &c, 1) == 0 ? 0 : 2; }
    if (mode == "closed") { close(1); close(2); usleep(5000000); return 0; }
    if (mode == "flood") {
        const std::string data(8192, 'x');
        for (;;) {
            if (write(1, data.data(), data.size()) < 0) return 0;
            if (write(2, data.data(), data.size()) < 0) return 0;
        }
    }
    if (mode == "marker") { std::ofstream(argv[2]) << "executed"; return 0; }
    if (mode == "grandchild" || mode == "background") {
        const pid_t child = fork();
        if (child < 0) return 3;
        if (child == 0) {
            if (mode == "background") { close(1); close(2); }
            usleep(900000);
            std::ofstream(argv[2]) << "orphan";
            _exit(0);
        }
        if (mode == "background") return 0;
        usleep(5000000);
        return 0;
    }
    if (mode == "closed-parent") {
        // The process utility must work even when pipe() can return fd 0/1/2.
        close(0); close(1); close(2);
        const auto result = run_process({argv[0], "argument", "nested"}, 1000);
        return result.code == 0 && result.out == "nested" ? 0 : 4;
    }
    (void)argc;
    return 5;
}

std::size_t descriptors() {
    return std::distance(std::filesystem::directory_iterator("/proc/self/fd"),
                         std::filesystem::directory_iterator{});
}
} // namespace

int main(int argc, char** argv) {
    if (argc > 1) return helper(argc, argv);
    const auto binary = std::filesystem::canonical("/proc/self/exe").string();
    char pattern[] = "/tmp/dark-nexus-process-XXXXXX";
    const char* temporary = mkdtemp(pattern);
    if (!temporary) return 1;
    const std::filesystem::path root(temporary);
    const auto before = descriptors();

    auto result = run_process({binary, "normal"}, 1000);
    check(result.code == 7 && result.out == "output" && result.err == "diagnostic", "separate stdout, stderr and exit status");
    check(!result.cancelled && !result.timed_out && !result.truncated, "ordinary completion flags");
    result = run_process({binary, "argument", "$(touch BAD); --option"}, 1000);
    check(result.code == 0 && result.out == "$(touch BAD); --option", "arguments never pass through a shell");
    check(run_process({binary, "stdin"}, 1000).code == 0, "helper stdin is EOF");
    check(run_process({binary, "closed-parent"}, 2000).code == 0, "closed standard descriptors are safe");

    auto start = std::chrono::steady_clock::now();
    result = run_process({binary, "closed"}, 120);
    check(result.timed_out && result.code != 0, "deadline survives closed stdout and stderr");
    check(std::chrono::steady_clock::now() - start < std::chrono::seconds(2), "closed-stream timeout is bounded");
    start = std::chrono::steady_clock::now();
    result = run_process({binary, "flood"}, 120, nullptr, 1024);
    check(result.timed_out && result.truncated, "continuous output cannot bypass the deadline");
    check(result.out.size() <= 1024 && result.err.size() <= 1024, "both streams respect the memory cap");
    check(std::chrono::steady_clock::now() - start < std::chrono::seconds(2), "flood timeout is bounded");

    std::atomic<bool> cancel{false};
    std::thread cancellation([&] { std::this_thread::sleep_for(std::chrono::milliseconds(60)); cancel = true; });
    start = std::chrono::steady_clock::now();
    result = run_process({binary, "closed"}, 5000, &cancel);
    cancellation.join();
    check(result.cancelled && !result.timed_out, "cancellation differs from timeout");
    check(std::chrono::steady_clock::now() - start < std::chrono::seconds(2), "cancellation is prompt");
    result = run_process({binary, "marker", (root / "pre-cancelled").string()}, 1000, &cancel);
    check(result.cancelled && !std::filesystem::exists(root / "pre-cancelled"), "pre-cancelled requests spawn no helper");

    result = run_process({binary, "grandchild", (root / "grandchild").string()}, 120);
    check(result.timed_out, "timeout handles a child with descendants");
    result = run_process({binary, "background", (root / "background").string()}, 1000);
    check(result.code == 0 && !result.timed_out, "normal exit also cleans up background workers");
    std::this_thread::sleep_for(std::chrono::milliseconds(1050));
    check(!std::filesystem::exists(root / "grandchild") && !std::filesystem::exists(root / "background"), "no surviving descendant writes after cleanup");

    auto slow = std::async(std::launch::async, [&] { return run_process({binary, "closed"}, 300); });
    start = std::chrono::steady_clock::now();
    result = run_process({binary, "argument", "fast"}, 1000);
    check(result.code == 0 && result.out == "fast", "concurrent helpers have independent streams");
    check(std::chrono::steady_clock::now() - start < std::chrono::milliseconds(500), "fast helper does not inherit a slow helper's lifetime");
    check(slow.get().timed_out, "parallel slow helper retains its own deadline");
    check(run_process({(root / "missing").string()}, 1000).code == 127, "missing helper has a distinct exit status");
    std::ofstream(root / "not-executable") << "fixture";
    check(run_process({(root / "not-executable").string()}, 1000).code == 126, "non-executable helper is rejected");
    check(!run_process({}, 1000).err.empty(), "empty argv is rejected");
    check(!run_process({binary}, 0).err.empty(), "invalid timeout is rejected");
    check(descriptors() == before, "descriptors are released across success and failure paths");
    std::filesystem::remove_all(root);
    std::cout << checks << " process supervisor checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
