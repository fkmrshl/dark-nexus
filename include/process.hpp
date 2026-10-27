#pragma once

#include <atomic>
#include <cstddef>
#include <string>
#include <vector>

struct ProcessResult {
    std::string out, err;
    int code = -1;
    bool timed_out = false, cancelled = false, truncated = false;
};

// Run argv directly, with closed stdin and a separate process group. The
// deadline covers process exit as well as output. max_output caps each stream.
ProcessResult run_process(const std::vector<std::string>& args, int timeout_ms,
                          const std::atomic<bool>* cancel = nullptr,
                          std::size_t max_output = 4 * 1024 * 1024);
