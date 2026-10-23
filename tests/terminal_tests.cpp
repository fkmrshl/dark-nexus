#include "colors.hpp"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

int main() {
    // These captures outlive the terminal session installed by configure().
    static std::ostringstream captured_out;
    static std::ostringstream captured_err;
    std::cout.rdbuf(captured_out.rdbuf());
    std::cerr.rdbuf(captured_err.rdbuf());

    terminal::configure(terminal::ColorMode::Never);
    assert(!terminal::color_enabled());
    assert(!terminal::interactive());
    assert(std::string(CYAN).empty());
    assert(terminal::stdout_buffer() == captured_out.rdbuf());
    std::cout << "ordinary\n" << CYAN << "result" << RESET << '\n';
    std::cout << "\033[2K\r" << "open port 443\n";
    std::cout << "\033" << "[31" << "mred\033[0m\n";
    std::cout << "\033]0;window title\007" << "visible\n";
    std::cout << "\033]8;;https://example.test\033\\link\033]8;;\033\\\n";
    std::cout << "status\r" << "result after status\n";
    std::cout << "CRLF\r\n";
    assert(captured_out.str() ==
        "ordinary\nresult\nopen port 443\nred\nvisible\nlink\nstatus\nresult after status\nCRLF\n");
    std::cerr << "\033[31merror\033[0m\n";
    assert(captured_err.str() == "error\n");

    captured_out.str("");
    terminal::configure(terminal::ColorMode::Always);
    assert(terminal::color_enabled());
    std::cout << CYAN << "accent" << RESET << '\n';
    assert(captured_out.str() == "\033[36maccent\033[0m\n");
    if (!isatty(STDOUT_FILENO)) {
        assert(!terminal::interactive());
        captured_out.str("");
        std::cout << "\033[2K\r" << "result\n";
        assert(captured_out.str() == "result\n");
    }

    setenv("NO_COLOR", "", 1);
    terminal::configure(terminal::ColorMode::Auto);
    assert(!terminal::color_enabled());
    terminal::configure(terminal::ColorMode::Always);
    assert(terminal::color_enabled());
    unsetenv("NO_COLOR");
    setenv("TERM", "dumb", 1);
    terminal::configure(terminal::ColorMode::Auto);
    assert(!terminal::color_enabled());

    // Structured output writes through the original buffer without alteration.
    captured_out.str("");
    std::ostream report(terminal::stdout_buffer());
    report << "\"embedded\r\nline\",value\r\n";
    assert(captured_out.str() == "\"embedded\r\nline\",value\r\n");

    // A complete module write is serialized even when several workers emit
    // ANSI-wrapped results concurrently. Every result must survive exactly once.
    captured_out.str("");
    std::vector<std::thread> workers;
    for (int worker = 0; worker < 4; ++worker) {
        workers.emplace_back([worker] {
            for (int row = 0; row < 100; ++row) {
                const std::string result = "\033[36mworker=" + std::to_string(worker) +
                    " row=" + std::to_string(row) + "\033[0m\n";
                std::cout << result;
            }
        });
    }
    for (auto& worker : workers) worker.join();
    std::istringstream results(captured_out.str());
    std::string row;
    std::vector<std::string> lines;
    while (std::getline(results, row)) lines.push_back(row);
    std::sort(lines.begin(), lines.end());
    std::vector<std::string> expected;
    for (int worker = 0; worker < 4; ++worker)
        for (int row_number = 0; row_number < 100; ++row_number)
            expected.push_back("worker=" + std::to_string(worker) + " row=" + std::to_string(row_number));
    std::sort(expected.begin(), expected.end());
    assert(lines == expected);
    return 0;
}
