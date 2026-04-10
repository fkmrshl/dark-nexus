#include "modules.hpp"

void port_scan(const std::string& ip, int start, int end) {
    print_header("PORT SCAN: " + ip);
    ThreadPool pool(100);
    std::atomic<int> found{0}, scanned{0};
    int total = end - start + 1;

    for (int p = start; p <= end; p++) {
        pool.submit([ip, p, &found, &scanned, total] {
            if (tcp_probe(ip, p)) {
                std::lock_guard<std::mutex> lk(g_print_mtx);
                std::cout << "\r\033[K" << GREEN << "  [+] Port " << WHITE << p << RESET << "\n";
                found++;
            }
            scanned++;
            if (scanned % 10 == 0) draw_progress(scanned, total, "scanning...");
        });
    }
    pool.wait();
    std::cout << "\n";
}

void os_detect(const std::string& ip) {
    print_header("OS DETECTION: " + ip);
    bool is_win = tcp_probe(ip, 445) || tcp_probe(ip, 3389);
    bool is_nix = tcp_probe(ip, 22);
    print_row("Detection", is_win ? "Windows" : (is_nix ? "Linux/Unix" : "Unknown"));
}
