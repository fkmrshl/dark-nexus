#include "modules.hpp"

void port_scan(const std::string& ip, int start, int end_port) {
    print_header("PORT SCAN: " + ip);
    ThreadPool pool(100);
    std::atomic<int> scanned{0};
    std::vector<int> target_ports;
    
    if (start == 0) {
        target_ports = {21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443};
    } else {
        for (int p = start; p <= end_port; ++p) target_ports.push_back(p);
    }

    int total = target_ports.size();
    g_result.open_ports.clear();

    for (int port : target_ports) {
        pool.submit([ip, port, &scanned, total]() {
            auto [is_open, ms] = tcp_probe_ms(ip, port, 1000);
            if (is_open) {
                std::string service = svc(port);
                std::string b = smart_banner(ip, port, 1500);
                std::string risk = risk_label(port);
                
                std::lock_guard<std::mutex> lock(g_print_mtx);
                std::cout << "\r\033[K" << CYAN << "  [+] " << WHITE << std::setw(5) << port 
                          << CYAN << " | " << std::setw(12) << service 
                          << CYAN << " | " << risk 
                          << CYAN << " | " << ms << "ms";
                if (!b.empty()) std::cout << CYAN << " | " << GRAY << b;
                std::cout << RESET << "\n";
                
                g_result.open_ports.push_back({port, service});
            }
            scanned++;
            if (scanned % 5 == 0 || scanned == total) {
                std::lock_guard<std::mutex> lock(g_print_mtx);
                draw_progress(scanned, total, "scanning ports...");
            }
        });
    }
    pool.wait();
    std::cout << "\r\033[K";
    LOG_INFO("port_scan", "completed for " + ip);
}
