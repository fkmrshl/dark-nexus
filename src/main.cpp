#include "modules.hpp"

std::mutex g_print_mtx;
ScanResult g_result;

int main() {
    Logger::get().init("nexus.log");
    while (true) {
        std::cout << "\n" << CYAN << BOLD << "  DARK NEXUS" << RESET << " | Target: ";
        std::string target; std::cin >> target;
        if (target == "exit") break;

        std::cout << "  1. Port Scan\n  2. IP Intel\n  3. Full Recon\n  Choice: ";
        int c; std::cin >> c;

        std::string ip = resolve(target);
        if (ip.empty()) ip = target;

        if (c == 1) port_scan(ip, 1, 1024);
        else if (c == 2) ip_intel(ip);
        else if (c == 3) full_recon(ip);
    }
    return 0;
}
