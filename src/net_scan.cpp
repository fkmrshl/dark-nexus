#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"
#include "../include/os_fingerprint.hpp"

void net_scan(const std::string& subnet) {
    print_header("NETWORK SCAN // " + subnet + ".0/24");

    static const std::vector<int> PROBE_PORTS = {21,22,23,25,80,443,445,3389,8080,5985};

    std::cout << BLOOD_RED << "  phase 1: host discovery...\n" << RESET;

    struct HostInfo {
        std::string ip, hostname, os;
        std::vector<std::pair<int,std::string>> ports;
        bool alive = false;
    };

    std::vector<HostInfo> hosts(254);
    std::atomic<int> alive_c(0);

    ThreadPool pool(100);
    std::vector<std::future<void>> futs;
    futs.reserve(254);

    for (int i = 1; i <= 254; i++) {
        futs.push_back(pool.submit([&, i] {
            if (g_cancel_token.cancelled) return;
            std::string ip = subnet + "." + std::to_string(i);
            HostInfo& h = hosts[i - 1];
            h.ip = ip;

            auto pout = safe_exec({"ping", "-c1", "-W1", "-q", ip}, 2);
            bool alive = !pout.empty() && pout.find("1 received") != std::string::npos;
            if (!alive) {
                for (int p : PROBE_PORTS) {
                    if (tcp_probe(ip, p, 300)) {
                        alive = true;
                        break;
                    }
                }
            }
            if (!alive) return;

            h.alive = true;
            alive_c++;

            char hbuf[NI_MAXHOST] = {};
            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
            getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, sizeof(hbuf), nullptr, 0, 0);
            h.hostname = strlen(hbuf) ? sanitize(hbuf) : "";

            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << "\x1B[2K\r" << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(16) << ip;
            if (!h.hostname.empty()) std::cout << BLOOD_RED << " (" << WHITE << h.hostname << BLOOD_RED << ")";
            std::cout << RESET << "\n";
        }));
    }
    pool.wait();

    std::cout << BLOOD_RED << "\n  found " << WHITE << alive_c << BLOOD_RED << " hosts -- phase 2: port scan...\n\n" << RESET;

    std::vector<HostInfo*> alive_hosts;
    for (auto& h : hosts) {
        if (h.alive) alive_hosts.push_back(&h);
    }

    int ntasks = static_cast<int>(alive_hosts.size() * PROBE_PORTS.size());
    std::vector<std::future<void>> futs2;
    futs2.reserve(ntasks);
    std::mutex hosts_mtx;

    for (int i = 0; i < static_cast<int>(alive_hosts.size()); i++) {
        for (int p : PROBE_PORTS) {
            futs2.push_back(pool.submit([&, i, p] {
                auto [open, latency] = tcp_probe_ms(alive_hosts[i]->ip, p, 400);
                if (!open || latency <= 0) return;
                std::string b = banner(alive_hosts[i]->ip, p, 1000);
                std::lock_guard<std::mutex> lk(hosts_mtx);
                alive_hosts[i]->ports.emplace_back(p, b);
            }));
        }
    }
    pool.wait();

    std::cout << BLOOD_RED << "  results:\n\n" << RESET;
    int total_open = 0;
    for (auto* h : alive_hosts) {
        std::sort(h->ports.begin(), h->ports.end());
        std::vector<int> op;
        for (auto& [p, _] : h->ports) op.push_back(p);
        h->os = guess_os_from_ports(op);

        std::cout << BLOOD_RED << "  ┌─ " << WHITE << std::left << std::setw(16) << h->ip;
        if (!h->hostname.empty()) std::cout << BLOOD_RED << " [" << WHITE << h->hostname << BLOOD_RED << "]";
        std::cout << BLOOD_RED << "  os: " << WHITE << h->os << RESET << "\n";

        if (h->ports.empty()) std::cout << BLOOD_RED << "  │  " << WHITE << "no open ports\n" << RESET;
        for (auto& [p, b] : h->ports) {
            std::cout << BLOOD_RED << "  │  " << WHITE << std::setw(6) << p << " " << std::setw(18) << svc(p);
            if (!b.empty()) std::cout << "  " << sanitize(b);
            std::cout << RESET << "\n";
            total_open++;
        }
        std::cout << BLOOD_RED << "  └" << std::string(36, '-') << RESET << "\n";
    }

    std::cout << "\n" << BLOOD_RED << "  hosts alive: " << WHITE << alive_c << BLOOD_RED << "  open ports: " << WHITE << total_open << "\n" << RESET;
    LOG_INFO("net_scan", "done subnet=" + subnet + " alive=" + std::to_string(alive_c));
}
