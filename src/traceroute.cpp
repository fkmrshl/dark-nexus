#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

class TracerouteEngine {
public:
    explicit TracerouteEngine(const TraceConfig& cfg, ThreadPool& pool)
        : cfg_(cfg), pool_(pool) {}

    static uint16_t icmp_checksum(const void* data, int len) {
        auto p = reinterpret_cast<const uint16_t*>(data);
        uint32_t sum = 0;
        for (; len > 1; len -= 2) sum += *p++;
        if (len == 1) sum += *reinterpret_cast<const uint8_t*>(p);
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }

    bool resolve_target(std::string& out_ip) {
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_RAW;
        if (getaddrinfo(cfg_.target.c_str(), nullptr, &hints, &res) != 0 || !res)
            return false;
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf));
        out_ip = buf;
        freeaddrinfo(res);
        return true;
    }

    static std::string reverse_dns(const std::string& ip) {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        char host[NI_MAXHOST];
        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                        host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0)
            return host;
        return "";
    }

    static std::string as_lookup(const std::string& ip) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return "";

        uint8_t* o = reinterpret_cast<uint8_t*>(&addr.s_addr);
        std::string q = std::to_string((int)o[3]) + "." + std::to_string((int)o[2]) + "."
        + std::to_string((int)o[1]) + "." + std::to_string((int)o[0])
        + ".origin.asn.cymru.com";

        std::string result = safe_exec({"dig", "+short", "+time=1", "+tries=1", q, "TXT"}, 3);
        result = InputGuard::sanitize_output(result);
        result.erase(std::remove(result.begin(), result.end(), '"'), result.end());
        while (!result.empty() && (result.back() == '\n' || result.back() == ' '))
            result.pop_back();

        auto pipe_pos = result.find('|');
        if (pipe_pos != std::string::npos) {
            std::string asn = result.substr(0, pipe_pos);
            while (!asn.empty() && asn.back() == ' ') asn.pop_back();

            auto desc_pos = result.rfind('|');
            std::string desc = (desc_pos != std::string::npos && desc_pos != pipe_pos)
            ? result.substr(desc_pos + 1) : "";

            while (!desc.empty() && desc.front() == ' ') desc.erase(desc.begin());
            if (!asn.empty()) return "AS" + asn + (desc.empty() ? "" : " " + desc.substr(0, 30));
        }
        return "";
    }

    ProbeResult probe_icmp(int ttl, int probe_id, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl; pr.probe_id = probe_id;

        int sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_send < 0) return pr;
        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }

        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        struct timeval tv;
        tv.tv_sec  = cfg_.timeout_ms / 1000;
        tv.tv_usec = (cfg_.timeout_ms % 1000) * 1000;
        setsockopt(sock_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

        struct { struct icmphdr hdr; char data[56]; } packet{};
        packet.hdr.type             = ICMP_ECHO;
        packet.hdr.code             = 0;
        packet.hdr.un.echo.id       = htons(getpid() & 0xFFFF);
        packet.hdr.un.echo.sequence = htons((uint16_t)(ttl * 100 + probe_id));
        memset(packet.data, 0x42, sizeof(packet.data));
        packet.hdr.checksum = 0;
        packet.hdr.checksum = icmp_checksum(&packet, sizeof(packet));

        auto t_start = std::chrono::high_resolution_clock::now();
        ssize_t sent = sendto(sock_send, &packet, sizeof(packet), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent <= 0) { close(sock_send); close(sock_recv); return pr; }

        char buf[512];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);

        for (int attempts = 0; attempts < 3; attempts++) {
            ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&from, &fromlen);
            if (n <= 0) break;

            auto t_end = std::chrono::high_resolution_clock::now();
            double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();

            struct iphdr* ip_hdr = (struct iphdr*)buf;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n < ip_hdr_len + (int)sizeof(struct icmphdr)) continue;

            struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

            if (icmp_reply->type == ICMP_TIME_EXCEEDED && icmp_reply->code == ICMP_EXC_TTL) {
                pr.addr = addr_str; pr.rtt_ms = rtt;
                pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                pr.reply_ttl = ip_hdr->ttl;
                break;
            }
            if (icmp_reply->type == ICMP_ECHOREPLY) {
                uint16_t recv_id = ntohs(icmp_reply->un.echo.id);
                if (recv_id == (uint16_t)(getpid() & 0xFFFF)) {
                    pr.addr = addr_str; pr.rtt_ms = rtt;
                    pr.reached_target = true;
                    pr.icmp_type = icmp_reply->type; pr.reply_ttl = ip_hdr->ttl;
                    break;
                }
            }
            if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED) {
                pr.addr = addr_str; pr.rtt_ms = rtt;
                pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                pr.mtu_suggestion = ntohs(icmp_reply->un.frag.mtu);
                break;
            }
        }

        close(sock_send); close(sock_recv);
        if (cfg_.resolve_dns && !pr.addr.empty()) pr.hostname = reverse_dns(pr.addr);
        return pr;
    }

    ProbeResult probe_udp(int ttl, int probe_id, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl; pr.probe_id = probe_id;

        int sock_send = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_send < 0) return pr;
        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }

        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        struct timeval tv;
        tv.tv_sec  = cfg_.timeout_ms / 1000;
        tv.tv_usec = (cfg_.timeout_ms % 1000) * 1000;
        setsockopt(sock_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(cfg_.dst_port + ttl + probe_id);
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

        char payload[32];
        memset(payload, 0x42, sizeof(payload));

        auto t_start = std::chrono::high_resolution_clock::now();
        sendto(sock_send, payload, sizeof(payload), 0,
               (struct sockaddr*)&dest, sizeof(dest));

        char buf[512];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                             (struct sockaddr*)&from, &fromlen);
        if (n > 0) {
            auto t_end = std::chrono::high_resolution_clock::now();
            double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();

            struct iphdr* ip_hdr = (struct iphdr*)buf;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n >= ip_hdr_len + (int)sizeof(struct icmphdr)) {
                struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

                pr.addr = addr_str; pr.rtt_ms = rtt;
                pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                pr.reply_ttl = ip_hdr->ttl;

                if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_PORT_UNREACH)
                    pr.reached_target = true;
                if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED)
                    pr.mtu_suggestion = ntohs(icmp_reply->un.frag.mtu);
            }
        }

        close(sock_send); close(sock_recv);
        if (cfg_.resolve_dns && !pr.addr.empty()) pr.hostname = reverse_dns(pr.addr);
        return pr;
    }

    ProbeResult probe_tcp_syn(int ttl, int probe_id, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl; pr.probe_id = probe_id;

        int sock_send = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_send < 0) return pr;
        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }

        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        struct timeval tv;
        tv.tv_sec  = cfg_.timeout_ms / 1000;
        tv.tv_usec = (cfg_.timeout_ms % 1000) * 1000;
        setsockopt(sock_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(80);
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

        fcntl(sock_send, F_SETFL, O_NONBLOCK);
        auto t_start = std::chrono::high_resolution_clock::now();
        connect(sock_send, (struct sockaddr*)&dest, sizeof(dest));

        char buf[512];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                             (struct sockaddr*)&from, &fromlen);
        if (n > 0) {
            auto t_end = std::chrono::high_resolution_clock::now();
            double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();

            struct iphdr* ip_hdr = (struct iphdr*)buf;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n >= ip_hdr_len + (int)sizeof(struct icmphdr)) {
                struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

                pr.addr = addr_str; pr.rtt_ms = rtt;
                pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                pr.reply_ttl = ip_hdr->ttl;

                if (pr.addr == target_ip) pr.reached_target = true;
            }
        } else {
            fd_set wfds; FD_ZERO(&wfds); FD_SET(sock_send, &wfds);
            struct timeval stv{0, 10000};
            if (select(sock_send + 1, nullptr, &wfds, nullptr, &stv) > 0) {
                auto t_end = std::chrono::high_resolution_clock::now();
                double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();
                pr.addr = target_ip; pr.rtt_ms = rtt; pr.reached_target = true;
            }
        }

        close(sock_send); close(sock_recv);
        if (cfg_.resolve_dns && !pr.addr.empty()) pr.hostname = reverse_dns(pr.addr);
        return pr;
    }

    std::vector<HopStats> run(const std::string& target_ip) {
        std::vector<HopStats> hops;
        bool reached = false;

        for (int base = 1; base <= cfg_.max_hops && !reached; base += cfg_.parallel_hops) {
            int end   = std::min(base + cfg_.parallel_hops - 1, cfg_.max_hops);
            int count = end - base + 1;

            std::vector<std::vector<ProbeResult>> results(count,
                std::vector<ProbeResult>(cfg_.queries_per_hop));

            std::vector<std::future<void>> futs;
            futs.reserve(count * cfg_.queries_per_hop);

            for (int h = 0; h < count; h++) {
                for (int p = 0; p < cfg_.queries_per_hop; p++) {
                    int ttl = base + h;
                    int pid = p;
                    int hi  = h;
                    futs.push_back(pool_.submit([this, ttl, pid, hi, p,
                                                  &results, &target_ip] {
                        ProbeResult pr;
                        switch (cfg_.protocol) {
                            case TraceConfig::ICMP:    pr = probe_icmp(ttl, pid, target_ip);    break;
                            case TraceConfig::UDP:     pr = probe_udp(ttl, pid, target_ip);     break;
                            case TraceConfig::TCP_SYN: pr = probe_tcp_syn(ttl, pid, target_ip); break;
                        }
                        results[hi][p] = pr;
                    }));
                }
            }
            for (auto& f : futs) f.get();

            for (int h = 0; h < count; h++) {
                HopStats hs;
                hs.ttl  = base + h;
                hs.sent = cfg_.queries_per_hop;

                for (auto& pr : results[h]) {
                    if (pr.rtt_ms >= 0) {
                        hs.rtts.push_back(pr.rtt_ms);
                        hs.received++;
                        if (hs.addr.empty()) { hs.addr = pr.addr; hs.hostname = pr.hostname; }
                        if (pr.reached_target) { hs.is_target = true; reached = true; }
                        if (pr.mtu_suggestion > 0 && cfg_.detect_mtu) hs.mtu = pr.mtu_suggestion;
                    }
                }
                hs.compute();

                if (!hs.addr.empty() && cfg_.as_lookup)
                    hs.asn_info = as_lookup(hs.addr);

                hops.push_back(hs);
                if (hs.is_target) break;
            }
        }
        return hops;
    }

private:
    const TraceConfig& cfg_;
    ThreadPool& pool_;
};

static std::string rtt_bar(double rtt_ms) {
    if (rtt_ms < 0) return std::string(GRAY) + "         " + RESET;
    int buckets[] = {5, 15, 30, 60, 100, 200, 500, 1000, 2000};
    int idx = 0;
    for (int b : buckets) { if (rtt_ms < b) break; idx++; }
    const char* colors[] = {GREEN, GREEN, CYAN, CYAN, YELLOW, YELLOW, RED, RED, RED, RED};
    std::string bar = colors[idx];
    bar += std::string(std::min(idx + 1, 9), '|');
    bar += std::string(std::max(0, 9 - idx - 1), ' ');
    bar += RESET;
    return bar;
}

static const char* proto_label(TraceConfig::Protocol p) {
    switch (p) {
        case TraceConfig::ICMP:    return "ICMP Echo";
        case TraceConfig::UDP:     return "UDP";
        case TraceConfig::TCP_SYN: return "TCP SYN :80";
    }
    return "?";
}

void traceroute(const std::string& target) {
    print_header("ADVANCED TRACEROUTE // " + target);

    TraceConfig cfg;
    cfg.target = target;

    std::cout << YELLOW << "\n  protocol: [0] ALL  [1] ICMP  [2] UDP  [3] TCP-SYN  (default=1): " << RESET;
    std::string pc;
    std::getline(std::cin >> std::ws, pc);
    bool all_modes = (pc == "0");
    if      (pc == "2") cfg.protocol = TraceConfig::UDP;
    else if (pc == "3") cfg.protocol = TraceConfig::TCP_SYN;
    else                cfg.protocol = TraceConfig::ICMP;

    std::cout << YELLOW << "  probes/hop (default=5): " << RESET;
    std::string qc;
    std::getline(std::cin >> std::ws, qc);
    if (!qc.empty()) {
        try { cfg.queries_per_hop = std::max(1, std::min(10, std::stoi(qc))); } catch (...) {}
    }

    std::string target_ip;
    {
        target_ip = resolve(target);
        if (target_ip.empty()) {
            if (inet_addr(target.c_str()) != INADDR_NONE)
                target_ip = target;
            else {
                std::cout << RED << "  could not resolve " << target << "\n" << RESET;
                return;
            }
        }
    }

    auto run_pass = [&](TraceConfig::Protocol proto) -> std::vector<HopStats> {
        TraceConfig pcfg = cfg;
        pcfg.protocol = proto;

        std::cout << "\n" << CYAN << "  target:   " << WHITE << target_ip << "\n"
                  << CYAN << "  protocol: " << BOLD << WHITE << proto_label(proto) << "\n" << RESET
                  << CYAN << "  probes:   " << WHITE << pcfg.queries_per_hop << "/hop\n"
                  << CYAN << "  max hops: " << WHITE << pcfg.max_hops << "\n"
                  << CYAN << "  parallel: " << WHITE << pcfg.parallel_hops << " hops at once\n"
                  << RESET << "\n";

        std::cout << BOLD << WHITE
                  << "  HOP  ADDRESS           HOSTNAME                  "
                     "AVG      MIN      MAX      JITTER   LOSS  AS INFO\n"
                  << "  " << std::string(110, '-') << "\n" << RESET;

        ThreadPool pool(pcfg.parallel_hops * pcfg.queries_per_hop);
        TracerouteEngine engine(pcfg, pool);
        return engine.run(target_ip);
    };

    std::vector<std::pair<TraceConfig::Protocol, std::vector<HopStats>>> all_results;

    if (all_modes) {
        for (auto proto : {TraceConfig::ICMP, TraceConfig::UDP, TraceConfig::TCP_SYN}) {
            print_section(std::string("PASS // ") + proto_label(proto));
            all_results.push_back({proto, run_pass(proto)});
        }
    } else {
        all_results.push_back({cfg.protocol, run_pass(cfg.protocol)});
    }

    auto hops = all_results[0].second;

    for (auto& hs : hops) {
        std::cout << CYAN << "  " << std::setw(3) << hs.ttl << "  ";

        if (hs.received == 0) {
            std::cout << YELLOW << std::left << std::setw(18) << "*"
                      << std::setw(27) << "request timeout"
                      << GRAY  << std::string(36, ' ')
                      << RED   << "100%"
                      << RESET << "\n";
            continue;
        }

        std::string display_ip   = hs.addr;
        std::string display_host = hs.hostname.empty() ? "" : hs.hostname;
        if (display_host.size() > 26) display_host = display_host.substr(0, 23) + "...";

        std::cout << (hs.is_target ? GREEN : WHITE)
                  << std::left << std::setw(18) << display_ip
                  << CYAN      << std::setw(27) << sanitize(display_host);

        auto fmt_ms = [](double ms) -> std::string {
            if (ms < 0) return "*       ";
            std::ostringstream ss;
            ss << std::fixed << std::setprecision(1) << ms << "ms";
            return ss.str();
        };

        std::cout << YELLOW << std::setw(9) << fmt_ms(hs.avg_rtt)
                  << GREEN  << std::setw(9) << fmt_ms(hs.min_rtt)
                  << RED    << std::setw(9) << fmt_ms(hs.max_rtt);

        if (cfg.show_jitter)
            std::cout << CYAN << std::setw(9) << fmt_ms(hs.jitter);

        if (cfg.show_loss) {
            std::string loss_str = std::to_string((int)hs.loss_pct) + "%";
            std::cout << (hs.loss_pct > 0 ? RED : GREEN) << std::setw(6) << loss_str;
        }

        if (hs.mtu > 0)
            std::cout << MAGENTA << "  MTU:" << hs.mtu;

        if (!hs.asn_info.empty())
            std::cout << GRAY << "  " << hs.asn_info.substr(0, 28);

        std::cout << "  " << rtt_bar(hs.avg_rtt);
        std::cout << RESET << "\n";

        if (hs.is_target)
            std::cout << "\n" << GREEN << BOLD << "  [+] destination reached in " << hs.ttl << " hops\n" << RESET;
    }

    print_section("TRACE SUMMARY");

    if (!hops.empty()) {
        double total_latency = 0;
        int    total_loss    = 0;
        int    total_hops    = hops.size();
        int    timeout_hops  = 0;
        double max_jitter    = 0;
        std::string worst_hop;

        for (auto& hs : hops) {
            if (hs.received == 0) { timeout_hops++; continue; }
            total_latency += hs.avg_rtt;
            if (hs.loss_pct > 0) total_loss++;
            if (hs.jitter > max_jitter) { max_jitter = hs.jitter; worst_hop = hs.addr; }
        }

        auto& last = hops.back();
        std::cout << CYAN  << "  [hops]          " << WHITE << total_hops << "\n" << RESET;
        std::cout << CYAN  << "  [total RTT]     " << WHITE << std::fixed << std::setprecision(1)
                  << total_latency << "ms\n" << RESET;
        std::cout << CYAN  << "  [timeout hops]  " << (timeout_hops > 0 ? YELLOW : GREEN)
                  << timeout_hops << "\n" << RESET;
        std::cout << CYAN  << "  [hops w/ loss]  " << (total_loss > 0 ? RED : GREEN)
                  << total_loss << "\n" << RESET;
        if (max_jitter > 0)
            std::cout << CYAN << "  [worst jitter]  " << WHITE
                      << std::fixed << std::setprecision(1) << max_jitter << "ms  "
                      << GRAY << "@ " << worst_hop << "\n" << RESET;
        std::cout << CYAN  << "  [reached]       "
                  << (last.is_target ? GREEN "yes" : RED "no (TTL exhausted)")
                  << "\n" << RESET;

        std::cout << "\n";
        double avg_rtt = (total_hops > 0) ? total_latency / total_hops : 0;
        if      (avg_rtt < 20 && total_loss == 0 && timeout_hops == 0)
            std::cout << GREEN  << BOLD << "  [quality] EXCELLENT -- low latency, no loss\n" << RESET;
        else if (avg_rtt < 80 && total_loss <= 1)
            std::cout << GREEN  << "  [quality] GOOD -- acceptable path\n" << RESET;
        else if (avg_rtt < 200 || total_loss <= 2)
            std::cout << YELLOW << "  [quality] FAIR -- some congestion or loss detected\n" << RESET;
        else
            std::cout << RED    << "  [quality] POOR -- high latency or significant loss\n" << RESET;
    }

    if (all_modes && all_results.size() > 1) {
        print_section("PROTOCOL COMPARISON");
        std::cout << "\n" << BOLD << WHITE
                  << "  " << std::left << std::setw(12) << "PROTOCOL"
                  << std::setw(8)  << "HOPS"
                  << std::setw(12) << "TOTAL RTT"
                  << std::setw(10) << "AVG/HOP"
                  << std::setw(10) << "TIMEOUTS"
                  << std::setw(8)  << "REACHED"
                  << "QUALITY\n"
                  << "  " << std::string(80, '-') << "\n" << RESET;

        for (auto& [proto, ph] : all_results) {
            double total_rtt = 0; int timeouts = 0; bool reached = false; int valid = 0;
            for (auto& h : ph) {
                if (h.received == 0) { timeouts++; continue; }
                total_rtt += h.avg_rtt; valid++;
                if (h.is_target) reached = true;
            }
            double avg_per_hop = valid > 0 ? total_rtt / valid : 0;
            std::string quality; const char* qcolor;
            if      (avg_per_hop < 20 && timeouts == 0) { quality = "EXCELLENT"; qcolor = GREEN; }
            else if (avg_per_hop < 80 && timeouts <= 1)  { quality = "GOOD";      qcolor = GREEN; }
            else if (avg_per_hop < 200 || timeouts <= 2) { quality = "FAIR";      qcolor = YELLOW;}
            else                                          { quality = "POOR";      qcolor = RED;   }

            std::cout << "  " << CYAN  << std::left << std::setw(12) << proto_label(proto)
                      << WHITE << std::setw(8)  << ph.size()
                      << YELLOW<< std::setw(12) << (std::to_string((int)total_rtt) + "ms")
                      << CYAN  << std::setw(10) << (std::to_string((int)avg_per_hop) + "ms")
                      << (timeouts > 0 ? RED : GRAY) << std::setw(10) << timeouts
                      << (reached ? GREEN : RED) << std::setw(8) << (reached ? "yes" : "no")
                      << qcolor << quality << RESET << "\n";
        }
    }

    LOG_INFO("traceroute", "done target=" + target + " hops=" + std::to_string(hops.size()));
}

void full_recon(const std::string& ip) {
    std::cout << "\n" << MAGENTA << BOLD
              << "  +" << std::string(56,'=') << "+\n"
              << "  |  FULL RECON // " << std::left << std::setw(40) << ip << "|\n"
              << "  +" << std::string(56,'=') << "+\n" << RESET;
    ip_intel(ip);
    dns_lookup(ip);
    os_detect(ip);
    port_scan(ip, 0, 0);
}
