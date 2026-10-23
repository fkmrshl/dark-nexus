#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

static std::atomic<uint16_t> g_probe_counter{1};

class TracerouteEngine {
public:
    explicit TracerouteEngine(const TraceConfig& cfg, ThreadPool& pool, CancellationToken& cancel_token)
    : cfg_(cfg), pool_(pool), cancel_token_(cancel_token) {}

    static void configure_mtu(int socket, bool enabled) {
#ifdef IP_MTU_DISCOVER
        int mode = enabled ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
        setsockopt(socket, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode));
#else
        (void)socket;
        (void)enabled;
#endif
    }

    // ICMP errors quote an IP header and at least eight transport bytes. Check
    // every length before dereferencing and correlate the original destination.
    static const char* quoted_transport(const char* packet, ssize_t length,
                                        int outer_header_length, int protocol,
                                        const std::string& target_ip) {
        const int offset = outer_header_length + sizeof(struct icmphdr);
        if (length < offset + static_cast<int>(sizeof(struct iphdr))) return nullptr;
        const auto* original = reinterpret_cast<const struct iphdr*>(packet + offset);
        if (original->version != 4 || original->ihl < 5 || original->protocol != protocol)
            return nullptr;
        const int original_length = original->ihl * 4;
        if (length < offset + original_length + 8) return nullptr;
        struct in_addr destination{};
        if (inet_pton(AF_INET, target_ip.c_str(), &destination) != 1 ||
            original->daddr != destination.s_addr) return nullptr;
        return packet + offset + original_length;
    }

    static uint16_t checksum(const void* data, int len) {
        auto p = reinterpret_cast<const uint16_t*>(data);
        uint32_t sum = 0;
        for (; len > 1; len -= 2) sum += *p++;
        if (len == 1) sum += *reinterpret_cast<const uint8_t*>(p);
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }

    struct pseudo_header {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    };

    static uint16_t tcp_checksum(const struct pseudo_header* ph, const struct tcphdr* tcph) {
        uint32_t sum = 0;

        auto p = reinterpret_cast<const uint16_t*>(ph);
        for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) sum += *p++;

        p = reinterpret_cast<const uint16_t*>(tcph);
        for (size_t i = 0; i < sizeof(struct tcphdr) / 2; i++) sum += *p++;

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }

    bool resolve_target(std::string& out_ip) {
        std::string target_copy = cfg_.target;
        auto future = pool_.submit([target_copy]() -> std::string {
            struct addrinfo hints{}, *res = nullptr;
            hints.ai_family   = AF_INET;
            hints.ai_socktype = SOCK_RAW;
            if (getaddrinfo(target_copy.c_str(), nullptr, &hints, &res) != 0 || !res)
                return "";
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf));
            std::string resolved = buf;
            freeaddrinfo(res);
            return resolved;
        });

        if (future.wait_for(std::chrono::seconds(2)) == std::future_status::ready) {
            out_ip = future.get();
            if (!out_ip.empty()) return true;
        }

        // Fallback to inet_aton
        struct in_addr addr;
        if (inet_aton(cfg_.target.c_str(), &addr) != 0) {
            out_ip = inet_ntoa(addr);
            return true;
        }
        return false;
    }

    std::string reverse_dns(const std::string& ip) {
        auto future = pool_.submit([ip]() -> std::string {
            struct sockaddr_in sa{};
            sa.sin_family = AF_INET;
            inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
            char host[NI_MAXHOST];
            if (getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0)
                return host;
            return "";
        });

        if (future.wait_for(std::chrono::milliseconds(cfg_.dns_timeout_ms)) == std::future_status::ready) {
            return future.get();
        }
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

    ProbeResult probe_icmp(int ttl, int _probe_id, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl;

        uint16_t probe_id = g_probe_counter.fetch_add(1, std::memory_order_relaxed);
        pr.probe_id = probe_id;

        int sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_send < 0) return pr;
        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }

        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        configure_mtu(sock_send, cfg_.detect_mtu);

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

        uint16_t seq = (uint16_t)(ttl * 100 + _probe_id);

        struct { struct icmphdr hdr; char data[56]; } packet{};
        packet.hdr.type             = ICMP_ECHO;
        packet.hdr.code             = 0;
        packet.hdr.un.echo.id       = htons(probe_id);
        packet.hdr.un.echo.sequence = htons(seq);
        memset(packet.data, 0x42, sizeof(packet.data));
        packet.hdr.checksum = 0;
        packet.hdr.checksum = checksum(&packet, sizeof(packet));

        if (cancel_token_.cancelled) { close(sock_send); close(sock_recv); return pr; }

        auto t_start = std::chrono::high_resolution_clock::now();
        ssize_t sent = sendto(sock_send, &packet, sizeof(packet), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent <= 0) { close(sock_send); close(sock_recv); return pr; }

        char buf[1500]; // MTU size to avoid truncation
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);

        auto deadline = t_start + std::chrono::milliseconds(cfg_.timeout_ms);

        while (std::chrono::high_resolution_clock::now() < deadline) {
            if (cancel_token_.cancelled) break;

            auto now = std::chrono::high_resolution_clock::now();
            auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            if (remaining_ms < 1) break;
            remaining_ms = std::min<decltype(remaining_ms)>(remaining_ms, 100);

            struct timeval tv;
            tv.tv_sec  = remaining_ms / 1000;
            tv.tv_usec = (remaining_ms % 1000) * 1000;
            setsockopt(sock_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&from, &fromlen);
            if (n <= 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (std::chrono::high_resolution_clock::now() >= deadline) break;
                    continue;
                }
                break;
            }

            auto t_end = std::chrono::high_resolution_clock::now();
            double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();

            if (n < 20) continue;
            struct iphdr* ip_hdr = (struct iphdr*)buf;
            if (ip_hdr->ihl < 5 || ip_hdr->version != 4) continue;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n < ip_hdr_len + (int)sizeof(struct icmphdr)) continue;

            struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

            if (icmp_reply->type == ICMP_TIME_EXCEEDED && icmp_reply->code == ICMP_EXC_TTL) {
                // Extract original IP + ICMP header
                const char* quoted = quoted_transport(buf, n, ip_hdr_len, IPPROTO_ICMP, target_ip);
                if (quoted) {
                    const auto* orig_icmp = reinterpret_cast<const struct icmphdr*>(quoted);
                    if (ntohs(orig_icmp->un.echo.id) == probe_id && ntohs(orig_icmp->un.echo.sequence) == seq) {
                        pr.addr = addr_str; pr.rtt_ms = rtt;
                        pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                        pr.reply_ttl = ip_hdr->ttl;
                        break;
                    }
                }
            } else if (icmp_reply->type == ICMP_ECHOREPLY) {
                if (std::string(addr_str) == target_ip && ntohs(icmp_reply->un.echo.id) == probe_id && ntohs(icmp_reply->un.echo.sequence) == seq) {
                    pr.addr = addr_str; pr.rtt_ms = rtt;
                    pr.reached_target = true;
                    pr.icmp_type = icmp_reply->type; pr.reply_ttl = ip_hdr->ttl;
                    break;
                }
            } else if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED) {
                const char* quoted = quoted_transport(buf, n, ip_hdr_len, IPPROTO_ICMP, target_ip);
                if (quoted) {
                    const auto* orig_icmp = reinterpret_cast<const struct icmphdr*>(quoted);
                    if (ntohs(orig_icmp->un.echo.id) == probe_id && ntohs(orig_icmp->un.echo.sequence) == seq) {
                        pr.addr = addr_str; pr.rtt_ms = rtt;
                        pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                        pr.mtu_suggestion = ntohs(icmp_reply->un.frag.mtu);
                        break;
                    }
                }
            }
        }

        close(sock_send); close(sock_recv);
        return pr;
    }

    ProbeResult probe_udp(int ttl, int _probe_id, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl;

        uint16_t probe_id = g_probe_counter.fetch_add(1, std::memory_order_relaxed);
        pr.probe_id = probe_id;

        int sock_send = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_send < 0) return pr;
        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }

        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        configure_mtu(sock_send, cfg_.detect_mtu);

        uint16_t dst_port = static_cast<uint16_t>(1 + (cfg_.dst_port - 1 + ttl + _probe_id) % 65535);

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(dst_port);
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

        char payload[32];
        memset(payload, 0x42, sizeof(payload));

        if (cancel_token_.cancelled) { close(sock_send); close(sock_recv); return pr; }

        auto t_start = std::chrono::high_resolution_clock::now();
        ssize_t sent = sendto(sock_send, payload, sizeof(payload), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent <= 0) { close(sock_send); close(sock_recv); return pr; }

        struct sockaddr_in local{};
        socklen_t local_size = sizeof(local);
        if (getsockname(sock_send, reinterpret_cast<struct sockaddr*>(&local), &local_size) != 0) {
            close(sock_send); close(sock_recv); return pr;
        }

        char buf[1500]; // MTU size to avoid truncation
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);

        auto deadline = t_start + std::chrono::milliseconds(cfg_.timeout_ms);

        while (std::chrono::high_resolution_clock::now() < deadline) {
            if (cancel_token_.cancelled) break;

            auto now = std::chrono::high_resolution_clock::now();
            auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            if (remaining_ms < 1) break;
            remaining_ms = std::min<decltype(remaining_ms)>(remaining_ms, 100);

            struct timeval tv;
            tv.tv_sec  = remaining_ms / 1000;
            tv.tv_usec = (remaining_ms % 1000) * 1000;
            setsockopt(sock_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&from, &fromlen);
            if (n <= 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (std::chrono::high_resolution_clock::now() >= deadline) break;
                    continue;
                }
                break;
            }

            auto t_end = std::chrono::high_resolution_clock::now();
            double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();

            if (n < 20) continue;
            struct iphdr* ip_hdr = (struct iphdr*)buf;
            if (ip_hdr->ihl < 5 || ip_hdr->version != 4) continue;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n < ip_hdr_len + (int)sizeof(struct icmphdr)) continue;

            struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

            // Extract original IP + UDP header
            if (icmp_reply->type != ICMP_TIME_EXCEEDED && icmp_reply->type != ICMP_DEST_UNREACH) continue;
            const char* quoted = quoted_transport(buf, n, ip_hdr_len, IPPROTO_UDP, target_ip);
            if (quoted) {
                const auto* orig_udp = reinterpret_cast<const struct udphdr*>(quoted);
                if (ntohs(orig_udp->dest) == dst_port && orig_udp->source == local.sin_port) {
                    pr.addr = addr_str; pr.rtt_ms = rtt;
                    pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                    pr.reply_ttl = ip_hdr->ttl;

                    if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_PORT_UNREACH && pr.addr == target_ip)
                        pr.reached_target = true;
                    if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED)
                        pr.mtu_suggestion = ntohs(icmp_reply->un.frag.mtu);
                    break;
                }
            }
        }

        close(sock_send); close(sock_recv);
        return pr;
    }

    ProbeResult probe_tcp_syn(int ttl, int /* probe_index */, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl;

        uint16_t probe_id = g_probe_counter.fetch_add(1, std::memory_order_relaxed);
        pr.probe_id = probe_id;

        if (use_tcp_fallback_) {
            return probe_tcp_fallback(ttl, probe_id, target_ip);
        }

        int sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock_send < 0) {
            use_tcp_fallback_ = true;
            return probe_tcp_fallback(ttl, probe_id, target_ip);
        }

        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(cfg_.dst_port);
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);
        const uint16_t src_port = static_cast<uint16_t>(1 +
            (cfg_.src_port - 1 + probe_id) % 65535);
        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        configure_mtu(sock_send, cfg_.detect_mtu);

        struct tcphdr tcph_only{};
        tcph_only.source = htons(src_port);
        tcph_only.dest = htons(cfg_.dst_port);
        tcph_only.seq = htonl(probe_id * 1000 + ttl);
        tcph_only.ack_seq = 0;
        tcph_only.doff = 5;
        tcph_only.syn = 1;
        tcph_only.window = htons(5840);
        tcph_only.check = 0;

        // Retrieve local IP bound to the destination to compute checksum
        struct sockaddr_in local_addr{};
        socklen_t local_len = sizeof(local_addr);
        int dgram_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (dgram_sock >= 0) {
            connect(dgram_sock, (struct sockaddr*)&dest, sizeof(dest));
            getsockname(dgram_sock, (struct sockaddr*)&local_addr, &local_len);
            close(dgram_sock);
        }

        struct pseudo_header ph{};
        ph.source_address = local_addr.sin_addr.s_addr;
        ph.dest_address = dest.sin_addr.s_addr;
        ph.placeholder = 0;
        ph.protocol = IPPROTO_TCP;
        ph.tcp_length = htons(sizeof(struct tcphdr));
        tcph_only.check = tcp_checksum(&ph, &tcph_only);

        if (cancel_token_.cancelled) { close(sock_send); close(sock_recv); return pr; }

        auto t_start = std::chrono::high_resolution_clock::now();
        ssize_t sent = sendto(sock_send, &tcph_only, sizeof(tcph_only), 0,
                              (struct sockaddr*)&dest, sizeof(dest));

        if (sent <= 0) {
            close(sock_send); close(sock_recv);
            use_tcp_fallback_ = true;
            return probe_tcp_fallback(ttl, probe_id, target_ip);
        }

        char buf[1500];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);

        auto deadline = t_start + std::chrono::milliseconds(cfg_.timeout_ms);
        bool response_received = false;

        while (!cancel_token_.cancelled) {
            auto now = std::chrono::high_resolution_clock::now();
            int remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            if (remaining_ms <= 0) break;

            struct pollfd pfds[2];
            pfds[0].fd = sock_recv;
            pfds[0].events = POLLIN;
            pfds[1].fd = sock_send;
            pfds[1].events = POLLIN | POLLERR;

            int res = poll(pfds, 2, std::min(remaining_ms, 100));
            if (res < 0) {
                if (errno == EINTR) continue;
                break;
            } else if (res == 0) {
                continue; // Re-check cancellation and the probe deadline.
            }

            if (pfds[0].revents & POLLIN) {
                ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                                     (struct sockaddr*)&from, &fromlen);
                if (n >= 20) {
                    auto t_end = std::chrono::high_resolution_clock::now();
                    double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();

                    struct iphdr* ip_hdr = (struct iphdr*)buf;
                    if (ip_hdr->ihl >= 5 && ip_hdr->version == 4) {
                        int ip_hdr_len = ip_hdr->ihl * 4;
                        if (n >= ip_hdr_len + (int)sizeof(struct icmphdr)) {
                        struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
                        char addr_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

                        // Extract original IP + TCP header
                        const char* quoted = quoted_transport(buf, n, ip_hdr_len, IPPROTO_TCP, target_ip);
                        if (quoted && (icmp_reply->type == ICMP_TIME_EXCEEDED || icmp_reply->type == ICMP_DEST_UNREACH)) {
                            const auto* orig_tcp = reinterpret_cast<const struct tcphdr*>(quoted);
                            if (ntohs(orig_tcp->source) == src_port && ntohs(orig_tcp->dest) == cfg_.dst_port) {
                                pr.addr = addr_str; pr.rtt_ms = rtt;
                                pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                                pr.reply_ttl = ip_hdr->ttl;
                                response_received = true;

                                if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED)
                                    pr.mtu_suggestion = ntohs(icmp_reply->un.frag.mtu);
                                break;
                            }
                        }
                    }
                    }
                }
            }

            if (pfds[1].revents & (POLLIN | POLLERR)) {
                // If the raw TCP socket becomes readable, it means we might have received a SYN-ACK or RST.
                ssize_t n = recvfrom(sock_send, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
                if (n >= 20) {
                    struct iphdr* ip_hdr = (struct iphdr*)buf;
                    if (ip_hdr->ihl >= 5 && ip_hdr->version == 4) {
                        int ip_hdr_len = ip_hdr->ihl * 4;
                        if (n >= ip_hdr_len + (int)sizeof(struct tcphdr)) {
                        struct tcphdr* tcph = (struct tcphdr*)(buf + ip_hdr_len);
                        if (ntohs(tcph->dest) == src_port && ntohs(tcph->source) == cfg_.dst_port &&
                            from.sin_addr.s_addr == dest.sin_addr.s_addr && (tcph->rst || (tcph->syn && tcph->ack))) {
                            auto t_end = std::chrono::high_resolution_clock::now();
                            double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();

                            char addr_str[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

                            pr.addr = addr_str; pr.rtt_ms = rtt;
                            pr.reached_target = true;
                            response_received = true;
                            break;
                        }
                        }
                    }
                }
            }
        }

        close(sock_send); close(sock_recv);

        if (response_received && pr.addr == target_ip) pr.reached_target = true;
        return pr;
    }

    ProbeResult probe_tcp_fallback(int ttl, int probe_id, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl; pr.probe_id = probe_id;

        int sock_send = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_send < 0) return pr;
        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }

        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        configure_mtu(sock_send, cfg_.detect_mtu);

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(cfg_.dst_port);
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

        fcntl(sock_send, F_SETFL, O_NONBLOCK);

        if (cancel_token_.cancelled) { close(sock_send); close(sock_recv); return pr; }

        auto t_start = std::chrono::high_resolution_clock::now();
        connect(sock_send, (struct sockaddr*)&dest, sizeof(dest));

        struct sockaddr_in local{};
        socklen_t local_size = sizeof(local);
        getsockname(sock_send, reinterpret_cast<struct sockaddr*>(&local), &local_size);

        char buf[1500];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);

        auto deadline = t_start + std::chrono::milliseconds(cfg_.timeout_ms);

        while (!cancel_token_.cancelled) {
            auto now = std::chrono::high_resolution_clock::now();
            int remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            if (remaining_ms <= 0) break;

            struct pollfd pfds[2];
            pfds[0].fd = sock_recv;
            pfds[0].events = POLLIN;
            pfds[1].fd = sock_send;
            pfds[1].events = POLLOUT;

            int res = poll(pfds, 2, std::min(remaining_ms, 100));
            if (res < 0) {
                if (errno == EINTR) continue;
                break;
            } else if (res == 0) {
                continue; // Re-check cancellation and the probe deadline.
            }

            if (pfds[0].revents & POLLIN) {
                ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                                     (struct sockaddr*)&from, &fromlen);
                if (n >= 20) {
                    auto t_end = std::chrono::high_resolution_clock::now();
                    double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();

                    struct iphdr* ip_hdr = (struct iphdr*)buf;
                    if (ip_hdr->ihl >= 5 && ip_hdr->version == 4) {
                        int ip_hdr_len = ip_hdr->ihl * 4;
                        if (n >= ip_hdr_len + (int)sizeof(struct icmphdr)) {
                            struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
                        char addr_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

                        const char* quoted = quoted_transport(buf, n, ip_hdr_len, IPPROTO_TCP, target_ip);
                        if (!quoted || (icmp_reply->type != ICMP_TIME_EXCEEDED && icmp_reply->type != ICMP_DEST_UNREACH)) continue;
                        const auto* original = reinterpret_cast<const struct tcphdr*>(quoted);
                        if (original->source != local.sin_port || ntohs(original->dest) != cfg_.dst_port) continue;
                        pr.addr = addr_str; pr.rtt_ms = rtt;
                        pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                        pr.reply_ttl = ip_hdr->ttl;

                        if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED)
                            pr.mtu_suggestion = ntohs(icmp_reply->un.frag.mtu);
                        break;
                        }
                    }
                }
            }

            if (pfds[1].revents & (POLLOUT | POLLERR | POLLHUP)) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(sock_send, SOL_SOCKET, SO_ERROR, &err, &len) == 0) {
                    if (err == 0 || err == EISCONN || err == ECONNREFUSED) {
                        auto t_end = std::chrono::high_resolution_clock::now();
                        double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();
                        pr.addr = target_ip; pr.rtt_ms = rtt; pr.reached_target = true;
                        break;
                    }
                    // A failed connection must not become a successful probe
                    // on a later poll after SO_ERROR has been consumed.
                    if (err != EINPROGRESS && err != EALREADY) break;
                }
            }
        }

        close(sock_send); close(sock_recv);
        return pr;
    }
    std::vector<HopStats> run(const std::string& target_ip) {
        std::vector<HopStats> hops;
        bool reached = false;

        for (int base = 1; base <= cfg_.max_hops && !reached && !cancel_token_.cancelled; base += cfg_.parallel_hops) {
            int end   = std::min(base + cfg_.parallel_hops - 1, cfg_.max_hops);
            int count = end - base + 1;

            auto results = std::make_shared<std::vector<std::vector<ProbeResult>>>(count,
                                                          std::vector<ProbeResult>(cfg_.queries_per_hop));

            std::vector<std::future<void>> futs;
            futs.reserve(count * cfg_.queries_per_hop);

            for (int h = 0; h < count; h++) {
                for (int p = 0; p < cfg_.queries_per_hop; p++) {
                    int ttl = base + h;
                    int pid = p;
                    int hi  = h;
                    std::string ip_copy = target_ip;
                    futs.push_back(pool_.submit([this, ttl, pid, hi, p,
                                                results, ip_copy] {
                                                    ProbeResult pr;
                                                    switch (cfg_.protocol) {
                                                        case TraceConfig::ICMP:    pr = probe_icmp(ttl, pid, ip_copy);    break;
                                                        case TraceConfig::UDP:     pr = probe_udp(ttl, pid, ip_copy);     break;
                                                        case TraceConfig::TCP_SYN: pr = probe_tcp_syn(ttl, pid, ip_copy); break;
                                                    }
                                                    (*results)[hi][p] = pr;
                                                }));
                }
            }

            // Never inspect shared results or destroy the engine while probes
            // still hold references to them. Each probe owns a bounded timeout.
            for (auto& future : futs) future.wait();
            for (auto& future : futs) future.get();

            for (int h = 0; h < count; h++) {
                HopStats hs;
                hs.ttl  = base + h;
                hs.sent = cfg_.queries_per_hop;

                for (auto& pr : (*results)[h]) {
                    if (pr.rtt_ms >= 0) {
                        hs.rtts.push_back(pr.rtt_ms);
                        hs.received++;
                        if (hs.addr.empty()) { hs.addr = pr.addr; hs.hostname = pr.hostname; }
                        if (pr.reached_target) { hs.is_target = true; reached = true; }
                        if (pr.mtu_suggestion > 0 && cfg_.detect_mtu) hs.mtu = pr.mtu_suggestion;
                    }
                }
                hs.compute();
                hops.push_back(hs);
                if (hs.is_target) {
                    reached = true;
                    break;
                }
            }
        }

        if (cfg_.resolve_dns && !cancel_token_.cancelled) {
            std::unordered_map<std::string, std::string> cache;
            for (auto& hop : hops) {
                if (cancel_token_.cancelled) break;
                if (hop.addr.empty()) continue;
                auto existing = cache.find(hop.addr);
                if (existing == cache.end())
                    existing = cache.emplace(hop.addr, reverse_dns(hop.addr)).first;
                hop.hostname = existing->second;
            }
        }

        if (cfg_.as_lookup && !cancel_token_.cancelled) {
            std::unordered_map<std::string, std::string> asn_cache;
            std::vector<std::string> unique_ips;
            for (const auto& hs : hops) {
                if (!hs.addr.empty() && asn_cache.find(hs.addr) == asn_cache.end()) {
                    asn_cache[hs.addr] = "";
                    unique_ips.push_back(hs.addr);
                }
            }

            if (!unique_ips.empty()) {
                std::vector<std::future<std::pair<std::string, std::string>>> asn_futs;
                for (const auto& ip : unique_ips) {
                    asn_futs.push_back(pool_.submit([ip]() {
                        return std::make_pair(ip, as_lookup(ip));
                    }));
                }

                auto asn_timeout = std::chrono::seconds(4);
                for (auto& f : asn_futs) {
                    if (f.wait_for(asn_timeout) == std::future_status::ready) {
                        auto res = f.get();
                        asn_cache[res.first] = res.second;
                    }
                }

                for (auto& hs : hops) {
                    if (!hs.addr.empty()) {
                        hs.asn_info = asn_cache[hs.addr];
                    }
                }
            }
        }
        return hops;
    }

private:
    const TraceConfig& cfg_;
    ThreadPool& pool_;
    CancellationToken& cancel_token_;
    std::atomic<bool> use_tcp_fallback_{false};
};

static const char* proto_label(TraceConfig::Protocol protocol) {
    switch (protocol) {
        case TraceConfig::ICMP: return "ICMP";
        case TraceConfig::UDP: return "UDP";
        case TraceConfig::TCP_SYN: return "TCP SYN";
    }
    return "unknown";
}

void traceroute(const std::string& target) {
    traceroute(target, TraceConfig{});
}

void traceroute(const std::string& target, const TraceConfig& config) {
    TraceConfig cfg = config;
    cfg.target = target;
    if (cfg.max_hops < 1 || cfg.max_hops > 255 ||
        cfg.queries_per_hop < 1 || cfg.queries_per_hop > 10 ||
        cfg.parallel_hops < 1 || cfg.parallel_hops > 32 ||
        cfg.timeout_ms < 1 || cfg.timeout_ms > 600000 ||
        cfg.dns_timeout_ms < 1 || cfg.dst_port < 1 || cfg.dst_port > 65535 ||
        cfg.src_port < 1 || cfg.src_port > 65535 ||
        (cfg.protocol != TraceConfig::ICMP && cfg.protocol != TraceConfig::UDP &&
         cfg.protocol != TraceConfig::TCP_SYN))
        throw std::invalid_argument("invalid traceroute configuration");

    // Every protocol needs raw ICMP reception for intermediate hops. Fail once
    // with a useful error instead of returning an entire table of false timeouts.
    FdGuard permission_check(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
    if (permission_check.get() < 0)
        throw std::runtime_error("traceroute requires raw socket access (CAP_NET_RAW): " +
                                 std::string(std::strerror(errno)));

    const std::string target_ip = resolve(target);
    if (target_ip.empty())
        throw std::runtime_error("could not resolve traceroute target: " + target);

    print_header("Traceroute · " + target);
    std::cout << "  " << target_ip << "  " << proto_label(cfg.protocol);
    if (cfg.protocol != TraceConfig::ICMP) std::cout << "  port " << cfg.dst_port;
    std::cout << "  " << cfg.max_hops << " hops  " << cfg.queries_per_hop
              << " probes/hop  " << cfg.timeout_ms << " ms timeout\n\n";
    std::cout << "  " << std::left << std::setw(5) << "HOP"
              << std::setw(18) << "ADDRESS";
    if (cfg.resolve_dns) std::cout << std::setw(27) << "HOSTNAME";
    std::cout << std::setw(10) << "AVG ms" << std::setw(10) << "MIN ms"
              << std::setw(10) << "MAX ms";
    if (cfg.show_jitter) std::cout << std::setw(11) << "JITTER ms";
    if (cfg.show_loss) std::cout << std::setw(8) << "LOSS";
    if (cfg.as_lookup) std::cout << "AS";
    std::cout << '\n';

    ThreadPool pool(std::min(cfg.parallel_hops, cfg.max_hops) * cfg.queries_per_hop);
    TracerouteEngine engine(cfg, pool, g_cancel_token);
    const auto hops = engine.run(target_ip);
    bool reached = false;
    int timeouts = 0;

    for (const auto& hop : hops) {
        TraceHop result;
        result.ttl = hop.ttl;
        result.addr = hop.addr;
        result.hostname = hop.hostname;
        result.avg_rtt_ms = hop.received ? hop.avg_rtt : -1.0;
        result.loss_pct = hop.loss_pct;
        result.asn = hop.asn_info;
        {
            std::lock_guard<std::mutex> lock(g_result_mtx);
            g_result.trace.push_back(result);
        }
        std::cout << "  " << std::left << std::setw(5) << hop.ttl;
        if (!hop.received) {
            ++timeouts;
            std::cout << "*  request timeout\n";
            continue;
        }
        std::cout << std::setw(18) << hop.addr;
        if (cfg.resolve_dns) {
            const std::string hostname = sanitize(hop.hostname);
            std::cout << std::setw(27) << (hostname.size() > 26 ?
                         hostname.substr(0, 23) + "..." : hostname);
        }
        auto ms = [](double value) {
            std::ostringstream output;
            output << std::fixed << std::setprecision(1) << value;
            return output.str();
        };
        std::cout << std::setw(10) << ms(hop.avg_rtt)
                  << std::setw(10) << ms(hop.min_rtt)
                  << std::setw(10) << ms(hop.max_rtt);
        if (cfg.show_jitter) std::cout << std::setw(11) << ms(hop.jitter);
        if (cfg.show_loss) std::cout << std::setw(8) << (std::to_string(static_cast<int>(hop.loss_pct)) + "%");
        if (cfg.as_lookup) std::cout << sanitize(hop.asn_info);
        if (cfg.detect_mtu && hop.mtu > 0) std::cout << "  MTU " << hop.mtu;
        std::cout << '\n';
        reached = reached || hop.is_target;
    }

    std::cout << "\n  " << hops.size() << " hops  " << timeouts << " timeouts  "
              << (g_cancel_token.cancelled ? "interrupted" :
                  reached ? "destination reached" : "destination not reached") << '\n';
    LOG_INFO("traceroute", "done target=" + target + " hops=" + std::to_string(hops.size()));
}

void full_recon(const std::string& ip) {
    print_header("Recon · " + ip);
    ip_intel(ip);
    dns_lookup(ip);
    os_detect(ip);
    port_scan(ip, 0, 0, false);
}
