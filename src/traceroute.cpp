#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

static std::atomic<uint16_t> g_probe_counter{1};

class TracerouteEngine {
public:
    explicit TracerouteEngine(const TraceConfig& cfg, ThreadPool& pool, CancellationToken& cancel_token)
    : cfg_(cfg), pool_(pool), cancel_token_(cancel_token) {}

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

        for (int attempts = 0; attempts < 3; attempts++) {
            if (cancel_token_.cancelled) break;

            auto now = std::chrono::high_resolution_clock::now();
            auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            if (remaining_ms < 1) remaining_ms = 1;

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

            struct iphdr* ip_hdr = (struct iphdr*)buf;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n < ip_hdr_len + (int)sizeof(struct icmphdr)) continue;

            struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

            if (icmp_reply->type == ICMP_TIME_EXCEEDED && icmp_reply->code == ICMP_EXC_TTL) {
                // Extract original IP + ICMP header
                int orig_ip_hdr_len = ((struct iphdr*)(buf + ip_hdr_len + 8))->ihl * 4;
                if (n >= ip_hdr_len + 8 + orig_ip_hdr_len + 8) {
                    struct icmphdr* orig_icmp = (struct icmphdr*)(buf + ip_hdr_len + 8 + orig_ip_hdr_len);
                    if (ntohs(orig_icmp->un.echo.id) == probe_id && ntohs(orig_icmp->un.echo.sequence) == seq) {
                        pr.addr = addr_str; pr.rtt_ms = rtt;
                        pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                        pr.reply_ttl = ip_hdr->ttl;
                        break;
                    }
                }
            } else if (icmp_reply->type == ICMP_ECHOREPLY) {
                if (ntohs(icmp_reply->un.echo.id) == probe_id && ntohs(icmp_reply->un.echo.sequence) == seq) {
                    pr.addr = addr_str; pr.rtt_ms = rtt;
                    pr.reached_target = true;
                    pr.icmp_type = icmp_reply->type; pr.reply_ttl = ip_hdr->ttl;
                    break;
                }
            } else if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED) {
                int orig_ip_hdr_len = ((struct iphdr*)(buf + ip_hdr_len + 8))->ihl * 4;
                if (n >= ip_hdr_len + 8 + orig_ip_hdr_len + 8) {
                    struct icmphdr* orig_icmp = (struct icmphdr*)(buf + ip_hdr_len + 8 + orig_ip_hdr_len);
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
        if (cfg_.resolve_dns && !pr.addr.empty()) pr.hostname = reverse_dns(pr.addr);
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

        uint16_t dst_port = cfg_.dst_port + ttl + _probe_id;

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

        char buf[1500]; // MTU size to avoid truncation
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);

        auto deadline = t_start + std::chrono::milliseconds(cfg_.timeout_ms);

        for (int attempts = 0; attempts < 3; attempts++) {
            if (cancel_token_.cancelled) break;

            auto now = std::chrono::high_resolution_clock::now();
            auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            if (remaining_ms < 1) remaining_ms = 1;

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

            struct iphdr* ip_hdr = (struct iphdr*)buf;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n < ip_hdr_len + (int)sizeof(struct icmphdr)) continue;

            struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));

            // Extract original IP + UDP header
            int orig_ip_hdr_len = ((struct iphdr*)(buf + ip_hdr_len + 8))->ihl * 4;
            if (n >= ip_hdr_len + 8 + orig_ip_hdr_len + 8) {
                struct udphdr* orig_udp = (struct udphdr*)(buf + ip_hdr_len + 8 + orig_ip_hdr_len);
                if (ntohs(orig_udp->dest) == dst_port) {
                    pr.addr = addr_str; pr.rtt_ms = rtt;
                    pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                    pr.reply_ttl = ip_hdr->ttl;

                    if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_PORT_UNREACH)
                        pr.reached_target = true;
                    if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED)
                        pr.mtu_suggestion = ntohs(icmp_reply->un.frag.mtu);
                    break;
                }
            }
        }

        close(sock_send); close(sock_recv);
        if (cfg_.resolve_dns && !pr.addr.empty()) pr.hostname = reverse_dns(pr.addr);
        return pr;
    }

    ProbeResult probe_tcp_syn(int ttl, int _probe_id, const std::string& target_ip) {
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

        int on = 1;
        setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(cfg_.dst_port);
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

        uint16_t src_port = cfg_.src_port + ttl + _probe_id;

        char packet[40];
        memset(packet, 0, sizeof(packet));

        struct iphdr* iph = (struct iphdr*)packet;
        struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htons(probe_id);
        iph->frag_off = 0;
        iph->ttl = ttl;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = 0; // Kernel will fill this
        iph->daddr = dest.sin_addr.s_addr;

        tcph->source = htons(src_port);
        tcph->dest = htons(cfg_.dst_port);
        tcph->seq = htonl(probe_id * 1000 + ttl);
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin=0; tcph->syn=1; tcph->rst=0; tcph->psh=0; tcph->ack=0; tcph->urg=0;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        // Pseudo header for TCP checksum (simplified, assumes kernel fills some IP data if IP_HDRINCL allows)
        // Without knowing our own IP reliably, IP_HDRINCL on TCP requires manual checksumming.
        // We will fallback if raw TCP injection fails.
        // For accurate RAW TCP we need to populate IP source address, which is complex in this context.
        // Standard traceroute tools actually use SOCK_RAW with IPPROTO_TCP but *don't* set IP_HDRINCL, letting the kernel build the IP header. Let's do that!

        close(sock_send);

        // Re-open without IP_HDRINCL
        sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock_send < 0) {
            close(sock_recv);
            use_tcp_fallback_ = true;
            return probe_tcp_fallback(ttl, probe_id, target_ip);
        }

        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

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

            int res = poll(pfds, 2, remaining_ms);
            if (res < 0) {
                if (errno == EINTR) continue;
                break;
            } else if (res == 0) {
                break; // Timeout
            }

            if (pfds[0].revents & POLLIN) {
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

                        // Extract original IP + TCP header
                        int orig_ip_hdr_len = ((struct iphdr*)(buf + ip_hdr_len + 8))->ihl * 4;
                        if (n >= ip_hdr_len + 8 + orig_ip_hdr_len + 8) {
                            struct tcphdr* orig_tcp = (struct tcphdr*)(buf + ip_hdr_len + 8 + orig_ip_hdr_len);
                            if (ntohs(orig_tcp->source) == src_port || ntohs(orig_tcp->dest) == cfg_.dst_port) {
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

            if (pfds[1].revents & (POLLIN | POLLERR)) {
                // If the raw TCP socket becomes readable, it means we might have received a SYN-ACK or RST.
                ssize_t n = recvfrom(sock_send, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
                if (n > 0) {
                    struct iphdr* ip_hdr = (struct iphdr*)buf;
                    int ip_hdr_len = ip_hdr->ihl * 4;
                    if (n >= ip_hdr_len + (int)sizeof(struct tcphdr)) {
                        struct tcphdr* tcph = (struct tcphdr*)(buf + ip_hdr_len);
                        if (ntohs(tcph->dest) == src_port) {
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

        close(sock_send); close(sock_recv);

        if (!response_received) {
            if (++tcp_timeouts_ >= 3) {
                use_tcp_fallback_ = true;
            }
        } else {
            tcp_timeouts_ = 0;
            if (pr.addr == target_ip) pr.reached_target = true;
        }

        if (cfg_.resolve_dns && !pr.addr.empty()) pr.hostname = reverse_dns(pr.addr);
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

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(cfg_.dst_port);
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

        fcntl(sock_send, F_SETFL, O_NONBLOCK);

        if (cancel_token_.cancelled) { close(sock_send); close(sock_recv); return pr; }

        auto t_start = std::chrono::high_resolution_clock::now();
        connect(sock_send, (struct sockaddr*)&dest, sizeof(dest));

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

            int res = poll(pfds, 2, remaining_ms);
            if (res < 0) {
                if (errno == EINTR) continue;
                break;
            } else if (res == 0) {
                break; // Timeout
            }

            if (pfds[0].revents & POLLIN) {
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

                        // Accept ICMP related to our destination IP
                        pr.addr = addr_str; pr.rtt_ms = rtt;
                        pr.icmp_type = icmp_reply->type; pr.icmp_code = icmp_reply->code;
                        pr.reply_ttl = ip_hdr->ttl;

                        if (pr.addr == target_ip) pr.reached_target = true;
                        break;
                    }
                }
            }

            if (pfds[1].revents & (POLLOUT | POLLERR | POLLHUP)) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(sock_send, SOL_SOCKET, SO_ERROR, &err, &len) == 0) {
                    if (err == 0 || err == EISCONN) {
                        auto t_end = std::chrono::high_resolution_clock::now();
                        double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();
                        pr.addr = target_ip; pr.rtt_ms = rtt; pr.reached_target = true;
                        break;
                    }
                }
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

            auto wait_timeout = std::chrono::milliseconds((int)(cfg_.timeout_ms * 1.5));
            for (auto& f : futs) {
                if (f.wait_for(wait_timeout) == std::future_status::timeout) {
                    LOG_WARN("traceroute", "A probe future timed out and was abandoned.");
                }
            }

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
                    asn_futs.push_back(pool_.submit([this, ip]() {
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
    std::atomic<int> tcp_timeouts_{0};
    std::atomic<bool> use_tcp_fallback_{false};
};

static std::string rtt_bar(double rtt_ms) {
    if (rtt_ms < 0) return std::string(BLOOD_RED) + "         " + RESET;
    int buckets[] = {5, 15, 30, 60, 100, 200, 500, 1000, 2000};
    int idx = 0;
    for (int b : buckets) { if (rtt_ms < b) break; idx++; }
    std::string bar = std::string(WHITE);
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

static CancellationToken* g_cancel_token_ptr = nullptr;

void traceroute(const std::string& target) {
    print_header("ADVANCED TRACEROUTE // " + target);

    CancellationToken token;
    g_cancel_token_ptr = &token;

    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = [](int) {
        if (g_cancel_token_ptr) {
            g_cancel_token_ptr->cancelled = true;
            const char* msg = "\n\033[38;2;139;0;0m  [!] Received SIGINT, cancelling traceroute...\033[0m\n";
            auto dummy = ::write(STDOUT_FILENO, msg, strlen(msg));
            (void)dummy;
        }
    };
    sigaction(SIGINT, &sa, &old_sa);

    TraceConfig cfg;
    cfg.target = target;

    std::cout << BLOOD_RED << "\n  protocol: [0] ALL  [1] ICMP  [2] UDP  [3] TCP-SYN  (default=1): " << RESET;
    std::string pc;
    std::getline(std::cin >> std::ws, pc);
    bool all_modes = (pc == "0");
    if      (pc == "2") cfg.protocol = TraceConfig::UDP;
    else if (pc == "3") cfg.protocol = TraceConfig::TCP_SYN;
    else                cfg.protocol = TraceConfig::ICMP;

    std::cout << BLOOD_RED << "  probes/hop (default=5): " << RESET;
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
                std::cout << BLOOD_RED << "  could not resolve " << WHITE << target << "\n" << RESET;
                return;
            }
        }
    }

    auto run_pass = [&](TraceConfig::Protocol proto) -> std::vector<HopStats> {
        TraceConfig pcfg = cfg;
        pcfg.protocol = proto;

        std::cout << "\n" << BLOOD_RED << "  target:   " << WHITE << target_ip << "\n"
        << BLOOD_RED << "  protocol: " << WHITE << BOLD << proto_label(proto) << "\n" << RESET
        << BLOOD_RED << "  probes:   " << WHITE << pcfg.queries_per_hop << BLOOD_RED << "/hop\n"
        << BLOOD_RED << "  max hops: " << WHITE << pcfg.max_hops << "\n"
        << BLOOD_RED << "  parallel: " << WHITE << pcfg.parallel_hops << BLOOD_RED << " hops at once\n"
        << RESET << "\n";

        std::cout << BLOOD_RED << BOLD
        << "  HOP  ADDRESS           HOSTNAME                  "
        "AVG      MIN      MAX      JITTER   LOSS  AS INFO\n"
        << "  " << std::string(110, '-') << "\n" << RESET;

        ThreadPool pool(pcfg.parallel_hops * pcfg.queries_per_hop);
        TracerouteEngine engine(pcfg, pool, token);
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
        std::cout << BLOOD_RED << "  " << WHITE << std::setw(3) << hs.ttl << "  ";

        if (hs.received == 0) {
            std::cout << WHITE << std::left << std::setw(18) << "*"
            << BLOOD_RED << std::setw(27) << "request timeout"
            << BLOOD_RED << std::string(36, ' ')
            << WHITE   << "100%"
            << RESET << "\n";
            continue;
        }

        std::string display_ip   = hs.addr;
        std::string display_host = hs.hostname.empty() ? "" : hs.hostname;
        if (display_host.size() > 26) display_host = display_host.substr(0, 23) + "...";

        std::cout << WHITE
        << std::left << std::setw(18) << display_ip
        << WHITE     << std::setw(27) << sanitize(display_host);

        auto fmt_ms = [](double ms) -> std::string {
            if (ms < 0) return "*       ";
            std::ostringstream ss;
            ss << std::fixed << std::setprecision(1) << ms << "ms";
            return ss.str();
        };

        std::cout << WHITE << std::setw(9) << fmt_ms(hs.avg_rtt)
        << WHITE << std::setw(9) << fmt_ms(hs.min_rtt)
        << WHITE << std::setw(9) << fmt_ms(hs.max_rtt);

        if (cfg.show_jitter)
            std::cout << WHITE << std::setw(9) << fmt_ms(hs.jitter);

        if (cfg.show_loss) {
            std::string loss_str = std::to_string((int)hs.loss_pct) + "%";
            std::cout << WHITE << std::setw(6) << loss_str;
        }

        if (hs.mtu > 0)
            std::cout << BLOOD_RED << "  MTU:" << WHITE << hs.mtu;

        if (!hs.asn_info.empty())
            std::cout << WHITE << "  " << hs.asn_info.substr(0, 28);

        std::cout << "  " << rtt_bar(hs.avg_rtt);
        std::cout << RESET << "\n";

        if (hs.is_target)
            std::cout << "\n" << BLOOD_RED << BOLD << "  [+] " << WHITE << "destination reached in " << hs.ttl << BLOOD_RED << " hops\n" << RESET;
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
        std::cout << BLOOD_RED << "  [hops]          " << WHITE << total_hops << "\n" << RESET;
        std::cout << BLOOD_RED << "  [total RTT]     " << WHITE << std::fixed << std::setprecision(1)
        << total_latency << "ms\n" << RESET;
        std::cout << BLOOD_RED << "  [timeout hops]  " << WHITE << timeout_hops << "\n" << RESET;
        std::cout << BLOOD_RED << "  [hops w/ loss]  " << WHITE << total_loss << "\n" << RESET;
        if (max_jitter > 0)
            std::cout << BLOOD_RED << "  [worst jitter]  " << WHITE
            << std::fixed << std::setprecision(1) << max_jitter << "ms  "
            << BLOOD_RED << "@ " << WHITE << worst_hop << "\n" << RESET;
        std::cout << BLOOD_RED << "  [reached]       " << WHITE
        << (last.is_target ? "yes" : "no (TTL exhausted)")
        << "\n" << RESET;

        std::cout << "\n";
        double avg_rtt = (total_hops > 0) ? total_latency / total_hops : 0;
        if      (avg_rtt < 20 && total_loss == 0 && timeout_hops == 0)
            std::cout << BLOOD_RED << BOLD << "  [quality] " << WHITE << "EXCELLENT -- low latency, no loss\n" << RESET;
        else if (avg_rtt < 80 && total_loss <= 1)
            std::cout << BLOOD_RED << "  [quality] " << WHITE << "GOOD -- acceptable path\n" << RESET;
        else if (avg_rtt < 200 || total_loss <= 2)
            std::cout << BLOOD_RED << "  [quality] " << WHITE << "FAIR -- some congestion or loss detected\n" << RESET;
        else
            std::cout << BLOOD_RED << "  [quality] " << WHITE << "POOR -- high latency or significant loss\n" << RESET;
    }

    if (all_modes && all_results.size() > 1) {
        print_section("PROTOCOL COMPARISON");
        std::cout << "\n" << BLOOD_RED << BOLD
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
            std::string quality;
            if      (avg_per_hop < 20 && timeouts == 0) { quality = "EXCELLENT"; }
            else if (avg_per_hop < 80 && timeouts <= 1)  { quality = "GOOD"; }
            else if (avg_per_hop < 200 || timeouts <= 2) { quality = "FAIR"; }
            else                                          { quality = "POOR"; }

            std::cout << "  " << BLOOD_RED << std::left << std::setw(12) << proto_label(proto)
            << WHITE << std::setw(8)  << ph.size()
            << WHITE << std::setw(12) << (std::to_string((int)total_rtt) + "ms")
            << WHITE << std::setw(10) << (std::to_string((int)avg_per_hop) + "ms")
            << WHITE << std::setw(10) << timeouts
            << WHITE << std::setw(8) << (reached ? "yes" : "no")
            << WHITE << quality << RESET << "\n";
        }
    }

    LOG_INFO("traceroute", "done target=" + target + " hops=" + std::to_string(hops.size()));

    sigaction(SIGINT, &old_sa, nullptr);
    g_cancel_token_ptr = nullptr;
}

void full_recon(const std::string& ip) {
    std::cout << "\n" << BLOOD_RED << BOLD
    << "  +" << std::string(56,'=') << "+\n"
    << "  |  " << WHITE << "FULL RECON // " << std::left << std::setw(40) << ip << BLOOD_RED << "|\n"
    << "  +" << std::string(56,'=') << "+\n" << RESET;
    ip_intel(ip);
    dns_lookup(ip);
    os_detect(ip);
    port_scan(ip, 0, 0, false);
}
