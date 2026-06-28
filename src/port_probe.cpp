#include "../include/port_probe.hpp"
#include "../include/security.hpp"
#include <cstdint>

namespace {

int port_scan_sock_af(const std::string& ip) {
    return port_scan_is_v6(ip) ? AF_INET6 : AF_INET;
}

bool port_scan_fill_endpoint(const std::string& ip, int port, sockaddr_storage& ss, socklen_t& slen) {
    memset(&ss, 0, sizeof(ss));
    if (port_scan_is_v6(ip)) {
        auto* sa = reinterpret_cast<sockaddr_in6*>(&ss);
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET6, ip.c_str(), &sa->sin6_addr) != 1) return false;
        slen = sizeof(sockaddr_in6);
        return true;
    }

    auto* sa = reinterpret_cast<sockaddr_in*>(&ss);
    sa->sin_family = AF_INET;
    sa->sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &sa->sin_addr) != 1) return false;
    slen = sizeof(sockaddr_in);
    return true;
}

bool port_tcp_connect_wait(int fd, int timeout_ms) {
    if (timeout_ms <= 0) return false;
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    int sel = poll(&pfd, 1, timeout_ms);
    if (sel <= 0) return false;
    if (!(pfd.revents & POLLOUT)) return false;
    int sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen) != 0) return false;
    return sockerr == 0;
}

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t tcp_csum(const struct pseudo_header* ph, const struct tcphdr* tcph) {
    uint32_t sum = 0;
    auto p = reinterpret_cast<const uint16_t*>(ph);
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) sum += *p++;
    p = reinterpret_cast<const uint16_t*>(tcph);
    for (size_t i = 0; i < sizeof(struct tcphdr) / 2; i++) sum += *p++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

struct UdpProbe {
    int port;
    std::vector<uint8_t> payload;
};

const std::vector<UdpProbe> UDP_PROBES = {
    {53,   {0xAB,0xCD,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
            0x07,'v','e','r','s','i','o','n',0x04,'b','i','n','d',0x00,
            0x00,0x10,0x00,0x03}},
    {161,  {0x30,0x26,0x02,0x01,0x01,0x04,0x06,'p','u','b','l','i','c',
            0xa0,0x19,0x02,0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x02,
            0x01,0x00,0x30,0x0b,0x30,0x09,0x06,0x05,0x2b,0x06,0x01,
            0x02,0x01,0x05,0x00}},
    {123,  {0x1b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}},
    {5353, {0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
            0x05,'_','h','t','t','p',0x04,'_','t','c','p',0x05,'l','o',
            'c','a','l',0x00,0x00,0x0c,0x00,0x01}},
};

}

bool port_scan_is_v6(const std::string& ip) {
    return InputGuard::is_valid_ipv6(ip);
}

FdGuard port_tcp_socket(const std::string& ip) {
    return FdGuard(socket(port_scan_sock_af(ip), SOCK_STREAM, 0));
}

bool port_tcp_connect_to(const std::string& ip, int port, int timeout_ms, int fd) {
    sockaddr_storage ss{};
    socklen_t slen = 0;
    if (!port_scan_fill_endpoint(ip, port, ss, slen)) return false;

    fcntl(fd, F_SETFL, O_NONBLOCK);
    int cr = connect(fd, reinterpret_cast<sockaddr*>(&ss), slen);
    if (cr == 0) {
        int sockerr = 0;
        socklen_t errlen = sizeof(sockerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen);
        return sockerr == 0;
    }
    if (errno != EINPROGRESS) return false;
    return port_tcp_connect_wait(fd, timeout_ms);
}

AdaptiveConfig calibrate_port_target(const std::string& ip) {
    AdaptiveConfig cfg;
    std::vector<int> rtts;
    int cal_ports[] = {80,443,22,8080,53};

    for (int p : cal_ports) {
        auto t0 = std::chrono::high_resolution_clock::now();
        FdGuard fd(port_tcp_socket(ip));
        if (fd.get() < 0) continue;
        sockaddr_storage ss{};
        socklen_t slen = 0;
        if (!port_scan_fill_endpoint(ip, p, ss, slen)) continue;
        fcntl(fd.get(), F_SETFL, O_NONBLOCK);
        connect(fd.get(), reinterpret_cast<sockaddr*>(&ss), slen);
        struct pollfd pfd{};
        pfd.fd = fd.get();
        pfd.events = POLLOUT;
        int r = poll(&pfd, 1, 800);
        auto t1 = std::chrono::high_resolution_clock::now();
        if (r > 0) {
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
            rtts.push_back(ms);
        }
    }

    if (rtts.empty()) {
        cfg.connect_ms = 1500;
        cfg.banner_ms = 3000;
        cfg.retry_count = 2;
        cfg.pool_size = 50;
        cfg.median_rtt = -1;
        return cfg;
    }

    std::sort(rtts.begin(), rtts.end());
    cfg.median_rtt = rtts[rtts.size() / 2];
    cfg.connect_ms = std::max(200, std::min(3000, cfg.median_rtt * 3));
    cfg.banner_ms = std::max(500, std::min(5000, cfg.median_rtt * 5));
    cfg.retry_count = (cfg.median_rtt < 50) ? 1 : 2;

    if (cfg.median_rtt < 20) cfg.pool_size = 300;
    else if (cfg.median_rtt < 100) cfg.pool_size = 150;
    else cfg.pool_size = 60;

    return cfg;
}

std::pair<int,bool> port_probe_connect(const std::string& ip, int port, int timeout_ms, int retries) {
    for (int attempt = 0; attempt <= retries; attempt++) {
        FdGuard sock(port_tcp_socket(ip));
        if (sock.get() < 0) return {-1, false};

        sockaddr_storage ss{};
        socklen_t slen = 0;
        if (!port_scan_fill_endpoint(ip, port, ss, slen)) return {-1, false};
        fcntl(sock.get(), F_SETFL, O_NONBLOCK);

        auto t0 = std::chrono::high_resolution_clock::now();
        int cr = connect(sock.get(), reinterpret_cast<sockaddr*>(&ss), slen);

        if (cr == 0) {
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - t0).count();
            return {std::max(1, ms), false};
        }

        if (errno != EINPROGRESS) return {-1, false};

        struct pollfd pfd{};
        pfd.fd = sock.get();
        pfd.events = POLLOUT;
        int sel = poll(&pfd, 1, timeout_ms);

        if (sel > 0 && (pfd.revents & POLLOUT)) {
            int sockerr = 0;
            socklen_t errlen = sizeof(sockerr);
            getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &sockerr, &errlen);
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - t0).count();
            if (sockerr == 0) return {std::max(1, ms), false};
            return {-1, false};
        }

        if (sel == 0) {
            if (attempt == retries) return {-1, true};
            usleep(50000);
            continue;
        }
        return {-1, false};
    }
    return {-1, true};
}

std::pair<int,bool> port_probe_syn(const std::string& ip, int port, int timeout_ms, int retries) {
    if (port_scan_is_v6(ip) || !has_cap_net_raw()) return port_probe_connect(ip, port, timeout_ms, retries);

    for (int attempt = 0; attempt <= retries; attempt++) {
        FdGuard sock_send(socket(AF_INET, SOCK_RAW, IPPROTO_TCP));
        if (sock_send.get() < 0) return port_probe_connect(ip, port, timeout_ms, retries);

        FdGuard sock_recv(socket(AF_INET, SOCK_RAW, IPPROTO_TCP));
        if (sock_recv.get() < 0) return port_probe_connect(ip, port, timeout_ms, retries);

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &dest.sin_addr);

        struct sockaddr_in local_addr{};
        socklen_t local_len = sizeof(local_addr);
        FdGuard dgram_sock(socket(AF_INET, SOCK_DGRAM, 0));
        if (dgram_sock.get() >= 0) {
            connect(dgram_sock.get(), reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
            getsockname(dgram_sock.get(), reinterpret_cast<struct sockaddr*>(&local_addr), &local_len);
        }

        uint16_t src_port = static_cast<uint16_t>(32768 + ((port * 31337 + attempt * 7919) % 30000));

        struct tcphdr tcph{};
        tcph.source = htons(src_port);
        tcph.dest = htons(port);
        tcph.seq = htonl(1337 + port);
        tcph.ack_seq = 0;
        tcph.doff = 5;
        tcph.syn = 1;
        tcph.window = htons(5840);
        tcph.check = 0;

        struct pseudo_header ph{};
        ph.source_address = local_addr.sin_addr.s_addr;
        ph.dest_address = dest.sin_addr.s_addr;
        ph.placeholder = 0;
        ph.protocol = IPPROTO_TCP;
        ph.tcp_length = htons(sizeof(struct tcphdr));
        tcph.check = tcp_csum(&ph, &tcph);

        auto t0 = std::chrono::high_resolution_clock::now();
        ssize_t sent = sendto(sock_send.get(), &tcph, sizeof(tcph), 0,
                              reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
        if (sent <= 0) return port_probe_connect(ip, port, timeout_ms, retries);

        char buf[1500];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);

        auto deadline = t0 + std::chrono::milliseconds(timeout_ms);

        while (!g_cancel_token.cancelled) {
            auto now = std::chrono::high_resolution_clock::now();
            int remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            if (remaining <= 0) break;

            struct pollfd pfd{};
            pfd.fd = sock_recv.get();
            pfd.events = POLLIN;
            int res = poll(&pfd, 1, remaining);

            if (res > 0) {
                ssize_t n = recvfrom(sock_recv.get(), buf, sizeof(buf), 0,
                                     reinterpret_cast<struct sockaddr*>(&from), &fromlen);
                if (n >= 20) {
                    struct iphdr* iph = reinterpret_cast<struct iphdr*>(buf);
                    if (iph->ihl >= 5 && iph->version == 4) {
                        int iph_len = iph->ihl * 4;
                        if (n >= iph_len + static_cast<int>(sizeof(struct tcphdr))) {
                            struct tcphdr* rtcph = reinterpret_cast<struct tcphdr*>(buf + iph_len);
                            if (ntohs(rtcph->source) == port && ntohs(rtcph->dest) == src_port) {
                                if (rtcph->syn && rtcph->ack) {
                                    tcph.syn = 0;
                                    tcph.rst = 1;
                                    tcph.ack = 0;
                                    tcph.seq = rtcph->ack_seq;
                                    tcph.check = 0;
                                    tcph.check = tcp_csum(&ph, &tcph);
                                    sendto(sock_send.get(), &tcph, sizeof(tcph), 0,
                                           reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
                                    int ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::high_resolution_clock::now() - t0).count();
                                    return {std::max(1, ms), false};
                                }
                                if (rtcph->rst) return {-1, false};
                            }
                        }
                    }
                }
            } else if (res == 0) {
                break;
            } else if (errno != EINTR) {
                break;
            }
        }

        if (attempt == retries) {
            auto verify = port_probe_connect(ip, port, std::max(timeout_ms, 400), 0);
            if (verify.first > 0) return verify;
            return {-1, true};
        }
    }

    auto verify = port_probe_connect(ip, port, std::max(timeout_ms, 400), 0);
    if (verify.first > 0) return verify;
    return {-1, true};
}

std::pair<int,bool> port_probe_udp_smart(const std::string& ip, int port, int timeout_ms) {
    FdGuard sock(socket(AF_INET, SOCK_DGRAM, 0));
    if (sock.get() < 0) return {-1, false};

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x00};
    for (const auto& probe : UDP_PROBES) {
        if (probe.port == port) {
            payload = probe.payload;
            break;
        }
    }

    auto t0 = std::chrono::high_resolution_clock::now();
    connect(sock.get(), reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    send(sock.get(), payload.data(), payload.size(), 0);

    char buf[1024];
    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;

    if (poll(&pfd, 1, timeout_ms) > 0) {
        ssize_t n;
        do {
            n = recv(sock.get(), buf, sizeof(buf), 0);
        } while (n < 0 && errno == EINTR);

        if (n > 0) {
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - t0).count();
            return {std::max(1, ms), false};
        }
        if (n < 0 && errno == ECONNREFUSED) return {-1, false};
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return {-1, true};
    }

    return {-1, true};
}
