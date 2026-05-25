#include "../include/dark_nexus.hpp"
#include "../include/dns_engine.hpp"
#include "../include/security.hpp"
#include "../include/user_agents.hpp"

bool valid_target(const std::string& s) {
    return InputGuard::is_valid_host(s);
}

bool valid_username(const std::string& s) {
    return InputGuard::is_valid_username(s);
}

bool valid_port(int p) {
    return InputGuard::is_valid_port(p);
}

std::string resolve(const std::string& host) {
    auto ips = DnsEngine::get().resolve(host);
    return ips.empty() ? "" : ips[0];
}

bool tcp_probe(const std::string& ip, int port, int ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return false; }

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    int r = poll(&pfd, 1, ms);
    close(fd);
    return r > 0;
}

std::pair<bool,int> tcp_probe_ms(const std::string& ip, int port, int ms) {
    auto t0 = std::chrono::high_resolution_clock::now();
    bool ok  = tcp_probe(ip, port, ms);
    int  el  = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::high_resolution_clock::now() - t0).count();
    return {ok, el};
}

std::string ptr_lookup(const std::string& ip) {
    return DnsEngine::get().resolve_ptr(ip);
}

[[maybe_unused]] static uint16_t icmp_cksum(const void* data, int len) {
    const uint16_t* buf = reinterpret_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) { sum += *reinterpret_cast<const uint8_t*>(buf); }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

std::string svc(int port) {
    static const std::map<int,std::string> db = {
        {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
        {80,"HTTP"},{110,"POP3"},{111,"RPC"},{135,"MSRPC"},{139,"NetBIOS"},
        {143,"IMAP"},{179,"BGP"},{389,"LDAP"},{443,"HTTPS"},{445,"SMB"},
        {465,"SMTPS"},{512,"rexec"},{513,"rlogin"},{514,"rsh"},
        {548,"AFP"},{587,"Submission"},{636,"LDAPS"},{993,"IMAPS"},
        {995,"POP3S"},{1080,"SOCKS"},{1433,"MSSQL"},{1521,"Oracle"},
        {2049,"NFS"},{2375,"Docker"},{2376,"Docker-TLS"},
        {3000,"Grafana"},{3306,"MySQL"},{3389,"RDP"},{4444,"Metasploit"},
        {5432,"Postgres"},{5900,"VNC"},{5985,"WinRM"},{5986,"WinRM-S"},
        {6379,"Redis"},{6443,"K8s"},{7001,"WebLogic"},{8080,"HTTP-Alt"},
        {8443,"HTTPS-Alt"},{8888,"Jupyter"},{9000,"SonarQube"},
        {9090,"Prometheus"},{9200,"Elastic"},{9300,"ES-Cluster"},
        {10000,"Webmin"},{11211,"Memcached"},{27017,"MongoDB"},{50070,"Hadoop"},
    };
    auto it = db.find(port);
    return it != db.end() ? it->second : "unknown";
}

std::string risk_label(int port) {
    static const std::vector<int> hi = {21,23,512,513,514,3389,5900,445,2375,111,4444,7001,50070};
    static const std::vector<int> md = {22,3306,5432,27017,6379,1433,9200,1521,8888,10000};
    if (std::find(hi.begin(), hi.end(), port) != hi.end()) { return "HIGH"; }
    if (std::find(md.begin(), md.end(), port) != md.end()) { return "MED"; }
    return "LOW";
}

std::string banner(const std::string& ip, int port, int ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return ""; }

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, ms) <= 0) { close(fd); return ""; }
    if (port == 80 || port == 8080 || port == 8888) {
        std::string req = "HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n";
        send(fd, req.c_str(), req.size(), 0);
    }
    std::vector<char> buf(512, 0);
    struct pollfd rpfd{};
    rpfd.fd = fd;
    rpfd.events = POLLIN;
    std::string result;
    if (poll(&rpfd, 1, ms) > 0) {
        ssize_t n = recv(fd, buf.data(), buf.size() - 1, 0);
        if (n > 0) {
            result = std::string(buf.data(), n);
            result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());
            auto nl = result.find('\n');
            if (nl != std::string::npos) { result = result.substr(0, nl); }
            if (result.size() > 70) { result = result.substr(0, 70) + "..."; }
        }
    }
    close(fd);
    return sanitize(result);
}

std::string smart_banner(const std::string& ip, int port, int ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return ""; }



    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));

    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, ms) <= 0) { close(fd); return ""; }

    int sockerr = 0; socklen_t errlen = sizeof(sockerr);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen);
    if (sockerr != 0) { close(fd); return ""; }


    std::string probe;
    switch (port) {
        case 80: case 8080: case 8888: case 8000: case 3000: case 9090:
            probe = "GET / HTTP/1.1\r\nHost: " + ip +
            "\r\nUser-Agent: " + random_ua() + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            break;
        case 443: case 8443: case 9443:
            probe = "GET / HTTP/1.0\r\nUser-Agent: " + random_ua() + "\r\nConnection: close\r\n\r\n";
            break;
        case 25: case 587:
            probe = "EHLO probe.local\r\n";
            break;
        case 6379:
            probe = "INFO\r\n";
            break;
        case 11211:
            probe = "version\r\n";
            break;
        default:
            break;
    }

    if (!probe.empty()) {
        send(fd, probe.c_str(), probe.size(), MSG_NOSIGNAL);
    }

    std::string result;
    std::vector<char> buf(2048, 0);

    auto t_start = std::chrono::steady_clock::now();

    while (result.size() < 4096) {
        auto now = std::chrono::steady_clock::now();
        int elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - t_start).count();
        if (elapsed >= ms) break;

        struct pollfd rpfd{};
        rpfd.fd = fd;
        rpfd.events = POLLIN;
        int s = poll(&rpfd, 1, 100);
        if (s > 0) {
            ssize_t n = recv(fd, buf.data(), buf.size() - 1, 0);
            if (n > 0) {
                result.append(buf.data(), static_cast<size_t>(n));
                if (result.find("\r\n\r\n") != std::string::npos || result.find("\n\n") != std::string::npos) {
                    break;
                }
            } else if (n == 0) {
                break;
            } else {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    break;
                }
            }
        } else if (s < 0 && errno != EINTR) {
            break;
        }
    }
    close(fd);

    result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());
    if (port == 80 || port == 8080 || port == 8888 || port == 8000 ||
        port == 443 || port == 8443 || port == 3000 || port == 9090) {
        auto end = result.find("\n\n");
    if (end != std::string::npos) { result = result.substr(0, end); }
        }
        auto nl = result.find('\n');
        std::string first = (nl != std::string::npos) ? result.substr(0, nl) : result;
        if (first.size() > 80) { first = first.substr(0, 80) + "..."; }

        return sanitize(first);
}

bool udp_probe(const std::string& ip, int port, int ms) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    timeval tv{ ms / 1000, (ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    char payload[] = "\x00\x00\x00\x00";
    sendto(fd, payload, sizeof(payload)-1, 0, (sockaddr*)&sa, sizeof(sa));

    char buf[128];
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int r = poll(&pfd, 1, ms);
    if (r > 0) {
        recv(fd, buf, sizeof(buf), 0);
        close(fd);
        return true;
    }
    close(fd);
    return false;
}


std::string smb_os_probe(const std::string& ip, int ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(445);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));

    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, ms) <= 0) { close(fd); return ""; }

    const uint8_t smb_nego[] = {
        0x00, 0x00, 0x00, 0x54, 0xff, 0x53, 0x4d, 0x42,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x31, 0x00, 0x00, 0x02, 0x4c, 0x41, 0x4e,
        0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 0x02,
        0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30,
        0x32, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41,
        0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30,
        0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20,
        0x30, 0x2e, 0x31, 0x32, 0x00
    };

    send(fd, smb_nego, sizeof(smb_nego), MSG_NOSIGNAL);

    pfd.events = POLLIN;
    std::string res;
    if (poll(&pfd, 1, ms) > 0) {
        std::vector<char> buf(4096, 0);
        ssize_t n = recv(fd, buf.data(), buf.size()-1, 0);
        if (n > 47) {
            std::string raw(buf.data(), n);
            std::string extracted;
            for(size_t i = 47; i < raw.size(); i++){
                if(raw[i] >= 32 && raw[i] <= 126) extracted += raw[i];
                else if (!extracted.empty() && extracted.back() != ' ') extracted += " ";
            }
            if(extracted.find("Windows") != std::string::npos) res = extracted;
            else if(extracted.find("Samba") != std::string::npos) res = extracted;
        }
    }
    close(fd);

    std::string clean;
    bool in_space = false;
    for (char c : res) {
        if (c == ' ') {
            if (!in_space) clean += c;
            in_space = true;
        } else {
            clean += c;
            in_space = false;
        }
    }
    return sanitize(clean);
}


std::string analyze_http_headers(const std::string& ip, int port, int ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));

    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, ms) <= 0) { close(fd); return ""; }

    std::string req = "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: " + random_ua() + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    send(fd, req.c_str(), req.size(), MSG_NOSIGNAL);

    pfd.events = POLLIN;
    std::string res;
    if (poll(&pfd, 1, ms) > 0) {
        std::vector<char> buf(4096, 0);
        ssize_t n = recv(fd, buf.data(), buf.size()-1, 0);
        if (n > 0) res = std::string(buf.data(), n);
    }
    close(fd);

    if (res.empty()) return "";

    std::string server, xpb, waf;
    std::istringstream stream(res);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string l = line;
        std::transform(l.begin(), l.end(), l.begin(), ::tolower);

        if (l.find("server: ") == 0) server = line.substr(8);
        else if (l.find("x-powered-by: ") == 0) xpb = line.substr(14);
        else if (l.find("cf-ray: ") == 0) waf = "Cloudflare";
        else if (l.find("x-sucuri") != std::string::npos) waf = "Sucuri";
        else if (l.find("akamai") != std::string::npos) waf = "Akamai";
    }

    std::string final_sig;
    if (!server.empty()) final_sig += "Server=" + server + " ";
    if (!xpb.empty()) final_sig += "XPB=" + xpb + " ";
    if (!waf.empty()) final_sig += "WAF=" + waf + " ";

    if (!final_sig.empty() && final_sig.back() == ' ') final_sig.pop_back();
    return sanitize(final_sig);
}


#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

std::string tcp_syn_fingerprint(const std::string& ip, int port, int ms) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return "";

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &dest.sin_addr);

    close(sock);

    int sniff_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sniff_sock < 0) return "";

    fcntl(sniff_sock, F_SETFL, O_NONBLOCK);

    int conn_sock = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(conn_sock, F_SETFL, O_NONBLOCK);
    connect(conn_sock, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));

    struct pollfd pfd{};
    pfd.fd = sniff_sock;
    pfd.events = POLLIN;

    auto start = std::chrono::steady_clock::now();
    std::string sig = "";

    while(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() < ms) {
        if (poll(&pfd, 1, 10) > 0) {
            char buffer[65536];
            struct sockaddr_in saddr;
            socklen_t saddr_len = sizeof(saddr);
            ssize_t data_size = recvfrom(sniff_sock, buffer, 65536, 0, (struct sockaddr*)&saddr, &saddr_len);

            if (data_size > 0 && saddr.sin_addr.s_addr == dest.sin_addr.s_addr) {
                struct iphdr *iph = (struct iphdr*)buffer;
                int iph_len = iph->ihl * 4;
                struct tcphdr *tcph = (struct tcphdr*)(buffer + iph_len);

                if (tcph->syn == 1 && tcph->ack == 1 && ntohs(tcph->source) == port) {
                    uint16_t window = ntohs(tcph->window);
                    int ttl = iph->ttl;

                    if (ttl > 64 && ttl <= 128) {
                        if (window == 8192 || window == 64240 || window == 65535 || window == 16384) sig = "Windows";
                        else sig = "Windows/Unknown";
                    } else if (ttl <= 64) {
                        if (window == 29200 || window == 5840 || window == 14600) sig = "Linux (Kernel 2.6 - 5.x)";
                        else if (window == 65535) sig = "macOS/FreeBSD";
                        else sig = "Linux/Unix";
                    } else if (ttl > 128) {
                        if (window == 4128 || window == 16384) sig = "Network Device (Cisco/Juniper)";
                        else sig = "Embedded System";
                    }

                    sig += " (TTL=" + std::to_string(ttl) + " IWS=" + std::to_string(window) + ")";
                    break;
                }
            }
        }
    }

    close(conn_sock);
    close(sniff_sock);
    return sig;
}
