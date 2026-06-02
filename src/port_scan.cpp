#include <unordered_set>
#include <set>
#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"
#include "../include/port_scan_engine.hpp"
#include "../include/user_agents.hpp"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#endif

static RateLimiter port_rl(10000.0);
static const std::vector<int> TOP1000 = {
    1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,
    70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,
    135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,
    280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,
    464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,
    563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,
    705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,
    888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,
    1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,
    1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,
    1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,
    1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,
    1072,1073,1074,1075,1076,1077,1078,1079,1080,1110,1234,1433,1434,1521,
    1720,1723,1755,1900,2000,2001,2049,2121,2181,2375,2376,3000,3128,3306,
    3389,3690,4444,4445,4899,5000,5432,5900,5901,6000,6001,6379,6443,7001,
    7443,8000,8008,8080,8081,8443,8888,9000,9090,9200,9300,10000,11211,
    27017,50070
};

static const std::unordered_set<int> HTTP_PORTS = {
    80, 443, 8080, 8443, 8008, 8888, 3000, 5000, 9000, 9090, 10000,
    2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
    8880, 4443, 7443, 8081, 8181, 8888, 3001, 4000, 6001, 7000
};
static const std::unordered_set<int> TLS_PORTS = {
    443, 8443, 465, 993, 995, 636, 5671, 6443, 4443, 7443, 2083, 2087, 2053, 2096
};

static const std::vector<int> TOP100 = {
    21,22,23,25,53,80,110,111,135,139,143,443,445,
    993,995,1723,3306,3389,5900,8080,8443,8888,
    27017,6379,5432,2375,2376,6443,9200,9300,
    11211,5672,5671,4369,15672,3000,8000,9000,
    1433,1521,5000,5001,5985,5986,47001,49152
};

struct AdaptiveConfig {
    int connect_ms;
    int banner_ms;
    int retry_count;
    int pool_size;
    int median_rtt;
};


static int service_priority(int port) {
    if (port==80||port==443||port==22||port==445||port==3389||port==8080) return 100;
    if (port==21||port==25||port==53||port==110||port==143||port==3306||port==5432) return 50;
    return 10;
}

static std::string extract_version(const std::string& banner_raw, int port) {
    if (banner_raw.empty()) return "";
    std::regex re(R"(([A-Za-z0-9_\-]+[/\-][\d\.]+))");
    std::smatch m;
    if (std::regex_search(banner_raw, m, re)) return m[1].str();
    if (port==22 && banner_raw.find("SSH-")==0) return banner_raw;
    return "";
}

static std::vector<VulnHint> check_vulns(int port, const std::string& version_str,
                                          const std::string& bnr)
{
    std::vector<VulnHint> vulns;
    std::string bl=bnr, vl=version_str;
    std::transform(bl.begin(),bl.end(),bl.begin(),::tolower);
    std::transform(vl.begin(),vl.end(),vl.begin(),::tolower);

    if (port==22 && vl.find("openssh")!=std::string::npos) {
        std::regex re_ver("openssh[_\\s]([0-9]+)\\.([0-9]+)");
        std::smatch m;
        if (std::regex_search(vl,m,re_ver)) {
            int maj=std::stoi(m[1].str()), mn=std::stoi(m[2].str());
            if (maj<9||(maj==9&&mn<8))
                vulns.push_back({"CVE-2024-6387","regreSSHion - signal handler race","CRIT"});
            if (maj<9||(maj==9&&mn<3))
                vulns.push_back({"CVE-2023-38408","agent forwarding RCE","HIGH"});
            if (maj<8||(maj==8&&mn<5))
                vulns.push_back({"CVE-2021-41617","privilege escalation","MED"});
        }
    }

    if (port==21) {
        if (bl.find("anonymous")!=std::string::npos||bl.find("anon")!=std::string::npos)
            vulns.push_back({"N/A","anonymous FTP possibly allowed","MED"});
        if (vl.find("vsftpd 2.3.4")!=std::string::npos)
            vulns.push_back({"CVE-2011-2523","vsFTPd 2.3.4 backdoor","CRIT"});
        if (vl.find("proftpd 1.3.5")!=std::string::npos)
            vulns.push_back({"CVE-2015-3306","mod_copy RCE","CRIT"});
    }

    if (port==80 || port==443 || port==8080 || port==8443) {
        if (bl.find("apache/2.4.49")!=std::string::npos)
            vulns.push_back({"CVE-2021-41773","Path Traversal/RCE","CRIT"});
        if (bl.find("apache/2.4.50")!=std::string::npos)
            vulns.push_back({"CVE-2021-42013","RCE","CRIT"});

        std::regex re_apache("apache/2\\.4\\.(\\d+)");
        std::smatch m_ap;
        if (std::regex_search(bl,m_ap,re_apache) && std::stoi(m_ap[1].str()) < 54)
            vulns.push_back({"CVE-2022-26377","SSRF","HIGH"});

        std::regex re_ngx("nginx/1\\.(\\d+)\\.(\\d+)");
        std::smatch m_ng;
        if (std::regex_search(bl,m_ng,re_ngx)) {
            int minor = std::stoi(m_ng[1].str());
            int patch = std::stoi(m_ng[2].str());
            if (minor < 20 || (minor == 20 && patch < 1))
                vulns.push_back({"CVE-2021-23017","resolver overflow","HIGH"});
            if (minor < 24)
                vulns.push_back({"INFO","outdated nginx version","INFO"});
        }

        if (!version_str.empty())
            vulns.push_back({"INFO","server version disclosed: "+version_str,"INFO"});
    }

    if (port==3306) {
        if (bl.find("5.6.")!=std::string::npos)
            vulns.push_back({"N/A","MySQL 5.6 EOL - no security patches","CRIT"});
        if (bl.find("5.7.")!=std::string::npos)
            vulns.push_back({"CVE-2022-21417","MySQL 5.7 EOL","HIGH"});
        if (bl.find("mysql_native_password")==std::string::npos && bl.find("caching_sha2_password")==std::string::npos && !bl.empty())
            vulns.push_back({"N/A","MySQL unauthenticated access","CRIT"});
    }

    if (port==1433 && !bl.empty())
        vulns.push_back({"CHECK","MSSQL exposed - audit xp_cmdshell, sa account","HIGH"});

    if (port==161 && !bl.empty())
        vulns.push_back({"CHECK","SNMP open - test community strings: public, private, community","HIGH"});

    if (port==123 && !bl.empty())
        vulns.push_back({"CHECK","NTP exposed - test monlist: ntpdc -c monlist <ip>","MED"});

    if (port==500 && !bl.empty())
        vulns.push_back({"CHECK","IKE/VPN exposed - check for aggressive mode","MED"});

    if (port==2376 && !bl.empty())
        vulns.push_back({"CHECK","Docker TLS API - verify client cert required","HIGH"});

    if (port==445||port==139)
        vulns.push_back({"CHECK","SMB exposed - EternalBlue/SMBGhost/PrintNightmare","HIGH"});
    if (port==23)
        vulns.push_back({"N/A","telnet cleartext - credentials sniffable","HIGH"});
    if (port==6379) {
        if (bl.find("noauth")==std::string::npos&&bl.find("denied")==std::string::npos&&!bl.empty())
            vulns.push_back({"N/A","redis possibly unauthenticated - RCE risk","CRIT"});
    }
    if (port==27017) vulns.push_back({"CHECK","MongoDB exposed - check auth","HIGH"});
    if (port==2375)  vulns.push_back({"N/A","Docker API unencrypted - full host compromise","CRIT"});
    if (port==9200)  vulns.push_back({"CHECK","Elasticsearch exposed - check auth & data","HIGH"});
    if (port==3389)  vulns.push_back({"CHECK","RDP exposed - check BlueKeep CVE-2019-0708","HIGH"});
    if (port==6443)  vulns.push_back({"CHECK","K8s API exposed - check RBAC","HIGH"});
    if (port==11211) vulns.push_back({"CHECK","Memcached exposed - DDoS amplification","HIGH"});

    return vulns;
}

static AdaptiveConfig calibrate_target(const std::string& ip) {
    AdaptiveConfig cfg;
    std::vector<int> rtts;
    int cal_ports[]={80,443,22,8080,53};

    for (int p : cal_ports) {
        auto t0=std::chrono::high_resolution_clock::now();
        int fd=socket(AF_INET,SOCK_STREAM,0);
        if (fd<0) continue;
        sockaddr_in sa{};
        sa.sin_family=AF_INET; sa.sin_port=htons(p);
        inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
        fcntl(fd,F_SETFL,O_NONBLOCK);
        connect(fd,(sockaddr*)&sa,sizeof(sa));
        struct pollfd pfd{};
        pfd.fd=fd; pfd.events=POLLOUT;
        int r=poll(&pfd, 1, 800);
        auto t1=std::chrono::high_resolution_clock::now();
        close(fd);
        if (r>0) {
            int ms=std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count();
            rtts.push_back(ms);
        }
    }

    if (rtts.empty()) {
        cfg.connect_ms=1500; cfg.banner_ms=3000;
        cfg.retry_count=2;   cfg.pool_size=50;
        cfg.median_rtt=-1;
        return cfg;
    }

    std::sort(rtts.begin(),rtts.end());
    cfg.median_rtt=rtts[rtts.size()/2];
    cfg.connect_ms=std::max(200,std::min(3000,cfg.median_rtt*3));
    cfg.banner_ms =std::max(500,std::min(5000,cfg.median_rtt*5));
    cfg.retry_count=(cfg.median_rtt<50)?1:2;

    if      (cfg.median_rtt<20)  cfg.pool_size=300;
    else if (cfg.median_rtt<100) cfg.pool_size=150;
    else                         cfg.pool_size=60;

    return cfg;
}

static std::pair<int,bool> probe_connect(const std::string& ip, int port, int timeout_ms, int retries) {
    for (int attempt=0; attempt<=retries; attempt++) {
        FdGuard sock(socket(AF_INET, SOCK_STREAM, 0));
        if (sock.get() < 0) return {-1, false};

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        fcntl(sock.get(), F_SETFL, O_NONBLOCK);

        auto t0 = std::chrono::high_resolution_clock::now();
        int cr = connect(sock.get(), (sockaddr*)&sa, sizeof(sa));

        if (cr == 0) {
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
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
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
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

static uint16_t csum(const void* data, int len) {
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

static uint16_t tcp_csum(const struct pseudo_header* ph, const struct tcphdr* tcph) {
    uint32_t sum = 0;
    auto p = reinterpret_cast<const uint16_t*>(ph);
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) sum += *p++;
    p = reinterpret_cast<const uint16_t*>(tcph);
    for (size_t i = 0; i < sizeof(struct tcphdr) / 2; i++) sum += *p++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static std::pair<int,bool> probe_syn(const std::string& ip, int port, int timeout_ms, int retries) {
    if (!has_cap_net_raw()) return probe_connect(ip, port, timeout_ms, retries);

    for (int attempt = 0; attempt <= retries; attempt++) {
        FdGuard sock_send(socket(AF_INET, SOCK_RAW, IPPROTO_TCP));
        if (sock_send.get() < 0) return probe_connect(ip, port, timeout_ms, retries);

        FdGuard sock_recv(socket(AF_INET, SOCK_RAW, IPPROTO_TCP));
        if (sock_recv.get() < 0) return probe_connect(ip, port, timeout_ms, retries);

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &dest.sin_addr);

        struct sockaddr_in local_addr{};
        socklen_t local_len = sizeof(local_addr);
        FdGuard dgram_sock(socket(AF_INET, SOCK_DGRAM, 0));
        if (dgram_sock.get() >= 0) {
            connect(dgram_sock.get(), (struct sockaddr*)&dest, sizeof(dest));
            getsockname(dgram_sock.get(), (struct sockaddr*)&local_addr, &local_len);
        }

        uint16_t src_port = 33434 + (port % 10000) + attempt;

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
        ssize_t sent = sendto(sock_send.get(), &tcph, sizeof(tcph), 0, (struct sockaddr*)&dest, sizeof(dest));
        if (sent <= 0) return probe_connect(ip, port, timeout_ms, retries);

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
                ssize_t n = recvfrom(sock_recv.get(), buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
                if (n > 0) {
                    struct iphdr* iph = (struct iphdr*)buf;
                    int iph_len = iph->ihl * 4;
                    if (n >= iph_len + (int)sizeof(struct tcphdr)) {
                        struct tcphdr* rtcph = (struct tcphdr*)(buf + iph_len);
                        if (ntohs(rtcph->source) == port && ntohs(rtcph->dest) == src_port) {
                            if (rtcph->syn && rtcph->ack) {
                                // SEND RST
                                tcph.syn = 0; tcph.rst = 1; tcph.ack = 0; tcph.seq = rtcph->ack_seq;
                                tcph.check = 0; tcph.check = tcp_csum(&ph, &tcph);
                                sendto(sock_send.get(), &tcph, sizeof(tcph), 0, (struct sockaddr*)&dest, sizeof(dest));
                                int ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
                                return {std::max(1, ms), false};
                            } else if (rtcph->rst) {
                                return {-1, false};
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
        if (attempt == retries) return {-1, true};
    }
    return {-1, true};
}

static TLSInfo inspect_tls(const std::string& ip, int port, int timeout_ms) {
    TLSInfo tls{};
#ifdef HAVE_OPENSSL
    FdGuard sock(socket(AF_INET, SOCK_STREAM, 0));
    if (sock.get() < 0) return tls;

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    fcntl(sock.get(), F_SETFL, O_NONBLOCK);
    connect(sock.get(), (sockaddr*)&sa, sizeof(sa));

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return tls;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    SSL* ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); return tls; }

    SSL_set_fd(ssl, sock.get());
    SSL_set_tlsext_host_name(ssl, ip.c_str());

    auto deadline = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(timeout_ms);
    bool connected = false;

    while (!g_cancel_token.cancelled) {
        auto now = std::chrono::high_resolution_clock::now();
        int remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (remaining <= 0) break;

        int ret = SSL_connect(ssl);
        if (ret == 1) {
            connected = true;
            break;
        }

        int err = SSL_get_error(ssl, ret);
        struct pollfd pfd{};
        pfd.fd = sock.get();

        if (err == SSL_ERROR_WANT_READ) {
            pfd.events = POLLIN;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            pfd.events = POLLOUT;
        } else {
            break;
        }

        int r = poll(&pfd, 1, remaining);
        if (r <= 0) break;
    }

    if (connected) {
        tls.tls_version = SSL_get_version(ssl);
        X509* cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            char buf[256];
            X509_NAME* subj = X509_get_subject_name(cert);
            if (subj) {
                X509_NAME_get_text_by_NID(subj, NID_commonName, buf, sizeof(buf));
                tls.cn = InputGuard::sanitize_output(buf);
            }
            X509_NAME* issuer = X509_get_issuer_name(cert);
            if (issuer) {
                X509_NAME_get_text_by_NID(issuer, NID_commonName, buf, sizeof(buf));
                tls.issuer = InputGuard::sanitize_output(buf);
            }

            STACK_OF(GENERAL_NAME)* sans = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
            if (sans) {
                int num_sans = sk_GENERAL_NAME_num(sans);
                for (int i = 0; i < num_sans; i++) {
                    GENERAL_NAME* gen = sk_GENERAL_NAME_value(sans, i);
                    if (gen->type == GEN_DNS) {
                        std::string san((char*)ASN1_STRING_get0_data(gen->d.dNSName), ASN1_STRING_length(gen->d.dNSName));
                        tls.sans.push_back(InputGuard::sanitize_output(san));
                    }
                }
                sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
            }

            tls.self_signed = (tls.cn == tls.issuer && !tls.cn.empty());

            const ASN1_TIME* notAfter = X509_get0_notAfter(cert);
            int day, sec;
            if (ASN1_TIME_diff(&day, &sec, nullptr, notAfter)) {
                if (day < 0 || sec < 0) tls.expired = true;
                else tls.expired = false;
            }

            X509_free(cert);
        }
        SSL_shutdown(ssl);
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
#endif
    return tls;
}

static HttpInfo probe_http(const std::string& ip, int port, int timeout_ms, bool aggressive) {
    HttpInfo info{};
    FdGuard sock(socket(AF_INET, SOCK_STREAM, 0));
    if (sock.get() < 0) return info;

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    fcntl(sock.get(), F_SETFL, O_NONBLOCK);
    connect(sock.get(), (sockaddr*)&sa, sizeof(sa));

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLOUT;

    if (poll(&pfd, 1, timeout_ms) <= 0) return info;

    std::string ua = random_ua();
    std::string req = "GET / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: " + ua + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    send(sock.get(), req.c_str(), req.size(), MSG_NOSIGNAL);

    pfd.events = POLLIN;
    std::string res;
    if (poll(&pfd, 1, timeout_ms) > 0) {
        std::vector<char> buf(4096, 0);
        ssize_t n = recv(sock.get(), buf.data(), buf.size()-1, 0);
        if (n > 0) res = std::string(buf.data(), n);
    }

    if (res.empty()) return info;

    std::istringstream stream(res);
    std::string line;
    if (std::getline(stream, line)) {
        if (line.size() > 9 && line.substr(0, 4) == "HTTP") {
            try { info.status_code = std::stoi(line.substr(9, 3)); } catch (...) {}
        }
    }

    while (std::getline(stream, line) && line != "\r" && !line.empty()) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string l = line;
        std::transform(l.begin(), l.end(), l.begin(), ::tolower);

        if (l.find("server: ") == 0) info.server = InputGuard::sanitize_output(line.substr(8));
        else if (l.find("x-powered-by: ") == 0) info.powered_by = InputGuard::sanitize_output(line.substr(14));
        else if (l.find("strict-transport-security: ") == 0) info.hsts = true;
        else if (l.find("content-security-policy: ") == 0) info.csp = true;
        else if (l.find("x-frame-options: ") == 0) info.x_frame = true;
    }

    auto title_start = res.find("<title>");
    if (title_start != std::string::npos) {
        title_start += 7;
        auto title_end = res.find("</title>", title_start);
        if (title_end != std::string::npos) {
            std::string title = res.substr(title_start, title_end - title_start);
            if (title.size() > 80) title = title.substr(0, 80) + "...";
            info.title = InputGuard::sanitize_output(title);
        }
    }

    if (aggressive && (info.status_code == 200 || info.status_code == 403 || info.status_code == 401)) {
        std::vector<std::string> paths = {"/.git/HEAD", "/admin", "/.env", "/api/v1", "/swagger-ui.html"};
        for (const auto& path : paths) {
            FdGuard psock(socket(AF_INET, SOCK_STREAM, 0));
            if (psock.get() < 0) continue;
            fcntl(psock.get(), F_SETFL, O_NONBLOCK);
            connect(psock.get(), (sockaddr*)&sa, sizeof(sa));

            pfd.fd = psock.get();
            pfd.events = POLLOUT;
            if (poll(&pfd, 1, 1000) <= 0) continue;

            std::string preq = "GET " + path + " HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: " + ua + "\r\nConnection: close\r\n\r\n";
            send(psock.get(), preq.c_str(), preq.size(), MSG_NOSIGNAL);

            pfd.events = POLLIN;
            if (poll(&pfd, 1, 1000) > 0) {
                std::vector<char> pbuf(1024, 0);
                ssize_t n = recv(psock.get(), pbuf.data(), pbuf.size()-1, 0);
                if (n > 0) {
                    std::string pres(pbuf.data(), n);
                    if (pres.find("HTTP/1.1 200") != std::string::npos || pres.find("HTTP/1.0 200") != std::string::npos) {
                        info.interesting_paths.push_back(InputGuard::sanitize_output(path));

                        if (path == "/.git/HEAD" && pres.find("ref: refs/") != std::string::npos) {
                            info.interesting_paths.back() += " (git repo exposed)";
                        } else if (path == "/.env" && pres.find("=") != std::string::npos) {
                            info.interesting_paths.back() += " (env file exposed)";
                        }
                    }
                }
            }
        }
    }

    return info;
}

struct UdpProbe {
    int port;
    std::vector<uint8_t> payload;
};

static const std::vector<UdpProbe> UDP_PROBES = {
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

static std::pair<int,bool> probe_udp_smart(const std::string& ip, int port, int timeout_ms) {
    FdGuard sock(socket(AF_INET, SOCK_DGRAM, 0));
    if (sock.get() < 0) return {-1, false};

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
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
    sendto(sock.get(), payload.data(), payload.size(), 0, (sockaddr*)&sa, sizeof(sa));

    char buf[1024];
    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;

    if (poll(&pfd, 1, timeout_ms) > 0) {
        socklen_t len = sizeof(sa);
        ssize_t n = recvfrom(sock.get(), buf, sizeof(buf), 0, (sockaddr*)&sa, &len);
        if (n > 0) {
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
            return {std::max(1, ms), false}; // Response received -> open
        }
        if (n < 0 && errno == ECONNREFUSED) return {-1, false}; // Port unreach -> closed
    }

    // Timeout -> open|filtered (user explicitly requested returning filtered for timeout to avoid 100% false positives)
    return {-1, true};
}

static int sev_rank(const std::string& s) {
    if (s=="CRIT") return 0;
    if (s=="HIGH") return 1;
    if (s=="MED")  return 2;
    return 3;
}

std::string guess_os_from_ports(const std::vector<int>& open) {
    auto has=[&](int p){return std::find(open.begin(),open.end(),p)!=open.end();};
    if(has(3389)||has(5985)||has(5986)||has(445)||has(135)) return "Windows";
    if(has(22)&&!has(3389)){
        if(has(631))  return "Linux (CUPS)";
        if(has(2049)) return "Linux (NFS)";
        return "Linux/Unix";
    }
    if(has(548)||has(5353)) return "macOS/Darwin";
    if(has(23))             return "Network Device";
    if(has(161))            return "SNMP Device";
    return "unknown";
}

PortScanEngine::PortScanEngine(PortScanConfig cfg, CancellationToken& token) : cfg_(cfg), token_(token) {}

std::pair<int,bool> PortScanEngine::probe_connect(int port) {
    return ::probe_connect(cfg_.ip, port, cfg_.connect_ms, cfg_.retry_count);
}

std::pair<int,bool> PortScanEngine::probe_syn(int port) {
    return ::probe_syn(cfg_.ip, port, cfg_.connect_ms, cfg_.retry_count);
}

bool PortScanEngine::probe_udp_smart(int port) {
    auto res = ::probe_udp_smart(cfg_.ip, port, cfg_.connect_ms);
    return res.first > 0;
}

TLSInfo PortScanEngine::inspect_tls(int port) {
    return ::inspect_tls(cfg_.ip, port, cfg_.banner_ms);
}

HttpInfo PortScanEngine::probe_http(int port) {
    return ::probe_http(cfg_.ip, port, cfg_.banner_ms, cfg_.aggressive);
}

std::string PortScanEngine::smart_banner(int port) {
    return ::smart_banner(cfg_.ip, port, cfg_.banner_ms);
}

ScanResults PortScanEngine::run() {
    ScanResults results;
    std::mutex mx;
    std::atomic<int> done_c{0}, open_c{0}, filt_c{0};
    int total = cfg_.ports.size();

    std::vector<int> sorted_ports = cfg_.ports;
    std::sort(sorted_ports.begin(), sorted_ports.end(), [](int a, int b){
        return service_priority(a) > service_priority(b);
    });

    print_section("PHASE 1 // DISCOVERY");
    std::cout << BLOOD_RED << "  sweeping " << WHITE << total << BLOOD_RED << " ports...\n" << RESET;

    auto scan_start = std::chrono::steady_clock::now();
    {
        int psz = std::min(cfg_.pool_size, (int)sorted_ports.size());
        ThreadPool pool(psz);
        std::vector<std::future<void>> futs;
        futs.reserve(total);

        for (int i = 0; i < total; i++) {
            futs.push_back(pool.submit([&, i] {
                if (token_.cancelled) return;

                int p = sorted_ports[i];
                port_rl.acquire();

                std::pair<int,bool> res;
                if (cfg_.udp_scan) {
                    res = ::probe_udp_smart(cfg_.ip, p, cfg_.connect_ms);
                } else if (cfg_.syn_scan) {
                    res = probe_syn(p);
                } else {
                    res = probe_connect(p);
                }

                auto [lat, filtered] = res;
                done_c++;

                if (lat > 0) {
                    PortResult pr{};
                    pr.port = p; pr.latency_ms = lat;

                    std::lock_guard<std::mutex> lk(mx);
                    results.open_ports.push_back(pr);
                    open_c++;

                    std::lock_guard<std::mutex> plk(g_print_mtx);
                    std::cout << BLOOD_RED << "  [+] " << WHITE
                              << std::left << std::setw(6) << p
                              << "/" << (cfg_.udp_scan ? "udp" : "tcp") << "  " << "open" << "  " << std::setw(16) << svc(p)
                              << "(" << lat << "ms)" << RESET << "\n";

                } else if (filtered) {
                    std::lock_guard<std::mutex> lk(mx);
                    results.filtered_ports.push_back(p);
                    filt_c++;
                }
            }));
        }
        auto per_task_timeout = std::chrono::milliseconds(
            (cfg_.connect_ms + cfg_.banner_ms) * (cfg_.retry_count + 1) + 500
        );
        for (auto& f : futs) {
            f.wait_for(per_task_timeout);
        }
    }

    if (token_.cancelled) {
        std::cout << BLOOD_RED << "\n  [!] scan interrupted - partial results\n" << RESET;
    }

    auto scan_end = std::chrono::steady_clock::now();
    results.total_time_s = std::chrono::duration<double>(scan_end - scan_start).count();
    results.ports_per_sec = (int)(total / std::max(results.total_time_s, 0.01));

    std::sort(results.open_ports.begin(), results.open_ports.end(),
              [](const PortResult& a, const PortResult& b){ return a.port < b.port; });

    if (!results.open_ports.empty()) {
        print_section("PHASE 2 // DEEP ANALYSIS");
        std::cout << BLOOD_RED << "  analyzing " << WHITE << results.open_ports.size() << BLOOD_RED << " open ports...\n" << RESET;

        std::atomic<int> deep_done{0};
        int deep_total = results.open_ports.size();

        ThreadPool dpool(std::min(20, deep_total));
        std::vector<std::future<void>> dfuts;
        for (int i = 0; i < deep_total; i++) {
            dfuts.push_back(dpool.submit([&, i] {
                if (token_.cancelled) return;

                int p = results.open_ports[i].port;
                results.open_ports[i].service = svc(p);
                results.open_ports[i].risk = risk_label(p);
                results.open_ports[i].banner_raw = smart_banner(p);
                results.open_ports[i].version = extract_version(results.open_ports[i].banner_raw, p);
                results.open_ports[i].vulns = check_vulns(p, results.open_ports[i].version, results.open_ports[i].banner_raw);

                if (cfg_.tls_inspect && TLS_PORTS.count(p)) {
                    results.open_ports[i].tls = inspect_tls(p);
                    results.open_ports[i].tls_port = true;
                    if (results.open_ports[i].tls.expired) {
                        results.open_ports[i].vulns.push_back({"N/A", "TLS Certificate Expired", "HIGH"});
                    }
                    if (results.open_ports[i].tls.self_signed) {
                        results.open_ports[i].vulns.push_back({"N/A", "TLS Self-Signed Certificate", "MED"});
                    }
                }

                if (cfg_.http_probe && HTTP_PORTS.count(p)) {
                    results.open_ports[i].http = probe_http(p);
                    results.open_ports[i].http_port = true;
                    if ((p==443||p==8443) && !results.open_ports[i].http.hsts && results.open_ports[i].http.status_code > 0)
                        results.open_ports[i].vulns.push_back({"INFO", "missing HSTS header", "INFO"});
                    if (!results.open_ports[i].http.x_frame && results.open_ports[i].http.status_code > 0)
                        results.open_ports[i].vulns.push_back({"INFO", "clickjacking risk (missing X-Frame-Options)", "INFO"});
                    if (!results.open_ports[i].http.csp && results.open_ports[i].http.status_code > 0)
                        results.open_ports[i].vulns.push_back({"INFO", "no Content-Security-Policy", "INFO"});
                }

                deep_done++;
                if (deep_done % 3 == 0 || deep_done == deep_total) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(deep_done, deep_total, "banners...");
                }
            }));
        }
        auto deep_timeout = std::chrono::milliseconds(cfg_.banner_ms * 3 + 1000);
        for (auto& f : dfuts) {
            f.wait_for(deep_timeout);
        }
        std::cout << "\n";
    }

    std::vector<int> open_port_list;
    for (const auto& pr : results.open_ports) open_port_list.push_back(pr.port);
    results.os_hint = guess_os_from_ports(open_port_list);

    return results;
}

void PortScanEngine::print_results(const ScanResults& r) {
    if (r.open_ports.empty()) {
        std::cout << "\n" << BLOOD_RED << "  no open ports found\n" << RESET;
        if (!r.filtered_ports.empty()) {
            std::cout << BLOOD_RED << "  " << WHITE << r.filtered_ports.size() << BLOOD_RED << " filtered (fw silently drops)\n" << RESET;
        }
        return;
    }

    print_section("PHASE 3 // RESULTS");
    std::cout << "\n" << BLOOD_RED << BOLD
              << "  PORT      SERVICE         VERSION                  LATENCY   RISK      BANNER\n"
              << "  " << std::string(100, '-') << "\n" << RESET;

    int vuln_crit = 0, vuln_high = 0, vuln_med = 0, vuln_info = 0;
    std::vector<VulnHint> all_vulns;

    for (const auto& pr : r.open_ports) {
        std::string risk_color = WHITE;
        if (pr.risk == "HIGH") risk_color = BLOOD_RED;

        std::cout << BLOOD_RED << "  " << WHITE << std::left << std::setw(10) << pr.port
                  << std::setw(16) << pr.service
                  << std::setw(25) << (pr.version.empty() ? "-" : pr.version)
                  << std::setw(10) << (std::to_string(pr.latency_ms) + "ms")
                  << risk_color << std::setw(10) << pr.risk << WHITE;

        std::string dbnr = pr.banner_raw;
        if (dbnr.size() > 45) dbnr = dbnr.substr(0, 45) + "...";
        std::cout << sanitize(dbnr) << RESET << "\n";

        PortEntry pe;
        pe.port = pr.port;
        pe.protocol = cfg_.udp_scan ? "udp" : "tcp";
        pe.service = pr.service;
        pe.banner = pr.banner_raw.size() > 200 ? pr.banner_raw.substr(0, 200) + "..." : pr.banner_raw;
        pe.version = pr.version;
        pe.risk = pr.risk;
        pe.latency_ms = pr.latency_ms;
        pe.tls = pr.tls_port;
        pe.tls_version = pr.tls.tls_version;
        pe.tls_cn = pr.tls.cn;
        pe.tls_expired = pr.tls.expired;

        for (const auto& v : pr.vulns) {
            all_vulns.push_back(v);
            pe.vulns.push_back(v.cve + ":" + v.severity + ":" + v.desc);
            if      (v.severity == "CRIT") vuln_crit++;
            else if (v.severity == "HIGH") vuln_high++;
            else if (v.severity == "MED")  vuln_med++;
            else                         vuln_info++;
        }

        std::lock_guard<std::mutex> lk(g_result_mtx);
        g_result.ports.push_back(pe);
        g_result.open_ports.push_back({pr.port, pr.service}); // legacy
    }

    g_result.os_guess = r.os_hint;

    print_section("SCAN STATS");
    std::cout << BLOOD_RED << "  [os guess]      " << WHITE << r.os_hint << "\n";
    std::cout << BLOOD_RED << "  [open ports]    " << WHITE << r.open_ports.size() << "\n";
    std::cout << BLOOD_RED << "  [filtered]      " << WHITE << r.filtered_ports.size() << "\n";
    std::cout << BLOOD_RED << "  [scan time]     " << WHITE << std::fixed << std::setprecision(2) << r.total_time_s << "s\n";
    std::cout << BLOOD_RED << "  [speed]         " << WHITE << r.ports_per_sec << " ports/sec\n";

    if (!all_vulns.empty()) {
    // Deduplicate by (cve + desc) key
    {
        std::set<std::string> seen_vulns;
        std::vector<VulnHint> deduped;
        deduped.reserve(all_vulns.size());
        for (auto& v : all_vulns) {
            std::string key = v.cve + "|" + v.desc;
            if (seen_vulns.insert(key).second) {
                deduped.push_back(v);
            }
        }
        all_vulns = std::move(deduped);
    }
    // Re-sort by severity: CRIT > HIGH > MED > INFO
    std::sort(all_vulns.begin(), all_vulns.end(), [](const VulnHint& a, const VulnHint& b){
        return sev_rank(a.severity) < sev_rank(b.severity);
    });
    // Recount after dedup
    vuln_crit = vuln_high = vuln_med = vuln_info = 0;
    for (auto& v : all_vulns) {
        if      (v.severity=="CRIT") vuln_crit++;
        else if (v.severity=="HIGH") vuln_high++;
        else if (v.severity=="MED")  vuln_med++;
        else                         vuln_info++;
    }
        print_section("VULNERABILITY HINTS");
        std::cout << BLOOD_RED << "  " << WHITE << vuln_crit << BLOOD_RED << " CRIT  " << WHITE << vuln_high << BLOOD_RED << " HIGH  " << WHITE << vuln_med << BLOOD_RED << " MED\n\n" << RESET;

        for (const auto& v : all_vulns) {
            std::string c_col = WHITE;
            if (v.severity == "CRIT") c_col = BLOOD_RED;
            else if (v.severity == "HIGH") c_col = YELLOW;

            std::cout << "  " << c_col << "[" << std::left << std::setw(4) << v.severity << "] " << std::setw(14) << v.cve << " " << WHITE << v.desc << "\n" << RESET;
        }
    }

    LOG_INFO("port_scan", "done target=" + cfg_.ip +
        " open=" + std::to_string(r.open_ports.size()) +
        " filtered=" + std::to_string(r.filtered_ports.size()) +
        " time=" + std::to_string((int)r.total_time_s) + "s");
}

// Calling conventions:
//   start=0, end_port=0          → top-1000 TCP ports
//   start=0, end_port=-1         → top-100 TCP ports
//   start=N, end_port=0          → single port N (TCP or UDP)
//   start=N, end_port=M (M>=N)   → range N..M
//   scan_udp=true                → use UDP probes instead of TCP SYN/connect
//
// For UDP single port: caller should pass start=N, end_port=0, scan_udp=true
// For UDP range 1-1024: caller passes start=1, end_port=1024, scan_udp=true
//   The caller (menu) should default UDP end_port to 1024 if user skips it.

void port_scan(const std::string& ip, int start, int end_port, bool scan_udp) {
    print_header("PORT SCAN // " + ip);

    PortScanConfig cfg{};
    cfg.ip = ip;
    cfg.udp_scan = scan_udp;
    cfg.syn_scan = true;
    cfg.tls_inspect = true;
    cfg.http_probe = true;
    cfg.aggressive = true;

    if (start == 0 && end_port == 0) {
        // no range given → top-1000
        cfg.ports = TOP1000;
        std::cout << BLOOD_RED << "  mode: " << WHITE << "top-1000 ports\n" << RESET;
    } else if (start > 0 && end_port == 0) {
        // single port check (e.g. start=8080, end=0 means "just check port 8080")
        cfg.ports = {start};
        std::cout << BLOOD_RED << "  mode: " << WHITE << "single port → " << start << "\n" << RESET;
    } else if (start == 0 && end_port > 0) {
        // top-100 shortcut kept for backward compat (caller can send start=0,end=-1 for top-100)
        cfg.ports = TOP100;
        std::cout << BLOOD_RED << "  mode: " << WHITE << "top-100 ports\n" << RESET;
    } else {
        // explicit range
        int lo = std::max(1, start);
        int hi = std::min(65535, end_port);
        cfg.ports.reserve(hi - lo + 1);
        for (int p = lo; p <= hi; p++) cfg.ports.push_back(p);
        std::cout << BLOOD_RED << "  range: " << WHITE << lo << "-" << hi
                  << BLOOD_RED << " (" << WHITE << cfg.ports.size() << BLOOD_RED << " ports)\n" << RESET;
    }

    if (cfg.udp_scan) {
        std::cout << BLOOD_RED << "\n  [*] UDP SCAN SELECTED — sending protocol-aware probes\n"
                  << "      note: open|filtered = no ICMP unreachable received (normal for UDP)\n"
                  << RESET;
    }

    print_section("PHASE 0 // CALIBRATION");
    std::cout << BLOOD_RED << "  measuring target latency...\n" << RESET;

    auto acfg = calibrate_target(ip);
    cfg.connect_ms = acfg.connect_ms;
    cfg.banner_ms = acfg.banner_ms;
    cfg.retry_count = acfg.retry_count;
    cfg.pool_size = acfg.pool_size;

    // For large ranges: reduce retries, tighten timeouts to avoid stalling
    int port_count = (int)cfg.ports.size();
    if (port_count > 5000) {
        cfg.retry_count = 1;
        // clamp connect timeout tighter for large sweeps
        cfg.connect_ms = std::max(150, std::min(cfg.connect_ms, 800));
        // scale pool up to handle volume but cap at system limits
        cfg.pool_size  = std::min(500, cfg.pool_size * 2);
        std::cout << BLOOD_RED << "  [large-range] " << WHITE
                  << "adjusted: timeout=" << cfg.connect_ms << "ms"
                  << " retries=1 threads=" << cfg.pool_size << "\n" << RESET;
    } else if (port_count > 1000) {
        cfg.retry_count = std::min(cfg.retry_count, 1);
        cfg.pool_size   = std::min(300, cfg.pool_size + 50);
    }
    // UDP needs longer timeout per-port (single attempt, ICMP wait)
    if (cfg.udp_scan) {
        cfg.connect_ms = std::max(cfg.connect_ms, 1500);
        cfg.pool_size  = std::min(cfg.pool_size, 100); // UDP is I/O bound, fewer threads
    }
    cfg.median_rtt = acfg.median_rtt;

    std::cout << BLOOD_RED << "  rtt: " << WHITE
              << (cfg.median_rtt >= 0 ? std::to_string(cfg.median_rtt) + "ms" : "n/a")
              << BLOOD_RED << "  timeout: " << WHITE << cfg.connect_ms << "ms"
              << BLOOD_RED << "  retries: " << WHITE << cfg.retry_count
              << BLOOD_RED << "  threads: " << WHITE << cfg.pool_size << "\n" << RESET;

    std::string hostname = ptr_lookup(ip);
    if (!hostname.empty() && hostname != ip)
        std::cout << BLOOD_RED << "  ptr: " << WHITE << hostname << "\n" << RESET;

    PortScanEngine engine(cfg, g_cancel_token);
    ScanResults res = engine.run();
    engine.print_results(res);
}

void net_scan(const std::string& subnet) {
    print_header("NETWORK SCAN // " + subnet + ".0/24");

    static const std::vector<int> PROBE_PORTS={21,22,23,25,80,443,445,3389,8080,5985};

    std::cout<<BLOOD_RED<<"  phase 1: host discovery...\n"<<RESET;

    struct HostInfo {
        std::string ip, hostname, os;
        std::vector<std::pair<int,std::string>> ports;
        bool alive=false;
    };
    std::vector<HostInfo> hosts(254);
    std::atomic<int> cur(0), alive_c(0);

    ThreadPool pool(100);
    std::vector<std::future<void>> futs;
    futs.reserve(254);

    for (int i=1;i<=254;i++) {
        futs.push_back(pool.submit([&,i]{
            if (g_cancel_token.cancelled) return;
            std::string ip=subnet+"."+std::to_string(i);
            HostInfo& h=hosts[i-1]; h.ip=ip;

            auto pout=safe_exec({"ping","-c1","-W1","-q",ip},2);
            bool alive=!pout.empty()&&pout.find("1 received")!=std::string::npos;
            if(!alive) for(int p:PROBE_PORTS){if(tcp_probe(ip,p,300)){alive=true;break;}}
            if(!alive) return;

            h.alive=true; alive_c++;

            // Threaded ptr_lookup equivalent via getnameinfo, no blocking future destructor since we use ThreadPool directly.
            // Even though getnameinfo blocks, we submit to thread pool and limit timeout to avoid hang.
            // To ensure getnameinfo doesn't block infinitely, we can resolve directly here since it's already in a pool thread!
            char hbuf[NI_MAXHOST]={};
            sockaddr_in sa{}; sa.sin_family=AF_INET;
            inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
            getnameinfo((sockaddr*)&sa,sizeof(sa),hbuf,sizeof(hbuf),nullptr,0,0);
            h.hostname=strlen(hbuf)?sanitize(hbuf):"";

            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout<<BLOOD_RED<<"  [+] "<<WHITE<<std::left<<std::setw(16)<<ip;
            if(!h.hostname.empty()) std::cout<<BLOOD_RED<<" ("<<WHITE<<h.hostname<<BLOOD_RED<<")";
            std::cout<<RESET<<"\n";
        }));
    }
    for (auto& f:futs) {
        if (f.wait_for(std::chrono::seconds(2)) == std::future_status::timeout) {
            // Abandon task
        }
    }

    std::cout<<BLOOD_RED<<"\n  found "<<WHITE<<alive_c<<BLOOD_RED<<" hosts -- phase 2: port scan...\n\n"<<RESET;

    std::vector<HostInfo*> alive_hosts;
    for (auto& h:hosts) if(h.alive) alive_hosts.push_back(&h);

    std::atomic<int> task(0);
    int ntasks=alive_hosts.size()*PROBE_PORTS.size();
    std::vector<std::future<void>> futs2; futs2.reserve(ntasks);

    for (int i=0;i<(int)alive_hosts.size();i++) {
        for (int p:PROBE_PORTS) {
            futs2.push_back(pool.submit([&,i,p]{
                auto [lat, filtered] = probe_connect(alive_hosts[i]->ip, p, 400, 1);
                if(lat <= 0) return;
                std::string b=banner(alive_hosts[i]->ip,p,1000);
                std::lock_guard<std::mutex> lk(g_print_mtx);
                alive_hosts[i]->ports.emplace_back(p,b);
            }));
        }
    }
    for (auto& f:futs2) f.get();

    std::cout<<BLOOD_RED<<"  results:\n\n"<<RESET;
    int total_open=0;
    for (auto* h:alive_hosts) {
        std::sort(h->ports.begin(),h->ports.end());
        std::vector<int> op; for(auto& [p,_]:h->ports) op.push_back(p);
        h->os=guess_os_from_ports(op);

        std::cout<<BLOOD_RED<<"  ┌─ "<<WHITE<<std::left<<std::setw(16)<<h->ip;
        if(!h->hostname.empty()) std::cout<<BLOOD_RED<<" ["<<WHITE<<h->hostname<<BLOOD_RED<<"]";
        std::cout<<BLOOD_RED<<"  os: "<<WHITE<<h->os<<RESET<<"\n";

        if(h->ports.empty()) std::cout<<BLOOD_RED<<"  │  "<<WHITE<<"no open ports\n"<<RESET;
        for (auto& [p,b]:h->ports) {
            std::cout<<BLOOD_RED<<"  │  "<<WHITE<<std::setw(6)<<p<<" "<<std::setw(18)<<svc(p);
            if(!b.empty()) std::cout << "  " << sanitize(b);
            std::cout<<RESET<<"\n";
            total_open++;
        }
        std::cout<<BLOOD_RED<<"  └"<<std::string(36,'-')<<RESET<<"\n";
    }

    std::cout<<"\n"<<BLOOD_RED<<"  hosts alive: "<<WHITE<<alive_c<<BLOOD_RED<<"  open ports: "<<WHITE<<total_open<<"\n"<<RESET;
    LOG_INFO("net_scan","done subnet="+subnet+" alive="+std::to_string(alive_c));
}
