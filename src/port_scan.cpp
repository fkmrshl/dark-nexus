#include <atomic>
#include <cstdint>
#include <memory>
#include <sys/resource.h>
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
#include <openssl/bio.h>
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

static bool is_tls_http_port(int port) {
    return TLS_PORTS.count(port) && HTTP_PORTS.count(port);
}

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

static int sev_rank(const std::string& s) {
    if (s == "CRIT") return 0;
    if (s == "HIGH") return 1;
    if (s == "MED")  return 2;
    return 3;
}

static bool is_significant_severity(const std::string& sev) {
    return sev == "CRIT" || sev == "HIGH" || sev == "MED";
}

static void add_vuln_hint(std::vector<VulnHint>& out, std::set<std::string>& seen,
                          const std::string& cve, const std::string& desc,
                          const std::string& sev) {
    if (!is_significant_severity(sev)) return;
    std::string key = cve + "|" + desc;
    if (seen.insert(key).second)
        out.push_back({cve, desc, sev});
}

static std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static std::string fingerprint_text(const std::string& banner, const std::string& version,
                                    const HttpInfo* http) {
    std::string hay = lower_copy(banner) + " " + lower_copy(version);
    if (http && !http->server.empty())
        hay += " " + lower_copy(http->server);
    if (http && !http->powered_by.empty())
        hay += " " + lower_copy(http->powered_by);
    return hay;
}

static void check_web_version_cves(const std::string& hay, std::vector<VulnHint>& out,
                                   std::set<std::string>& seen) {
    if (hay.find("apache/2.4.49") != std::string::npos)
        add_vuln_hint(out, seen, "CVE-2021-41773", "Apache 2.4.49 path traversal/RCE", "CRIT");
    if (hay.find("apache/2.4.50") != std::string::npos)
        add_vuln_hint(out, seen, "CVE-2021-42013", "Apache 2.4.50 RCE", "CRIT");

    std::regex re_apache(R"(apache/2\.4\.(\d+))");
    std::smatch m_ap;
    if (std::regex_search(hay, m_ap, re_apache)) {
        int patch = std::stoi(m_ap[1].str());
        if (patch < 54)
            add_vuln_hint(out, seen, "CVE-2022-26377", "Apache 2.4." + m_ap[1].str() + " SSRF", "HIGH");
    }

    std::regex re_ngx(R"(nginx/1\.(\d+)\.(\d+))");
    std::smatch m_ng;
    if (std::regex_search(hay, m_ng, re_ngx)) {
        int minor = std::stoi(m_ng[1].str());
        int patch = std::stoi(m_ng[2].str());
        if (minor < 20 || (minor == 20 && patch < 1))
            add_vuln_hint(out, seen, "CVE-2021-23017", "nginx resolver overflow (1." + m_ng[1].str() + "." + m_ng[2].str() + ")", "HIGH");
    }
}

static void check_tls_hints(int port, const TLSInfo* tls, std::vector<VulnHint>& out,
                            std::set<std::string>& seen) {
    if (!tls || !TLS_PORTS.count(port)) return;

    if (tls->expired)
        add_vuln_hint(out, seen, "N/A", "TLS certificate expired", "HIGH");
    if (tls->self_signed)
        add_vuln_hint(out, seen, "N/A", "TLS certificate is self-signed", "MED");

    const std::string& ver = tls->tls_version;
    if (ver.find("TLSv1.0") != std::string::npos || ver.find("TLSv1.1") != std::string::npos)
        add_vuln_hint(out, seen, "N/A", "Deprecated TLS version negotiated (" + ver + ")", "HIGH");

    if (!tls->cipher.empty()) {
        std::string c = lower_copy(tls->cipher);
        if (c.find("null") != std::string::npos || c.find("export") != std::string::npos ||
            c.find("des") != std::string::npos || c.find("rc4") != std::string::npos)
            add_vuln_hint(out, seen, "N/A", "Weak TLS cipher negotiated: " + tls->cipher, "HIGH");
    }
}

static void check_http_security_hints(int port, const HttpInfo* http, std::vector<VulnHint>& out,
                                      std::set<std::string>& seen) {
    if (!http || http->status_code <= 0) return;

    const bool https = is_tls_http_port(port) || port == 443 || port == 8443;

    if (https && !http->hsts)
        add_vuln_hint(out, seen, "N/A", "HTTPS response missing Strict-Transport-Security", "MED");

    if (https && http->status_code == 200 && !http->csp)
        add_vuln_hint(out, seen, "N/A", "HTTPS response missing Content-Security-Policy", "MED");

    if (http->status_code == 200 && !http->x_frame)
        add_vuln_hint(out, seen, "N/A", "HTTP 200 response missing X-Frame-Options", "MED");

    if (!http->powered_by.empty()) {
        std::string pb = lower_copy(http->powered_by);
        if (pb.find("php/") != std::string::npos) {
            std::regex re_php(R"(php/(\d+)\.(\d+))");
            std::smatch m;
            if (std::regex_search(pb, m, re_php)) {
                int maj = std::stoi(m[1].str()), min = std::stoi(m[2].str());
                bool php_eol = (maj < 7)
                            || (maj == 7 && min < 4)
                            || (maj == 8 && min == 0);
                if (php_eol)
                    add_vuln_hint(out, seen, "N/A",
                        "End-of-life PHP disclosed (" +
                        InputGuard::sanitize_output(http->powered_by) + ")", "HIGH");
            }
        }
    }
}

static void check_redirect_hints(int port, const HttpInfo* http, std::vector<VulnHint>& out,
                                 std::set<std::string>& seen) {
    if (!http || http->status_code < 300 || http->status_code >= 400) return;
    if (http->redirect_location.empty()) return;

    std::string loc = lower_copy(http->redirect_location);
    const bool https_port = is_tls_http_port(port) || port == 443 || port == 8443;

    if (https_port && loc.rfind("http://", 0) == 0)
        add_vuln_hint(out, seen, "N/A", "HTTPS redirects to cleartext HTTP: " + http->redirect_location, "HIGH");

    if ((port == 80 || port == 8080) && loc.rfind("http://", 0) == 0 && loc.find("https://") == std::string::npos)
        add_vuln_hint(out, seen, "N/A", "HTTP redirect does not upgrade to HTTPS", "MED");
}

static void check_port_exposure_hints(int port, std::vector<VulnHint>& out,
                                      std::set<std::string>& seen) {
    struct ExposureEntry { int port; const char* sev; const char* desc; };
    static const ExposureEntry kExposure[] = {
        {3389,  "HIGH", "RDP exposed on network — brute-force/exploit surface"},
        {5432,  "HIGH", "PostgreSQL exposed on network — verify auth and network ACLs"},
        {1433,  "HIGH", "MSSQL exposed on network — verify auth and network ACLs"},
        {27017, "CRIT", "MongoDB exposed — unauthenticated by default pre-4.0"},
        {9200,  "CRIT", "Elasticsearch HTTP API exposed — unauthenticated by default"},
        {9300,  "HIGH", "Elasticsearch transport layer exposed"},
        {2379,  "CRIT", "etcd API exposed — Kubernetes secrets accessible"},
        {5984,  "HIGH", "CouchDB admin API exposed"},
        {11211, "HIGH", "Memcached exposed — no auth, DDoS amplification vector"},
        {5900,  "HIGH", "VNC exposed — remote desktop without VPN"},
        {5901,  "HIGH", "VNC exposed — remote desktop without VPN"},
        {4444,  "CRIT", "Port 4444 — common Metasploit/C2 indicator"},
        {6000,  "MED",  "X11 display server exposed — session hijacking risk"},
        {50070, "CRIT", "Hadoop NameNode web UI exposed"},
    };
    for (const auto& e : kExposure) {
        if (port == e.port)
            add_vuln_hint(out, seen, "N/A", e.desc, e.sev);
    }
}

static std::vector<VulnHint> check_vulns(int port, const std::string& version_str,
                                          const std::string& bnr, const TLSInfo* tls,
                                          const HttpInfo* http) {
    std::vector<VulnHint> vulns;
    std::set<std::string> seen;
    check_port_exposure_hints(port, vulns, seen);
    std::string bl = lower_copy(bnr);
    std::string vl = lower_copy(version_str);
    std::string hay = fingerprint_text(bnr, version_str, http);
    const bool has_banner = !bnr.empty();

    if (port == 22 && vl.find("openssh") != std::string::npos) {
        std::regex re_ver(R"(openssh[_\s]([0-9]+)\.([0-9]+))");
        std::smatch m;
        if (std::regex_search(vl, m, re_ver)) {
            int maj = std::stoi(m[1].str()), mn = std::stoi(m[2].str());
            if (maj < 9 || (maj == 9 && mn < 8))
                add_vuln_hint(vulns, seen, "CVE-2024-6387", "OpenSSH regreSSHion (signal handler race)", "CRIT");
            if (maj < 9 || (maj == 9 && mn < 3))
                add_vuln_hint(vulns, seen, "CVE-2023-38408", "OpenSSH agent forwarding RCE", "HIGH");
            if (maj < 8 || (maj == 8 && mn < 5))
                add_vuln_hint(vulns, seen, "CVE-2021-41617", "OpenSSH privilege escalation", "MED");
        }
    }

    if (port == 21 && has_banner) {
        if (bl.find("anonymous") != std::string::npos || bl.find("230 login") != std::string::npos)
            add_vuln_hint(vulns, seen, "N/A", "FTP banner suggests anonymous login allowed", "MED");
        if (hay.find("vsftpd 2.3.4") != std::string::npos)
            add_vuln_hint(vulns, seen, "CVE-2011-2523", "vsFTPd 2.3.4 backdoor", "CRIT");
        if (hay.find("proftpd 1.3.5") != std::string::npos)
            add_vuln_hint(vulns, seen, "CVE-2015-3306", "ProFTPD 1.3.5 mod_copy RCE", "CRIT");
    }

    if (HTTP_PORTS.count(port))
        check_web_version_cves(hay, vulns, seen);

    if (port == 3306 && has_banner) {
        if (bl.find("5.6.") != std::string::npos)
            add_vuln_hint(vulns, seen, "N/A", "MySQL 5.6 (EOL, no security patches)", "CRIT");
        if (bl.find("5.7.") != std::string::npos)
            add_vuln_hint(vulns, seen, "CVE-2022-21417", "MySQL 5.7 reached EOL", "HIGH");
        if (bl.find("mysql_native_password") == std::string::npos &&
            bl.find("caching_sha2_password") == std::string::npos)
            add_vuln_hint(vulns, seen, "N/A", "MySQL handshake without expected auth plugin", "HIGH");
    }

    if (port == 6379 && has_banner) {
        if (bl.find("noauth") == std::string::npos && bl.find("denied") == std::string::npos &&
            bl.find("-err") == std::string::npos && bl.find("-noauth") == std::string::npos)
            add_vuln_hint(vulns, seen, "N/A", "Redis responded without authentication error", "CRIT");
    }

    if (port == 23)
        add_vuln_hint(vulns, seen, "N/A", "Telnet service exposes cleartext credentials", "HIGH");

    if (port == 2375)
        add_vuln_hint(vulns, seen, "N/A", "Docker API on unencrypted port 2375", "CRIT");

    if (port == 161 && has_banner)
        add_vuln_hint(vulns, seen, "N/A", "SNMP service responded to probe (verify community strings)", "MED");

    if (port == 9200 && has_banner) {
        if (bl.find("\"cluster_name\"") != std::string::npos ||
            bl.find("you know, for search") != std::string::npos)
            add_vuln_hint(vulns, seen, "N/A",
                "Elasticsearch responded without auth (CVE-2014-3120 class)", "CRIT");
    }

    if (port == 27017 && has_banner) {
        if (bl.find("mongodb-open") != std::string::npos ||
            bl.find("ismaster") != std::string::npos)
            add_vuln_hint(vulns, seen, "N/A",
                "MongoDB accepts connections without auth challenge", "CRIT");
    }

    if (port == 11211 && has_banner) {
        if (bl.find("version") != std::string::npos ||
            bl.find("stat") != std::string::npos)
            add_vuln_hint(vulns, seen, "N/A",
                "Memcached responded to stats probe — no auth configured", "HIGH");
    }

    check_tls_hints(port, tls, vulns, seen);
    check_http_security_hints(port, http, vulns, seen);
    check_redirect_hints(port, http, vulns, seen);

    return vulns;
}

static std::vector<VulnHint> dedupe_and_sort_vulns(std::vector<VulnHint> vulns) {
    std::set<std::string> seen;
    std::vector<VulnHint> deduped;
    deduped.reserve(vulns.size());
    for (auto& v : vulns) {
        if (!is_significant_severity(v.severity)) continue;
        std::string key = v.cve + "|" + v.desc;
        if (seen.insert(key).second)
            deduped.push_back(std::move(v));
    }
    std::sort(deduped.begin(), deduped.end(), [](const VulnHint& a, const VulnHint& b) {
        return sev_rank(a.severity) < sev_rank(b.severity);
    });
    return deduped;
}

static AdaptiveConfig calibrate_target(const std::string& ip) {
    AdaptiveConfig cfg;
    std::vector<int> rtts;
    int cal_ports[]={80,443,22,8080,53};

    for (int p : cal_ports) {
        auto t0=std::chrono::high_resolution_clock::now();
        FdGuard fd(socket(AF_INET,SOCK_STREAM,0));
        if (fd.get()<0) continue;
        sockaddr_in sa{};
        sa.sin_family=AF_INET; sa.sin_port=htons(p);
        inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
        fcntl(fd.get(),F_SETFL,O_NONBLOCK);
        connect(fd.get(),(sockaddr*)&sa,sizeof(sa));
        struct pollfd pfd{};
        pfd.fd=fd.get(); pfd.events=POLLOUT;
        int r=poll(&pfd, 1, 800);
        auto t1=std::chrono::high_resolution_clock::now();
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
                if (n >= 20) {
                    struct iphdr* iph = (struct iphdr*)buf;
                    if (iph->ihl >= 5 && iph->version == 4) {
                        int iph_len = iph->ihl * 4;
                        if (n >= iph_len + (int)sizeof(struct tcphdr)) {
                        struct tcphdr* rtcph = (struct tcphdr*)(buf + iph_len);
                        if (ntohs(rtcph->source) == port && ntohs(rtcph->dest) == src_port) {
                            if (rtcph->syn && rtcph->ack) {
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

static std::string resolve_sni_host(const std::string& scan_ip) {
    const std::string& target = g_result.target;
    if (!target.empty() && target != scan_ip &&
        !InputGuard::is_valid_ipv4(target) && !InputGuard::is_valid_ipv6(target)) {
        return target;
    }
    std::string ptr = ptr_lookup(scan_ip);
    if (!ptr.empty() && ptr != scan_ip) return ptr;
    return scan_ip;
}

static bool tcp_connect_wait(int fd, int timeout_ms) {
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

static bool tcp_connect_to(const std::string& ip, int port, int timeout_ms, int fd) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) return false;

    fcntl(fd, F_SETFL, O_NONBLOCK);
    int cr = connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    if (cr == 0) {
        int sockerr = 0;
        socklen_t errlen = sizeof(sockerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen);
        return sockerr == 0;
    }
    if (errno != EINPROGRESS) return false;
    return tcp_connect_wait(fd, timeout_ms);
}

static std::string probe_redis_ping(const std::string& ip, int port, int timeout_ms) {
    if (g_cancel_token.cancelled) return {};
    FdGuard sock(socket(AF_INET, SOCK_STREAM, 0));
    if (sock.get() < 0) return {};
    if (!tcp_connect_to(ip, port, timeout_ms, sock.get())) return {};

    static const char kPing[] = "PING\r\n";
    if (send(sock.get(), kPing, sizeof(kPing) - 1, MSG_NOSIGNAL) < 0) return {};

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0 || !(pfd.revents & POLLIN)) return {};

    char buf[64];
    ssize_t n = recv(sock.get(), buf, sizeof(buf), 0);
    if (n <= 0) return {};
    return std::string(buf, static_cast<size_t>(n));
}

static std::string probe_mongo_ping(const std::string& ip, int port, int timeout_ms) {
    if (g_cancel_token.cancelled) return {};
    static const uint8_t kMongoIsMasterProbe[] = {
        0x3a,0x00,0x00,0x00, 0x01,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0xd4,0x07,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,0x6d,0x64,0x00,
        0x00,0x00,0x00,0x00, 0x01,0x00,0x00,0x00,
        0x13,0x00,0x00,0x00, 0x10,0x69,0x73,0x4d,
        0x61,0x73,0x74,0x65,0x72,0x00, 0x01,0x00,0x00,0x00, 0x00
    };

    FdGuard sock(socket(AF_INET, SOCK_STREAM, 0));
    if (sock.get() < 0) return {};
    if (!tcp_connect_to(ip, port, timeout_ms, sock.get())) return {};

    if (send(sock.get(), kMongoIsMasterProbe, sizeof(kMongoIsMasterProbe), MSG_NOSIGNAL) < 0)
        return {};

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0 || !(pfd.revents & POLLIN)) return {};

    char buf[512];
    ssize_t n = recv(sock.get(), buf, sizeof(buf), 0);
    if (n < 4) return {};

    uint32_t msg_len = static_cast<uint32_t>(static_cast<uint8_t>(buf[0]))
        | (static_cast<uint32_t>(static_cast<uint8_t>(buf[1])) << 8)
        | (static_cast<uint32_t>(static_cast<uint8_t>(buf[2])) << 16)
        | (static_cast<uint32_t>(static_cast<uint8_t>(buf[3])) << 24);
    if (msg_len < 16 || msg_len > 65536) return {};

    std::string resp(buf, static_cast<size_t>(n));
    std::string low = lower_copy(resp);
    if (low.find("ismaster") != std::string::npos)
        return resp;
    return "mongodb-open";
}

#ifdef HAVE_OPENSSL
namespace {

struct SSL_CTX_Deleter {
    void operator()(SSL_CTX* ctx) const noexcept {
        if (ctx) SSL_CTX_free(ctx);
    }
};
struct SSL_Deleter {
    void operator()(SSL* ssl) const noexcept {
        if (ssl) SSL_free(ssl);
    }
};
struct X509_Deleter {
    void operator()(X509* cert) const noexcept {
        if (cert) X509_free(cert);
    }
};

using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, SSL_CTX_Deleter>;
using SSL_ptr     = std::unique_ptr<SSL, SSL_Deleter>;
using X509_ptr    = std::unique_ptr<X509, X509_Deleter>;

std::string openssl_err_stack() {
    std::string msg;
    unsigned long err = 0;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!msg.empty()) msg += "; ";
        msg += buf;
    }
    return msg;
}

const char* ssl_error_label(int ssl_err) {
    switch (ssl_err) {
        case SSL_ERROR_NONE: return "NONE";
        case SSL_ERROR_SSL: return "SSL";
        case SSL_ERROR_WANT_READ: return "WANT_READ";
        case SSL_ERROR_WANT_WRITE: return "WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP: return "WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL: return "SYSCALL";
        case SSL_ERROR_ZERO_RETURN: return "ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT: return "WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT: return "WANT_ACCEPT";
        default: return "UNKNOWN";
    }
}

void log_tls_handshake_fail(const std::string& context, SSL* ssl, int ssl_connect_ret, int ssl_err) {
    std::string msg = context + " ssl_err=" + ssl_error_label(ssl_err) +
                      "(" + std::to_string(ssl_err) + ")";
    if (ssl_connect_ret != 1)
        msg += " ret=" + std::to_string(ssl_connect_ret);
    if (ssl && ssl_err == SSL_ERROR_SYSCALL) {
        if (errno != 0) msg += " errno=" + std::string(strerror(errno));
    }
    std::string stack = openssl_err_stack();
    if (!stack.empty()) msg += " openssl=[" + stack + "]";
    LOG_WARN("port_scan_tls", msg);
}

std::string asn1_time_to_string(const ASN1_TIME* t) {
    if (!t) return "";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    if (ASN1_TIME_print(bio, const_cast<ASN1_TIME*>(t)) != 1) {
        BIO_free(bio);
        return "";
    }
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string out;
    if (mem && mem->data && mem->length > 0)
        out.assign(mem->data, mem->length);
    BIO_free(bio);
    return InputGuard::sanitize_output(out);
}

bool ssl_connect_with_timeout(SSL* ssl, int fd, int timeout_ms, const std::string& log_ctx) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    int last_ret = -1;
    int last_err = SSL_ERROR_NONE;

    while (!g_cancel_token.cancelled) {
        auto now = std::chrono::steady_clock::now();
        int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining <= 0) {
            log_tls_handshake_fail(log_ctx + " deadline", ssl, last_ret, last_err);
            return false;
        }

        int ret = SSL_connect(ssl);
        last_ret = ret;
        if (ret == 1) return true;

        int err = SSL_get_error(ssl, ret);
        last_err = err;
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd{};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            if (poll(&pfd, 1, remaining) <= 0) {
                log_tls_handshake_fail(log_ctx + " poll", ssl, ret, err);
                return false;
            }
            continue;
        }
        log_tls_handshake_fail(log_ctx + " handshake", ssl, ret, err);
        return false;
    }
    log_tls_handshake_fail(log_ctx + " cancelled", ssl, last_ret, last_err);
    return false;
}

void populate_tls_cert_fields(TLSInfo& tls, X509* cert) {
    if (!cert) return;

    char buf[256];
    X509_NAME* subj = X509_get_subject_name(cert);
    if (subj) {
        if (X509_NAME_get_text_by_NID(subj, NID_commonName, buf, sizeof(buf)) > 0)
            tls.cn = InputGuard::sanitize_output(buf);
    }
    X509_NAME* issuer_name = X509_get_issuer_name(cert);
    if (issuer_name) {
        if (X509_NAME_get_text_by_NID(issuer_name, NID_commonName, buf, sizeof(buf)) > 0)
            tls.issuer = InputGuard::sanitize_output(buf);
    }

    STACK_OF(GENERAL_NAME)* sans = static_cast<STACK_OF(GENERAL_NAME)*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (sans) {
        int num_sans = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < num_sans; i++) {
            GENERAL_NAME* gen = sk_GENERAL_NAME_value(sans, i);
            if (gen && gen->type == GEN_DNS) {
                std::string san(
                    reinterpret_cast<const char*>(ASN1_STRING_get0_data(gen->d.dNSName)),
                    static_cast<size_t>(ASN1_STRING_length(gen->d.dNSName)));
                tls.sans.push_back(InputGuard::sanitize_output(san));
            }
        }
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    }

    tls.self_signed = (X509_check_issued(cert, cert) == X509_V_OK);

    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (not_after) {
        tls.expiry = asn1_time_to_string(not_after);
        int day = 0, sec = 0;
        if (ASN1_TIME_diff(&day, &sec, nullptr, not_after))
            tls.expired = (day < 0 || sec < 0);
    }
}

void populate_tls_from_ssl(SSL* ssl, TLSInfo& tls) {
    if (!ssl) return;
    tls.tls_version = SSL_get_version(ssl);
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        const char* name = SSL_CIPHER_get_name(cipher);
        if (name) tls.cipher = InputGuard::sanitize_output(name);
    }
    X509_ptr cert(SSL_get_peer_certificate(ssl));
    populate_tls_cert_fields(tls, cert.get());
}

bool tls_handshake_on_socket(int fd, SSL_CTX_ptr& ctx, SSL_ptr& ssl, TLSInfo& tls,
                             const std::string& ip, int port, int timeout_ms,
                             const std::string& sni_host) {
    const std::string& host = sni_host.empty() ? ip : sni_host;
    std::string log_ctx = "port=" + std::to_string(port) + " sni=" + host;

    ctx = SSL_CTX_ptr(SSL_CTX_new(TLS_client_method()));
    if (!ctx) {
        LOG_WARN("port_scan_tls", log_ctx + " SSL_CTX_new failed " + openssl_err_stack());
        return false;
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

    ssl = SSL_ptr(SSL_new(ctx.get()));
    if (!ssl) {
        LOG_WARN("port_scan_tls", log_ctx + " SSL_new failed " + openssl_err_stack());
        return false;
    }

    SSL_set_fd(ssl.get(), fd);
    if (SSL_set_tlsext_host_name(ssl.get(), host.c_str()) != 1) {
        LOG_WARN("port_scan_tls", log_ctx + " SNI set failed " + openssl_err_stack());
        return false;
    }

    if (!ssl_connect_with_timeout(ssl.get(), fd, timeout_ms, log_ctx))
        return false;

    populate_tls_from_ssl(ssl.get(), tls);
    return true;
}

bool ssl_write_all(SSL* ssl, int fd, const std::string& data, int timeout_ms,
                   const std::string& log_ctx) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t sent = 0;
    while (sent < data.size() && !g_cancel_token.cancelled) {
        auto now = std::chrono::steady_clock::now();
        int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining <= 0) return false;

        int ret = SSL_write(ssl, data.data() + sent, static_cast<int>(data.size() - sent));
        if (ret > 0) {
            sent += static_cast<size_t>(ret);
            continue;
        }
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd{};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            if (poll(&pfd, 1, remaining) <= 0) return false;
            continue;
        }
        log_tls_handshake_fail(log_ctx + " write", ssl, ret, err);
        return false;
    }
    return sent == data.size();
}

bool ssl_read_http_response(SSL* ssl, int fd, std::string& out, int timeout_ms, size_t max_bytes) {
    out.clear();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::vector<char> buf(4096);

    while (out.size() < max_bytes && !g_cancel_token.cancelled) {
        auto now = std::chrono::steady_clock::now();
        int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining <= 0) break;

        int ret = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
        if (ret > 0) {
            out.append(buf.data(), static_cast<size_t>(ret));
            if (out.find("\r\n\r\n") != std::string::npos) {
                size_t hdr_end = out.find("\r\n\r\n") + 4;
                if (out.size() >= hdr_end + 512 || out.size() >= max_bytes) break;
                if (out.find("<title>", hdr_end) != std::string::npos) break;
            }
            continue;
        }
        if (ret == 0) break;
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd{};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            if (poll(&pfd, 1, remaining) <= 0) break;
            continue;
        }
        break;
    }
    return !out.empty();
}

} // namespace
#endif

static std::string build_http_get_request(const std::string& path, const std::string& host_header) {
    return "GET " + path + " HTTP/1.1\r\n"
           "Host: " + host_header + "\r\n"
           "User-Agent: " + random_ua() + "\r\n"
           "Accept: */*\r\n"
           "Connection: close\r\n\r\n";
}

static bool is_redirect_status(int code) {
    return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
}

static void parse_http_response(const std::string& raw, HttpInfo& info) {
    if (raw.empty()) return;

    std::istringstream stream(raw);
    std::string line;
    if (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        static const std::regex status_re(R"(HTTP/\d(?:\.\d)?\s+(\d{3}))");
        std::smatch m;
        if (std::regex_search(line, m, status_re)) {
            try { info.status_code = std::stoi(m[1].str()); } catch (...) {}
        }
    }

    while (std::getline(stream, line)) {
        if (line == "\r" || line.empty()) break;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string l = line;
        std::transform(l.begin(), l.end(), l.begin(), ::tolower);

        if (l.find("server: ") == 0)
            info.server = InputGuard::sanitize_output(line.substr(8));
        else if (l.find("x-powered-by: ") == 0)
            info.powered_by = InputGuard::sanitize_output(line.substr(14));
        else if (l.find("strict-transport-security: ") == 0)
            info.hsts = true;
        else if (l.find("content-security-policy: ") == 0)
            info.csp = true;
        else if (l.find("x-frame-options: ") == 0)
            info.x_frame = true;
        else if (l.find("location: ") == 0)
            info.redirect_location = InputGuard::sanitize_output(line.substr(10));
    }

    auto title_start = raw.find("<title>");
    if (title_start != std::string::npos) {
        title_start += 7;
        auto title_end = raw.find("</title>", title_start);
        if (title_end != std::string::npos) {
            std::string title = raw.substr(title_start, title_end - title_start);
            if (title.size() > 80) title = title.substr(0, 80) + "...";
            info.title = InputGuard::sanitize_output(title);
        }
    }
}

static bool resolve_redirect_target(const std::string& location, const std::string& base_host,
                                    int base_port, std::string& path_out, std::string& host_out,
                                    int& port_out) {
    if (location.empty()) return false;
    std::string loc = location;
    while (!loc.empty() && (loc.back() == ' ' || loc.back() == '\t')) loc.pop_back();

    if (loc.rfind("https://", 0) == 0 || loc.rfind("http://", 0) == 0) {
        bool https = loc.rfind("https://", 0) == 0;
        size_t start = loc.find("://") + 3;
        size_t slash = loc.find('/', start);
        std::string authority = slash == std::string::npos ? loc.substr(start) : loc.substr(start, slash - start);
        path_out = slash == std::string::npos ? "/" : loc.substr(slash);
        size_t colon = authority.find(':');
        if (colon == std::string::npos) {
            host_out = authority;
            port_out = https ? 443 : 80;
        } else {
            host_out = authority.substr(0, colon);
            try { port_out = std::stoi(authority.substr(colon + 1)); } catch (...) { port_out = base_port; }
        }
        return true;
    }

    if (loc[0] == '/') {
        path_out = loc;
        host_out = base_host;
        port_out = base_port;
        return true;
    }

    path_out = "/" + loc;
    host_out = base_host;
    port_out = base_port;
    return true;
}

static void print_http_enrichment(const HttpInfo& http) {
    if (http.status_code <= 0) return;

    std::cout << BLOOD_RED << "            HTTP: " << WHITE << http.status_code;
    if (!http.redirect_location.empty())
        std::cout << " -> " << http.redirect_location;
    if (!http.server.empty())
        std::cout << " | Server: " << http.server;
    if (!http.title.empty())
        std::cout << " | Title: " << http.title;
    std::cout << RESET << "\n";

    std::cout << BLOOD_RED << "            Sec: " << WHITE
              << "HSTS=" << (http.hsts ? "yes" : "no")
              << " CSP=" << (http.csp ? "yes" : "no")
              << " X-Frame=" << (http.x_frame ? "yes" : "no")
              << RESET << "\n";
}

static void print_tls_enrichment(const TLSInfo& tls) {
    if (tls.tls_version.empty() && tls.cn.empty() && tls.cipher.empty()) return;

    if (!tls.tls_version.empty() || !tls.cipher.empty()) {
        std::cout << BLOOD_RED << "            TLS: " << WHITE;
        if (!tls.tls_version.empty()) std::cout << tls.tls_version;
        if (!tls.cipher.empty()) {
            if (!tls.tls_version.empty()) std::cout << " / ";
            std::cout << tls.cipher;
        }
        std::cout << RESET << "\n";
    }

    if (!tls.cn.empty() || !tls.issuer.empty() || !tls.expiry.empty() || tls.expired || tls.self_signed) {
        std::cout << BLOOD_RED << "            Cert: " << WHITE;
        if (!tls.cn.empty()) std::cout << "CN=" << tls.cn;
        if (!tls.issuer.empty()) std::cout << " | Issuer: " << tls.issuer;
        if (!tls.expiry.empty()) std::cout << " | exp: " << tls.expiry;
        if (tls.expired) std::cout << " (expired)";
        if (tls.self_signed) std::cout << " (self-signed)";
        std::cout << RESET << "\n";
    }

    if (!tls.sans.empty()) {
        std::cout << BLOOD_RED << "                  SANs: " << WHITE;
        size_t limit = std::min(tls.sans.size(), size_t{8});
        for (size_t i = 0; i < limit; ++i) {
            if (i) std::cout << ", ";
            std::cout << tls.sans[i];
        }
        if (tls.sans.size() > 8) std::cout << ", ...";
        std::cout << RESET << "\n";
    }
}

static TLSInfo inspect_tls(const std::string& ip, int port, int timeout_ms, const std::string& sni_host) {
    TLSInfo tls{};
#ifdef HAVE_OPENSSL
    FdGuard sock(socket(AF_INET, SOCK_STREAM, 0));
    if (sock.get() < 0) return tls;
    if (!tcp_connect_to(ip, port, timeout_ms, sock.get())) return tls;

    SSL_CTX_ptr ctx;
    SSL_ptr ssl;
    if (!tls_handshake_on_socket(sock.get(), ctx, ssl, tls, ip, port, timeout_ms, sni_host))
        return tls;
    SSL_shutdown(ssl.get());
#endif
    return tls;
}

static TlsHttpResult probe_tls_http(const std::string& ip, int port, int timeout_ms,
                                    const std::string& sni_host, int max_redirects) {
    TlsHttpResult result{};
#ifdef HAVE_OPENSSL
    auto t0 = std::chrono::steady_clock::now();
    auto ms_remaining = [&]() {
        int elapsed = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count());
        return std::max(0, timeout_ms - elapsed);
    };

    std::string connect_host = sni_host.empty() ? ip : sni_host;
    int connect_port = port;
    std::string path = "/";

    for (int hop = 0; hop <= max_redirects; ++hop) {
        int budget = ms_remaining();
        if (budget <= 0) break;

        FdGuard sock(socket(AF_INET, SOCK_STREAM, 0));
        if (sock.get() < 0) break;
        if (!tcp_connect_to(ip, connect_port, budget, sock.get())) break;

        SSL_CTX_ptr ctx;
        SSL_ptr ssl;
        TLSInfo hop_tls;
        if (!tls_handshake_on_socket(sock.get(), ctx, ssl, hop_tls, ip, connect_port, budget, connect_host))
            break;

        result.tls = hop_tls;
        result.tls_ok = !hop_tls.tls_version.empty() || !hop_tls.cn.empty();

        std::string log_ctx = "port=" + std::to_string(connect_port) + " sni=" + connect_host;
        std::string req = build_http_get_request(path, connect_host);
        if (!ssl_write_all(ssl.get(), sock.get(), req, budget, log_ctx))
            break;

        std::string raw;
        if (!ssl_read_http_response(ssl.get(), sock.get(), raw, ms_remaining(), 65536))
            break;

        HttpInfo hop_http;
        parse_http_response(raw, hop_http);
        result.http = hop_http;
        result.http_ok = hop_http.status_code > 0;

        SSL_shutdown(ssl.get());

        if (!is_redirect_status(hop_http.status_code) || hop >= max_redirects)
            break;

        std::string next_path, next_host;
        int next_port = connect_port;
        if (!resolve_redirect_target(hop_http.redirect_location, connect_host, connect_port,
                                     next_path, next_host, next_port))
            break;

        path = next_path;
        connect_host = next_host;
        connect_port = next_port;
    }
#endif
    return result;
}

static HttpInfo probe_http(const std::string& ip, int port, int timeout_ms, bool aggressive,
                           const std::string& host_header) {
    HttpInfo info{};
    if (TLS_PORTS.count(port)) return info;

    FdGuard sock(socket(AF_INET, SOCK_STREAM, 0));
    if (sock.get() < 0) return info;

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    fcntl(sock.get(), F_SETFL, O_NONBLOCK);
    connect(sock.get(), (sockaddr*)&sa, sizeof(sa));

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLOUT;

    if (poll(&pfd, 1, timeout_ms) <= 0) return info;

    int sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &sockerr, &errlen);
    if (sockerr != 0) return info;

    const std::string& host = host_header.empty() ? ip : host_header;
    std::string req = build_http_get_request("/", host);
    send(sock.get(), req.c_str(), req.size(), MSG_NOSIGNAL);

    pfd.events = POLLIN;
    std::string res;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::vector<char> buf(4096);
    while (res.size() < 65536) {
        auto now = std::chrono::steady_clock::now();
        int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining <= 0) break;
        pfd.revents = 0;
        if (poll(&pfd, 1, remaining) <= 0) break;
        ssize_t n = recv(sock.get(), buf.data(), buf.size(), 0);
        if (n > 0) {
            res.append(buf.data(), static_cast<size_t>(n));
            if (res.find("\r\n\r\n") != std::string::npos) break;
        } else if (n == 0) {
            break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            break;
        }
    }

    parse_http_response(res, info);

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

            std::string preq = build_http_get_request(path, host);
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
    connect(sock.get(), (sockaddr*)&sa, sizeof(sa));
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
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
            return {std::max(1, ms), false};
        }
        if (n < 0 && errno == ECONNREFUSED) return {-1, false};
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return {-1, true};
    }

    return {-1, true};
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
    const std::string& sni = cfg_.sni_host.empty() ? cfg_.ip : cfg_.sni_host;
    return ::inspect_tls(cfg_.ip, port, cfg_.banner_ms, sni);
}

TlsHttpResult PortScanEngine::probe_tls_http(int port) {
    const std::string& sni = cfg_.sni_host.empty() ? cfg_.ip : cfg_.sni_host;
    return ::probe_tls_http(cfg_.ip, port, cfg_.banner_ms, sni, 3);
}

HttpInfo PortScanEngine::probe_http(int port) {
    const std::string& sni = cfg_.sni_host.empty() ? cfg_.ip : cfg_.sni_host;
    return ::probe_http(cfg_.ip, port, cfg_.banner_ms, cfg_.aggressive, sni);
}

std::string PortScanEngine::smart_banner(int port) {
    return ::smart_banner(cfg_.ip, port, cfg_.banner_ms, TLS_PORTS.count(port) != 0);
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
    std::atomic<int> phase1_done{0};
    {
        int psz = std::min(cfg_.pool_size, (int)sorted_ports.size());
        ThreadPool pool(psz);
        std::vector<std::future<void>> futs;
        futs.reserve(total);

        for (int i = 0; i < total; i++) {
            futs.push_back(pool.submit([&, i] {
                if (g_cancel_token.cancelled) return;

                int p = sorted_ports[i];
                if (cfg_.exclude_ports.count(p)) return;

                if (!cfg_.skip_rate_limiting) {
                    port_rl.acquire();
                }

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

                {
                    int prog = ++phase1_done;
                    if (prog % 200 == 0 || prog == total) {
                        std::lock_guard<std::mutex> lk(g_print_mtx);
                        draw_progress(prog, total,
                            std::to_string(open_c.load()) + " open, " +
                            std::to_string(filt_c.load()) + " filtered");
                    }
                }

                if (lat > 0) {
                    PortResult pr{};
                    pr.port = p; pr.latency_ms = lat;

                    std::lock_guard<std::mutex> lk(mx);
                    results.open_ports.push_back(pr);
                    open_c++;

                    std::lock_guard<std::mutex> plk(g_print_mtx);
                    std::cout << "\x1B[2K\r" << BLOOD_RED << "  [+] " << WHITE
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
        pool.wait();
    }

    if (g_cancel_token.cancelled) {
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
        std::mutex results_mtx;

        ThreadPool dpool(std::min(20, deep_total));
        std::vector<std::future<void>> dfuts;
        for (int i = 0; i < deep_total; i++) {
            dfuts.push_back(dpool.submit([&, i] {
                if (g_cancel_token.cancelled) return;

                int p;
                {
                    std::lock_guard<std::mutex> lk(results_mtx);
                    p = results.open_ports[i].port;
                }

                std::string svc_name = svc(p);
                std::string r_label = risk_label(p);
                std::string b_raw;
                std::string ver;
                std::vector<VulnHint> vulns;

                TLSInfo tls;
                HttpInfo http;
                bool is_tls = false;
                bool is_http = false;

                if (cfg_.tls_inspect && cfg_.http_probe && is_tls_http_port(p)) {
                    auto r = probe_tls_http(p);
                    tls = r.tls;
                    http = r.http;
                    is_tls = r.tls_ok;
                    is_http = r.http_ok;
                    if (http.status_code > 0)
                        b_raw = "HTTP/" + std::to_string(http.status_code) +
                                (http.server.empty() ? "" : " " + http.server);
                    else if (is_tls)
                        b_raw = tls.tls_version;
                    ver = http.server.empty() ? extract_version(b_raw, p) : http.server;
                } else {
                    if (!is_tls_http_port(p))
                        b_raw = smart_banner(p);
                    ver = extract_version(b_raw, p);

                    if (cfg_.tls_inspect && TLS_PORTS.count(p)) {
                        tls = inspect_tls(p);
                        is_tls = !tls.tls_version.empty() || !tls.cn.empty();
                    }

                    if (cfg_.http_probe && HTTP_PORTS.count(p) && !TLS_PORTS.count(p)) {
                        http = probe_http(p);
                        is_http = http.status_code > 0;
                    }
                }

                if (p == 6379 && b_raw.empty()) {
                    std::string ping_resp = probe_redis_ping(cfg_.ip, p, cfg_.connect_ms);
                    if (!ping_resp.empty()) b_raw = ping_resp;
                }
                if (p == 27017 && b_raw.empty()) {
                    std::string mongo_resp = probe_mongo_ping(cfg_.ip, p, cfg_.connect_ms);
                    if (!mongo_resp.empty()) b_raw = mongo_resp;
                }

                const TLSInfo* tls_ptr = is_tls ? &tls : nullptr;
                const HttpInfo* http_ptr = is_http ? &http : nullptr;
                vulns = check_vulns(p, ver, b_raw, tls_ptr, http_ptr);

                {
                    std::lock_guard<std::mutex> lk(results_mtx);
                    results.open_ports[i].service = svc_name;
                    results.open_ports[i].risk = r_label;
                    results.open_ports[i].banner_raw = b_raw;
                    results.open_ports[i].version = ver;
                    results.open_ports[i].vulns = vulns;
                    if (is_tls) {
                        results.open_ports[i].tls = tls;
                        results.open_ports[i].tls_port = true;
                    }
                    if (is_http) {
                        results.open_ports[i].http = http;
                        results.open_ports[i].http_port = true;
                    }
                }

                deep_done++;
                if (deep_done % 3 == 0 || deep_done == deep_total) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(deep_done, deep_total, "banners...");
                }
            }));
        }
        dpool.wait();
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

        if (pr.tls_port && (!pr.tls.tls_version.empty() || !pr.tls.cn.empty() || !pr.tls.cipher.empty()))
            print_tls_enrichment(pr.tls);
        if (pr.http_port && pr.http.status_code > 0)
            print_http_enrichment(pr.http);

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
            if (!is_significant_severity(v.severity)) continue;
            all_vulns.push_back(v);
            pe.vulns.push_back(v.cve + ":" + v.severity + ":" + v.desc);
        }

        std::lock_guard<std::mutex> lk(g_result_mtx);
        g_result.ports.push_back(pe);
        g_result.open_ports.push_back({pr.port, pr.service});
    }

    g_result.os_guess = r.os_hint;

    print_section("SCAN STATS");
    std::cout << BLOOD_RED << "  [os guess]      " << WHITE << r.os_hint << "\n";
    std::cout << BLOOD_RED << "  [open ports]    " << WHITE << r.open_ports.size() << "\n";
    std::cout << BLOOD_RED << "  [filtered]      " << WHITE << r.filtered_ports.size() << "\n";
    std::cout << BLOOD_RED << "  [scan time]     " << WHITE << std::fixed << std::setprecision(2) << r.total_time_s << "s\n";
    std::cout << BLOOD_RED << "  [speed]         " << WHITE << r.ports_per_sec << " ports/sec\n";

    print_section("SECURITY HINTS");
    all_vulns = dedupe_and_sort_vulns(std::move(all_vulns));

    if (all_vulns.empty()) {
        std::cout << WHITE
                  << "  No significant information disclosures or security misconfigurations detected.\n"
                  << RESET;
    } else {
        int vuln_crit = 0, vuln_high = 0, vuln_med = 0;
        for (const auto& v : all_vulns) {
            if (v.severity == "CRIT") vuln_crit++;
            else if (v.severity == "HIGH") vuln_high++;
            else if (v.severity == "MED") vuln_med++;
        }
        std::cout << BLOOD_RED << "  " << WHITE << vuln_crit << BLOOD_RED << " CRIT  "
                  << WHITE << vuln_high << BLOOD_RED << " HIGH  "
                  << WHITE << vuln_med << BLOOD_RED << " MED\n\n" << RESET;

        for (const auto& v : all_vulns) {
            std::string c_col = WHITE;
            if (v.severity == "CRIT") c_col = BLOOD_RED;
            else if (v.severity == "HIGH") c_col = YELLOW;

            std::cout << "  " << c_col << "[" << std::left << std::setw(4) << v.severity << "] "
                      << std::setw(14) << v.cve << " " << WHITE << v.desc << "\n" << RESET;
        }
    }

    LOG_INFO("port_scan", "done target=" + cfg_.ip +
        " open=" + std::to_string(r.open_ports.size()) +
        " filtered=" + std::to_string(r.filtered_ports.size()) +
        " time=" + std::to_string((int)r.total_time_s) + "s");
}

void port_scan(const std::string& ip, int start, int end_port, bool scan_udp, int timing_profile, const std::set<int>& exclude_ports) {
    print_header("PORT SCAN // " + ip);

    PortScanConfig cfg{};
    cfg.ip = ip;
    cfg.udp_scan = scan_udp;
    cfg.syn_scan = true;
    cfg.tls_inspect = true;
    cfg.http_probe = true;
    cfg.aggressive = true;

    if (timing_profile >= 0 && timing_profile <= 5) {
        cfg.timing = static_cast<PortScanConfig::TimingProfile>(timing_profile);
    } else {
        cfg.timing = PortScanConfig::TimingProfile::T3;
    }
    cfg.exclude_ports = exclude_ports;

    if (start == 0 && end_port == 0) {
        cfg.ports = TOP1000;
        std::cout << BLOOD_RED << "  mode: " << WHITE << "top-1000 ports\n" << RESET;
    } else if (start > 0 && end_port == 0) {
        cfg.ports = {start};
        std::cout << BLOOD_RED << "  mode: " << WHITE << "single port → " << start << "\n" << RESET;
    } else if (start == 0 && end_port > 0) {
        cfg.ports = TOP100;
        std::cout << BLOOD_RED << "  mode: " << WHITE << "top-100 ports\n" << RESET;
    } else {
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

    int port_count = (int)cfg.ports.size();

    switch (cfg.timing) {
        case PortScanConfig::TimingProfile::T0:
            cfg.connect_ms = 5000; cfg.banner_ms = 10000;
            cfg.retry_count = 3;  cfg.pool_size = 5;
            break;
        case PortScanConfig::TimingProfile::T1:
            cfg.connect_ms = 2000; cfg.banner_ms = 5000;
            cfg.retry_count = 2;  cfg.pool_size = 10;
            break;
        case PortScanConfig::TimingProfile::T2:
            cfg.connect_ms = 1500; cfg.banner_ms = 3000;
            cfg.retry_count = 2;  cfg.pool_size = 30;
            break;
        case PortScanConfig::TimingProfile::T3:
            break;
        default:
            break;
    }

    auto acfg = calibrate_target(ip);

    {
        struct rlimit rl;
        getrlimit(RLIMIT_NOFILE, &rl);
        int available_fds = (int)rl.rlim_cur - 50;
        int needed_fds    = acfg.pool_size * 3;
        if (needed_fds > available_fds) {
            int safe_pool = available_fds / 3;
            std::cout << BLOOD_RED << "  [!] FD limit " << available_fds
                      << " < needed " << needed_fds
                      << " - reducing pool to " << safe_pool << "\n" << RESET;
            acfg.pool_size = std::max(10, safe_pool);
        }
    }

    cfg.median_rtt = acfg.median_rtt;

    if (cfg.timing == PortScanConfig::TimingProfile::T3 ||
        cfg.timing == PortScanConfig::TimingProfile::T4 ||
        cfg.timing == PortScanConfig::TimingProfile::T5) {
        cfg.connect_ms = acfg.connect_ms;
        cfg.banner_ms = acfg.banner_ms;
        cfg.retry_count = acfg.retry_count;
        cfg.pool_size = acfg.pool_size;
    } else {
        cfg.connect_ms = std::max(cfg.connect_ms, acfg.connect_ms);
        cfg.banner_ms  = std::max(cfg.banner_ms, acfg.banner_ms);
    }

    if (port_count > 5000) {
        cfg.retry_count = std::min(cfg.retry_count, 1);
        cfg.connect_ms = std::max(150, std::min(cfg.connect_ms, 800));
        cfg.pool_size  = std::max(cfg.pool_size, 150);
        cfg.skip_rate_limiting = true;
        std::cout << BLOOD_RED << "  [large-range] " << WHITE
                  << "adjusted: timeout=" << cfg.connect_ms << "ms"
                  << " retries=" << cfg.retry_count << " threads=" << cfg.pool_size << "\n" << RESET;
    } else if (port_count > 1000) {
        cfg.retry_count = std::min(cfg.retry_count, 1);
        cfg.pool_size   = std::max(cfg.pool_size, 80);
    }

    if ((cfg.timing == PortScanConfig::TimingProfile::T0 ||
         cfg.timing == PortScanConfig::TimingProfile::T1) &&
        port_count > 100) {
        cfg.pool_size = std::max(cfg.pool_size, 20);
    }

    if (cfg.udp_scan) {
        if (port_count > 10000) {
            cfg.connect_ms = std::min(cfg.connect_ms, 400);
            cfg.pool_size  = std::min(cfg.pool_size, 50);
        } else if (port_count > 5000) {
            cfg.connect_ms = std::min(cfg.connect_ms, 600);
            cfg.pool_size  = std::min(cfg.pool_size, 75);
        } else if (port_count > 1000) {
            cfg.connect_ms = std::min(cfg.connect_ms, 1000);
            cfg.pool_size  = std::min(cfg.pool_size, 100);
        } else {
            cfg.connect_ms = std::max(cfg.connect_ms, 1200);
            cfg.pool_size  = std::min(cfg.pool_size, 100);
        }
    }

    if (cfg.udp_scan && port_count > 1000) {
        cfg.retry_count = 0;
        std::cout << BLOOD_RED << "  [udp] retry_count forced to 0 (UDP has no retries)\n" << RESET;
    }

    switch (cfg.timing) {
        case PortScanConfig::TimingProfile::T4:
            cfg.connect_ms  = std::max(100, cfg.connect_ms / 2);
            cfg.banner_ms   = std::max(500, cfg.banner_ms  / 2);
            cfg.retry_count = 1;
            cfg.pool_size   = cfg.pool_size * 2;
            break;
        case PortScanConfig::TimingProfile::T5:
            cfg.connect_ms  = 50;
            cfg.banner_ms   = 300;
            cfg.retry_count = 0;
            cfg.pool_size   = std::min(1000, cfg.pool_size * 4);
            break;
        default:
            break;
    }

    cfg.pool_size = std::min(cfg.pool_size, 600);

    std::cout << BLOOD_RED << "  rtt: " << WHITE
              << (cfg.median_rtt >= 0 ? std::to_string(cfg.median_rtt) + "ms" : "n/a")
              << BLOOD_RED << "  timeout: " << WHITE << cfg.connect_ms << "ms"
              << BLOOD_RED << "  retries: " << WHITE << cfg.retry_count
              << BLOOD_RED << "  threads: " << WHITE << cfg.pool_size << "\n" << RESET;

    cfg.sni_host = resolve_sni_host(ip);
    if (!cfg.sni_host.empty() && cfg.sni_host != ip)
        std::cout << BLOOD_RED << "  sni: " << WHITE << cfg.sni_host << "\n" << RESET;

    std::string hostname = ptr_lookup(ip);
    if (!hostname.empty() && hostname != ip)
        std::cout << BLOOD_RED << "  ptr: " << WHITE << hostname << "\n" << RESET;

    if (cfg.skip_rate_limiting) {
        std::cout << BLOOD_RED << "  [opt] rate limiter disabled for large scan\n" << RESET;
    }

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


            char hbuf[NI_MAXHOST]={};
            sockaddr_in sa{}; sa.sin_family=AF_INET;
            inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
            getnameinfo((sockaddr*)&sa,sizeof(sa),hbuf,sizeof(hbuf),nullptr,0,0);
            h.hostname=strlen(hbuf)?sanitize(hbuf):"";

            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout<<"\x1B[2K\r"<<BLOOD_RED<<"  [+] "<<WHITE<<std::left<<std::setw(16)<<ip;
            if(!h.hostname.empty()) std::cout<<BLOOD_RED<<" ("<<WHITE<<h.hostname<<BLOOD_RED<<")";
            std::cout<<RESET<<"\n";
        }));
    }
    pool.wait();

    std::cout<<BLOOD_RED<<"\n  found "<<WHITE<<alive_c<<BLOOD_RED<<" hosts -- phase 2: port scan...\n\n"<<RESET;

    std::vector<HostInfo*> alive_hosts;
    for (auto& h:hosts) if(h.alive) alive_hosts.push_back(&h);

    std::atomic<int> task(0);
    int ntasks=alive_hosts.size()*PROBE_PORTS.size();
    std::vector<std::future<void>> futs2; futs2.reserve(ntasks);
    std::mutex hosts_mtx;

    for (int i=0;i<(int)alive_hosts.size();i++) {
        for (int p:PROBE_PORTS) {
            futs2.push_back(pool.submit([&,i,p]{
                auto [lat, filtered] = probe_connect(alive_hosts[i]->ip, p, 400, 1);
                if(lat <= 0) return;
                std::string b=banner(alive_hosts[i]->ip,p,1000);
                std::lock_guard<std::mutex> lk(hosts_mtx);
                alive_hosts[i]->ports.emplace_back(p,b);
            }));
        }
    }
    pool.wait();

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
