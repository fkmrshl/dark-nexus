#include "../include/port_vuln.hpp"
#include "../include/security.hpp"

static std::string vuln_lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    return value;
}

static int vuln_sev_rank(const std::string& severity) {
    if (severity == "CRIT") return 0;
    if (severity == "HIGH") return 1;
    if (severity == "MED") return 2;
    return 3;
}

bool port_vuln_is_significant(const std::string& severity) {
    return severity == "CRIT" || severity == "HIGH" || severity == "MED";
}

static void add_vuln_hint(std::vector<VulnHint>& out, std::set<std::string>& seen,
                          const std::string& cve, const std::string& desc,
                          const std::string& severity) {
    if (!port_vuln_is_significant(severity)) return;
    std::string key = cve + "|" + desc;
    if (seen.insert(key).second) out.push_back({cve, desc, severity});
}

static std::string fingerprint_text(const std::string& banner,
                                    const std::string& version,
                                    const HttpInfo* http) {
    std::string hay = vuln_lower_copy(banner) + " " + vuln_lower_copy(version);
    if (http && !http->server.empty()) hay += " " + vuln_lower_copy(http->server);
    if (http && !http->powered_by.empty()) hay += " " + vuln_lower_copy(http->powered_by);
    return hay;
}

static bool http_port_like(int port) {
    static const std::set<int> ports = {
        80, 443, 8080, 8443, 8008, 8888, 3000, 5000, 9000, 9090, 10000,
        2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
        8880, 4443, 7443, 8081, 8181, 3001, 4000, 6001, 7000
    };
    return ports.count(port) != 0;
}

static bool tls_port_like(int port) {
    static const std::set<int> ports = {
        443, 8443, 465, 993, 995, 636, 5671, 6443, 4443, 7443, 2083, 2087, 2053, 2096
    };
    return ports.count(port) != 0;
}

static bool tls_http_port_like(int port) {
    return tls_port_like(port) && http_port_like(port);
}

static void check_web_version_cves(const std::string& hay,
                                   std::vector<VulnHint>& out,
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

static void check_tls_hints(int port,
                            const TLSInfo* tls,
                            std::vector<VulnHint>& out,
                            std::set<std::string>& seen) {
    if (!tls || !tls_port_like(port)) return;

    if (tls->expired) add_vuln_hint(out, seen, "N/A", "TLS certificate expired", "HIGH");
    if (tls->self_signed) add_vuln_hint(out, seen, "N/A", "TLS certificate is self-signed", "MED");

    const std::string& ver = tls->tls_version;
    if (ver.find("TLSv1.0") != std::string::npos || ver.find("TLSv1.1") != std::string::npos)
        add_vuln_hint(out, seen, "N/A", "Deprecated TLS version negotiated (" + ver + ")", "HIGH");

    if (!tls->cipher.empty()) {
        std::string cipher = vuln_lower_copy(tls->cipher);
        if (cipher.find("null") != std::string::npos || cipher.find("export") != std::string::npos ||
            cipher.find("des") != std::string::npos || cipher.find("rc4") != std::string::npos)
            add_vuln_hint(out, seen, "N/A", "Weak TLS cipher negotiated: " + tls->cipher, "HIGH");
    }
}

static void check_http_security_hints(int port,
                                      const HttpInfo* http,
                                      std::vector<VulnHint>& out,
                                      std::set<std::string>& seen) {
    if (!http || http->status_code <= 0) return;

    const bool https = tls_http_port_like(port) || port == 443 || port == 8443;

    if (https && !http->hsts)
        add_vuln_hint(out, seen, "N/A", "HTTPS response missing Strict-Transport-Security", "MED");
    if (https && http->status_code == 200 && !http->csp)
        add_vuln_hint(out, seen, "N/A", "HTTPS response missing Content-Security-Policy", "MED");
    if (http->status_code == 200 && !http->x_frame)
        add_vuln_hint(out, seen, "N/A", "HTTP 200 response missing X-Frame-Options", "MED");

    if (!http->powered_by.empty()) {
        std::string powered = vuln_lower_copy(http->powered_by);
        if (powered.find("php/") != std::string::npos) {
            std::regex re_php(R"(php/(\d+)\.(\d+))");
            std::smatch m;
            if (std::regex_search(powered, m, re_php)) {
                int major = std::stoi(m[1].str());
                int minor = std::stoi(m[2].str());
                bool php_eol = (major < 7) || (major == 7 && minor < 4) || (major == 8 && minor == 0);
                if (php_eol)
                    add_vuln_hint(out, seen, "N/A", "End-of-life PHP disclosed (" + InputGuard::sanitize_output(http->powered_by) + ")", "HIGH");
            }
        }
    }
}

static void check_redirect_hints(int port,
                                 const HttpInfo* http,
                                 std::vector<VulnHint>& out,
                                 std::set<std::string>& seen) {
    if (!http || http->status_code < 300 || http->status_code >= 400) return;
    if (http->redirect_location.empty()) return;

    std::string loc = vuln_lower_copy(http->redirect_location);
    const bool https_port = tls_http_port_like(port) || port == 443 || port == 8443;

    if (https_port && loc.rfind("http://", 0) == 0)
        add_vuln_hint(out, seen, "N/A", "HTTPS redirects to cleartext HTTP: " + http->redirect_location, "HIGH");
    if ((port == 80 || port == 8080) && loc.rfind("http://", 0) == 0 && loc.find("https://") == std::string::npos)
        add_vuln_hint(out, seen, "N/A", "HTTP redirect does not upgrade to HTTPS", "MED");
}

static void check_port_exposure_hints(int port,
                                      std::vector<VulnHint>& out,
                                      std::set<std::string>& seen) {
    struct ExposureEntry { int port; const char* severity; const char* desc; };
    static const ExposureEntry exposure[] = {
        {3389, "HIGH", "RDP exposed on network - brute-force/exploit surface"},
        {5432, "HIGH", "PostgreSQL exposed on network - verify auth and network ACLs"},
        {1433, "HIGH", "MSSQL exposed on network - verify auth and network ACLs"},
        {27017, "CRIT", "MongoDB exposed - unauthenticated by default pre-4.0"},
        {9200, "CRIT", "Elasticsearch HTTP API exposed - unauthenticated by default"},
        {9300, "HIGH", "Elasticsearch transport layer exposed"},
        {2379, "CRIT", "etcd API exposed - Kubernetes secrets accessible"},
        {5984, "HIGH", "CouchDB admin API exposed"},
        {11211, "HIGH", "Memcached exposed - no auth, DDoS amplification vector"},
        {5900, "HIGH", "VNC exposed - remote desktop without VPN"},
        {5901, "HIGH", "VNC exposed - remote desktop without VPN"},
        {4444, "CRIT", "Port 4444 - common Metasploit/C2 indicator"},
        {6000, "MED", "X11 display server exposed - session hijacking risk"},
        {50070, "CRIT", "Hadoop NameNode web UI exposed"}
    };

    for (const auto& item : exposure) {
        if (port == item.port) add_vuln_hint(out, seen, "N/A", item.desc, item.severity);
    }
}

std::vector<VulnHint> check_port_vulns(int port,
                                       const std::string& version,
                                       const std::string& banner,
                                       const TLSInfo* tls,
                                       const HttpInfo* http) {
    std::vector<VulnHint> vulns;
    std::set<std::string> seen;
    check_port_exposure_hints(port, vulns, seen);

    std::string bl = vuln_lower_copy(banner);
    std::string hay = fingerprint_text(banner, version, http);
    const bool has_banner = !banner.empty();

    if (port == 22) {
        std::regex re_ver(R"(openssh[_\s]([0-9]+)\.([0-9]+))");
        std::smatch m;
        if (std::regex_search(hay, m, re_ver)) {
            int major = std::stoi(m[1].str());
            int minor = std::stoi(m[2].str());
            if (major < 9 || (major == 9 && minor < 8))
                add_vuln_hint(vulns, seen, "CVE-2024-6387", "OpenSSH regreSSHion (signal handler race)", "CRIT");
            if (major < 9 || (major == 9 && minor < 3))
                add_vuln_hint(vulns, seen, "CVE-2023-38408", "OpenSSH agent forwarding RCE", "HIGH");
            if (major < 8 || (major == 8 && minor < 5))
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

    if (http_port_like(port)) check_web_version_cves(hay, vulns, seen);

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
        if (bl.find("\"cluster_name\"") != std::string::npos || bl.find("you know, for search") != std::string::npos)
            add_vuln_hint(vulns, seen, "N/A", "Elasticsearch responded without auth (CVE-2014-3120 class)", "CRIT");
    }

    if (port == 27017 && has_banner) {
        if (bl.find("mongodb-open") != std::string::npos || bl.find("ismaster") != std::string::npos)
            add_vuln_hint(vulns, seen, "N/A", "MongoDB accepts connections without auth challenge", "CRIT");
    }

    if (port == 11211 && has_banner) {
        if (bl.find("version") != std::string::npos || bl.find("stat") != std::string::npos)
            add_vuln_hint(vulns, seen, "N/A", "Memcached responded to stats probe - no auth configured", "HIGH");
    }

    check_tls_hints(port, tls, vulns, seen);
    check_http_security_hints(port, http, vulns, seen);
    check_redirect_hints(port, http, vulns, seen);

    return vulns;
}

std::vector<VulnHint> dedupe_port_vulns(std::vector<VulnHint> vulns) {
    std::set<std::string> seen;
    std::vector<VulnHint> deduped;
    deduped.reserve(vulns.size());

    for (auto& vuln : vulns) {
        if (!port_vuln_is_significant(vuln.severity)) continue;
        std::string key = vuln.cve + "|" + vuln.desc;
        if (seen.insert(key).second) deduped.push_back(std::move(vuln));
    }

    std::sort(deduped.begin(), deduped.end(), [](const VulnHint& a, const VulnHint& b) {
        return vuln_sev_rank(a.severity) < vuln_sev_rank(b.severity);
    });
    return deduped;
}
