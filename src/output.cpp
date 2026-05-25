#include "../include/output.hpp"
#include "../include/security.hpp"
#include <iostream>
#include <iomanip>

static std::string escape_csv(const std::string& s) {
    if (s.find(',') == std::string::npos &&
        s.find('"') == std::string::npos &&
        s.find('\n') == std::string::npos &&
        s.find('\r') == std::string::npos) {
        return s;
    }
    std::string escaped = "\"";
    for (char c : s) {
        if (c == '"') escaped += "\"\"";
        else escaped += c;
    }
    escaped += "\"";
    return escaped;
}

static std::string join_strings(const std::vector<std::string>& vec, const std::string& delim = " ") {
    std::string res;
    for (size_t i = 0; i < vec.size(); ++i) {
        if (i > 0) res += delim;
        res += vec[i];
    }
    return res;
}

bool OutputWriter::write(const ScanResult& r, const std::string& path) {
    if (path.empty()) return false;

    if (path.find(".json") == path.length() - 5) {
        return write_json(r, path);
    } else if (path.find(".csv") == path.length() - 4) {
        return write_csv(r, path);
    } else {
        // Assume text output
        std::ofstream f(path);
        if (!f.is_open()) return false;
        f << "Scan Report: " << r.target << "\n";
        f << "Type: " << r.scan_type << "\n";
        f << "Started: " << r.start_time << "\n";
        f << "Ended: " << r.end_time << "\n";
        f << "Duration (ms): " << r.duration_ms << "\n";
        f << "Resolved IP: " << r.resolved_ip << "\n\n";

        if (!r.geo_country.empty() || !r.geo_city.empty()) {
            f << "=== Geo ===\n";
            f << "Country: " << r.geo_country << "\n";
            f << "City: " << r.geo_city << "\n";
            f << "ISP: " << r.geo_isp << "\n";
            f << "AS: " << r.geo_as << "\n";
            f << "Proxy: " << (r.proxy ? "true" : "false") << "\n";
            f << "Hosting: " << (r.hosting ? "true" : "false") << "\n\n";
        }

        if (!r.os_guess.empty()) {
            f << "=== OS ===\n";
            f << r.os_guess << "\n\n";
        }

        if (!r.ports.empty()) {
            f << "=== Open Ports ===\n";
            for (const auto& p : r.ports) {
                f << p.port << "/" << p.protocol << " " << p.service << " (" << p.version << ") " << p.banner << "\n";
            }
            f << "\n";
        }

        if (!r.subdomains.empty()) {
            f << "=== Subdomains ===\n";
            for (const auto& s : r.subdomains) {
                f << s.sub << " " << join_strings(s.ips, ",") << " " << s.title << "\n";
            }
            f << "\n";
        }

        if (!r.osint.empty()) {
            f << "=== OSINT ===\n";
            for (const auto& o : r.osint) {
                f << o.platform << " (" << o.certainty << ") " << o.url << "\n";
            }
            f << "\n";
        }

        if (!r.trace.empty()) {
            f << "=== Trace ===\n";
            for (const auto& t : r.trace) {
                f << t.ttl << " " << t.addr << " (" << t.hostname << ") " << t.avg_rtt_ms << "ms\n";
            }
            f << "\n";
        }

        if (!r.dns_records.empty()) {
            f << "=== DNS Records ===\n";
            for (const auto& d : r.dns_records) {
                f << d << "\n";
            }
            f << "\n";
        }

        std::cout << BLOOD_RED << "  [+] saved txt: " << WHITE << path << "\n" << RESET;
        return true;
    }
}

std::string OutputWriter::to_json_str(const ScanResult& r) {
    json j = r;
    return j.dump(2);
}

bool OutputWriter::write_json(const ScanResult& r, const std::string& path) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << to_json_str(r) << "\n";
    std::cout << BLOOD_RED << "  [+] saved json: " << WHITE << path << "\n" << RESET;
    return true;
}

bool OutputWriter::write_csv(const ScanResult& r, const std::string& path) {
    std::string base_path = path;
    if (base_path.find(".csv") == base_path.length() - 4) {
        base_path = base_path.substr(0, base_path.length() - 4);
    }

    if (!r.ports.empty()) {
        std::string ports_path = base_path + "_ports.csv";
        std::ofstream fp(ports_path);
        if (fp.is_open()) {
            fp << "port,protocol,service,version,risk,latency_ms,tls,tls_version,banner,vulns\r\n";
            for (const auto& p : r.ports) {
                fp << p.port << ","
                   << escape_csv(p.protocol) << ","
                   << escape_csv(p.service) << ","
                   << escape_csv(p.version) << ","
                   << escape_csv(p.risk) << ","
                   << p.latency_ms << ","
                   << (p.tls ? "true" : "false") << ","
                   << escape_csv(p.tls_version) << ","
                   << escape_csv(p.banner) << ","
                   << escape_csv(join_strings(p.vulns, ";")) << "\r\n";
            }
            std::cout << BLOOD_RED << "  [+] saved csv: " << WHITE << ports_path << "\n" << RESET;
        }
    }

    if (!r.subdomains.empty()) {
        std::string sub_path = base_path + "_subdomains.csv";
        std::ofstream fs(sub_path);
        if (fs.is_open()) {
            fs << "subdomain,ips,cname,http_code,server,waf,language,cms,source,title,takeover\r\n";
            for (const auto& s : r.subdomains) {
                fs << escape_csv(s.sub) << ","
                   << escape_csv(join_strings(s.ips, " ")) << ","
                   << escape_csv(s.cname) << ","
                   << escape_csv(s.http_code) << ","
                   << escape_csv(s.server) << ","
                   << escape_csv(s.waf) << ","
                   << escape_csv(s.language) << ","
                   << escape_csv(s.cms) << ","
                   << escape_csv(s.source) << ","
                   << escape_csv(s.title) << ","
                   << (s.takeover_possible ? "true" : "false") << "\r\n";
            }
            std::cout << BLOOD_RED << "  [+] saved csv: " << WHITE << sub_path << "\n" << RESET;
        }
    }

    if (!r.osint.empty()) {
        std::string osint_path = base_path + "_osint.csv";
        std::ofstream fo(osint_path);
        if (fo.is_open()) {
            fo << "platform,url,category,certainty\r\n";
            for (const auto& o : r.osint) {
                fo << escape_csv(o.platform) << ","
                   << escape_csv(o.url) << ","
                   << escape_csv(o.category) << ","
                   << escape_csv(o.certainty) << "\r\n";
            }
            std::cout << BLOOD_RED << "  [+] saved csv: " << WHITE << osint_path << "\n" << RESET;
        }
    }
    return true;
}