#include <atomic>
#include <sys/resource.h>
#include <set>
#include "../include/dark_nexus.hpp"
#include "../include/port_scan_engine.hpp"
#include "../include/security.hpp"
#include "../include/os_fingerprint.hpp"
#include "../include/port_enrich.hpp"
#include "../include/port_probe.hpp"
#include "../include/port_vuln.hpp"

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

static const std::vector<int> TOP100 = {
    21,22,23,25,53,80,110,111,135,139,143,443,445,
    993,995,1723,3306,3389,5900,8080,8443,8888,
    27017,6379,5432,2375,2376,6443,9200,9300,
    11211,5672,5671,4369,15672,3000,8000,9000,
    1433,1521,5000,5001,5985,5986,47001,49152
};

static std::string port_display_clip(std::string value, size_t limit) {
    value = sanitize(value);
    if (value.size() <= limit) return value;
    if (limit <= 3) return value.substr(0, limit);
    return value.substr(0, limit - 3) + "...";
}

static void print_port_detail(const std::string& label, const std::string& value) {
    if (value.empty()) return;
    std::cout << BLOOD_RED << "    | " << std::left << std::setw(9) << label
              << WHITE << value << RESET << "\n";
}

PortScanEngine::PortScanEngine(PortScanConfig cfg, CancellationToken& token) : cfg_(cfg), token_(token) {}

std::pair<int,bool> PortScanEngine::probe_connect(int port) {
    return port_probe_connect(cfg_.ip, port, cfg_.connect_ms, cfg_.retry_count);
}

std::pair<int,bool> PortScanEngine::probe_syn(int port) {
    return port_probe_syn(cfg_.ip, port, cfg_.connect_ms, cfg_.retry_count);
}

bool PortScanEngine::probe_udp_smart(int port) {
    auto res = port_probe_udp_smart(cfg_.ip, port, cfg_.connect_ms);
    return res.first > 0;
}

TLSInfo PortScanEngine::inspect_tls(int port) {
    const std::string& sni = cfg_.sni_host.empty() ? cfg_.ip : cfg_.sni_host;
    return port_inspect_tls(cfg_.ip, port, cfg_.banner_ms, sni);
}

TlsHttpResult PortScanEngine::probe_tls_http(int port) {
    const std::string& sni = cfg_.sni_host.empty() ? cfg_.ip : cfg_.sni_host;
    return port_probe_tls_http(cfg_.ip, port, cfg_.banner_ms, sni, 3);
}

HttpInfo PortScanEngine::probe_http(int port) {
    const std::string& sni = cfg_.sni_host.empty() ? cfg_.ip : cfg_.sni_host;
    return port_probe_http(cfg_.ip, port, cfg_.banner_ms, cfg_.aggressive, sni);
}

std::string PortScanEngine::smart_banner(int port) {
    return ::smart_banner(cfg_.ip, port, cfg_.banner_ms, port_is_tls_candidate(port) != 0);
}

ScanResults PortScanEngine::run() {
    ScanResults results;
    std::mutex mx;
    std::atomic<int> done_c{0}, open_c{0}, filt_c{0};
    int total = cfg_.ports.size();

    std::vector<int> sorted_ports = cfg_.ports;
    std::sort(sorted_ports.begin(), sorted_ports.end(), [](int a, int b){
        return port_service_priority(a) > port_service_priority(b);
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
                    res = port_probe_udp_smart(cfg_.ip, p, cfg_.connect_ms);
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

                if (cfg_.tls_inspect && cfg_.http_probe && port_is_tls_http_port(p)) {
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
                    ver = http.server.empty() ? port_extract_version(b_raw, p) : http.server;
                } else {
                    if (!port_is_tls_http_port(p))
                        b_raw = smart_banner(p);
                    if (!port_banner_usable(b_raw))
                        b_raw.clear();
                    ver = port_extract_version(b_raw, p);

                    if (!port_is_tls_http_port(p) && b_raw.empty()) {
                        std::string probed;
                        if (p == 22)
                            probed = port_probe_ssh_banner(cfg_.ip, p, cfg_.connect_ms);
                        else if (p == 21)
                            probed = port_probe_ftp_banner(cfg_.ip, p, cfg_.connect_ms);
                        else if (p == 25 || p == 587 || p == 465)
                            probed = port_probe_smtp_banner(cfg_.ip, p, cfg_.connect_ms);
                        else if (p == 3306)
                            probed = port_probe_mysql_banner(cfg_.ip, p, cfg_.connect_ms);
                        else if (p == 5432)
                            probed = port_probe_postgres_banner(cfg_.ip, p, cfg_.connect_ms);
                        if (port_banner_usable(probed))
                            b_raw = probed;
                    }
                    if (!b_raw.empty() && ver.empty())
                        ver = port_extract_version(b_raw, p);

                    if (cfg_.tls_inspect && port_is_tls_candidate(p)) {
                        tls = inspect_tls(p);
                        is_tls = !tls.tls_version.empty() || !tls.cn.empty();
                    }

                    if (cfg_.http_probe && port_is_http_candidate(p) && !port_is_tls_candidate(p)) {
                        http = probe_http(p);
                        is_http = http.status_code > 0;
                        if (is_http) {
                            if (http.status_code > 0)
                                b_raw = "HTTP/" + std::to_string(http.status_code) +
                                        (http.server.empty() ? "" : " " + http.server);
                            if (!http.server.empty())
                                ver = http.server;
                            else if (ver.empty())
                                ver = port_extract_version(b_raw, p);
                        }
                    }
                }

                if (p == 6379 && b_raw.empty()) {
                    std::string ping_resp = port_probe_redis_ping(cfg_.ip, p, cfg_.connect_ms);
                    if (!ping_resp.empty()) b_raw = ping_resp;
                }
                if (p == 27017 && b_raw.empty()) {
                    std::string mongo_resp = port_probe_mongo_ping(cfg_.ip, p, cfg_.connect_ms);
                    if (!mongo_resp.empty()) b_raw = mongo_resp;
                }

                if (!port_banner_usable(b_raw))
                    b_raw.clear();

                const TLSInfo* tls_ptr = is_tls ? &tls : nullptr;
                const HttpInfo* http_ptr = is_http ? &http : nullptr;
                vulns = check_port_vulns(p, ver, b_raw, tls_ptr, http_ptr);

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

    OsFingerprintInput os_input;
    for (const auto& pr : results.open_ports) {
        os_input.open_ports.push_back(pr.port);
        std::string extra;
        if (!pr.http.server.empty()) extra += "Server: " + pr.http.server;
        if (!pr.http.powered_by.empty()) {
            if (!extra.empty()) extra += " ";
            extra += "Powered-By: " + pr.http.powered_by;
        }
        if (!pr.tls.cn.empty()) {
            if (!extra.empty()) extra += " ";
            extra += "TLS CN: " + pr.tls.cn;
        }
        os_input.port_signals.push_back(make_os_port_signal(pr.port, pr.banner_raw, extra, true));
        if (extra.find("WAF=") != std::string::npos || extra.find("Cloudflare") != std::string::npos)
            os_input.waf_verdict = extra;
    }
    results.os_hint = fingerprint_os(os_input).verdict;

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
              << "  PORT      SERVICE         VERSION                  LATENCY   RISK\n"
              << "  " << std::string(78, '-') << "\n" << RESET;

    std::vector<VulnHint> all_vulns;

    for (const auto& pr : r.open_ports) {
        std::string risk_color = WHITE;
        if (pr.risk == "HIGH") risk_color = BLOOD_RED;

        std::string ver_disp = pr.version.empty() ? "-" : port_display_clip(pr.version, 24);

        std::cout << BLOOD_RED << "  " << WHITE << std::left << std::setw(10) << pr.port
                  << std::setw(16) << pr.service
                  << std::setw(25) << ver_disp
                  << std::setw(10) << (std::to_string(pr.latency_ms) + "ms")
                  << risk_color << std::setw(10) << pr.risk << RESET << "\n";

        if (!pr.banner_raw.empty())
            print_port_detail("banner", port_display_clip(pr.banner_raw, 96));

        if (pr.tls_port && (!pr.tls.tls_version.empty() || !pr.tls.cn.empty() || !pr.tls.cipher.empty()))
            print_port_tls_enrichment(pr.tls);
        if (pr.http_port && pr.http.status_code > 0) {
            print_port_http_enrichment(pr.http);
            print_port_powered_by_line(pr.http);
        }

        int hint_shown = 0;
        for (const auto& v : pr.vulns) {
            if (!port_vuln_is_significant(v.severity)) continue;
            std::string c_col = WHITE;
            if (v.severity == "CRIT") c_col = BLOOD_RED;
            else if (v.severity == "HIGH") c_col = YELLOW;
            std::cout << BLOOD_RED << "    | " << std::left << std::setw(9) << "hint"
                      << WHITE << "[" << c_col << v.severity << WHITE << "] "
                      << v.cve << " " << sanitize(v.desc) << RESET << "\n";
            if (++hint_shown >= 3) break;
        }

        if ((pr.tls_port || pr.http_port || !pr.banner_raw.empty() || hint_shown > 0) && &pr != &r.open_ports.back())
            std::cout << "\n";

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
            if (!port_vuln_is_significant(v.severity)) continue;
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

    print_port_stack_disclosures(r);

    print_section("SECURITY HINTS");
    all_vulns = dedupe_port_vulns(std::move(all_vulns));

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

void port_scan(const std::string& ip, int start, int end_port, bool scan_udp, int timing_profile,
               const std::set<int>& exclude_ports, ScanAddrFamily addr_family,
               const std::vector<int>& selected_ports) {
    std::string scan_ip = resolve_for_scan(ip, addr_family);
    if (scan_ip.empty()) scan_ip = ip;

    print_header("PORT SCAN // " + scan_ip);

    PortScanConfig cfg{};
    cfg.ip = scan_ip;
    cfg.udp_scan = scan_udp;
    cfg.syn_scan = true;
    cfg.tls_inspect = true;
    cfg.http_probe = true;
    cfg.aggressive = true;

    if (addr_family == ScanAddrFamily::IPv4)
        std::cout << BLOOD_RED << "  address: " << WHITE << "IPv4 only\n" << RESET;
    else if (addr_family == ScanAddrFamily::IPv6)
        std::cout << BLOOD_RED << "  address: " << WHITE << "IPv6 only\n" << RESET;
    else
        std::cout << BLOOD_RED << "  address: " << WHITE << "auto (IPv4 preferred, else IPv6)\n" << RESET;

    if (port_scan_is_v6(cfg.ip)) {
        cfg.syn_scan = false;
        std::cout << BLOOD_RED << "  stack: " << WHITE << "IPv6 target (TCP connect scan)\n" << RESET;
    }

    if (timing_profile >= 0 && timing_profile <= 5) {
        cfg.timing = static_cast<PortScanConfig::TimingProfile>(timing_profile);
    } else {
        cfg.timing = PortScanConfig::TimingProfile::T3;
    }
    cfg.exclude_ports = exclude_ports;

    if (!selected_ports.empty()) {
        cfg.ports = selected_ports;
        std::sort(cfg.ports.begin(), cfg.ports.end());
        cfg.ports.erase(std::unique(cfg.ports.begin(), cfg.ports.end()), cfg.ports.end());
        std::cout << BLOOD_RED << "  mode: " << WHITE << "custom list"
                  << BLOOD_RED << " (" << WHITE << cfg.ports.size() << BLOOD_RED << " ports)\n" << RESET;
    } else if (start == 0 && end_port == 0) {
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
        std::cout << BLOOD_RED << "\n  [*] UDP SCAN SELECTED - sending protocol-aware probes\n"
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

    auto acfg = calibrate_port_target(ip);

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
            if (cfg.median_rtt > 0)
                cfg.connect_ms = std::max(cfg.connect_ms, std::min(1500, cfg.median_rtt * 5));
            cfg.banner_ms   = std::max(500, cfg.banner_ms  / 2);
            cfg.retry_count = std::max(cfg.retry_count, 1);
            cfg.pool_size   = cfg.pool_size * 2;
            break;
        case PortScanConfig::TimingProfile::T5:
            cfg.connect_ms  = 50;
            if (cfg.median_rtt > 0)
                cfg.connect_ms = std::max(cfg.connect_ms, std::min(800, cfg.median_rtt * 3));
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

    cfg.sni_host = port_resolve_sni_host(ip);
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
