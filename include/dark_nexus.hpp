#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <future>
#include <queue>
#include <condition_variable>
#include <functional>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <regex>
#include <chrono>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ares.h>
#include <sys/select.h>
#include <fstream>
#include <random>
#include <unordered_set>
#include <unordered_map>

#include "colors.hpp"
#include "logger.hpp"
#include "traceroute.hpp"
#include "thread_pool.hpp"

struct FdGuard {
    int fd;
    explicit FdGuard(int f) : fd(f) {}
    ~FdGuard() { if (fd >= 0) close(fd); }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
    int release() { int f = fd; fd = -1; return f; }
    int get() const { return fd; }
};

struct PortEntry {
    int port = 0;
    std::string protocol;
    std::string service;
    std::string banner;
    std::string version;
    std::string risk;
    int latency_ms = 0;
    bool tls = false;
    std::string tls_version;
    std::string tls_cn;
    bool tls_expired = false;
    std::vector<std::string> vulns;
};

struct SubEntry {
    std::string sub;
    std::vector<std::string> ips;
    std::string cname;
    std::string http_code;
    std::string server;
    std::string waf;
    std::string language;
    std::string cms;
    std::string source;
    std::string title;
    bool takeover_possible = false;
};

struct OsintEntry {
    std::string platform;
    std::string url;
    std::string category;
    std::string certainty;
};

struct TraceHop {
    int ttl = 0;
    std::string addr;
    std::string hostname;
    double avg_rtt_ms = -1.0;
    double loss_pct = 0.0;
    std::string asn;
};

struct ScanResult {
    std::string schema_version = "2.0";
    std::string tool_version = "dark-nexus/2.0";
    std::string scan_type;
    std::string target;
    std::string resolved_ip;
    std::string start_time;
    std::string end_time;
    int duration_ms = 0;

    std::string geo_country;
    std::string geo_city;
    std::string geo_isp;
    std::string geo_as;
    bool proxy = false;
    bool hosting = false;

    std::string os_guess;
    std::vector<PortEntry> ports;
    std::vector<SubEntry> subdomains;
    std::vector<OsintEntry> osint;
    std::vector<TraceHop> trace;
    std::vector<std::string> dns_records;

    std::vector<std::pair<int,std::string>> open_ports; // legacy
    std::vector<std::string> osint_hits; // legacy
};

struct CancellationToken {
    std::atomic<bool> cancelled{false};
};

extern ScanResult   g_result;
extern std::mutex   g_print_mtx;
extern std::mutex g_result_mtx;
extern CancellationToken g_cancel_token;

std::string safe_exec(const std::vector<std::string>& args, int t = 8);
std::string safe_curl(const std::string& url, int t = 8);

bool        valid_target(const std::string& s);
bool        valid_username(const std::string& s);
bool        valid_port(int p);
std::string sanitize(const std::string& s);
std::string resolve(const std::string& host);
bool        tcp_probe(const std::string& ip, int port, int ms = 500);
bool        udp_probe(const std::string& ip, int port, int ms = 500);
std::string smb_os_probe(const std::string& ip, int ms);
std::string analyze_http_headers(const std::string& ip, int port, int ms);
std::string tcp_syn_fingerprint(const std::string& ip, int port, int ms);
std::pair<bool,int> tcp_probe_ms(const std::string& ip, int port, int ms = 1000);
std::string ptr_lookup(const std::string& ip);
std::string svc(int port);
std::string risk_label(int port);
std::string banner(const std::string& ip, int port, int ms = 1500);
std::string smart_banner(const std::string& ip, int port, int ms = 2000);

std::string now_str();
void        export_json(const std::string& fname);
std::string json_val(const std::string& json, const std::string& key);
int         term_width();
void        draw_progress(int done, int total, const std::string& label = "");
void        print_sep();
void        print_header(const std::string& title);
void        print_section(const std::string& title);
void        print_row(const std::string& label, const std::string& val);
std::vector<std::string> split_lines(const std::string& s);
std::string dig_short(const std::string& domain, const std::string& type, int t = 6);
std::string dig_full(const std::string& domain, const std::string& type, int t = 6);

void        port_scan(const std::string& ip, int start, int end_port, bool scan_udp = false);
void        net_scan(const std::string& subnet);
std::string guess_os_from_ports(const std::vector<int>& open);

void os_detect(const std::string& ip);

void ip_intel(const std::string& ip);

void dns_lookup(const std::string& domain);
void whois_lookup(const std::string& target);
void site_lookup(const std::string& raw);

void osint_scan(const std::string& username);

void traceroute(const std::string& target);
void full_recon(const std::string& ip);
std::string auto_find_wordlist();

void subdomain_scan(const std::string& domain,
                    const std::string& wordlist_path = "",
                    int max_threads = 200,
                    bool run_permutations = true,
                    bool deep_passive = true,
                    bool do_enrich = true);
std::string auto_find_wordlist();
