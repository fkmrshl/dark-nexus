#pragma once

#include <string>
#include <vector>
#include "dark_nexus.hpp"

struct ScanMode { enum Type { SYN, CONNECT, UDP, ALL } type; };

struct PortScanConfig {
    std::string ip;
    std::vector<int> ports;
    int connect_ms;
    int banner_ms;
    int retry_count;
    int pool_size;
    int median_rtt;
    bool syn_scan;
    bool udp_scan;
    bool tls_inspect;
    bool http_probe;
    bool aggressive;
};

struct VulnHint {
    std::string cve;
    std::string desc;
    std::string severity;
};

struct TLSInfo {
    std::string cn;
    std::vector<std::string> sans;
    std::string issuer;
    std::string expiry;
    bool self_signed;
    bool expired;
    std::string tls_version;
};

struct HttpInfo {
    int status_code;
    std::string server;
    std::string powered_by;
    std::string title;
    bool hsts;
    bool csp;
    bool x_frame;
    std::vector<std::string> interesting_paths;
};

struct PortResult {
    int port;
    int latency_ms;
    std::string service;
    std::string banner_raw;
    std::string version;
    std::string risk;
    std::vector<VulnHint> vulns;
    TLSInfo tls;
    HttpInfo http;
    bool tls_port;
    bool http_port;
};

struct ScanResults {
    std::vector<PortResult> open_ports;
    std::vector<int> filtered_ports;
    std::string os_hint;
    double total_time_s;
    int ports_per_sec;
};

class PortScanEngine {
public:
    explicit PortScanEngine(PortScanConfig cfg, CancellationToken& token);
    ScanResults run();
    void print_results(const ScanResults& r);
private:
    PortScanConfig cfg_;
    CancellationToken& token_;
    std::pair<int,bool> probe_connect(int port);
    std::pair<int,bool> probe_syn(int port);
    bool               probe_udp_smart(int port);
    TLSInfo            inspect_tls(int port);
    HttpInfo           probe_http(int port);
    std::string        smart_banner(int port);
};
