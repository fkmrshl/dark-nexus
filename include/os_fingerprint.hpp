#pragma once

#include <array>
#include <string>
#include <vector>

struct OsTtlSignal {
    std::vector<int> observed;
    int ttl = 0;
    int initial_ttl = 0;
    int hops = 0;
    bool stable = false;
};

struct OsPortSignal {
    int port = 0;
    std::string name;
    std::string category;
    std::string banner;
    std::string extra;
    bool open = false;
    std::array<int, 4> weights{0, 0, 0, 0};
};

struct OsFingerprintInput {
    std::vector<int> open_ports;
    std::vector<OsPortSignal> port_signals;
    std::string tcp_syn_signature;
    std::string smb_verdict;
    std::string waf_verdict;
    OsTtlSignal ttl;
};

struct OsFingerprintResult {
    std::string verdict = "unknown";
    std::array<int, 4> scores{0, 0, 0, 0};
    OsTtlSignal ttl;
};

OsPortSignal make_os_port_signal(int port,
                                 const std::string& banner = "",
                                 const std::string& extra = "",
                                 bool open = true);
OsTtlSignal collect_os_ttl_signal(const std::string& ip, int probes = 3, int timeout_sec = 1);
OsFingerprintResult fingerprint_os(const OsFingerprintInput& input);
std::string os_score_line(const OsFingerprintResult& result);
