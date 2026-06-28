#pragma once

#include <string>
#include <vector>
#include <cmath>
#include <numeric>
#include <algorithm>

struct TraceConfig {
    std::string target;
    int max_hops        = 40;
    int queries_per_hop = 5;
    int timeout_ms      = 2000;
    int parallel_hops   = 8;
    int src_port        = 33434;
    int dst_port        = 33434;
    int dns_timeout_ms  = 500;
    bool resolve_dns    = true;
    bool detect_mtu     = true;
    bool show_jitter    = true;
    bool show_loss      = true;
    bool as_lookup      = true;
    enum Protocol { ICMP, UDP, TCP_SYN } protocol = ICMP;
};

struct ProbeResult {
    int ttl              = 0;
    int probe_id         = 0;
    std::string addr;
    std::string hostname;
    double rtt_ms        = -1.0;
    bool reached_target  = false;
    int icmp_type        = -1;
    int icmp_code        = -1;
    int reply_ttl        = 0;
    int mtu_suggestion   = 0;
};

struct HopStats {
    int ttl = 0;
    std::string addr;
    std::string hostname;
    std::string asn_info;
    std::vector<double> rtts;
    int sent     = 0;
    int received = 0;
    double min_rtt = 0, max_rtt = 0, avg_rtt = 0, stddev = 0, jitter = 0;
    double loss_pct = 0;
    int mtu = 0;
    bool is_target = false;

    void compute() {
        if (rtts.empty()) { loss_pct = 100.0; return; }
        std::sort(rtts.begin(), rtts.end());
        min_rtt = rtts.front();
        max_rtt = rtts.back();
        avg_rtt = std::accumulate(rtts.begin(), rtts.end(), 0.0) / rtts.size();
        double var = 0;
        for (auto r : rtts) var += (r - avg_rtt) * (r - avg_rtt);
        stddev = std::sqrt(var / rtts.size());
        if (rtts.size() > 1) {
            double j = 0;
            for (size_t i = 1; i < rtts.size(); i++)
                j += std::abs(rtts[i] - rtts[i-1]);
            jitter = j / (rtts.size() - 1);
        }
        loss_pct = 100.0 * (1.0 - (double)received / sent);
    }
};
