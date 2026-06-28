#include "../include/dark_nexus.hpp"
#include "../include/os_fingerprint.hpp"
#include "../include/security.hpp"

static bool has_port(const std::vector<int>& ports, int port) {
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}

OsPortSignal make_os_port_signal(int port,
                                 const std::string& banner,
                                 const std::string& extra,
                                 bool open) {
    OsPortSignal signal;
    signal.port = port;
    signal.name = svc(port);
    signal.category = "generic";
    signal.banner = banner;
    signal.extra = extra;
    signal.open = open;

    switch (port) {
        case 22: signal = {port, "SSH", "remote", banner, extra, open, {1, 10, 8, 5}}; break;
        case 23: signal = {port, "Telnet", "remote", banner, extra, open, {2, 1, 1, 10}}; break;
        case 80: signal = {port, "HTTP", "web", banner, extra, open, {5, 7, 5, 3}}; break;
        case 111: signal = {port, "RPCBind", "unix", banner, extra, open, {0, 9, 8, 0}}; break;
        case 135: signal = {port, "MSRPC", "windows", banner, extra, open, {10, 0, 0, 0}}; break;
        case 139: signal = {port, "NetBIOS-NS", "windows", banner, extra, open, {10, 1, 0, 0}}; break;
        case 161: signal = {port, "SNMP", "monitor", banner, extra, open, {5, 4, 3, 10}}; break;
        case 443: signal = {port, "HTTPS", "web", banner, extra, open, {5, 7, 5, 3}}; break;
        case 445: signal = {port, "SMB", "windows", banner, extra, open, {10, 2, 1, 0}}; break;
        case 548: signal = {port, "AFP", "apple", banner, extra, open, {0, 1, 10, 0}}; break;
        case 631: signal = {port, "CUPS", "unix", banner, extra, open, {0, 8, 7, 1}}; break;
        case 2049: signal = {port, "NFS", "unix", banner, extra, open, {0, 9, 7, 1}}; break;
        case 3389: signal = {port, "RDP", "windows", banner, extra, open, {10, 0, 0, 0}}; break;
        case 5432: signal = {port, "PostgreSQL", "db", banner, extra, open, {2, 9, 7, 0}}; break;
        case 5985: signal = {port, "WinRM", "windows", banner, extra, open, {10, 0, 0, 0}}; break;
        case 5986: signal = {port, "WinRM TLS", "windows", banner, extra, open, {10, 0, 0, 0}}; break;
        case 6379: signal = {port, "Redis", "db", banner, extra, open, {1, 9, 5, 0}}; break;
        default: break;
    }

    return signal;
}

OsTtlSignal collect_os_ttl_signal(const std::string& ip, int probes, int timeout_sec) {
    OsTtlSignal signal;
    if (probes < 1) probes = 1;
    if (timeout_sec < 1) timeout_sec = 1;

    auto output = safe_exec({"ping", "-c" + std::to_string(probes), "-W" + std::to_string(timeout_sec), ip}, timeout_sec * probes + 2);
    size_t pos = 0;
    while (true) {
        size_t ttl_pos = output.find("ttl=", pos);
        if (ttl_pos == std::string::npos) ttl_pos = output.find("TTL=", pos);
        if (ttl_pos == std::string::npos) break;
        try {
            signal.observed.push_back(std::stoi(output.substr(ttl_pos + 4)));
        } catch (...) {
        }
        pos = ttl_pos + 4;
    }

    if (!signal.observed.empty()) {
        signal.ttl = signal.observed.front();
        signal.stable = signal.observed.size() > 1;
        for (size_t i = 1; i < signal.observed.size(); ++i) {
            if (signal.observed[i] != signal.observed.front()) {
                signal.stable = false;
                break;
            }
        }

        if (signal.ttl <= 32) signal.initial_ttl = 32;
        else if (signal.ttl <= 64) signal.initial_ttl = 64;
        else if (signal.ttl <= 128) signal.initial_ttl = 128;
        else signal.initial_ttl = 255;

        signal.hops = signal.initial_ttl - signal.ttl;
    }

    return signal;
}

OsFingerprintResult fingerprint_os(const OsFingerprintInput& input) {
    OsFingerprintResult result;
    result.ttl = input.ttl;

    for (const auto& signal : input.port_signals) {
        if (!signal.open) continue;
        for (size_t i = 0; i < result.scores.size(); ++i) {
            result.scores[i] += signal.weights[i];
        }
    }

    if (input.port_signals.empty()) {
        if (has_port(input.open_ports, 3389) || has_port(input.open_ports, 5985) ||
            has_port(input.open_ports, 5986) || has_port(input.open_ports, 445) ||
            has_port(input.open_ports, 135)) result.scores[0] += 25;
        if (has_port(input.open_ports, 22) && !has_port(input.open_ports, 3389)) result.scores[1] += 18;
        if (has_port(input.open_ports, 631) || has_port(input.open_ports, 2049)) result.scores[1] += 10;
        if (has_port(input.open_ports, 548) || has_port(input.open_ports, 5353)) result.scores[2] += 22;
        if (has_port(input.open_ports, 23) || has_port(input.open_ports, 161)) result.scores[3] += 18;
    }

    if (result.ttl.initial_ttl == 128) result.scores[0] += 15;
    else if (result.ttl.initial_ttl == 64) result.scores[1] += 15;
    else if (result.ttl.initial_ttl == 255) result.scores[3] += 15;

    static const char* names[4] = {"Windows", "Linux/Unix", "BSD/macOS", "Network Device"};
    int best = 0;
    for (int i = 1; i < 4; ++i) {
        if (result.scores[i] > result.scores[best]) best = i;
    }

    if (!input.smb_verdict.empty()) {
        result.verdict = input.smb_verdict;
    } else if (input.tcp_syn_signature.find("Windows") != std::string::npos) {
        result.verdict = "Windows (Confirmed via TCP SYN)";
    } else if (input.tcp_syn_signature.find("Linux") != std::string::npos) {
        result.verdict = input.tcp_syn_signature;
    } else if (input.tcp_syn_signature.find("macOS") != std::string::npos) {
        result.verdict = "macOS / FreeBSD";
    } else if (input.tcp_syn_signature.find("Network Device") != std::string::npos) {
        result.verdict = input.tcp_syn_signature;
    } else if (result.scores[best] > 0) {
        result.verdict = names[best];
        if (!input.waf_verdict.empty()) result.verdict += " (Behind Proxy/WAF)";
    }

    return result;
}

std::string os_score_line(const OsFingerprintResult& result) {
    static const char* names[4] = {"Windows", "Linux/Unix", "BSD/macOS", "Network Device"};
    std::ostringstream out;
    for (int i = 0; i < 4; ++i) {
        if (i) out << " ";
        out << names[i] << ":" << result.scores[i];
    }
    return out.str();
}

std::string guess_os_from_ports(const std::vector<int>& open) {
    OsFingerprintInput input;
    input.open_ports = open;
    return fingerprint_os(input).verdict;
}
