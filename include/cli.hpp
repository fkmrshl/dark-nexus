#pragma once

#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace cli {

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class Color { Auto, Always, Never };
enum class Family { Auto, IPv4, IPv6 };

struct Options {
    std::string module, target, output, format, log_file, wordlist;
    bool help = false, version = false, list_modules = false, doctor = false;
    bool quiet = false, no_log = false;
    Color color = Color::Auto;
    Family family = Family::Auto;
    int timing = 3, threads = 0, timeout_ms = 0, retries = -1;
    int banner_timeout_ms = 0;
    std::vector<int> ports;
    std::set<int> exclude_ports;
    // Zero means that an explicit port list is present in ports.
    int top_ports = 1000;
    bool udp = false, connect = false, no_tls = false, no_http = false;
    bool deep = false, no_permutations = false, no_enrich = false;
    bool no_deep_passive = false;
    bool bruteforce = false, passive_only = false;
    bool permutations = false, deep_passive = false, http = false;
    bool js = false, cname = false, tech = false, service_hints = false;
    bool no_js = false, no_cname = false, no_tech = false, no_service_hints = false;
    bool full_addresses = false;
    std::string protocol = "icmp";
    int max_hops = 40, probes = 5, parallel_hops = 8;
    int destination_port = 33434;
    bool no_rdns = false, no_asn = false, no_mtu = false;
};

// Arguments exclude argv[0]. Parsing and validation perform no network or file I/O.
Options parse(const std::vector<std::string>& args);
std::string help(const std::string& module = "");
std::string modules();

} // namespace cli
