#include "../include/cli.hpp"
#include "../include/port_presets.hpp"

#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {
int checks = 0;
int failures = 0;

void check(bool condition, const std::string& name) {
    ++checks;
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << name << '\n';
    }
}

void rejects(const std::vector<std::string>& args, const std::string& name) {
    try {
        cli::parse(args);
        check(false, name + " (accepted invalid arguments)");
    } catch (const cli::Error& error) {
        check(!std::string(error.what()).empty(), name);
    } catch (...) {
        check(false, name + " (wrong exception type)");
    }
}

void valid_cases() {
    check(cli::parse({}).help, "no arguments shows help");
    check(cli::parse({"--help"}).help, "global help");
    check(cli::parse({"-V"}).version, "version alias");
    check(cli::parse({"--list-modules"}).list_modules, "list modules");
    for (const auto& args : std::vector<std::vector<std::string>> {
            {"doctor"}, {"--doctor"}, {"doctor", "--no-log", "--no-color"},
            {"--doctor", "--json", "-"}, {"doctor", "--output", "-", "--format", "json"}}) {
        const auto options = cli::parse(args);
        check(options.doctor && options.target.empty() && options.module.empty(), "targetless doctor action");
    }
    for (const auto& args : std::vector<std::vector<std::string>> {
            {"--help", "doctor"}, {"--help=doctor"}, {"--doctor", "--help"}, {"doctor", "--help"}})
        check(cli::parse(args).doctor && cli::parse(args).help, "doctor help");
    check(cli::help("doctor").find("CAP_NET_RAW") != std::string::npos, "doctor detailed help");
    for (const auto& args : std::vector<std::vector<std::string>> {
            {"--help", "portscan"}, {"--help=portscan"},
            {"--portscan", "--help"}, {"--help", "--portscan"},
            {"--portscan", "127.0.0.1", "--help"}}) {
        const auto options = cli::parse(args);
        check(options.help && options.module == "portscan", "module help in either order");
    }
    const std::vector<std::string> names = {
        "portscan", "netscan", "os-detect", "ip-intel", "dns", "whois",
        "site", "osint", "traceroute", "recon", "subdomain"
    };
    for (const auto& name : names) {
        const auto options = cli::parse({"--" + name, "example.com"});
        check(options.module == name && options.target == "example.com", "select " + name);
        check(cli::help(name).find("--" + name) != std::string::npos, "help " + name);
    }
    const auto defaults = cli::parse({"--portscan", "127.0.0.1"});
    check(defaults.top_ports == 1000 && defaults.timing == 3 && defaults.ports.empty(),
          "default port selection");
    check(defaults.threads == 0 && defaults.timeout_ms == 0 && defaults.retries == -1 &&
              defaults.log_file.empty() && defaults.format.empty(), "unset override defaults");

    const auto ports = cli::parse({"--portscan=127.0.0.1", "-p22,80-82,81,443", "-T4",
                                  "--exclude=81-82,443", "--threads=16", "--timeout=250",
                                  "--retries=2", "--banner-timeout=1000", "--connect",
                                  "--ipv6", "--no-tls", "--no-http"});
    check(ports.ports == std::vector<int>({22, 80, 81, 82, 443}) && ports.top_ports == 0,
          "mixed ranges deduplicate and sort");
    check(ports.exclude_ports == std::set<int>({81, 82, 443}), "exclude ranges");
    check(ports.timing == 4 && ports.threads == 16 && ports.timeout_ms == 250 &&
              ports.retries == 2 && ports.banner_timeout_ms == 1000, "port numeric options");
    check(ports.connect && !ports.udp && ports.family == cli::Family::IPv6 && ports.no_tls &&
              ports.no_http, "port switches");
    check(cli::parse({"--portscan", "x", "-T0"}).timing == 0, "short timing lower bound");
    check(cli::parse({"--portscan", "x", "-T", "5"}).timing == 5, "separate timing value");
    check(cli::parse({"--portscan", "x", "--ports", "1-65535"}).ports.size() == 65535,
          "full port range has no overflow");
    check(cli::parse({"--portscan", "x", "--ipv4"}).family == cli::Family::IPv4, "IPv4 switch");
    for (const auto& item : std::vector<std::pair<std::string, int>> {
            {"0", 1000}, {"0-1", 100}, {"0U", 1000}, {"0-1u", 100}}) {
        const auto legacy = cli::parse({"--portscan", "x", item.first, "-T4"});
        check(legacy.top_ports == item.second && legacy.timing == 4 &&
                  legacy.udp == (item.first.back() == 'U' || item.first.back() == 'u'),
              "legacy preset " + item.first);
    }
    const auto legacy = cli::parse({"--portscan", "x", "22,80-81U", "--no-color"});
    check(legacy.ports == std::vector<int>({22, 80, 81}) && legacy.udp, "legacy explicit UDP ports");
    check(cli::parse({"--portscan", "x", "-T4"}).top_ports == 1000,
          "timing switch is not consumed as legacy ports");
    check(cli::parse({"--portscan", "x", "--top-ports", "100"}).top_ports == 100,
          "top 100 selection");

    const auto global = cli::parse({"--dns=example.com", "-q", "--color", "always", "-o-",
                                   "--format=json", "--log-file", "session.log"});
    check(global.quiet && global.color == cli::Color::Always && global.output == "-" &&
              global.format == "json" && global.log_file == "session.log", "global options");
    check(cli::parse({"--whois", "example.com", "--json", "out.txt"}).format == "json",
          "JSON alias explicitly chooses JSON");
    check(cli::parse({"--dns", "example.test", "--timeout", "100"}).timeout_ms == 100 &&
          cli::parse({"--whois", "example.test", "--timeout", "200"}).timeout_ms == 200,
          "DNS and WHOIS helper deadlines");
    check(cli::parse({"--dns", "x", "--color=auto", "--no-log"}).no_log, "explicit no logging");
    check(cli::parse({"--osint", "--", "-username"}).target == "-username", "delimiter target");
    check(cli::parse({"--osint=--help"}).target == "--help", "inline target can begin with dash");

    const auto sub = cli::parse({"--subdomain", "example.com", "--mode", "D", "--wordlist=names.txt",
                                "--threads", "512", "--no-permutations", "--no-enrich", "--no-deep-passive"});
    check(sub.deep && sub.wordlist == "names.txt" && sub.threads == 512 && sub.no_permutations &&
              sub.no_enrich && sub.no_deep_passive, "subdomain options");
    check(!cli::parse({"--subdomain", "x", "--mode=F", "--wordlist", "names.txt"}).deep,
          "wordlist with fast mode");
    check(cli::parse({"--subdomain", "x", "--mode=deep"}).deep, "long deep mode");
    for (const auto& mode : {"fast", "deep"}) {
        const auto compact = cli::parse({"--subdomain", "example.test", "--mode", mode});
        check(compact.wordlist.empty() && !compact.bruteforce && !compact.passive_only,
              std::string(mode) + " does not implicitly enable a large wordlist");
        const auto brute = cli::parse({"--subdomain", "example.test", "--mode", mode,
                                       "--bruteforce", "--wordlist", "selected.txt"});
        check(brute.bruteforce && brute.wordlist == "selected.txt",
              std::string(mode) + " preserves explicit wordlist with brute force");
        const auto passive = cli::parse({"--passive-only", "--subdomain", "example.test",
                                         "--mode", mode, "--no-enrich"});
        check(passive.passive_only && passive.no_enrich && !passive.bruteforce &&
                  passive.wordlist.empty(), std::string(mode) + " passive candidate profile");
    }
    check(cli::parse({"--bruteforce", "--subdomain", "example.test"}).bruteforce,
          "brute force switch before module");
    check(cli::parse({"--subdomain", "example.test", "--wordlist=selected.txt",
                       "--bruteforce"}).wordlist == "selected.txt",
          "explicit wordlist takes priority independent of flag order");
    check(cli::help("subdomain").find("--bruteforce") != std::string::npos &&
              cli::help("subdomain").find("--passive-only") != std::string::npos,
          "subdomain help documents discovery controls");

    const auto trace = cli::parse({"--traceroute", "192.0.2.1", "--protocol=udp", "--max-hops=255",
                                  "--probes=10", "--parallel-hops=32", "--destination-port=65535",
                                  "--timeout=60000", "--no-rdns", "--no-asn", "--no-mtu"});
    check(trace.protocol == "udp" && trace.max_hops == 255 && trace.probes == 10 &&
              trace.parallel_hops == 32 && trace.destination_port == 65535 &&
              trace.timeout_ms == 60000 && trace.no_rdns && trace.no_asn && trace.no_mtu,
          "traceroute options");
    check(cli::help().find('\033') == std::string::npos &&
              cli::modules().find('\033') == std::string::npos, "plain help and catalog");
    check(cli::help("portscan").find("--retries") != std::string::npos &&
              cli::help("subdomain").find("--wordlist") != std::string::npos &&
              cli::help("traceroute").find("--max-hops") != std::string::npos, "scoped help options");
}

void invalid_cases() {
    for (const auto& args : std::vector<std::vector<std::string>> {
            {"doctor", "target"}, {"--doctor=target"}, {"--doctor", "doctor"},
            {"doctor", "--doctor"}, {"--doctor", "--version"}, {"doctor", "--list-modules"},
            {"--doctor", "--dns", "example.com"}, {"doctor", "--ports", "80"},
            {"doctor", "--quiet"}, {"doctor", "--log-file", "diagnostic.log"},
            {"doctor", "--output", "report.json"}, {"doctor", "--json", "report.json"},
            {"doctor", "--output", "-", "--format", "txt"},
            {"doctor", "--output", "-", "--format", "csv"}, {"doctor", "--format", "json"},
            {"--doctor", "--doctor"}, {"--doctor", "--no-log", "--log-file", "x"}})
        rejects(args, "doctor conflicting or unsupported option");
    const std::vector<std::vector<std::string>> invalid = {
        {"--dns"}, {"--dns", ""}, {"--dns", " "}, {"--dns="}, {"--dns", "x\ny"},
        {"--dns", "x", "unexpected"}, {"x"}, {"portscan", "x"}, {"--unknown", "x"},
        {"--portscan", "x", "--prot", "80"}, {"--portscan", "x", "-Z"},
        {"--dns", "x", "--whois", "x"}, {"--dns", "x", "--dns", "x"},
        {"--dns", "x", "--output"}, {"--dns", "x", "--output="},
        {"--dns", "x", "--output", "--help"}, {"--dns", "x", "--format", "json"},
        {"--dns", "x", "-o", "a.json", "--format", "xml"},
        {"--dns", "x", "--json", "a", "--format", "csv"},
        {"--dns", "x", "-o", "a", "--output", "b"},
        {"--dns", "x", "--no-log", "--log-file", "a"},
        {"--dns", "x", "--color", "red"}, {"--dns", "x", "--color=never", "--no-color"},
        {"--dns", "x", "--quiet", "-q"}, {"--dns", "x", "--quiet=true"},
        {"--dns", "x", "--no-color=1"}, {"--help", "absent"}, {"--help=absent"},
        {"--help", "--version"}, {"--help", "-h"}, {"--version", "--dns", "x"},
        {"--list-modules", "--portscan"}, {"--portscan", "x", "--ipv4", "--ipv6"},
        {"--portscan", "x", "--udp", "--connect"}, {"--portscan", "x", "0U", "--connect"},
        {"--portscan", "x", "--udp", "--retries=1"},
        {"--portscan", "x", "0U", "--retries=0"},
        {"--portscan", "x", "-p80", "--top-ports=100"},
        {"--portscan", "x", "80", "-p80"}, {"--portscan", "x", "80", "81"},
        {"--portscan", "x", "-p80", "--exclude=80"},
        {"--portscan", "x", "-p80,81", "--exclude=79-82"},
        {"--portscan", "x", "--top-ports", "500"},
        {"--portscan", "x", "--timing=3", "-T4"},
        {"--subdomain", "x", "--mode="}, {"--subdomain", "x", "--mode", "other"},
        {"--subdomain", "x", "--passive-only", "--bruteforce"},
        {"--subdomain", "x", "--bruteforce", "--passive-only"},
        {"--subdomain", "x", "--passive-only", "--wordlist", "a"},
        {"--subdomain", "x", "--wordlist", "a", "--passive-only"},
        {"--subdomain", "x", "--bruteforce=true"},
        {"--subdomain", "x", "--passive-only=false"},
        {"--subdomain", "x", "--bruteforce", "--bruteforce"},
        {"--subdomain", "x", "--passive-only", "--passive-only"},
        {"--subdomain", "x", "--wordlist"}, {"--traceroute", "x", "--protocol=all"},
        {"--traceroute", "x", "--protocol=ICMP"},
        {"--portscan", "x", "--", "--help"}
    };
    int number = 0;
    for (const auto& args : invalid) rejects(args, "invalid case " + std::to_string(++number));

    rejects({"--portscan", "x", "--exclude=1-65535"}, "default preset entirely excluded");
    rejects({"--portscan", "x", "--top-ports=100", "--exclude=1-65535"},
            "explicit preset entirely excluded");
    rejects({"--portscan", "x", "0-1U", "--exclude=1-65535"},
            "legacy UDP preset entirely excluded");
    std::string top100_excluded;
    for (const int port : port_presets::TOP100) {
        if (!top100_excluded.empty()) top100_excluded += ',';
        top100_excluded += std::to_string(port);
    }
    rejects({"--portscan", "x", "--top-ports=100", "--exclude=" + top100_excluded},
            "all ports in selected smaller preset excluded");
    check(cli::parse({"--portscan", "x", "--top-ports=1000", "--exclude=" + top100_excluded}).top_ports == 1000,
          "same exclusions leave ports in larger preset");
    check(cli::parse({"--portscan", "x", "--top-ports=100", "--exclude=80,443"}).top_ports == 100,
          "partial preset exclusions are accepted");

    for (const auto& bad : std::vector<std::string> {
            "", "0", "65536", "-1", "+80", "80x", "80.0", "80,", ",80", "80,,81",
            "80-", "-80", "82-80", "80-81-82", "0-80", "80, 81", "999999999999999999999"}) {
        rejects({"--portscan", "x", "--ports=" + bad}, "invalid ports: " + bad);
        rejects({"--portscan", "x", "--exclude=" + bad}, "invalid excludes: " + bad);
    }
    for (const auto& item : std::vector<std::pair<std::string, std::string>> {
            {"--timing", "6"}, {"--timing", "-1"}, {"--timing", "3x"}, {"-T", "44"},
            {"--threads", "0"}, {"--threads", "513"}, {"--threads", "999999999999999999"},
            {"--timeout", "0"}, {"--timeout", "60001"}, {"--retries", "11"},
            {"--retries", "-1"}, {"--banner-timeout", "0"}, {"--banner-timeout", "60001"}}) {
        rejects({"--portscan", "x", item.first + "=" + item.second}, "port range " + item.first);
    }
    for (const auto& item : std::vector<std::pair<std::string, std::string>> {
            {"--max-hops", "0"}, {"--max-hops", "256"}, {"--probes", "0"}, {"--probes", "11"},
            {"--parallel-hops", "0"}, {"--parallel-hops", "33"},
            {"--destination-port", "0"}, {"--destination-port", "65536"}}) {
        rejects({"--traceroute", "x", item.first + "=" + item.second}, "trace range " + item.first);
    }
    const std::vector<std::pair<std::string, std::string>> port_flags = {
        {"--ports", "80"}, {"--top-ports", "100"}, {"--exclude", "80"}, {"--timing", "3"},
        {"--retries", "0"}, {"--banner-timeout", "10"}, {"--udp", ""}, {"--connect", ""},
        {"--ipv4", ""}, {"--ipv6", ""}, {"--no-tls", ""}, {"--no-http", ""}
    };
    for (const auto& item : port_flags) {
        std::vector<std::string> args {"--dns", "x", item.first};
        if (!item.second.empty()) args.push_back(item.second);
        rejects(args, "port flag scope " + item.first);
    }
    for (const auto& item : std::vector<std::pair<std::string, std::string>> {
            {"--threads", "2"}, {"--mode", "deep"}, {"--wordlist", "a"},
            {"--bruteforce", ""}, {"--passive-only", ""},
            {"--no-permutations", ""}, {"--no-enrich", ""}, {"--no-deep-passive", ""},
            {"--protocol", "tcp"}, {"--max-hops", "2"}, {"--probes", "2"},
            {"--parallel-hops", "2"}, {"--destination-port", "80"},
            {"--no-rdns", ""}, {"--no-asn", ""}, {"--no-mtu", ""}}) {
        std::vector<std::string> args {"--whois", "x", item.first};
        if (!item.second.empty()) args.push_back(item.second);
        rejects(args, "module scope " + item.first);
    }
    try {
        cli::help("absent");
        check(false, "invalid help module");
    } catch (const cli::Error&) {
        check(true, "invalid help module");
    }
}
} // namespace

int main() {
    try {
        valid_cases();
        invalid_cases();
    } catch (const std::exception& error) {
        std::cerr << "Unexpected exception: " << error.what() << '\n';
        return 1;
    }
    std::cout << checks << " CLI checks, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
