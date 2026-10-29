#include "cli.hpp"
#include "doctor.hpp"
#include "environment.hpp"
#include "dark_nexus.hpp"
#include "output.hpp"
#include "security.hpp"
#include "terminal.hpp"
#include <csignal>
#include <filesystem>
#include <limits>

namespace {
volatile std::sig_atomic_t interrupted = 0;

void interrupt_scan(int) {
    if (interrupted) _exit(130);
    interrupted = 1;
    g_cancel_token.cancelled.store(true, std::memory_order_relaxed);
}

class NullBuffer : public std::streambuf {
    int_type overflow(int_type c) override { return traits_type::not_eof(c); }
};

// Keep reports on stdout separate from the existing module status output.
class ScanOutput {
public:
    explicit ScanOutput(const cli::Options& options) : previous_(std::cout.rdbuf()) {
        if (options.quiet) std::cout.rdbuf(&sink_);
        else if (options.output == "-") std::cout.rdbuf(std::cerr.rdbuf());
    }
    ~ScanOutput() { std::cout.flush(); std::cout.rdbuf(previous_); }
private:
    NullBuffer sink_;
    std::streambuf* previous_;
};

ScanAddrFamily family_for(cli::Family family) {
    if (family == cli::Family::IPv4) return ScanAddrFamily::IPv4;
    if (family == cli::Family::IPv6) return ScanAddrFamily::IPv6;
    return ScanAddrFamily::Auto;
}

void require_helper(const std::string& helper) {
    if (!environment::find_in_path(helper, environment::current()).empty()) return;
    throw std::runtime_error("required helper not found on PATH: " + helper);
}

void validate_target(const cli::Options& options) {
    if (options.module == "site") {
        if (!InputGuard::is_safe_url(options.target) && !valid_target(options.target))
            throw cli::Error("site target must be a hostname or an http(s) URL");
    } else if (options.module == "dns" || options.module == "whois") {
        unsigned char address[sizeof(in6_addr)] = {};
        const bool literal = inet_pton(AF_INET, options.target.c_str(), address) == 1 ||
                             inet_pton(AF_INET6, options.target.c_str(), address) == 1;
        std::string hostname = options.target;
        if (!hostname.empty() && hostname.back() == '.') hostname.pop_back();
        if (!literal && (options.target.find(':') != std::string::npos || !valid_target(hostname)))
            throw cli::Error("invalid hostname or IP address: " + options.target);
    } else if (!valid_target(options.target)) {
        throw cli::Error("invalid hostname or IP address: " + options.target);
    }
    if (options.module == "subdomain" &&
        (InputGuard::is_valid_ipv4(options.target) || InputGuard::is_valid_ipv6(options.target)))
        throw cli::Error("subdomain scanning requires a domain name");
    if (!options.wordlist.empty()) {
        std::error_code error;
        if (!std::filesystem::is_regular_file(options.wordlist, error))
            throw cli::Error("wordlist must be a readable regular file: " + options.wordlist);
        std::ifstream wordlist(options.wordlist);
        if (!wordlist) throw cli::Error("cannot read wordlist: " + options.wordlist);
    }
}

void run_module(const cli::Options& options) {
    const auto& module = options.module;
    const auto& target = options.target;
    g_result.scan_type = module == "portscan" ? "port_scan" : module;

    // Domain modules keep the original domain: MX/TXT/WHOIS are not IP queries.
    if (module == "dns") return dns_lookup(target, options.timeout_ms ? options.timeout_ms : 6000);
    if (module == "whois") return whois_lookup(target, options.timeout_ms ? options.timeout_ms : 10000);
    if (module == "site") return site_lookup(target);
    if (module == "subdomain") {
        std::string wordlist = options.wordlist;
        if (wordlist.empty() && !options.passive_only && (options.deep || options.bruteforce)) {
            wordlist = auto_find_wordlist();
            if (wordlist.empty()) throw std::runtime_error(
                "deep / --bruteforce requires a readable DNS wordlist; use --wordlist PATH, "
                "reinstall the project wordlist, or choose --passive-only");
        }
        const bool enrich = !options.no_enrich;
        SubdomainFeatures features;
        features.http = enrich && !options.no_http;
        features.cname = enrich && (options.deep || options.cname || options.service_hints) && !options.no_cname;
        features.tech = features.http && (options.deep || options.tech) && !options.no_tech;
        features.js = features.http && !options.passive_only && (options.deep || options.js) && !options.no_js;
        features.service_hints = features.http && features.cname &&
            (options.deep || options.service_hints) && !options.no_service_hints;
        features.full_addresses = options.full_addresses;
        return subdomain_scan(target, wordlist, options.threads ? options.threads : 200,
                              (options.deep || options.permutations) && !options.no_permutations && !options.passive_only,
                              options.deep, enrich,
                              (options.deep || options.deep_passive) && !options.no_deep_passive,
                              options.passive_only, features);
    }

    const auto family = family_for(options.family);
    const auto ip = resolve_for_scan(target, family);
    if (ip.empty()) throw std::runtime_error("cannot resolve target in the requested address family: " + target);
    g_result.resolved_ip = ip;
    if (module != "portscan" && !InputGuard::is_valid_ipv4(ip))
        throw std::runtime_error(module + " currently requires an IPv4 target");

    if (module == "portscan") {
        PortScanOverrides overrides;
        overrides.threads = options.threads;
        overrides.timeout_ms = options.timeout_ms;
        overrides.banner_timeout_ms = options.banner_timeout_ms;
        overrides.retries = options.retries;
        overrides.connect = options.connect;
        overrides.tls = !options.no_tls;
        overrides.http = !options.no_http;
        port_scan(ip, 0, options.top_ports == 100 ? 1 : 0, options.udp, options.timing,
                  options.exclude_ports, family, options.ports, overrides);
    } else if (module == "netscan") {
        net_scan(ip.substr(0, ip.rfind('.')));
    } else if (module == "os-detect") {
        os_detect(ip);
    } else if (module == "ip-intel") {
        ip_intel(ip);
    } else if (module == "recon") {
        full_recon(ip);
    } else if (module == "traceroute") {
        TraceConfig config;
        config.max_hops = options.max_hops;
        config.queries_per_hop = options.probes;
        config.timeout_ms = options.timeout_ms ? options.timeout_ms : 2000;
        config.parallel_hops = options.parallel_hops;
        config.dst_port = options.destination_port;
        config.resolve_dns = !options.no_rdns;
        config.as_lookup = !options.no_asn;
        config.detect_mtu = !options.no_mtu;
        config.protocol = options.protocol == "tcp" ? TraceConfig::TCP_SYN :
                          options.protocol == "udp" ? TraceConfig::UDP : TraceConfig::ICMP;
        traceroute(ip, config);
    }
}
} // namespace

int main(int argc, char** argv) {
    try {
        const cli::Options options = cli::parse({argv + 1, argv + argc});
        const auto color = options.color == cli::Color::Always ? terminal::ColorMode::Always :
                           options.color == cli::Color::Never ? terminal::ColorMode::Never :
                           terminal::ColorMode::Auto;
        terminal::configure(color);
        if (options.help) { std::cout << cli::help(options.doctor ? "doctor" : options.module); return 0; }
        if (options.version) { std::cout << "dark-nexus 2.0.0\n"; return 0; }
        if (options.list_modules) { std::cout << cli::modules(); return 0; }
        if (options.doctor) {
            signal(SIGPIPE, SIG_IGN);
            const auto report = doctor::inspect(environment::current());
            if (options.output == "-") {
                std::ostream output(terminal::stdout_buffer());
                if (!doctor::write_json(report, output)) throw std::runtime_error("failed to write doctor report to stdout");
            } else if (!doctor::write_text(report, std::cout)) {
                throw std::runtime_error("failed to write doctor report to stdout");
            }
            return report.exit_code();
        }
        validate_target(options);
        if (!drop_privileges()) throw std::runtime_error("failed to drop privileges");
        if (!options.no_log && !options.log_file.empty()) {
            if (!Logger::get().init(options.log_file))
                throw std::runtime_error("cannot open log file: " + options.log_file);
        }

        struct sigaction action{};
        action.sa_handler = interrupt_scan;
        sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, nullptr);
        sigaction(SIGTERM, &action, nullptr);
        signal(SIGPIPE, SIG_IGN);
        g_cancel_token.cancelled = false;
        g_result.target = options.target;
        g_result.scan_type = options.module == "portscan" ? "port_scan" : options.module;
        const auto start = std::chrono::steady_clock::now();
        const auto start_text = now_str();
        LOG_INFO("main", "started module=" + options.module + " target=" + options.target);
        {
            ScanOutput output(options);
            try {
                if (options.module == "dns") require_helper("dig");
                if (options.module == "whois") require_helper("whois");
                run_module(options);
            } catch (const std::exception& error) {
                // Preserve collected records and finish a requested export even
                // when a module fails or the user cancels an operation.
                if (!interrupted) g_result.errors.push_back(sanitize(error.what()));
            }
        }
        const bool has_results = !g_result.dns_records.empty() || !g_result.whois_records.empty() ||
            !g_result.ports.empty() || !g_result.subdomains.empty() ||
            !g_result.subdomain_candidates.empty() ||
            !g_result.trace.empty() || !g_result.open_ports.empty() || !g_result.os_guess.empty() ||
            !g_result.geo_country.empty() || !g_result.geo_city.empty();
        g_result.status = interrupted ? "cancelled" : g_result.errors.empty() ? "complete" :
                          has_results ? "partial" : "failed";
        for (const auto& error : g_result.errors) std::cerr << "dark-nexus: " << sanitize(error) << '\n';
        if (!options.quiet)
            for (const auto& warning : g_result.warnings) std::cerr << "dark-nexus: warning: " << sanitize(warning) << '\n';
        // Command metadata describes the full run, including chained modules.
        g_result.target = options.target;
        g_result.start_time = start_text;
        g_result.end_time = now_str();
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        g_result.duration_ms = static_cast<int>(std::min<long long>(elapsed, std::numeric_limits<int>::max()));

        if (!options.output.empty()) {
            const std::string format = OutputWriter::format_for(options.output, options.format);
            if (options.output == "-") {
                std::ostream report(terminal::stdout_buffer());
                if (!OutputWriter::write_stream(g_result, report, format))
                    throw std::runtime_error("failed to write report to stdout");
            } else {
                const std::filesystem::path path(options.output);
                if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
                if (!OutputWriter::write(g_result, options.output, format))
                    throw std::runtime_error("failed to write report: " + options.output);
                if (!options.quiet) std::cerr << "Report saved: " << options.output << '\n';
            }
        }
        if (interrupted) {
            std::cerr << "dark-nexus: interrupted; results may be incomplete\n";
            return 130;
        }
        return g_result.errors.empty() ? 0 : 1;
    } catch (const cli::Error& error) {
        std::cerr << "dark-nexus: " << error.what() << "\nTry 'dark-nexus --help'.\n";
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "dark-nexus: " << error.what() << '\n';
        return interrupted ? 130 : 1;
    }
}
