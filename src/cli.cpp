#include "../include/cli.hpp"
#include "../include/port_presets.hpp"

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <sstream>
#include <utility>

namespace cli {
namespace {

const std::vector<std::pair<std::string, std::string>>& catalog() {
    static const std::vector<std::pair<std::string, std::string>> entries = {
        {"portscan", "Discover TCP or UDP ports and identify services"},
        {"subdomain", "Discover subdomains from passive sources and DNS"},
        {"dns", "Inspect DNS records for a domain"},
        {"whois", "Query domain or IP registration data"},
        {"ip-intel", "Collect IP, network and service information"},
        {"site", "Resolve a website URL and collect IP information"},
        {"osint", "Search public sources for a username, email or phone"},
        {"traceroute", "Measure the route to a host"},
        {"os-detect", "Estimate an operating system from network signals"},
        {"netscan", "Discover hosts on an IPv4 /24 network"},
        {"recon", "Run the combined IP reconnaissance workflow"}
    };
    return entries;
}

bool is_module(const std::string& value) {
    const auto& entries = catalog();
    return std::any_of(entries.begin(), entries.end(), [&](const auto& entry) {
        return entry.first == value;
    });
}

void require_text(const std::string& value, const std::string& name) {
    if (value.empty() || std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isspace(c) != 0;
        })) {
        throw Error(name + " must not be empty");
    }
    if (std::any_of(value.begin(), value.end(), [](unsigned char c) {
            return std::iscntrl(c) != 0;
        })) {
        throw Error(name + " contains a control character");
    }
}

int integer(const std::string& value, int low, int high, const std::string& flag) {
    if (value.empty()) throw Error(flag + " requires an integer");
    int result = 0;
    for (unsigned char c : value) {
        if (c < '0' || c > '9') {
            throw Error(flag + " requires an integer from " + std::to_string(low) +
                        " to " + std::to_string(high));
        }
        const int digit = c - '0';
        if (result > (high - digit) / 10 || digit > high) {
            throw Error(flag + " must be from " + std::to_string(low) +
                        " to " + std::to_string(high));
        }
        result = result * 10 + digit;
    }
    if (result < low || result > high) {
        throw Error(flag + " must be from " + std::to_string(low) +
                    " to " + std::to_string(high));
    }
    return result;
}

std::set<int> port_set(const std::string& specification, const std::string& flag) {
    if (specification.empty()) throw Error(flag + " requires a port list");
    std::set<int> result;
    std::size_t start = 0;
    while (start < specification.size()) {
        const auto comma = specification.find(',', start);
        const auto token = specification.substr(start, comma == std::string::npos
                                                          ? comma : comma - start);
        const auto dash = token.find('-');
        int first, last;
        if (dash == std::string::npos) {
            first = last = integer(token, 1, 65535, flag);
        } else {
            first = integer(token.substr(0, dash), 1, 65535, flag);
            last = integer(token.substr(dash + 1), 1, 65535, flag);
            if (first > last) throw Error(flag + " has a descending port range: " + token);
        }
        for (int port = first; port <= last; ++port) result.insert(port);
        if (comma == std::string::npos) break;
        start = comma + 1;
        if (start == specification.size()) throw Error(flag + " has an empty port entry");
    }
    return result;
}

} // namespace

Options parse(const std::vector<std::string>& args) {
    Options options;
    if (args.empty()) {
        options.help = true;
        return options;
    }

    std::set<std::string> seen;
    std::vector<std::string> positional;
    // Retain the spelling for useful diagnostics when checking module scope.
    std::vector<std::pair<std::string, std::string>> scoped;
    bool delimiter = false;
    bool explicit_target = false;
    bool port_selection = false;
    auto once = [&](const std::string& key, const std::string& spelling) {
        if (!seen.insert(key).second) throw Error("duplicate or conflicting option: " + spelling);
    };
    auto select_module = [&](const std::string& name) {
        if (!is_module(name)) throw Error("unknown module: " + name);
        once("module", "--" + name);
        options.module = name;
    };

    for (std::size_t index = 0; index < args.size(); ++index) {
        const std::string& argument = args[index];
        if (!delimiter && argument == "--") {
            delimiter = true;
            continue;
        }
        if (delimiter || argument.empty() || argument.front() != '-') {
            positional.push_back(argument);
            continue;
        }

        const auto equal = argument.find('=');
        std::string flag = argument.substr(0, equal);
        bool attached = equal != std::string::npos;
        std::string inline_value = attached ? argument.substr(equal + 1) : "";
        if (!attached && argument.size() > 2 && argument[0] == '-' && argument[1] != '-' &&
            (argument[1] == 'T' || argument[1] == 'p' || argument[1] == 'o')) {
            flag = argument.substr(0, 2);
            attached = true;
            inline_value = argument.substr(2);
        }
        auto value = [&]() {
            if (attached) {
                require_text(inline_value, flag);
                return inline_value;
            }
            if (index + 1 >= args.size() || args[index + 1] == "--" ||
                (!args[index + 1].empty() && args[index + 1][0] == '-' && args[index + 1] != "-")) {
                throw Error(flag + " requires a value");
            }
            std::string result = args[++index];
            require_text(result, flag);
            return result;
        };
        auto switch_option = [&](bool& field, const std::string& key) {
            if (attached) throw Error(flag + " does not take a value");
            once(key, flag);
            field = true;
        };
        auto scope = [&](const std::string& names) { scoped.emplace_back(flag, names); };

        if (flag.size() > 2 && flag.substr(0, 2) == "--" && is_module(flag.substr(2))) {
            select_module(flag.substr(2));
            if (attached) {
                options.target = value();
                explicit_target = true;
            }
        } else if (flag == "--doctor") {
            switch_option(options.doctor, "doctor");
        } else if (flag == "--help" || flag == "-h") {
            once("help", flag);
            options.help = true;
            if (attached) {
                const auto subject = value();
                if (subject == "doctor") { once("doctor", "doctor"); options.doctor = true; }
                else select_module(subject);
            }
        } else if (flag == "--version" || flag == "-V") {
            switch_option(options.version, "version");
        } else if (flag == "--list-modules") {
            switch_option(options.list_modules, "list-modules");
        } else if (flag == "--quiet" || flag == "-q") {
            switch_option(options.quiet, "quiet");
        } else if (flag == "--no-log") {
            switch_option(options.no_log, "no-log");
        } else if (flag == "--log-file") {
            once("log-file", flag);
            options.log_file = value();
        } else if (flag == "--color") {
            once("color", flag);
            const auto color = value();
            if (color == "auto") options.color = Color::Auto;
            else if (color == "always") options.color = Color::Always;
            else if (color == "never") options.color = Color::Never;
            else throw Error("--color must be auto, always or never");
        } else if (flag == "--no-color") {
            if (attached) throw Error(flag + " does not take a value");
            once("color", flag);
            options.color = Color::Never;
        } else if (flag == "--output" || flag == "-o" || flag == "--json") {
            once("output", flag);
            options.output = value();
            if (flag == "--json") {
                once("format", flag);
                options.format = "json";
            }
        } else if (flag == "--format") {
            once("format", flag);
            options.format = value();
            if (options.format != "json" && options.format != "csv" && options.format != "txt") {
                throw Error("--format must be json, csv or txt");
            }
        } else if (flag == "--ipv4" || flag == "--ipv6") {
            if (attached) throw Error(flag + " does not take a value");
            once("family", flag);
            options.family = flag == "--ipv4" ? Family::IPv4 : Family::IPv6;
            scope("portscan");
        } else if (flag == "--ports" || flag == "-p") {
            once("port-selection", flag);
            const auto ports = port_set(value(), flag);
            options.ports.assign(ports.begin(), ports.end());
            options.top_ports = 0;
            port_selection = true;
            scope("portscan");
        } else if (flag == "--top-ports") {
            once("port-selection", flag);
            options.top_ports = integer(value(), 100, 1000, flag);
            if (options.top_ports != 100 && options.top_ports != 1000) {
                throw Error("--top-ports must be 100 or 1000");
            }
            port_selection = true;
            scope("portscan");
        } else if (flag == "--exclude") {
            once("exclude", flag);
            options.exclude_ports = port_set(value(), flag);
            scope("portscan");
        } else if (flag == "--timing" || flag == "-T") {
            once("timing", flag);
            options.timing = integer(value(), 0, 5, flag);
            scope("portscan");
        } else if (flag == "--threads") {
            once("threads", flag);
            options.threads = integer(value(), 1, 512, flag);
            scope("portscan subdomain");
        } else if (flag == "--timeout") {
            once("timeout", flag);
            options.timeout_ms = integer(value(), 1, 60000, flag);
            scope("portscan traceroute dns whois");
        } else if (flag == "--banner-timeout") {
            once("banner-timeout", flag);
            options.banner_timeout_ms = integer(value(), 1, 60000, flag);
            scope("portscan");
        } else if (flag == "--retries") {
            once("retries", flag);
            options.retries = integer(value(), 0, 10, flag);
            scope("portscan");
        } else if (flag == "--udp") {
            switch_option(options.udp, "udp");
            scope("portscan");
        } else if (flag == "--connect") {
            switch_option(options.connect, "connect");
            scope("portscan");
        } else if (flag == "--no-tls") {
            switch_option(options.no_tls, "no-tls");
            scope("portscan");
        } else if (flag == "--no-http") {
            switch_option(options.no_http, "no-http");
            scope("portscan");
        } else if (flag == "--mode") {
            once("mode", flag);
            const auto mode = value();
            if (mode == "deep" || mode == "D" || mode == "d") options.deep = true;
            else if (mode == "fast" || mode == "F" || mode == "f") options.deep = false;
            else throw Error("--mode must be fast or deep (F or D)");
            scope("subdomain");
        } else if (flag == "--wordlist") {
            once("wordlist", flag);
            options.wordlist = value();
            scope("subdomain");
        } else if (flag == "--no-permutations") {
            switch_option(options.no_permutations, "no-permutations");
            scope("subdomain");
        } else if (flag == "--no-enrich") {
            switch_option(options.no_enrich, "no-enrich");
            scope("subdomain");
        } else if (flag == "--no-deep-passive") {
            switch_option(options.no_deep_passive, "no-deep-passive");
            scope("subdomain");
        } else if (flag == "--protocol") {
            once("protocol", flag);
            options.protocol = value();
            if (options.protocol != "icmp" && options.protocol != "udp" && options.protocol != "tcp") {
                throw Error("--protocol must be icmp, udp or tcp");
            }
            scope("traceroute");
        } else if (flag == "--max-hops") {
            once("max-hops", flag);
            options.max_hops = integer(value(), 1, 255, flag);
            scope("traceroute");
        } else if (flag == "--probes") {
            once("probes", flag);
            options.probes = integer(value(), 1, 10, flag);
            scope("traceroute");
        } else if (flag == "--parallel-hops") {
            once("parallel-hops", flag);
            options.parallel_hops = integer(value(), 1, 32, flag);
            scope("traceroute");
        } else if (flag == "--destination-port") {
            once("destination-port", flag);
            options.destination_port = integer(value(), 1, 65535, flag);
            scope("traceroute");
        } else if (flag == "--no-rdns") {
            switch_option(options.no_rdns, "no-rdns");
            scope("traceroute");
        } else if (flag == "--no-asn") {
            switch_option(options.no_asn, "no-asn");
            scope("traceroute");
        } else if (flag == "--no-mtu") {
            switch_option(options.no_mtu, "no-mtu");
            scope("traceroute");
        } else {
            throw Error("unknown option: " + argument);
        }
    }

    if (options.module.empty() && !positional.empty() && positional.front() == "doctor") {
        once("doctor", "doctor");
        options.doctor = true;
        positional.erase(positional.begin());
    }
    if (options.doctor) {
        if (!options.module.empty() || !options.target.empty() || !positional.empty())
            throw Error("doctor does not accept a target or a scan module");
        if (options.version || options.list_modules || !scoped.empty())
            throw Error("doctor cannot be combined with other actions or scan options");
        if (options.quiet || !options.log_file.empty())
            throw Error("doctor does not accept --quiet or --log-file");
        if ((!options.output.empty() && options.output != "-") ||
            (!options.format.empty() && options.format != "json"))
            throw Error("doctor supports stdout text or JSON only; use --json -");
        if (!options.format.empty() && options.output.empty()) throw Error("--format requires --output");
        return options;
    }
    if (options.help && options.module.empty() && !positional.empty()) {
        select_module(positional.front());
        positional.erase(positional.begin());
    }
    if (!explicit_target && !positional.empty()) {
        options.target = positional.front();
        require_text(options.target, "target");
        positional.erase(positional.begin());
    }
    if (!options.target.empty()) require_text(options.target, "target");
    else if (explicit_target || (!options.help && !options.version && !options.list_modules)) {
        throw Error("a target is required; see --help");
    }

    if (!positional.empty() && options.module == "portscan") {
        if (port_selection) throw Error("positional ports conflict with --ports or --top-ports");
        auto legacy = positional.front();
        positional.erase(positional.begin());
        if (!legacy.empty() && (legacy.back() == 'U' || legacy.back() == 'u')) {
            options.udp = true;
            legacy.pop_back();
        }
        if (legacy == "0") options.top_ports = 1000;
        else if (legacy == "0-1") options.top_ports = 100;
        else {
            const auto ports = port_set(legacy, "ports");
            options.ports.assign(ports.begin(), ports.end());
            options.top_ports = 0;
        }
    }
    if (!positional.empty()) throw Error("unexpected argument: " + positional.front());

    const int actions = static_cast<int>(options.help) + static_cast<int>(options.version) +
                        static_cast<int>(options.list_modules);
    if (actions > 1) throw Error("choose one of --help, --version or --list-modules");
    if ((options.version || options.list_modules) &&
        (!options.module.empty() || !options.target.empty() || !scoped.empty())) {
        throw Error("--version and --list-modules cannot be combined with a scan");
    }
    if (options.module.empty() && !options.help && !options.version && !options.list_modules) {
        throw Error("a module is required; see --list-modules");
    }
    if (options.no_log && !options.log_file.empty()) throw Error("--no-log conflicts with --log-file");
    if (!options.format.empty() && options.output.empty()) throw Error("--format requires --output");
    if (options.udp && options.connect) throw Error("--udp conflicts with --connect");
    if (options.udp && seen.count("retries")) throw Error("--retries is only available for TCP scans");
    for (const auto& item : scoped) {
        std::istringstream names(item.second);
        std::string name;
        bool allowed = false;
        while (names >> name) allowed = allowed || options.module == name;
        if (!allowed) throw Error(item.first + " is only available for " + item.second);
    }
    if (options.module == "portscan" && !options.exclude_ports.empty()) {
        const auto& selected = options.top_ports == 0 ? options.ports :
                               options.top_ports == 100 ? port_presets::TOP100 : port_presets::TOP1000;
        if (std::all_of(selected.begin(), selected.end(), [&](int port) {
                return options.exclude_ports.count(port) != 0;
            })) {
            throw Error("--exclude removes every selected port");
        }
    }
    return options;
}

std::string modules() {
    std::ostringstream out;
    for (const auto& entry : catalog()) {
        out << "  --" << entry.first;
        out << std::string(15 - entry.first.size(), ' ') << entry.second << '\n';
    }
    return out.str();
}

std::string help(const std::string& module) {
    if (module == "doctor") {
        return "dark-nexus doctor | local environment\n\n"
               "Usage: dark-nexus doctor [--json -] [--no-color]\n"
               "       dark-nexus --doctor [--output - --format json]\n\n"
               "Inspect core helper paths, optional OSINT helpers, DNS wordlists and\n"
               "effective CAP_NET_RAW metadata. No helpers are executed, no network\n"
               "requests are sent, and no system files are changed.\n\n"
               "Missing core helpers: exit 1 (affected workflows are listed).\n"
               "Optional helpers, wordlist or raw capabilities: warnings, exit 0.\n"
               "Invalid arguments: exit 2. Root capabilities are checked before\n"
               "scan privilege dropping; run doctor as your normal user.\n\n"
               "Only stdout text or JSON is supported; no target is accepted.\n";
    }
    if (!module.empty() && !is_module(module)) throw Error("unknown module: " + module);
    std::ostringstream out;
    out << "dark-nexus | network intelligence\n\n"
        << "Usage: dark-nexus --" << (module.empty() ? "<module>" : module)
        << " <target> [options]\n"
        << "       dark-nexus --help [module]\n\n";
    if (module.empty()) out << "       dark-nexus doctor [--json -]\n\n";
    if (module.empty()) out << "Modules\n" << modules() << '\n';
    else {
        for (const auto& entry : catalog()) {
            if (entry.first == module) out << entry.second << "\n\n";
        }
    }
    out << "Global options\n"
        << "  -h, --help [module]      Show help, or help for a module\n"
        << "  -V, --version            Show version\n"
        << "      --list-modules       List available modules\n"
        << "      --doctor             Inspect local dependencies without running scans\n"
        << "  -q, --quiet              Suppress scan output; keep errors and exports\n"
        << "      --color MODE         auto (default), always or never\n"
        << "      --no-color           Disable ANSI colors\n"
        << "  -o, --output PATH        Export to .json, .csv or .txt; '-' writes to stdout\n"
        << "      --format FORMAT      json, csv or txt; requires --output\n"
        << "      --json PATH          Export JSON (alias for --output + --format json)\n"
        << "      --log-file PATH      Enable logging to this file\n"
        << "      --no-log             Disable logging (default)\n";
    if (module == "portscan") {
        out << "\nPort scan options\n"
            << "  -p, --ports SPEC         Ports/ranges, e.g. 22,80,443,8000-8010\n"
            << "      --top-ports PRESET   Legacy 100/1000 presets (default: 1000)\n"
            << "                         Contain 46/259 ports; conflicts with --ports\n"
            << "      --exclude SPEC       Skip listed ports/ranges\n"
            << "      --udp                Use UDP probes\n"
            << "      --connect            Use TCP connect probes; conflicts with --udp\n"
            << "      --ipv4 / --ipv6      Restrict the address family\n"
            << "  -T0..5, --timing N       Timing profile (default: 3)\n"
            << "      --threads N          Worker count, 1..512 (default: timing profile)\n"
            << "      --timeout MS         Probe timeout, 1..60000 (default: timing profile)\n"
            << "      --retries N          Retry count, 0..10 (default: timing profile)\n"
            << "      --banner-timeout MS  Banner timeout, 1..60000 (default: timing profile)\n"
            << "      --no-tls             Skip TLS enrichment\n"
            << "      --no-http            Skip HTTP enrichment\n"
            << "\nLegacy: --portscan TARGET [PORTS]; 0=preset1000, 0-1=preset100, suffix U=UDP.\n"
            << "Example: dark-nexus --portscan 127.0.0.1 -p 22,80,443 -T3 --output ports.json\n";
    } else if (module == "dns" || module == "whois") {
        out << "\nLookup options\n"
            << "      --timeout MS         Per-helper deadline, 1..60000 (default: "
            << (module == "dns" ? "6000" : "10000") << ")\n";
        if (module == "dns")
            out << "                         Total DNS budget: 60 seconds; enrichment is bounded.\n"
                << "                         IP targets perform reverse PTR lookup.\n";
        out << "\nIncomplete lookups exit 1; requested reports retain partial data.\n";
    } else if (module == "subdomain") {
        out << "\nSubdomain options\n"
            << "      --mode MODE          fast (default) or deep; F/D are accepted\n"
            << "      --wordlist PATH      Custom DNS wordlist (available in either mode)\n"
            << "      --threads N          HTTP pipeline workers, 1..512 (default: 200)\n"
            << "      --no-permutations    Skip generated name permutations\n"
            << "      --no-enrich          Skip HTTP and technology enrichment\n"
            << "      --no-deep-passive    Skip additional passive sources in deep mode\n"
            << "\nExample: dark-nexus --subdomain example.com --mode deep --output names.json\n";
    } else if (module == "traceroute") {
        out << "\nTraceroute options\n"
            << "      --protocol MODE      icmp (default), udp or tcp\n"
            << "      --max-hops N         Hop limit, 1..255 (default: 40)\n"
            << "      --probes N           Probes per hop, 1..10 (default: 5)\n"
            << "      --parallel-hops N    Concurrent hops, 1..32 (default: 8)\n"
            << "      --timeout MS         Probe timeout, 1..60000 (default: 2000)\n"
            << "      --destination-port N TCP port / UDP base port, 1..65535 (default: 33434)\n"
            << "      --no-rdns            Skip reverse DNS lookups\n"
            << "      --no-asn             Skip ASN lookups\n"
            << "      --no-mtu             Skip MTU detection\n"
            << "\nExample: dark-nexus --traceroute 192.0.2.1 --protocol udp --max-hops 20\n";
    } else if (module.empty()) {
        out << "\nExamples\n"
            << "  dark-nexus --dns example.com\n"
            << "  dark-nexus --portscan 127.0.0.1 --ports 22,80,443 -T3\n"
            << "  dark-nexus --subdomain example.com --mode deep --output names.json\n"
            << "\nUse --help portscan, --help subdomain or --help traceroute for tuning options.\n";
    }
    out << "\nUse --key=value for long options; '--' ends option parsing.\n";
    return out.str();
}

} // namespace cli
