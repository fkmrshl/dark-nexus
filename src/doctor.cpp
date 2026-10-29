#include "doctor.hpp"
#include "terminal.hpp"

#include <cerrno>
#include <cstring>
#include <nlohmann/json.hpp>
#include <ostream>
#include <sys/capability.h>
#include <unistd.h>

namespace doctor {
namespace {
std::string clean(const std::string& value) {
    std::string result;
    for (unsigned char c : value) {
        if (c < 32 || c == 127) result += '?';
        else result += static_cast<char>(c);
    }
    return result;
}
} // namespace

std::string Report::status() const {
    std::string result = "ok";
    for (const auto& check : checks) {
        if (check.status == "fail") return "fail";
        if (check.status == "warn") result = "warn";
    }
    return result;
}

int Report::exit_code() const { return status() == "fail" ? 1 : 0; }

Report inspect(const environment::Context& context) {
    Report report;
    const std::vector<std::pair<std::string, std::vector<std::string>>> core = {
        {"dig", {"dns", "subdomain", "traceroute ASN enrichment", "recon"}},
        {"whois", {"whois", "ip-intel", "site", "recon"}},
        {"host", {"ip-intel", "site", "recon"}}, {"ping", {"os-detect", "netscan", "recon"}},
        {"curl", {"ip-intel", "site", "subdomain", "recon", "HTTP fallback"}},
        {"openssl", {"ip-intel certificate enrichment", "site", "recon"}},
        {"getent", {"subdomain system hostname-resolution fallback"}}
    };
    for (const auto& tool : core) {
        const auto path = environment::find_in_path(tool.first, context);
        report.checks.push_back({"core." + tool.first, path.empty() ? "fail" : "ok",
            path.empty() ? tool.first + ": executable not found on PATH" : path,
            path.empty() ? "Install " + tool.first + " with your distribution's package manager and ensure its directory is on PATH." : "",
            tool.second});
    }
    const auto wordlist = environment::find_wordlist(context);
    report.checks.push_back({"wordlist", wordlist.empty() ? "warn" : "ok",
        wordlist.empty() ? "No readable, non-empty DNS wordlist found in known locations; built-in words remain available." : wordlist,
        wordlist.empty() ? "Use --subdomain DOMAIN --wordlist PATH, or install best-dns-wordlist.txt in /usr/share/wordlists/dark-nexus/." : "",
        {"subdomain deep / --bruteforce"}});

    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {};
    const bool inspected = capget(&header, data) == 0;
    const bool raw = inspected && (data[CAP_NET_RAW / 32].effective & (1U << (CAP_NET_RAW % 32)));
    std::string detail;
    if (!inspected) detail = std::string("Cannot inspect effective capabilities: ") + std::strerror(errno);
    else detail = raw ? "CAP_NET_RAW is effective in this process." : "CAP_NET_RAW is not effective in this process.";
    detail += " Checked before privilege dropping; capability metadata does not guarantee raw socket access under containers or security policies.";
    if (geteuid() == 0) detail += " Running scans as root drops privileges, so this result may change; run doctor as your normal user.";
    report.checks.push_back({"raw", raw && geteuid() != 0 ? "ok" : "warn", detail,
        !raw || geteuid() == 0 ? "Prefer the installer-assigned cap_net_raw capability and run as a normal user; TCP connect scanning remains available." : "",
        {"traceroute", "UDP portscan", "raw network probes"}});
    return report;
}

bool write_text(const Report& report, std::ostream& output) {
    output << "dark-nexus 2.0.0 | doctor | local environment\n"
           << "Checks file metadata and current capabilities; helpers are never executed.\n\n";
    for (const auto& check : report.checks) {
        const auto style = check.status == "ok" ? terminal::Style::Success :
                           check.status == "warn" ? terminal::Style::Warning : terminal::Style::Accent;
        output << "  " << terminal::style(style) << check.status << terminal::style(terminal::Style::Reset)
               << "  " << check.id << "  " << clean(check.detail) << '\n';
        if (!check.remedy.empty()) output << "      " << clean(check.remedy) << '\n';
        if (check.status != "ok" && !check.workflows.empty()) {
            output << "      Affects: ";
            for (std::size_t i = 0; i < check.workflows.size(); ++i)
                output << (i ? ", " : "") << check.workflows[i];
            output << '\n';
        }
    }
    output << "\nStatus: " << report.status() << " (local checks only; network reachability and helper behavior are not tested)\n";
    output.flush();
    return output.good();
}

bool write_json(const Report& report, std::ostream& output) {
    nlohmann::json checks = nlohmann::json::array();
    for (const auto& check : report.checks)
        checks.push_back({{"id", check.id}, {"status", check.status}, {"detail", check.detail},
                          {"remedy", check.remedy}, {"workflows", check.workflows}});
    output << nlohmann::json({{"schema_version", 1}, {"version", "2.0.0"},
        {"status", report.status()}, {"checks", checks}}).dump(2, ' ', false,
        nlohmann::json::error_handler_t::replace) << '\n';
    output.flush();
    return output.good();
}

} // namespace doctor
