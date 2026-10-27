#include "output.hpp"
#include "security.hpp"
#include <algorithm>
#include <cctype>
#include <filesystem>

namespace {
std::string csv(const std::string& value) {
    if (value.find_first_of(",\"\r\n") == std::string::npos) return value;
    std::string result = "\"";
    for (const char c : value) result += c == '"' ? "\"\"" : std::string(1, c);
    return result + '"';
}

void csv_row(std::ostream& out, const std::string& type, const ScanResult& result,
             const std::string& identifier, const std::string& value, const json& details) {
    out << csv(type) << ',' << csv(result.target) << ',' << csv(identifier) << ','
        << csv(value) << ',' << csv(details.dump(-1, ' ', false, json::error_handler_t::replace)) << '\n';
}

void write_csv_report(const ScanResult& result, std::ostream& out) {
    out << "record_type,target,identifier,value,details\n";
    csv_row(out, "metadata", result, result.scan_type, result.tool_version,
            {{"schema_version", result.schema_version}, {"resolved_ip", result.resolved_ip},
             {"start_time", result.start_time}, {"end_time", result.end_time},
             {"duration_ms", result.duration_ms}, {"status", result.status}});
    for (const auto& error : result.errors)
        csv_row(out, "error", result, "", error, json::object());
    for (const auto& warning : result.warnings)
        csv_row(out, "warning", result, "", warning, json::object());
    if (!result.geo_country.empty() || !result.geo_city.empty())
        csv_row(out, "geo", result, result.resolved_ip, result.geo_country,
                {{"city", result.geo_city}, {"isp", result.geo_isp}, {"as", result.geo_as},
                 {"proxy", result.proxy}, {"hosting", result.hosting}});
    if (!result.os_guess.empty()) csv_row(out, "os", result, result.resolved_ip, result.os_guess, json::object());
    for (const auto& port : result.ports)
        csv_row(out, "port", result, std::to_string(port.port), port.service, json(port));
    for (const auto& subdomain : result.subdomains)
        csv_row(out, "subdomain", result, subdomain.sub, subdomain.title, json(subdomain));
    for (const auto& hit : result.osint)
        csv_row(out, "osint", result, hit.platform, hit.url, json(hit));
    for (const auto& hop : result.trace)
        csv_row(out, "trace", result, std::to_string(hop.ttl), hop.addr, json(hop));
    for (const auto& record : result.dns_records)
        csv_row(out, "dns", result, "", record, json::object());
    for (const auto& record : result.whois_records)
        csv_row(out, "whois", result, "", record, json::object());
}

void write_text_report(const ScanResult& r, std::ostream& out) {
    out << "Dark Nexus / " << sanitize(r.scan_type) << '\n'
        << "Target: " << sanitize(r.target) << '\n'
        << "Resolved IP: " << sanitize(r.resolved_ip) << '\n'
        << "Started: " << r.start_time << "\nEnded: " << r.end_time
        << "\nDuration: " << r.duration_ms << " ms\n"
        << "Status: " << sanitize(r.status) << '\n';
    for (const auto& error : r.errors) out << "Error: " << sanitize(error) << '\n';
    for (const auto& warning : r.warnings) out << "Warning: " << sanitize(warning) << '\n';
    if (!r.geo_country.empty() || !r.geo_city.empty())
        out << "\nLocation: " << sanitize(r.geo_country) << ", " << sanitize(r.geo_city)
            << "\nISP: " << sanitize(r.geo_isp) << "\nAS: " << sanitize(r.geo_as) << '\n';
    if (!r.os_guess.empty()) out << "\nOS: " << sanitize(r.os_guess) << '\n';
    if (!r.ports.empty()) {
        out << "\nPorts\n";
        for (const auto& p : r.ports)
            out << p.port << '/' << sanitize(p.protocol) << "  " << sanitize(p.service)
                << "  " << sanitize(p.version) << "  " << sanitize(p.banner) << '\n';
    }
    if (!r.subdomains.empty()) {
        out << "\nSubdomains\n";
        for (const auto& s : r.subdomains) {
            out << sanitize(s.sub);
            for (const auto& ip : s.ips) out << "  " << sanitize(ip);
            for (const auto& ip : s.ipv6) out << "  " << sanitize(ip);
            if (s.wildcard_match) out << "  [possible wildcard]";
            out << "  " << sanitize(s.title) << '\n';
        }
    }
    if (!r.osint.empty()) {
        out << "\nOSINT\n";
        for (const auto& hit : r.osint)
            out << sanitize(hit.platform) << "  " << sanitize(hit.certainty) << "  " << sanitize(hit.url) << '\n';
    }
    if (!r.trace.empty()) {
        out << "\nTrace\n";
        for (const auto& hop : r.trace)
            out << hop.ttl << "  " << sanitize(hop.addr) << "  " << sanitize(hop.hostname)
                << "  " << hop.avg_rtt_ms << " ms\n";
    }
    if (!r.dns_records.empty()) {
        out << "\nDNS\n";
        for (const auto& record : r.dns_records) out << sanitize(record) << '\n';
    }
    if (!r.whois_records.empty()) {
        out << "\nWHOIS\n";
        for (const auto& record : r.whois_records) out << sanitize(record) << '\n';
    }
}
} // namespace

std::string OutputWriter::format_for(const std::string& path, const std::string& requested) {
    if (!requested.empty()) {
        if (requested != "json" && requested != "csv" && requested != "txt")
            throw std::invalid_argument("unsupported report format: " + requested);
        return requested;
    }
    if (path == "-") return "json";
    auto extension = std::filesystem::path(path).extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (extension == ".json") return "json";
    if (extension == ".csv") return "csv";
    return "txt";
}

std::string OutputWriter::to_json_str(const ScanResult& result) {
    return json(result).dump(2, ' ', false, json::error_handler_t::replace);
}

bool OutputWriter::write_stream(const ScanResult& result, std::ostream& out, const std::string& format) {
    if (format == "json") out << to_json_str(result) << '\n';
    else if (format == "csv") write_csv_report(result, out);
    else if (format == "txt") write_text_report(result, out);
    else return false;
    out.flush();
    return out.good();
}

bool OutputWriter::write(const ScanResult& result, const std::string& path, const std::string& format) {
    if (path.empty()) return false;
    std::ofstream out(path);
    return out && write_stream(result, out, format_for(path, format));
}

bool OutputWriter::write_json(const ScanResult& result, const std::string& path) {
    return write(result, path, "json");
}

bool OutputWriter::write_csv(const ScanResult& result, const std::string& path) {
    return write(result, path, "csv");
}
