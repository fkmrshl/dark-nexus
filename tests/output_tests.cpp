#include "output.hpp"
#include <iostream>
#include <sstream>

int main() {
    ScanResult result;
    result.target = "example.test";
    result.scan_type = "fixture";
    PortEntry port;
    port.port = 443; port.protocol = "tcp"; port.service = "https";
    port.banner = "quoted \"value\", newline\ninvalid byte: \xff";
    result.ports.push_back(port);
    SubEntry subdomain;
    subdomain.sub = "ipv6.example.test";
    subdomain.ipv6 = {"2001:db8::42"};
    subdomain.wildcard_match = true;
    result.subdomains.push_back(subdomain);
    result.dns_records.push_back("example.test. 60 IN A 127.0.0.1");
    result.whois_records = {"Repeated: one", "Repeated: two"};
    result.status = "partial";
    result.errors = {"helper failed, partial reply"};
    result.warnings = {"optional lookup unavailable"};
    std::ostringstream json_out;
    if (!OutputWriter::write_stream(result, json_out, "json")) return 1;
    const auto parsed = json::parse(json_out.str());
    if (parsed.at("ports").at(0).at("port") != 443 || parsed.at("dns_records").size() != 1) return 1;
    if (parsed.at("subdomains").at(0).at("ipv6").at(0) != "2001:db8::42" ||
        parsed.at("subdomains").at(0).at("wildcard_match") != true) return 1;
    if (parsed.at("status") != "partial" || parsed.at("whois_records").size() != 2 ||
        parsed.at("errors").size() != 1 || parsed.at("warnings").size() != 1) return 1;
    const auto roundtrip = parsed.get<ScanResult>();
    if (roundtrip.status != "partial" || roundtrip.whois_records != result.whois_records ||
        roundtrip.errors != result.errors || roundtrip.warnings != result.warnings) return 1;
    auto legacy = parsed;
    legacy["subdomains"][0].erase("ipv6");
    legacy["subdomains"][0].erase("wildcard_match");
    for (const auto* field : {"status", "errors", "warnings", "whois_records"}) legacy.erase(field);
    const auto old_report = legacy.get<ScanResult>();
    if (!old_report.subdomains.at(0).ipv6.empty() || old_report.subdomains.at(0).wildcard_match) return 1;
    if (old_report.status != "complete" || !old_report.errors.empty() ||
        !old_report.warnings.empty() || !old_report.whois_records.empty()) return 1;
    std::ostringstream csv_out, text_out;
    if (!OutputWriter::write_stream(result, csv_out, "csv") ||
        csv_out.str().find("record_type,target,identifier,value,details\n") != 0 ||
        csv_out.str().find("port,example.test,443,https,") == std::string::npos ||
        csv_out.str().find("dns,example.test,") == std::string::npos ||
        csv_out.str().find("whois,example.test,,Repeated: two,") == std::string::npos ||
        csv_out.str().find("error,example.test,") == std::string::npos ||
        csv_out.str().find("warning,example.test,") == std::string::npos) return 1;
    if (!OutputWriter::write_stream(result, text_out, "txt") ||
        text_out.str().find("443/tcp") == std::string::npos ||
        text_out.str().find("Status: partial") == std::string::npos ||
        text_out.str().find("Repeated: two") == std::string::npos ||
        text_out.str().find("2001:db8::42") == std::string::npos ||
        text_out.str().find("Error: helper failed") == std::string::npos) return 1;
    if (OutputWriter::format_for("report.JSON") != "json" ||
        OutputWriter::format_for("-") != "json" ||
        OutputWriter::format_for("report.txt", "csv") != "csv") return 1;
    std::ostringstream invalid;
    if (OutputWriter::write_stream(result, invalid, "bad")) return 1;
    if (OutputWriter::write(result, "/nonexistent-dark-nexus-directory/report.json")) return 1;
    std::cout << "report serialization, escaping and errors passed\n";
}
