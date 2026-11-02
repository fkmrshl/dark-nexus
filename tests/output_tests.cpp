#include "output.hpp"
#include <iostream>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <unistd.h>

struct TempDirectory {
    std::filesystem::path previous = std::filesystem::current_path();
    std::filesystem::path path;
    TempDirectory() {
        char pattern[] = "/tmp/dark-nexus-output-XXXXXX";
        const char* created = mkdtemp(pattern);
        if (!created) throw std::runtime_error("mkdtemp failed");
        path = created;
        std::filesystem::current_path(path);
    }
    ~TempDirectory() {
        std::error_code error;
        std::filesystem::current_path(previous, error);
        std::filesystem::remove_all(path, error);
    }
};

json read_json(const std::string& path) {
    std::ifstream in(path);
    return json::parse(in);
}

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
    subdomain.stack = {"nginx"};
    subdomain.discovery_sources = {"fixture"};
    subdomain.doh_fallback = "used";
    SubdomainHttpObservation http;
    http.requested_url = http.effective_url = "https://ipv6.example.test";
    http.method = "GET"; http.http_code = 200; http.transport_code = 23;
    http.headers_complete = true; http.truncated = true;
    http.primary_ip = "2001:db8::42"; http.dns_pinned = true;
    http.error = "fixture capture limit";
    subdomain.http_code = "200";
    subdomain.http_observations.push_back(http);
    result.subdomains.push_back(subdomain);
    SubEntry candidate = subdomain;
    candidate.sub = "uncertain.example.test";
    candidate.dns_status = "wildcard";
    result.subdomain_candidates.push_back(candidate);
    result.dns_records.push_back("example.test. 60 IN A 127.0.0.1");
    result.whois_records = {"Repeated: one", "Repeated: two"};
    result.status = "partial";
    result.errors = {"helper failed, partial reply"};
    result.warnings = {"optional lookup unavailable"};
    std::ostringstream json_out;
    if (!OutputWriter::write_stream(result, json_out, "json")) return 1;
    const auto parsed = json::parse(json_out.str());
    if (parsed.at("schema_version") != "3.0") return 1;
    if (parsed.at("subdomain_counts") != json({{"resolved", 1}, {"candidates", 1}, {"total", 2}})) return 1;
    if (parsed.contains("osint") || parsed.contains("osint_hits")) return 1;
    if (parsed.at("ports").at(0).at("port") != 443 || parsed.at("dns_records").size() != 1) return 1;
    if (parsed.at("subdomains").at(0).at("ipv6").at(0) != "2001:db8::42" ||
        parsed.at("subdomains").at(0).at("wildcard_match") != true) return 1;
    if (parsed.at("status") != "partial" || parsed.at("whois_records").size() != 2 ||
        parsed.at("errors").size() != 1 || parsed.at("warnings").size() != 1) return 1;
    const auto roundtrip = parsed.get<ScanResult>();
    if (roundtrip.subdomains[0].stack != subdomain.stack ||
        roundtrip.subdomains[0].discovery_sources != subdomain.discovery_sources ||
        roundtrip.subdomains[0].doh_fallback != "used") return 1;
    if (roundtrip.subdomains[0].http_observations.size() != 1 ||
        !roundtrip.subdomains[0].http_observations[0].truncated ||
        roundtrip.subdomains[0].http_observations[0].body_complete ||
        roundtrip.subdomains[0].http_observations[0].http_code != 200 ||
        roundtrip.subdomains[0].http_observations[0].primary_ip != "2001:db8::42" ||
        !roundtrip.subdomains[0].http_observations[0].dns_pinned) return 1;
    auto legacy_http = parsed["subdomains"][0]["http_observations"][0];
    legacy_http.erase("primary_ip"); legacy_http.erase("dns_pinned");
    const auto old_http = legacy_http.get<SubdomainHttpObservation>();
    if (!old_http.primary_ip.empty() || old_http.dns_pinned || old_http.http_code != 200) return 1;
    if (roundtrip.subdomain_candidates.size() != 1 ||
        roundtrip.subdomain_candidates[0].dns_status != "wildcard") return 1;
    if (roundtrip.status != "partial" || roundtrip.whois_records != result.whois_records ||
        roundtrip.errors != result.errors || roundtrip.warnings != result.warnings) return 1;
    auto legacy = parsed;
    legacy["schema_version"] = "2.0";
    legacy["osint"] = json::array({{{"platform", "legacy fixture"}, {"url", "https://example.test/legacy"}}});
    legacy["osint_hits"] = {"https://example.test/legacy"};
    for (const auto* field : {"stack", "discovery_sources", "doh_fallback"}) legacy["subdomains"][0].erase(field);
    legacy["subdomains"][0].erase("ipv6");
    legacy["subdomains"][0].erase("wildcard_match");
    legacy["subdomains"][0].erase("dns_status");
    legacy["subdomains"][0].erase("http_observations");
    legacy.erase("subdomain_candidates");
    for (const auto* field : {"status", "errors", "warnings", "whois_records"}) legacy.erase(field);
    const auto old_report = legacy.get<ScanResult>();
    if (!old_report.subdomains.at(0).ipv6.empty() || old_report.subdomains.at(0).wildcard_match ||
        !old_report.subdomains.at(0).stack.empty() || !old_report.subdomains.at(0).discovery_sources.empty() ||
        !old_report.subdomains.at(0).doh_fallback.empty()) return 1;
    if (!old_report.subdomains.at(0).http_observations.empty()) return 1;
    if (!old_report.subdomain_candidates.empty() || old_report.subdomains.at(0).dns_status != "resolved") return 1;
    if (old_report.status != "complete" || !old_report.errors.empty() ||
        !old_report.warnings.empty() || !old_report.whois_records.empty()) return 1;
    const auto legacy_roundtrip = json(old_report);
    if (legacy_roundtrip.at("schema_version") != "3.0" ||
        legacy_roundtrip.contains("osint") || legacy_roundtrip.contains("osint_hits") ||
        legacy_roundtrip.at("subdomains").size() != 1) return 1;
    std::ostringstream csv_out, text_out;
    if (!OutputWriter::write_stream(result, csv_out, "csv") ||
        csv_out.str().find("record_type,target,identifier,value,details\n") != 0 ||
        csv_out.str().find("port,example.test,443,https,") == std::string::npos ||
        csv_out.str().find("dns,example.test,") == std::string::npos ||
        csv_out.str().find("whois,example.test,,Repeated: two,") == std::string::npos ||
        csv_out.str().find("error,example.test,") == std::string::npos ||
        csv_out.str().find("warning,example.test,") == std::string::npos) return 1;
    if (csv_out.str().find("subdomain_candidate,example.test,uncertain.example.test,wildcard,") == std::string::npos)
        return 1;
    if (!OutputWriter::write_stream(result, text_out, "txt") ||
        text_out.str().find("443/tcp") == std::string::npos ||
        text_out.str().find("Status: partial") == std::string::npos ||
        text_out.str().find("Repeated: two") == std::string::npos ||
        text_out.str().find("2001:db8::42") == std::string::npos ||
        text_out.str().find("Error: helper failed") == std::string::npos) return 1;
    if (text_out.str().find("Uncertain subdomain candidates") == std::string::npos ||
        text_out.str().find("uncertain.example.test  [wildcard]") == std::string::npos) return 1;
    if (OutputWriter::format_for("report.JSON") != "json" ||
        OutputWriter::format_for("-") != "json" ||
        OutputWriter::format_for("report.txt", "csv") != "csv") return 1;
    std::ostringstream invalid;
    if (OutputWriter::write_stream(result, invalid, "bad")) return 1;
    if (OutputWriter::write(result, "/nonexistent-dark-nexus-directory/report.json")) return 1;
    const auto running = OutputWriter::subdomain_checkpoint(result, false);
    const auto final = OutputWriter::subdomain_checkpoint(result, true);
    if (running.at("status") != "running" || running.at("end_time") != "" ||
        running.at("checkpoint").at("final") != false || final.at("status") != result.status ||
        final.at("checkpoint").at("final") != true || final.at("checkpoint").at("saved_at").get<std::string>().size() != 20 ||
        running.contains("results") || running.contains("rows")) return 1;
    ScanResult empty;
    empty.errors.push_back("error");
    if (OutputWriter::completion_status(empty, false) != "failed" ||
        OutputWriter::completion_status(empty, true) != "cancelled" ||
        OutputWriter::completion_status(result, false) != "partial") return 1;
    empty.errors.clear();
    if (OutputWriter::completion_status(empty, false) != "complete") return 1;
    TempDirectory temp;
    ScanResult report = result;
    report.target = "Example.Test.";
    report.errors.clear(); report.status = "complete";
    SubEntry first; first.sub = "aaa.example.test";
    report.subdomains.push_back(first);
    if (!OutputWriter::write_subdomain_reports(report) || report.target != "example.test") return 1;
    const auto disk = read_json("example.test_subdomains.json");
    auto checkpoint = read_json("example.test_subdomains_checkpoint.json");
    checkpoint.erase("checkpoint");
    if (disk != json::parse(OutputWriter::to_json_str(report)) || checkpoint != disk || disk.at("subdomains")[0].at("sub") != first.sub) return 1;
    std::ifstream csv_file("example.test_subdomains.csv");
    std::ostringstream csv_disk; csv_disk << csv_file.rdbuf();
    std::ostringstream csv_expected; OutputWriter::write_stream(report, csv_expected, "csv");
    if (csv_disk.str() != csv_expected.str() || csv_disk.str().find("subdomain_counts") == std::string::npos) return 1;
    std::filesystem::create_directory("explicit.json");
    if (OutputWriter::write(report, "explicit.json") || !std::filesystem::is_directory("explicit.json")) return 1;
    std::filesystem::create_directory("failure.test_subdomains.csv");
    report.target = "failure.test";
    if (OutputWriter::write_subdomain_reports(report) || report.status != "partial" ||
        report.errors.size() != 1 || !std::filesystem::is_directory("failure.test_subdomains.csv")) return 1;
    const auto failed_json = read_json("failure.test_subdomains.json");
    auto failed_checkpoint = read_json("failure.test_subdomains_checkpoint.json");
    failed_checkpoint.erase("checkpoint");
    if (failed_json != json::parse(OutputWriter::to_json_str(report)) || failed_checkpoint != failed_json) return 1;
    report.target = "../bad"; report.status = "cancelled";
    if (OutputWriter::write_subdomain_reports(report) || report.status != "cancelled") return 1;
    report.target = "127.0.0.1";
    if (OutputWriter::write_subdomain_reports(report) || report.status != "cancelled") return 1;
    std::cout << "report serialization, escaping and errors passed\n";
}
