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
    result.dns_records.push_back("example.test. 60 IN A 127.0.0.1");
    std::ostringstream json_out;
    if (!OutputWriter::write_stream(result, json_out, "json")) return 1;
    const auto parsed = json::parse(json_out.str());
    if (parsed.at("ports").at(0).at("port") != 443 || parsed.at("dns_records").size() != 1) return 1;
    std::ostringstream csv_out, text_out;
    if (!OutputWriter::write_stream(result, csv_out, "csv") ||
        csv_out.str().find("record_type,target,identifier,value,details\n") != 0 ||
        csv_out.str().find("port,example.test,443,https,") == std::string::npos ||
        csv_out.str().find("dns,example.test,") == std::string::npos) return 1;
    if (!OutputWriter::write_stream(result, text_out, "txt") ||
        text_out.str().find("443/tcp") == std::string::npos) return 1;
    if (OutputWriter::format_for("report.JSON") != "json" ||
        OutputWriter::format_for("-") != "json" ||
        OutputWriter::format_for("report.txt", "csv") != "csv") return 1;
    std::ostringstream invalid;
    if (OutputWriter::write_stream(result, invalid, "bad")) return 1;
    if (OutputWriter::write(result, "/nonexistent-dark-nexus-directory/report.json")) return 1;
    std::cout << "report serialization, escaping and errors passed\n";
}
