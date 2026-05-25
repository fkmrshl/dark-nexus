#pragma once
#include "dark_nexus.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using json = nlohmann::json;

class OutputWriter {
public:
    static bool write(const ScanResult& r, const std::string& path);
    static bool write_json(const ScanResult& r, const std::string& path);
    static bool write_csv(const ScanResult& r, const std::string& path);
    static std::string to_json_str(const ScanResult& r);
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(PortEntry, port, protocol, service, banner, version, risk, latency_ms, tls, tls_version, tls_cn, tls_expired, vulns)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(SubEntry, sub, ips, cname, http_code, server, waf, language, cms, source, title, takeover_possible)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(OsintEntry, platform, url, category, certainty)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(TraceHop, ttl, addr, hostname, avg_rtt_ms, loss_pct, asn)

namespace nlohmann {
    template <>
    struct adl_serializer<ScanResult> {
        static void to_json(json& j, const ScanResult& r) {
            j = json{
                {"schema_version", r.schema_version},
                {"tool_version", r.tool_version},
                {"scan_type", r.scan_type},
                {"target", r.target},
                {"resolved_ip", r.resolved_ip},
                {"start_time", r.start_time},
                {"end_time", r.end_time},
                {"duration_ms", r.duration_ms},
                {"geo", {
                    {"country", r.geo_country},
                    {"city", r.geo_city},
                    {"isp", r.geo_isp},
                    {"as", r.geo_as},
                    {"proxy", r.proxy},
                    {"hosting", r.hosting}
                }},
                {"os", r.os_guess},
                {"ports", r.ports},
                {"subdomains", r.subdomains},
                {"osint", r.osint},
                {"trace", r.trace},
                {"dns_records", r.dns_records}
            };
        }
        static void from_json(const json& j, ScanResult& r) {
            // Not strictly necessary since we only serialize, but good for completeness.
            j.at("schema_version").get_to(r.schema_version);
            j.at("tool_version").get_to(r.tool_version);
            j.at("scan_type").get_to(r.scan_type);
            j.at("target").get_to(r.target);
            j.at("resolved_ip").get_to(r.resolved_ip);
            j.at("start_time").get_to(r.start_time);
            j.at("end_time").get_to(r.end_time);
            j.at("duration_ms").get_to(r.duration_ms);
            auto geo = j.at("geo");
            geo.at("country").get_to(r.geo_country);
            geo.at("city").get_to(r.geo_city);
            geo.at("isp").get_to(r.geo_isp);
            geo.at("as").get_to(r.geo_as);
            geo.at("proxy").get_to(r.proxy);
            geo.at("hosting").get_to(r.hosting);
            j.at("os").get_to(r.os_guess);
            j.at("ports").get_to(r.ports);
            j.at("subdomains").get_to(r.subdomains);
            j.at("osint").get_to(r.osint);
            j.at("trace").get_to(r.trace);
            j.at("dns_records").get_to(r.dns_records);
        }
    };
}
