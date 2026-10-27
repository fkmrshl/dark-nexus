#include "subdomain_common.hpp"
#include "../include/user_agents.hpp"
#include "../include/security.hpp"
#include "dns_query.hpp"
#include "process.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <nlohmann/json.hpp>
#include <sstream>

namespace {
using json = nlohmann::json;
bool cancelled() { return g_cancel_token.cancelled.load(std::memory_order_relaxed); }
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
std::string encode(const std::string& value) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (unsigned char c : value) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') result += static_cast<char>(c);
        else { result += '%'; result += hex[c >> 4]; result += hex[c & 15]; }
    }
    return result;
}
bool fetched(const CurlResponse& response, const std::string& source) {
    if (response.cancelled || cancelled()) return false;
    if (response.success) return true;
    subdomain_warning(source + ": " + (response.error.empty() ? "HTTP " + std::to_string(response.http_code) : response.error));
    return false;
}
json document(const CurlResponse& response, const std::string& source) {
    if (!fetched(response, source)) return json();
    if (response.body.empty() && response.http_code == 204) return json::object();
    bool too_deep = false;
    const auto data = json::parse(response.body, [&](int depth, json::parse_event_t, json&) {
        if (depth > 32) { too_deep = true; return false; }
        return true;
    }, false);
    if (too_deep) { subdomain_warning(source + ": JSON nesting exceeded limit"); return json(); }
    if (data.is_discarded() || (!data.is_object() && !data.is_array())) {
        subdomain_warning(source + ": malformed JSON response");
        return json();
    }
    if (data.is_object() && ((data.contains("error") && !data["error"].is_null() && data["error"] != false) ||
        (data.contains("errors") && !data["errors"].empty()))) {
        subdomain_warning(source + ": API returned an error response");
        return json();
    }
    return data;
}
void add(const std::string& value, const std::string& domain, std::set<std::string>& output) {
    if (cancelled()) return;
    if (output.size() >= 50000) { subdomain_warning("Passive candidate limit of 50000 reached; additional names were skipped"); return; }
    if (const auto normalized = normalize_subdomain_name(value, domain)) output.insert(*normalized);
}
void strings(const json& data, const std::string& domain, std::set<std::string>& output, int depth = 0) {
    if (cancelled() || depth > 32 || output.size() >= 50000) return;
    if (data.is_string()) extract_subs(data.get_ref<const std::string&>(), domain, output);
    else if (data.is_array() || data.is_object()) for (const auto& value : data) strings(value, domain, output, depth + 1);
}
void source_json(const std::string& source, const std::string& url, const std::string& domain,
                 std::set<std::string>& output, const std::vector<std::string>& headers = {}) {
    if (cancelled()) return;
    const auto data = document(libcurl_get(url, "", random_ua(), 15, headers), source);
    if (!data.is_null()) strings(data, domain, output);
}
void labels(const json& data, const std::string& domain, std::set<std::string>& output) {
    if (!data.is_array()) return;
    for (const auto& label : data) if (label.is_string()) add(label.get<std::string>() + "." + domain, domain, output);
}
}

void passive_crtsh(const std::string& domain, std::set<std::string>& output) {
    if (cancelled()) return;
    const auto data = document(libcurl_get("https://crt.sh/?q=%25." + domain + "&output=json", "", random_ua(), 20), "crt.sh");
    if (data.is_null()) return;
    if (!data.is_array()) { subdomain_warning("crt.sh: expected a JSON array"); return; }
    for (const auto& entry : data) {
        if (cancelled()) return;
        if (!entry.is_object()) continue;
        for (const auto* key : {"common_name", "name_value"}) {
            if (!entry.contains(key) || !entry[key].is_string()) continue;
            std::istringstream names(entry[key].get<std::string>());
            std::string name;
            while (std::getline(names, name)) add(name, domain, output);
        }
    }
}

void passive_hackertarget(const std::string& domain, std::set<std::string>& output) {
    if (cancelled()) return;
    const auto response = libcurl_get("https://api.hackertarget.com/hostsearch/?q=" + domain, "", random_ua(), 15);
    if (!fetched(response, "HackerTarget")) return;
    const auto status = lower(response.body.substr(0, 200));
    if (status.rfind("error", 0) == 0 || status.rfind("api count exceeded", 0) == 0) {
        subdomain_warning("HackerTarget: API refused the query"); return;
    }
    if (status.empty() || status.rfind("no hosts found", 0) == 0) return;
    std::istringstream lines(response.body);
    std::string line;
    bool parsed = false;
    while (std::getline(lines, line)) {
        if (cancelled()) return;
        const auto comma = line.find(',');
        if (comma != std::string::npos) { parsed = true; add(line.substr(0, comma), domain, output); }
    }
    if (!parsed) subdomain_warning("HackerTarget: malformed host list response");
}

void passive_alienvault(const std::string& domain, std::set<std::string>& output) {
    source_json("AlienVault OTX", "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns", domain, output);
}
void passive_urlscan(const std::string& domain, std::set<std::string>& output) {
    source_json("urlscan.io", "https://urlscan.io/api/v1/search/?q=domain:" + domain + "&size=200", domain, output);
}
void passive_rapiddns(const std::string& domain, std::set<std::string>& output) {
    if (cancelled()) return;
    const auto response = libcurl_get("https://rapiddns.io/subdomain/" + domain + "?full=1&down=1", "", random_ua(), 15);
    if (fetched(response, "RapidDNS")) extract_subs(response.body, domain, output);
}
void passive_threatcrowd(const std::string& domain, std::set<std::string>& output) {
    source_json("ThreatCrowd", "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + domain, domain, output);
}

void passive_dnsdumpster(const std::string& domain, std::set<std::string>& output) {
    if (cancelled()) return;
    const auto response = libcurl_get("https://dnsdumpster.com/", "", random_ua(), 10);
    if (!fetched(response, "DNSDumpster")) return;
    const auto page = lower(response.body);
    const auto field = page.find("csrfmiddlewaretoken");
    const auto value = field == std::string::npos ? field : page.find("value", field);
    const auto equal = value == std::string::npos ? value : page.find('=', value + 5);
    const auto quote = equal == std::string::npos ? equal : page.find_first_not_of(" \t\r\n", equal + 1);
    const auto end = quote == std::string::npos ? quote : response.body.find(response.body[quote], quote + 1);
    if (field == std::string::npos || quote == std::string::npos || end == std::string::npos ||
        quote - field > 4096 || end - quote > 4096 ||
        (response.body[quote] != '\'' && response.body[quote] != '"')) {
        subdomain_warning("DNSDumpster: query form token unavailable"); return;
    }
    const auto token = response.body.substr(quote + 1, end - quote - 1);
    std::string cookie, line;
    std::istringstream headers(response.headers);
    while (std::getline(headers, line)) {
        if (lower(line).rfind("set-cookie:", 0) != 0) continue;
        auto value = line.substr(11);
        value = value.substr(0, value.find(';'));
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) value.pop_back();
        if (!cookie.empty()) cookie += ";";
        cookie += value;
    }
    if (cancelled()) return;
    std::vector<std::string> fields = {"Referer: https://dnsdumpster.com/", "Content-Type: application/x-www-form-urlencoded"};
    if (!cookie.empty()) fields.push_back("Cookie:" + cookie);
    const auto result = libcurl_post("https://dnsdumpster.com/", random_ua(), 20, fields,
        "csrfmiddlewaretoken=" + encode(token) + "&targetip=" + encode(domain) + "&user=free");
    if (fetched(result, "DNSDumpster")) extract_subs(result.body, domain, output);
}

void passive_virustotal(const std::string& domain, std::set<std::string>& output) {
    const auto* key = std::getenv("VT_API_KEY");
    if (!key || !*key || cancelled()) return;
    const auto url = "https://www.virustotal.com/api/v3/domains/" + domain + "/subdomains?limit=40";
    const std::vector<std::string> fields = {"x-apikey: " + std::string(key)};
    const auto data = document(libcurl_get(url, "", random_ua(), 15, fields), "VirusTotal");
    if (data.is_null()) return;
    strings(data, domain, output);
    if (cancelled() || !data.is_object() || !data.contains("meta") || !data["meta"].is_object() ||
        !data["meta"].contains("cursor") || !data["meta"]["cursor"].is_string()) return;
    const auto cursor = data["meta"]["cursor"].get<std::string>();
    if (cursor.size() > 4096) { subdomain_warning("VirusTotal: pagination cursor exceeded size limit"); return; }
    const auto page = document(libcurl_get(url + "&cursor=" + encode(cursor), "", random_ua(), 15, fields), "VirusTotal");
    if (!page.is_null()) strings(page, domain, output);
}

void passive_securitytrails(const std::string& domain, std::set<std::string>& output) {
    const auto* key = std::getenv("ST_API_KEY");
    if (!key || !*key || cancelled()) return;
    const auto data = document(libcurl_get("https://api.securitytrails.com/v1/domain/" + domain + "/subdomains?children_only=false&include_inactive=true",
        "", random_ua(), 15, {"apikey: " + std::string(key), "Accept: application/json"}), "SecurityTrails");
    if (data.is_null()) return;
    strings(data, domain, output);
    if (data.is_object() && data.contains("subdomains")) labels(data["subdomains"], domain, output);
}

void passive_shodan(const std::string& domain, std::set<std::string>& output) {
    const auto* key = std::getenv("SHODAN_API_KEY");
    if (!key || !*key || cancelled()) return;
    const auto data = document(libcurl_get("https://api.shodan.io/dns/domain/" + domain + "?key=" + encode(key), "", random_ua(), 15), "Shodan");
    if (data.is_null()) return;
    strings(data, domain, output);
    if (data.is_object() && data.contains("subdomains")) labels(data["subdomains"], domain, output);
    if (data.is_object() && data.contains("data") && data["data"].is_array())
        for (const auto& entry : data["data"]) if (entry.is_object() && entry.contains("subdomain") && entry["subdomain"].is_string())
            add(entry["subdomain"].get<std::string>() + "." + domain, domain, output);
}

void passive_censys(const std::string& domain, std::set<std::string>& output) {
    const auto* id = std::getenv("CENSYS_API_ID");
    const auto* secret = std::getenv("CENSYS_API_SECRET");
    if (!id || !*id || !secret || !*secret || cancelled()) return;
    const auto body = json({{"q", domain}, {"fields", {"parsed.names"}}, {"flatten", true}}).dump();
    const auto data = document(libcurl_post("https://search.censys.io/api/v1/search/certificates", random_ua(), 15,
        {"Content-Type: application/json"}, body, std::string(id) + ":" + secret), "Censys");
    if (!data.is_null()) strings(data, domain, output);
}

void dns_extra_records(const std::string& domain, std::set<std::string>& output) {
    for (const auto* type : {"MX", "TXT", "NS", "SRV"}) {
        if (cancelled()) return;
        const auto result = run_process({"dig", "-r", "+noall", "+answer", "+comments", "+nomultiline", "+time=5", "+tries=1", domain, type},
            8000, &g_cancel_token.cancelled, 256 * 1024);
        if (result.cancelled || cancelled()) return;
        auto answer = dns_query::parse_reply(result.out);
        if (result.code != 0 || result.timed_out || result.truncated || answer.malformed || answer.truncated ||
            (answer.status != "NOERROR" && answer.status != "NXDOMAIN") || !dns_query::correlate_reply(answer, domain, type)) {
            subdomain_warning(std::string("Passive DNS ") + type + ": query failed or returned an incomplete answer");
            continue;
        }
        for (const auto& record : answer.records) {
            if (cancelled()) return;
            if (record.type == "NS" || record.type == "CNAME") add(record.value, domain, output);
            else if (record.type == "MX" || record.type == "SRV") {
                std::istringstream fields(record.value);
                std::string value, last;
                while (fields >> value) last = value;
                add(last, domain, output);
            } else if (record.type == "TXT") extract_subs(dns_query::txt_value(record.value), domain, output);
        }
    }
}
