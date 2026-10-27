#include "../src/subdomain_common.hpp"
#include "dns_response.hpp"
#include "process.hpp"
#include <iostream>
#include <nlohmann/json.hpp>
#include <deque>

namespace {
int checks = 0, failures = 0;
std::deque<CurlResponse> responses;
std::vector<std::string> requested;
std::string process_mode;
void check(bool okay, const std::string& label) {
    ++checks;
    if (!okay) { ++failures; std::cerr << "FAIL: " << label << '\n'; }
}
void queue(const std::string& body, long status = 200, bool complete = true) {
    CurlResponse response;
    response.body = body;
    response.http_code = status;
    response.transport_code = complete ? 0 : 28;
    response.success = complete && status >= 200 && status < 300;
    if (!complete) response.error = "fixture timeout";
    responses.push_back(std::move(response));
}
CurlResponse next(const std::string& url) {
    requested.push_back(url);
    if (responses.empty()) throw std::logic_error("unexpected fixture request");
    auto response = std::move(responses.front());
    responses.pop_front();
    return response;
}
std::string doh(const std::string& answer, int status = 0) {
    return "{\"Status\":" + std::to_string(status) + ",\"Answer\":" + answer + "}";
}
}

void subdomain_warning(const std::string& warning) { g_result.warnings.push_back(warning); }
CurlResponse libcurl_get(const std::string& url, const std::string&, const std::string&, int,
                         const std::vector<std::string>&, SubdomainHttpMode) { return next(url); }
CurlResponse libcurl_post(const std::string& url, const std::string&, int,
                          const std::vector<std::string>&, const std::string&, const std::string&) { return next(url); }
ProcessResult run_process(const std::vector<std::string>& args, int, const std::atomic<bool>*, std::size_t) {
    ProcessResult result;
    if (process_mode == "failure") { result.code = 9; return result; }
    result.code = 0;
    result.out = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr ra; QUERY: 1\n";
    const auto& type = args.back();
    if (type == "MX") result.out += "example.test. 60 IN MX 10 mail.example.test.\n";
    if (type == "NS") result.out += "example.test. 60 IN NS ns.example.test.\n";
    if (type == "SRV") result.out += "example.test. 60 IN SRV 0 0 443 srv.example.test.\n";
    if (type == "TXT") result.out += "example.test. 60 IN TXT \"v=spf1 include:txt.example.test -all\"\n";
    return result;
}

int main() {
    for (const auto& name : {"WWW.Example.Test.", " *.api.example.test ", "deep.api.example.test"})
        check(normalize_subdomain_name(name, "example.test").has_value(), "strict child name normalized");
    for (const auto& name : {"example.test", "notexample.test", "foo.example.test.evil", "bad_name.example.test",
            "@api.example.test", "+trace", "10 mail.example.test", "a..example.test"})
        check(!normalize_subdomain_name(name, "example.test"), "invalid or out-of-scope name rejected");
    std::set<std::string> names;
    extract_subs("https://api.example.test/path www.example.test.evil notexample.test foo.example.test", "example.test", names);
    check(names == std::set<std::string>({"api.example.test", "foo.example.test"}), "text extraction respects full hostname boundary");
    names.clear();
    extract_subs(std::string(10000, 'a') + ".api.example.test other.example.test", "example.test", names);
    check(names == std::set<std::string>({"other.example.test"}), "overlong token cannot become a suffix candidate");

    queue(R"([{"name_value":"api.example.test\nwww.example.test","common_name":"*.deep.example.test"},{"name_value":"evil.test\nnotexample.test"}])");
    names.clear(); passive_crtsh("example.test", names);
    check(names == std::set<std::string>({"api.example.test", "www.example.test", "deep.example.test"}), "crt.sh JSON newlines and wildcard names decoded");
    queue("api.example.test,192.0.2.1\nnotexample.test,192.0.2.2\nwww.example.test.evil,192.0.2.3\n");
    names.clear(); passive_hackertarget("example.test", names);
    check(names == std::set<std::string>({"api.example.test"}), "HackerTarget hostname boundary enforced");
    queue("<html>api.example.test</html>", 429);
    names.clear(); const auto before = g_result.warnings.size(); passive_crtsh("example.test", names);
    check(names.empty() && g_result.warnings.size() > before, "rate-limited body cannot become passive evidence");
    queue("[{\"name_value\":\"api.example.test\"}]", 200, false);
    names.clear(); passive_crtsh("example.test", names);
    check(names.empty(), "partial failed HTTP body cannot become passive evidence");
    queue("invalid JSON");
    names.clear(); passive_crtsh("example.test", names);
    check(names.empty(), "malformed JSON cannot become passive evidence");
    queue("{\"nested\":" + std::string(100, '[') + "\"api.example.test\"" + std::string(100, ']') + "}");
    names.clear(); passive_crtsh("example.test", names);
    check(names.empty(), "deep JSON is rejected without unbounded recursion");
    setenv("ST_API_KEY", "fixture", 1);
    queue(R"({"subdomains":["api","deep.app","bad_name","foreign.test"],"other":"foo.example.test.evil"})");
    names.clear(); passive_securitytrails("example.test", names);
    check(names.count("api.example.test") && names.count("deep.app.example.test") && !names.count("bad_name.example.test"), "provider relative labels normalized");
    setenv("VT_API_KEY", "fixture", 1);
    queue(R"({"data":[{"id":"api.example.test"}],"meta":{"cursor":"safe&injected=1"}})");
    queue(R"({"data":[{"id":"www.example.test"}]})");
    names.clear(); passive_virustotal("example.test", names);
    check(names.size() == 2 && requested.back().find("cursor=safe%26injected%3D1") != std::string::npos, "pagination token URL encoded");

    const auto valid = doh(R"([{"name":"example.test.","type":5,"data":"alias.example.test."},{"name":"alias.example.test.","type":1,"data":"192.0.2.1"}])");
    auto result = dns_response::parse_doh_response(valid, "EXAMPLE.TEST", 1);
    check(result.valid && result.addresses == std::vector<std::string>({"192.0.2.1"}), "DoH reachable CNAME address accepted");
    result = dns_response::parse_doh_response(doh("[]", 3), "example.test", 1);
    check(result.valid && result.status == 3 && result.addresses.empty(), "DoH NXDOMAIN is a valid negative");
    const auto ipv6 = doh(R"([{"name":"example.test.","type":28,"data":"2001:0db8:0:0::1"}])");
    result = dns_response::parse_doh_response(ipv6, "example.test", 28);
    check(result.valid && result.addresses == std::vector<std::string>({"2001:db8::1"}), "DoH IPv6 address canonicalized");
    for (const auto& body : {
            R"({"Status":4294967296,"Answer":[]})", R"({"Status":18446744073709551615})",
            R"({"Status":0,"Answer":[{"name":"example.test","type":4294967297,"data":"192.0.2.1"}]})",
            R"({"Status":0,"Question":[{"name":"example.test","type":4294967297}]})",
            R"({"Status":0,"TC":true,"Answer":[]})", R"({"Status":2,"Answer":[]})",
            R"({"Status":0,"Answer":[{"name":"foreign.test","type":1,"data":"192.0.2.1"}]})",
            R"({"Status":0,"Answer":[{"name":"example.test","type":1,"data":"999.0.2.1"}]})",
            R"({"Status":0,"Answer":[{"name":"example.test","type":1,"data":"192.0.2.1\u0000evil"}]})",
            R"({"Status":3,"Answer":[{"name":"example.test","type":1,"data":"192.0.2.1"}]})",
            R"({"Status":0,"Answer":[{"name":"example.test","type":5,"data":"alias.example.test"},{"name":"alias.example.test","type":5,"data":"example.test"}]})"}) {
        result = dns_response::parse_doh_response(body, "example.test", 1);
        check(!result.valid && result.addresses.empty() && !result.error.empty(), "malformed or unrelated DoH answer rejected");
    }
    const auto nested = "{\"Status\":0,\"extra\":" + std::string(100, '[') + "0" + std::string(100, ']') + "}";
    check(!dns_response::parse_doh_response(nested, "example.test", 1).valid, "DoH JSON nesting capped");
    queue(doh("[]", 3));
    std::string provider;
    check(doh_query("example.test", "A", &provider).empty() && provider == "cloudflare", "valid negative does not cascade to second resolver");
    names.clear(); dns_extra_records("example.test", names);
    check(names == std::set<std::string>({"mail.example.test", "ns.example.test", "srv.example.test", "txt.example.test"}), "passive DNS records parsed by type");
    process_mode = "failure";
    names.clear(); dns_extra_records("example.test", names);
    check(names.empty(), "failed DNS helper cannot become passive evidence");
    const auto count = requested.size();
    g_cancel_token.cancelled = true;
    names.clear(); passive_crtsh("example.test", names); passive_dnsdumpster("example.test", names);
    check(doh_query("example.test").empty() && requested.size() == count, "pre-cancelled sources start no HTTP requests");
    g_cancel_token.cancelled = false;
    check(responses.empty(), "all HTTP fixtures consumed");
    std::cout << checks << " subdomain source checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
