#include "dark_nexus.hpp"
#include "dns_engine.hpp"
#include "output.hpp"
#include "security.hpp"
#include "subdomain_common.hpp"
#include "atomic_file.hpp"

#include <atomic>
#include <filesystem>
#include <csignal>
#include <stdexcept>
#include <sys/resource.h>

namespace {
std::string scenario;
std::mutex fixture_mutex;
std::vector<std::string> requested_names;
std::map<std::string, int> request_counts;
std::atomic<int> http_calls{0}, active_http{0}, http_after_cancel{0};
std::atomic<bool> finished{false};

bool wildcard_probe(const std::string& host) { return host.rfind("dnxwc-", 0) == 0; }
bool provider_fixture() { return scenario == "doh-provider-keep" || scenario == "doh-provider-merge"; }

long fixture_http() {
    if (g_cancel_token.cancelled) ++http_after_cancel;
    const int call = ++http_calls;
    ++active_http;
    struct Finish { ~Finish() { --active_http; } } finish;
    if (scenario == "worker-throw" && call == 1)
        throw std::runtime_error("fixture HTTP worker failure");
    if (scenario == "cancel") {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (!g_cancel_token.cancelled && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        return 0;
    }
    return 200;
}

void passive_fixture(std::set<std::string>& output) {
    if (scenario == "duplicate-family" || provider_fixture()) output.insert("www.example.test");
    if (scenario != "passive-invalid") return;
    output.insert({"VALID.EXAMPLE.TEST.", "foreign.test", "evilexample.test",
                   "bad host.example.test", "https://url.example.test", "bad..example.test"});
}
} // namespace

DnsEngine::DnsEngine() = default;
DnsEngine::~DnsEngine() = default;
DnsEngine& DnsEngine::get() { static DnsEngine engine; return engine; }
void DnsEngine::clear_cache() {}
void DnsEngine::load_resolvers(const std::string&) {}
int DnsEngine::channel_count() const { return 1; }
int DnsEngine::max_per_channel_concurrency() const { return 1; }
std::size_t DnsEngine::resolver_count() const { return 1; }

std::unordered_map<std::string, DnsLookupResult>
DnsEngine::resolve_batch_checked(const std::vector<std::string>& hosts, int, int) {
    std::unordered_map<std::string, DnsLookupResult> output;
    for (const auto& host : hosts) {
        int calls;
        {
            std::lock_guard<std::mutex> lock(fixture_mutex);
            requested_names.push_back(host);
            calls = ++request_counts[host];
        }
        auto& answer = output[host];
        if (wildcard_probe(host)) {
            if (scenario == "wildcard") answer.ipv4 = {"192.0.2.20"};
            continue;
        }
        if (scenario == "dns-failure" || (provider_fixture() && host == "www.example.test")) {
            answer.failed = true;
            answer.error = "fixture resolver timeout";
        } else if (scenario == "nxdomain") {
            // A successful negative reply has no addresses and no error.
        } else if (scenario == "ipv6" || (scenario == "duplicate-family" && calls > 1))
            answer.ipv6 = {"2001:db8::20"};
        else if (scenario == "mixed-failure") {
            answer.failed = true;
            answer.error = "fixture AAAA timeout";
            answer.ipv4 = {"192.0.2.20"};
        } else answer.ipv4 = {"192.0.2.20"};
    }
    return output;
}

std::unordered_map<std::string, std::vector<std::string>>
DnsEngine::resolve_batch(const std::vector<std::string>& hosts, int concurrency,
                         const std::unordered_set<std::string>*) {
    std::unordered_map<std::string, std::vector<std::string>> output;
    for (auto& [host, result] : resolve_batch_checked(hosts, concurrency, 1000))
        output[host] = result.ipv4;
    return output;
}

std::vector<std::string> DnsEngine::resolve(const std::string&) { return {"192.0.2.20"}; }
std::vector<std::string> DnsEngine::resolve_aaaa(const std::string&) { return {}; }
std::string DnsEngine::resolve_cname(const std::string&) { return {}; }
std::string DnsEngine::resolve_ptr(const std::string&) { return {}; }

void passive_crtsh(const std::string&, std::set<std::string>& out) { passive_fixture(out); }
void passive_hackertarget(const std::string&, std::set<std::string>&) {}
void passive_alienvault(const std::string&, std::set<std::string>&) {}
void passive_urlscan(const std::string&, std::set<std::string>&) {}
void passive_rapiddns(const std::string&, std::set<std::string>&) {}
void passive_threatcrowd(const std::string&, std::set<std::string>&) {}
void passive_dnsdumpster(const std::string&, std::set<std::string>&) {}
void passive_virustotal(const std::string&, std::set<std::string>&) {}
void passive_securitytrails(const std::string&, std::set<std::string>&) {}
void passive_shodan(const std::string&, std::set<std::string>&) {}
void passive_censys(const std::string&, std::set<std::string>&) {}
void dns_extra_records(const std::string&, std::set<std::string>&) {}

void http_jitter() {}
long fast_check(const std::string&, int) { return fixture_http(); }
CurlResponse fast_probe(const std::string&, int) {
    CurlResponse response;
    response.http_code = fixture_http();
    response.transport_code = 0;
    response.success = response.http_code == 200;
    response.headers = "Server: fixture\r\n";
    response.body = "<title>café Москва, \"quoted\"</title>";
    return response;
}
CurlResponse libcurl_get(const std::string& url, const std::string&, const std::string&, int,
                         const std::vector<std::string>&, SubdomainHttpMode) {
    if (provider_fixture()) {
        const bool cloudflare = url.rfind("https://cloudflare-dns.com/dns-query?", 0) == 0;
        const bool google = url.rfind("https://dns.google/resolve?", 0) == 0;
        if ((!cloudflare && !google) || url.find("name=www.example.test&type=") == std::string::npos)
            throw std::runtime_error("unexpected DoH request in provider fixture");
        const bool ipv6 = url.find("&type=AAAA") != std::string::npos;
        CurlResponse response;
        if (cloudflare && ipv6) {
            response.transport_code = 7;
            response.error = "fixture Cloudflare AAAA request unavailable";
            return response;
        }
        response.http_code = 200;
        response.transport_code = 0;
        response.success = true;
        nlohmann::json answer = {{"Status", 0}, {"Answer", nlohmann::json::array()}};
        if (!ipv6 || scenario == "doh-provider-merge")
            answer["Answer"].push_back({{"name", "www.example.test."}, {"type", ipv6 ? 28 : 1},
                {"TTL", 60}, {"data", ipv6 ? "2001:db8::42" : "192.0.2.42"}});
        response.body = answer.dump();
        return response;
    }
    if (url.find(".example.test") == std::string::npos)
        throw std::runtime_error("unexpected external HTTP provider in pipeline fixture");
    CurlResponse response;
    response.http_code = 200;
    response.transport_code = 0;
    response.success = true;
    response.body = "<title>café Москва, \"quoted\"</title>";
    return response;
}
WAFInfo detect_waf(const std::string&, const std::string&, const std::string&) { return {}; }
TechInfo detect_tech(const std::string&, const std::string&, const std::string&) { return {}; }
std::string parse_title(const std::string&) { return "café Москва, \"quoted\""; }

void subdomain_warning(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_result_mtx);
    if (g_result.warnings.size() < 64) g_result.warnings.push_back(message);
}

std::string sanitize_subdomain_text(const std::string& value, std::size_t limit) {
    return InputGuard::sanitize_output(value, limit);
}

void print_header(const std::string&) {}
void print_section(const std::string&) {}
std::string resolve(const std::string&) { return "192.0.2.20"; }
std::string safe_exec(const std::vector<std::string>&, int) {
    throw std::runtime_error("unexpected subprocess in fixture");
}
std::string safe_curl(const std::string&, int) {
    throw std::runtime_error("unexpected HTTP subprocess in fixture");
}
std::vector<std::string> split_lines(const std::string& input) {
    std::vector<std::string> result;
    std::istringstream stream(input);
    std::string line;
    while (std::getline(stream, line)) if (!line.empty()) result.push_back(line);
    return result;
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    scenario = argv[1];
    g_result.scan_type = "subdomain";
    g_result.target = "example.test";
    std::thread cancellation;
    if (scenario == "cancel") cancellation = std::thread([] {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!http_calls && !finished && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        if (http_calls && !finished) {
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            g_cancel_token.cancelled = true;
        }
    });
    const auto start = std::chrono::steady_clock::now();
    try {
        if (scenario == "atomic-failure") {
            rlimit previous{};
            if (getrlimit(RLIMIT_FSIZE, &previous) != 0) throw std::runtime_error("getrlimit failed");
            const auto old_handler = signal(SIGXFSZ, SIG_IGN);
            rlimit limited = previous;
            limited.rlim_cur = 256;
            if (setrlimit(RLIMIT_FSIZE, &limited) != 0) throw std::runtime_error("setrlimit failed");
            std::string error;
            const bool written = write_atomic_file("atomic.json", std::string(8192, 'x'), error);
            const bool restored = setrlimit(RLIMIT_FSIZE, &previous) == 0;
            signal(SIGXFSZ, old_handler);
            if (!restored || written || error.empty()) throw std::runtime_error("atomic failure fixture did not fail safely");
        } else if (scenario == "atomic-concurrent") {
            std::atomic<int> failures{0};
            std::vector<std::thread> writers;
            for (int index = 0; index < 8; ++index) writers.emplace_back([&, index] {
                std::string error;
                const auto text = nlohmann::json({{"writer", index}, {"payload", std::string(4096, 'x')}}).dump();
                if (!write_atomic_file("atomic.json", text, error)) ++failures;
            });
            for (auto& writer : writers) writer.join();
            if (failures) throw std::runtime_error("concurrent atomic writer failed");
        } else {
            const bool enrich = scenario == "cancel" || scenario == "worker-throw" || scenario == "unicode";
            subdomain_scan("example.test", "wordlist.txt", 1, false, scenario == "unicode", enrich, false);
        }
    } catch (const std::exception& error) {
        g_result.errors.push_back(error.what());
    }
    finished = true;
    if (cancellation.joinable()) cancellation.join();
    g_result.duration_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count());
    g_result.status = g_cancel_token.cancelled ? "cancelled" : g_result.errors.empty() ? "complete" :
                      g_result.subdomains.empty() ? "failed" : "partial";
    nlohmann::json result = g_result;
    result["fixture"] = {{"http_calls", http_calls.load()}, {"active_http", active_http.load()},
                          {"http_after_cancel", http_after_cancel.load()}, {"requested", requested_names}};
    std::ofstream output("fixture-report.json");
    output << result.dump(2, ' ', false, nlohmann::json::error_handler_t::replace) << '\n';
    if (!output) return 3;
    if (g_cancel_token.cancelled) return 130;
    return g_result.errors.empty() ? 0 : 1;
}
