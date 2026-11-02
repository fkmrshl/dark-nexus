#include "dark_nexus.hpp"
#include "dns_engine.hpp"
#include "output.hpp"
#include "security.hpp"
#include "subdomain_common.hpp"
#include "atomic_file.hpp"

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <csignal>
#include <stdexcept>
#include <sys/resource.h>

namespace {
std::string scenario;
std::mutex fixture_mutex;
std::vector<std::string> requested_names;
std::vector<int> candidate_concurrencies;
std::vector<int> candidate_timeouts;
std::vector<int> probe_concurrencies, probe_timeouts, probe_deadlines;
std::map<std::string, std::vector<std::string>> http_addresses;
std::map<std::string, int> request_counts;
std::atomic<int> http_calls{0}, active_http{0}, http_after_cancel{0};
std::atomic<int> head_calls{0}, get_calls{0}, cname_calls{0}, tech_calls{0}, waf_calls{0}, page_calls{0};
std::atomic<bool> finished{false};

bool wildcard_probe(const std::string& host) { return host.rfind("dnxwc-", 0) == 0; }
bool provider_fixture() { return scenario == "doh-provider-keep" || scenario == "doh-provider-merge" || scenario == "doh-native-recovery"; }
bool presentation_fixture() { return scenario.rfind("presentation", 0) == 0; }

bool classification_fixture() {
    return scenario == "wildcard" || scenario == "rotating-wildcard" ||
           scenario == "nested-wildcard" || scenario == "root-wildcard-child-clear" ||
           scenario.rfind("probe-", 0) == 0 || scenario == "scope-budget";
}

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
    return scenario == "rotating-wildcard" ? 308 : 200;
}

void passive_fixture(std::set<std::string>& output) {
    if (scenario == "js-overlap") output.insert("discovered.api.example.test");
    if (scenario == "duplicate-family" || provider_fixture()) output.insert("www.example.test");
    if (scenario == "doh-native-recovery") output.insert({"kept.example.test", "second.example.test"});
    if (scenario == "wildcard" || scenario == "rotating-wildcard" ||
        scenario.rfind("probe-", 0) == 0 ||
        scenario == "passive-first" || scenario == "passive-only")
        output.insert("observed.example.test");
    if (scenario == "nested-wildcard" || scenario == "root-wildcard-child-clear")
        output.insert("observed.api.example.test");
    if (scenario == "scope-budget" || scenario == "probe-deadline" || scenario == "permutation-budget") {
        for (int index = 0; index < 100; ++index)
            output.insert(scenario == "scope-budget" || scenario == "probe-deadline" ?
                "observed.scope" + std::to_string(index) + ".example.test" :
                "seed" + std::to_string(1000 + index) + "unit.example.test");
    }
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
DnsEngine::resolve_batch_checked(const std::vector<std::string>& hosts, int concurrency, int deadline_ms, int query_timeout_ms) {
    std::unordered_map<std::string, DnsLookupResult> output;
    if (std::any_of(hosts.begin(), hosts.end(), [](const auto& host) { return !wildcard_probe(host); })) {
        candidate_concurrencies.push_back(concurrency);
        candidate_timeouts.push_back(query_timeout_ms);
    } else {
        probe_concurrencies.push_back(concurrency);
        probe_timeouts.push_back(query_timeout_ms);
        probe_deadlines.push_back(deadline_ms);
    }
    for (const auto& host : hosts) {
        int calls;
        {
            std::lock_guard<std::mutex> lock(fixture_mutex);
            requested_names.push_back(host);
            calls = ++request_counts[host];
        }
        auto& answer = output[host];
        if (wildcard_probe(host)) {
            const auto parent = host.substr(host.find('.') + 1);
            if (scenario == "wildcard" || scenario == "rotating-wildcard" ||
                (scenario == "nested-wildcard" && parent == "api.example.test") ||
                (scenario == "root-wildcard-child-clear" && parent == "example.test"))
                answer.ipv4 = {scenario == "root-wildcard-child-clear" ? "192.0.2.20" :
                    "192.0.2." + std::to_string(40 + requested_names.size() % 6)};
            if (scenario == "probe-failure") {
                answer.failed = true;
                answer.error = "fixture wildcard probe timeout";
            }
            if (scenario == "probe-mixed") {
                const auto positives = std::count_if(requested_names.begin(), requested_names.end(), wildcard_probe);
                if (positives == 1) answer.ipv4 = {"192.0.2.40"};
            }
            if (scenario == "probe-missing") output.erase(host);
            if (scenario == "probe-exhausted" || scenario == "probe-no-retry" ||
                (scenario == "probe-transient" && calls == 1) ||
                (scenario == "probe-two-retries" && calls <= 2) ||
                (scenario == "probe-retry-positive" && calls == 1)) {
                answer.failed = answer.ipv4_failed = answer.ipv6_failed = true;
                answer.ipv4_retryable = answer.ipv6_retryable = true;
                answer.ipv4_error = answer.ipv6_error = answer.error = "fixture temporary probe failure";
            }
            if (scenario == "probe-retry-positive" && calls > 1) answer.ipv4 = {"192.0.2.40"};
            if (scenario == "probe-partial-transient" || scenario == "probe-partial-positive") {
                if (calls == 1) {
                    answer.failed = answer.ipv6_failed = answer.ipv6_retryable = true;
                    answer.ipv6_error = answer.error = "fixture probe AAAA timeout";
                    if (scenario == "probe-partial-positive" && host == requested_names.front())
                        answer.ipv4 = {"192.0.2.40"};
                } else {
                    answer.failed = answer.ipv4_failed = answer.ipv4_retryable = true;
                    answer.ipv4_error = answer.error = "fixture probe A timeout on repeat";
                }
            }
            continue;
        }
        if (scenario == "dns-permanent") {
            answer.failed = answer.ipv4_failed = answer.ipv6_failed = true;
            answer.ipv4_error = answer.ipv6_error = answer.error = "fixture malformed DNS response";
        } else if (scenario == "dns-exhausted" || scenario == "dns-no-retry" ||
            (scenario == "dns-two-retries" && calls <= 2) ||
            (scenario == "dns-transient" && calls == 1)) {
            answer.failed = answer.ipv4_failed = answer.ipv6_failed = true;
            answer.ipv4_retryable = answer.ipv6_retryable = true;
            answer.ipv4_error = answer.ipv6_error = answer.error = "fixture temporary DNS failure";
        } else if (scenario == "dns-partial-transient") {
            answer.failed = true;
            if (calls == 1) {
                answer.ipv4 = {"192.0.2.20"};
                answer.ipv6_failed = answer.ipv6_retryable = true;
                answer.ipv6_error = answer.error = "fixture AAAA timeout";
            } else {
                answer.ipv6 = {"2001:db8::20"};
                answer.ipv4_failed = answer.ipv4_retryable = true;
                answer.ipv4_error = answer.error = "fixture A timeout on repeat";
            }
        } else if (scenario == "dns-failure" || (provider_fixture() && host == "www.example.test" &&
                   (scenario != "doh-native-recovery" || calls == 1)) ||
                   (scenario == "doh-native-recovery" && (host == "kept.example.test" || (host == "second.example.test" && calls == 1)))) {
            answer.failed = true;
            answer.error = "fixture resolver timeout";
        } else if (scenario == "nxdomain" || (scenario == "streaming-tail" && host != "tailmarker.example.test")) {
            // A successful negative reply has no addresses and no error.
        } else if (scenario == "ipv6" || scenario == "http-ipv6" || (scenario == "duplicate-family" && calls > 1))
            answer.ipv6 = {"2001:db8::20"};
        else if (scenario == "mixed-failure") {
            answer.failed = true;
            answer.error = "fixture AAAA timeout";
            answer.ipv4 = {"192.0.2.20"};
        } else if (presentation_fixture()) {
            answer.ipv4 = {"192.0.2.20", "192.0.2.21"};
            answer.ipv6 = {"2001:db8::20"};
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
std::string DnsEngine::resolve_cname(const std::string&) {
    ++cname_calls;
    if (scenario.rfind("feature-", 0) == 0) return "fixture.github.io";
    return presentation_fixture() ? "edge.example.test" : "";
}
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
long fast_check(const std::string&, int) { ++head_calls; return fixture_http(); }
CurlResponse fast_probe(const std::string& sub, int, bool head, const std::vector<std::string>& addresses) {
    if (addresses.empty()) throw std::runtime_error("HTTP enrichment lost DNS addresses");
    { std::lock_guard<std::mutex> lock(fixture_mutex); http_addresses[sub] = addresses; }
    if (head) ++head_calls;
    else ++get_calls;
    CurlResponse response;
    response.primary_ip = addresses.front();
    response.dns_pinned = true;
    response.http_code = fixture_http();
    response.transport_code = 0;
    response.success = response.http_code >= 200 && response.http_code < 300;
    response.headers_complete = response.body_complete = true;
    response.requested_url = response.effective_url = "https://" + sub;
    response.method = head ? "HEAD" : "GET";
    response.headers = "Server: fixture\r\n";
    if (presentation_fixture())
        response.headers = "HTTP/1.1 200 Connection established\r\nServer: proxy\r\n\r\nHTTP/2 200\r\n"
            "sErVeR: " + std::string(50000, 'x') + "\r\nsErVeR: fixture\r\n";
    response.body = "<title>café Москва, \"quoted\"</title>";
    if (scenario == "js-relative" || scenario == "js-partial-script" || scenario == "js-overlap" || scenario == "js-http")
        response.body = scenario == "js-overlap" ?
            "<script src='https://www.example.test/assets/app.js'></script>" : "<script src='assets/app.js'></script>";
    if (scenario == "js-http") response.requested_url = response.effective_url = "http://" + sub;
    if (scenario == "js-partial-page") {
        response.success = response.body_complete = false;
        response.timed_out = true;
        response.transport_code = 28;
        response.error = "fixture partial JS page";
    }
    if (scenario == "http-truncated" || scenario == "http-timeout" || scenario == "http-headers-incomplete") {
        response.success = response.body_complete = false;
        response.truncated = scenario != "http-timeout";
        response.timed_out = scenario == "http-timeout";
        response.headers_complete = scenario != "http-headers-incomplete";
        response.transport_code = response.timed_out ? 28 : 23;
        response.error = response.timed_out ? "fixture body timeout" : "fixture capture limit";
    }
    if (scenario == "http-404") {
        response.http_code = 404;
        response.success = false;
    }
    response.attempts.push_back(response);
    return response;
}
CurlResponse libcurl_get(const std::string& raw_url, const std::string&, const std::string&, int,
                         const std::vector<std::string>&, SubdomainHttpMode) {
    ++page_calls;
    auto url = raw_url;
    if (!url.empty() && url.back() == '/') url.pop_back();
    if (provider_fixture()) {
        const bool cloudflare = url.rfind("https://cloudflare-dns.com/dns-query?", 0) == 0;
        const bool google = url.rfind("https://dns.google/resolve?", 0) == 0;
        const auto name_start = url.find("name=");
        const auto name_end = name_start == std::string::npos ? std::string::npos : url.find('&', name_start);
        const auto name = name_start == std::string::npos || name_end == std::string::npos ? "" : url.substr(name_start + 5, name_end - name_start - 5);
        if ((!cloudflare && !google) || (name != "www.example.test" &&
            !(scenario == "doh-native-recovery" && (name == "kept.example.test" || name == "second.example.test"))))
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
            answer["Answer"].push_back({{"name", name + "."}, {"type", ipv6 ? 28 : 1},
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
    response.headers_complete = response.body_complete = true;
    response.body = "<title>café Москва, \"quoted\"</title>";
    if (scenario == "js-relative" || scenario == "js-partial-page" || scenario == "js-partial-script" || scenario == "js-overlap" || scenario == "js-http") {
        if (url == "https://www.example.test" || (scenario == "js-overlap" && url == "https://discovered.api.example.test"))
            response.body = scenario == "js-overlap" ?
                "<script src = 'https://www.example.test/assets/app.js'></script>" :
                "<script src = 'assets/app.js'></script>";
        else if (url == "https://www.example.test/assets/app.js" ||
                 (scenario == "js-http" && url == "http://www.example.test/assets/app.js"))
            response.body = "const endpoint = 'https://discovered.api.example.test/api';";
        else throw std::runtime_error("unexpected script URL in JS discovery fixture: " + url);
        if ((scenario == "js-partial-page" && url == "https://www.example.test") ||
            (scenario == "js-partial-script" && url != "https://www.example.test")) {
            response.success = response.body_complete = false;
            response.transport_code = 28;
            response.timed_out = true;
            response.error = "fixture partial JS transfer";
        }
    }
    return response;
}
CurlResponse libcurl_get_deadline(const std::string& url, std::chrono::steady_clock::time_point deadline) {
    if (std::chrono::steady_clock::now() >= deadline || g_cancel_token.cancelled) return {};
    return libcurl_get(url, "", "fixture", 1, {}, SubdomainHttpMode::Verified);
}
WAFInfo detect_waf(const std::string&, const std::string&, const std::string&) { ++waf_calls; return {}; }
TechInfo detect_tech(const std::string&, const std::string&, const std::string&) {
    ++tech_calls;
    if (presentation_fixture()) return {{"FixtureStack"}, "FixtureCMS", "FixtureLanguage", ""};
    return {};
}
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
    if (argc < 2 || argc > 3) return 2;
    const std::string color = argc == 3 ? argv[2] : "never";
    if (color != "never" && color != "always" && color != "auto") return 2;
    terminal::configure(color == "always" ? terminal::ColorMode::Always :
                        color == "auto" ? terminal::ColorMode::Auto : terminal::ColorMode::Never);
    scenario = argv[1];
    g_result.scan_type = "subdomain";
    g_result.target = "example.test";
    g_result.start_time = "fixture-start";
    g_result.status = "running";
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
            const bool enrich = scenario == "cancel" || scenario == "worker-throw" || scenario == "unicode" ||
                                presentation_fixture() || scenario.rfind("js-", 0) == 0 || scenario.rfind("http-", 0) == 0 ||
                                classification_fixture() || provider_fixture() || scenario.rfind("feature-", 0) == 0;
            std::optional<SubdomainFeatures> features;
            if (scenario.rfind("feature-", 0) == 0) {
                features = SubdomainFeatures{};
                features->http = scenario == "feature-http" || scenario == "feature-tech" ||
                                 scenario == "feature-js" || scenario == "feature-hints";
                features->cname = scenario == "feature-cname" || scenario == "feature-hints";
                features->tech = scenario == "feature-tech";
                features->js = scenario == "feature-js";
                features->service_hints = scenario == "feature-hints";
            } else if (scenario == "presentation") {
                features = SubdomainFeatures{};
                features->full_addresses = true;
            } else if (scenario.rfind("http-", 0) == 0) {
                features = SubdomainFeatures{true, false, true, false, false, false};
            }
            subdomain_scan("example.test", "wordlist.txt", 1, scenario == "permutation-budget",
                           scenario == "unicode" || presentation_fixture() || scenario.rfind("js-", 0) == 0, enrich, false,
                           scenario == "passive-only", features, scenario == "probe-deadline" ? 16 : 128,
                           scenario == "dns-no-retry" || scenario == "probe-no-retry" ? 0 :
                           scenario == "dns-two-retries" || scenario == "probe-two-retries" ? 2 : 1,
                           scenario == "probe-deadline" ? 5000 : 500);
        }
    } catch (const std::exception& error) {
        g_result.errors.push_back(error.what());
    }
    finished = true;
    if (cancellation.joinable()) cancellation.join();
    g_result.duration_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count());
    g_result.end_time = "fixture-end";
    g_result.status = OutputWriter::completion_status(g_result, g_cancel_token.cancelled);
    if (scenario.rfind("atomic-", 0) != 0) OutputWriter::write_subdomain_reports(g_result);
    nlohmann::json result = g_result;
    result["fixture"] = {{"http_calls", http_calls.load()}, {"active_http", active_http.load()},
                          {"http_after_cancel", http_after_cancel.load()}, {"requested", requested_names},
                          {"dns_concurrencies", candidate_concurrencies},
                          {"dns_timeouts", candidate_timeouts},
                          {"probe_concurrencies", probe_concurrencies}, {"probe_timeouts", probe_timeouts},
                          {"probe_deadlines", probe_deadlines}, {"http_addresses", http_addresses},
                          {"head_calls", head_calls.load()}, {"get_calls", get_calls.load()},
                          {"cname_calls", cname_calls.load()}, {"tech_calls", tech_calls.load()},
                          {"waf_calls", waf_calls.load()}, {"page_calls", page_calls.load()}};
    std::ofstream output("fixture-report.json");
    output << result.dump(2, ' ', false, nlohmann::json::error_handler_t::replace) << '\n';
    if (!output) return 3;
    if (g_cancel_token.cancelled) return 130;
    return g_result.errors.empty() ? 0 : 1;
}
