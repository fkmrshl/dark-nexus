#include "subdomain_common.hpp"
#include <atomic>
#include <cassert>
#include <chrono>
#include <map>
#include <mutex>
#include <thread>
#include <curl/curl.h>
#include <iostream>

CancellationToken g_cancel_token;
namespace {
std::mutex mutex;
std::map<std::string, CurlResponse> fixtures;
std::map<std::string, int> calls;
std::vector<std::string> warnings;
std::atomic<int> active{0}, maximum{0};
std::atomic<int> delay_ms{0};
CurlResponse response(long status, const std::string& headers, const std::string& body) {
    CurlResponse r; r.http_code = status; r.success = status >= 200 && status < 300;
    r.headers_complete = r.body_complete = true; r.headers = headers; r.body = body; return r;
}
void reset() { assert(active == 0); fixtures.clear(); calls.clear(); warnings.clear(); maximum = 0; active = 0; delay_ms = 0; g_cancel_token.cancelled = false; }
}
void subdomain_warning(const std::string& warning) { std::lock_guard<std::mutex> lock(mutex); warnings.push_back(warning); }
CurlResponse libcurl_get_deadline(const std::string& url, std::chrono::steady_clock::time_point deadline) {
    const int n = ++active; int old = maximum.load();
    while (old < n && !maximum.compare_exchange_weak(old, n)) {}
    int remaining = delay_ms.load();
    while (remaining > 0 && std::chrono::steady_clock::now() < deadline && !g_cancel_token.cancelled) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        --remaining;
    }
    std::lock_guard<std::mutex> lock(mutex);
    ++calls[url]; --active;
    const auto it = fixtures.find(url); return it == fixtures.end() ? CurlResponse{} : it->second;
}
int main() {
    struct CurlGuard {
        CurlGuard() { assert(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK); }
        ~CurlGuard() { curl_global_cleanup(); }
    } guard;
    const auto html = response(200, "Content-Type: text/html\r\n", "<html></html>");
    assert(is_html_response(html));
    auto partial = html; partial.body_complete = false; assert(!is_html_response(partial));
    auto json = response(200, "Content-Type: application/json\r\n", "<html>"); assert(!is_html_response(json));
    reset();
    fixtures["http://example.test/a.js"] = response(200, "", "one.example.test");
    auto result = scrape_js_subdomains({{"http://example.test/", "<script src='/a.js'></script>"}}, "example.test");
    assert(result.names.count("one.example.test") == 1 && result.progress.cached_pages == 1);
    assert(calls["http://example.test/"] == 0 && calls["http://example.test/a.js"] == 1);
    reset();
    std::vector<SubdomainJsTarget> targets;
    for (int i = 0; i < 32; ++i) targets.push_back({"http://example.test/" + std::to_string(i), {}});
    targets.push_back({"http://example.test/good", {}});
    fixtures["http://example.test/good"] = response(200, "Content-Type: text/html\r\n", "<script src='/a.js'></script>");
    fixtures["http://example.test/a.js"] = response(200, "", "good.example.test");
    result = scrape_js_subdomains(targets, "example.test");
    assert(result.progress.pages_attempted == 33 && result.progress.pages_processed == 1 && result.names.count("good.example.test"));
    reset();
    fixtures["http://example.test/"] = response(302, "Location: http://foreign.test/x\r\n", "");
    result = scrape_js_subdomains({{"http://example.test/", {}}}, "example.test");
    assert(calls["http://foreign.test/x"] == 0 && result.progress.pages_processed == 0);
    reset();
    fixtures["http://example.test/"] = response(302, "Location: /next\r\n", "");
    fixtures["http://example.test/next"] = response(302, "Location: /\r\n", "");
    result = scrape_js_subdomains({{"http://example.test/", {}}}, "example.test");
    assert(calls["http://example.test/"] == 1 && calls["http://example.test/next"] == 1);
    reset();
    delay_ms = 20;
    SubdomainJsOptions parallel; parallel.workers = 2;
    result = scrape_js_subdomains({{"http://example.test/a", {}}, {"http://example.test/b", {}},
                                  {"http://example.test/c", {}}}, "example.test", parallel);
    assert(maximum == 2);
    reset();
    SubdomainJsOptions options; options.budget_ms = 10;
    delay_ms = 100; result = scrape_js_subdomains({{"http://example.test/", {}}}, "example.test", options);
    assert(result.progress.budget_exhausted && !g_cancel_token.cancelled);
    assert(!warnings.empty());
    reset();
    fixtures["http://example.test/start"] = response(302, "Location: /nested/index.html\r\n", "");
    fixtures["http://example.test/nested/index.html"] = response(200, "Content-Type: text/html\r\n", "<script src='app.js'></script>");
    fixtures["http://example.test/nested/app.js"] = response(200, "", "relative.example.test");
    result = scrape_js_subdomains({{"http://example.test/start", {}}}, "example.test");
    assert(result.names.count("relative.example.test") && calls["http://example.test/nested/app.js"] == 1);
    reset();
    result = scrape_js_subdomains({{"http://foreign.test/", "<script src='http://example.test/app.js'></script>"},
                                  {"http://user:pass@example.test/", "<script src='app.js'></script>"}}, "example.test");
    assert(calls.empty() && result.names.empty());
    reset();
    for (const auto& location : {"http://user:pass@example.test/a", "javascript:alert(1)", "https://foreign.test/a"}) {
        fixtures["http://example.test/"] = response(302, "Location: " + std::string(location) + "\r\n", "");
        result = scrape_js_subdomains({{"http://example.test/", {}}}, "example.test");
        assert(result.names.empty() && calls.size() == 1);
    }
    assert(!warnings.empty());
    reset();
    fixtures["http://example.test/"] = response(302, "Location: /one\r\nLocation: /two\r\n", "");
    result = scrape_js_subdomains({{"http://example.test/", {}}}, "example.test");
    assert(calls.size() == 1 && result.names.empty());
    reset();
    const std::string cached = "<script src='/one.js'></script><script src='/one.js'></script><script src='/two.js'></script>";
    fixtures["http://example.test/one.js"] = response(200, "", "one.example.test two.example.test three.example.test");
    fixtures["http://example.test/two.js"] = response(200, "", "should-not-fetch.example.test");
    options = {}; options.script_limit = 1; options.candidate_limit = 2;
    result = scrape_js_subdomains({{"http://example.test/", cached}, {"http://example.test/", cached}}, "example.test", options);
    assert(result.names.size() == 2 && result.progress.pages_attempted == 1 && result.progress.scripts_total == 1);
    assert(calls["http://example.test/one.js"] == 1 && calls["http://example.test/two.js"] == 0);
    reset();
    auto incomplete = response(200, "", "untrusted.example.test"); incomplete.success = incomplete.body_complete = false;
    fixtures["http://example.test/one.js"] = incomplete;
    result = scrape_js_subdomains({{"http://example.test/", "<script src='/one.js'></script>"}}, "example.test");
    assert(result.names.empty());
    reset();
    options = {}; options.script_limit = 0;
    result = scrape_js_subdomains({{"http://example.test/", {}}}, "example.test", options);
    assert(calls.empty());
    reset();
    // Internal callers cannot bypass the documented discovery ceilings.
    options = {}; options.page_limit = 1000; options.page_attempt_limit = 1000;
    options.script_limit = 1000; options.candidate_limit = 100000; options.redirect_limit = 1000;
    targets.clear();
    for (int i = 0; i < 65; ++i) targets.push_back({"http://example.test/page" + std::to_string(i), "<html></html>"});
    result = scrape_js_subdomains(targets, "example.test", options);
    assert(result.progress.pages_processed == 32 && result.progress.pages_attempted == 32);
    reset();
    for (auto& target : targets) target.html.reset();
    result = scrape_js_subdomains(targets, "example.test", options);
    assert(result.progress.pages_attempted == 64 && calls.size() == 64);
    reset();
    std::string first_scripts, second_scripts;
    for (int i = 0; i < 51; ++i) {
        auto& page = i < 50 ? first_scripts : second_scripts;
        page += "<script src='/asset" + std::to_string(i) + ".js'></script>";
    }
    result = scrape_js_subdomains({{"http://example.test/one", first_scripts},
                                  {"http://example.test/two", second_scripts}}, "example.test", options);
    assert(result.progress.scripts_total == 50 && result.progress.scripts_completed == 50 && calls.size() == 50);
    assert(calls.count("http://example.test/asset50.js") == 0);
    reset();
    std::string many_names;
    for (int i = 0; i < 5001; ++i) many_names += "name" + std::to_string(i) + ".example.test ";
    fixtures["http://example.test/many.js"] = response(200, "", many_names);
    result = scrape_js_subdomains({{"http://example.test/", "<script src='/many.js'></script>"}}, "example.test", options);
    assert(result.names.size() == 5000 && !warnings.empty());
    reset();
    for (int i = 0; i < 4; ++i)
        fixtures["http://example.test/hop" + std::to_string(i)] = response(302, "Location: /hop" + std::to_string(i + 1) + "\r\n", "");
    fixtures["http://example.test/hop4"] = html;
    result = scrape_js_subdomains({{"http://example.test/hop0", {}}}, "example.test", options);
    assert(calls.size() == 4 && calls.count("http://example.test/hop4") == 0 && result.progress.pages_processed == 0);
    reset();
    delay_ms = 1000;
    options = {}; options.workers = 2;
    std::thread cancel([] { std::this_thread::sleep_for(std::chrono::milliseconds(20)); g_cancel_token.cancelled = true; });
    const auto started = std::chrono::steady_clock::now();
    const auto caller = std::this_thread::get_id();
    result = scrape_js_subdomains({{"http://example.test/a", {}}, {"http://example.test/b", {}},
                                  {"http://example.test/c", {}}}, "example.test", options,
                                  [&](const auto&) { assert(std::this_thread::get_id() == caller); });
    cancel.join();
    assert(std::chrono::steady_clock::now() - started < std::chrono::seconds(2));
    assert(active == 0 && calls.size() <= 2 && result.names.empty());
    std::cout << "bounded JS discovery, cache, scope, redirects, deadlines and cancellation passed\n";
}
