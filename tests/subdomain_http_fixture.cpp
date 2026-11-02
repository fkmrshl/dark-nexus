#include "../src/subdomain_common.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <iostream>

thread_local std::mt19937 tl_rng{1};

// Test-only trust injection: exercise real TLS without changing production TLS policy.
extern "C" CURL* __real_curl_easy_init();
extern "C" CURL* __wrap_curl_easy_init() {
    CURL* handle = __real_curl_easy_init();
    const char* ca_bundle = std::getenv("DNX_FIXTURE_CA");
    if (handle && ca_bundle) curl_easy_setopt(handle, CURLOPT_CAINFO, ca_bundle);
    return handle;
}

static nlohmann::json observation(const SubdomainHttpObservation& o) {
    return {{"requested_url", o.requested_url}, {"effective_url", o.effective_url}, {"method", o.method},
        {"http_code", o.http_code}, {"transport_code", o.transport_code}, {"success", o.success},
        {"cancelled", o.cancelled}, {"timed_out", o.timed_out}, {"truncated", o.truncated},
        {"callback_failed", o.callback_failed}, {"headers_complete", o.headers_complete},
        {"body_complete", o.body_complete}, {"error", o.error},
        {"primary_ip", o.primary_ip}, {"dns_pinned", o.dns_pinned}};
}
int main(int argc, char** argv) {
    if (argc < 2) return 2;
    curl_global_init(CURL_GLOBAL_ALL);
    const std::string command = argv[1];
    if (command == "title") {
        const auto title = parse_title(std::string("<title>caf\xc3\xa9 ") + "\xff" + " title</title>");
        std::cout << nlohmann::json({{"title", title}}).dump() << '\n';
        curl_global_cleanup();
        return 0;
    }
    if (command == "warnings") {
        for (int i = 0; i < 100; ++i) subdomain_warning("fixture warning " + std::to_string(i));
        subdomain_warning("fixture warning 0");
        std::cout << nlohmann::json({{"count", g_result.warnings.size()}}).dump() << '\n';
        curl_global_cleanup();
        return 0;
    }
    if (argc < 3 || (argc > 3 && command != "pinned-probe")) return 2;
    std::vector<std::string> addresses;
    for (int i = 3; i < argc; ++i) addresses.emplace_back(argv[i]);
    if (command == "pre-cancel") g_cancel_token.cancelled = true;
    std::thread cancel;
    if (command == "cancel") cancel = std::thread([] {
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); g_cancel_token.cancelled = true;
    });
    const auto start = std::chrono::steady_clock::now();
    const auto response = command == "deadline" || command == "pre-deadline"
        ? libcurl_get_deadline(argv[2], start + std::chrono::milliseconds(command == "deadline" ? 100 : -1))
        : command == "probe" || command == "head-probe" || command == "pinned-probe"
        ? fast_probe(argv[2], 5, command == "head-probe", addresses)
        : libcurl_get(argv[2], "", "fixture", command == "timeout" ? 1 : 5, {},
            command == "target" ? SubdomainHttpMode::TargetProbe : SubdomainHttpMode::Verified);
    if (cancel.joinable()) cancel.join();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    auto output = observation(response);
    output["body_size"] = response.body.size();
    output["header_size"] = response.headers.size();
    output["headers"] = response.headers;
    output["elapsed_ms"] = elapsed;
    output["global_cancelled"] = g_cancel_token.cancelled.load();
    output["attempts"] = nlohmann::json::array();
    for (const auto& attempt : response.attempts) output["attempts"].push_back(observation(attempt));
    std::cout << output.dump() << '\n';
    curl_global_cleanup();
}
