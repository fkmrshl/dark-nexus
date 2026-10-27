#include "../src/subdomain_common.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <iostream>

thread_local std::mt19937 tl_rng{1};
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
    if (argc != 3) return 2;
    if (command == "pre-cancel") g_cancel_token.cancelled = true;
    std::thread cancel;
    if (command == "cancel") cancel = std::thread([] {
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); g_cancel_token.cancelled = true;
    });
    const auto start = std::chrono::steady_clock::now();
    const auto response = libcurl_get(argv[2], "", "fixture", command == "timeout" ? 1 : 5, {},
        command == "target" ? SubdomainHttpMode::TargetProbe : SubdomainHttpMode::Verified);
    if (cancel.joinable()) cancel.join();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    std::cout << nlohmann::json({{"http_code", response.http_code}, {"transport_code", response.transport_code},
        {"success", response.success}, {"cancelled", response.cancelled}, {"timed_out", response.timed_out},
        {"truncated", response.truncated}, {"body_size", response.body.size()}, {"header_size", response.headers.size()},
        {"error", response.error}, {"elapsed_ms", elapsed}}).dump() << '\n';
    curl_global_cleanup();
}
