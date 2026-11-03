#include "subdomain_common.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <charconv>
#include <iostream>
#include <string_view>

thread_local std::mt19937 tl_rng{std::random_device{}()};

namespace {
bool parse_number(const char* text, int min, int max, int& value) {
    const std::string_view input(text);
    const auto parsed = std::from_chars(input.data(), input.data() + input.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == input.data() + input.size() && value >= min && value <= max;
}
struct CurlGlobal {
    bool initialized = curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK;
    ~CurlGlobal() { if (initialized) curl_global_cleanup(); }
};
}

int main(int argc, char** argv) {
    int port = 0, workers = 0;
    if (argc != 4 || !parse_number(argv[1], 1, 65535, port) ||
        (std::string_view(argv[2]) != "cached" && std::string_view(argv[2]) != "uncached") ||
        !parse_number(argv[3], 1, 8, workers)) {
        std::cerr << "usage: subdomain_js_benchmark PORT cached|uncached WORKERS\n";
        return 2;
    }
    CurlGlobal curl;
    if (!curl.initialized) return 3;
    const bool cached = std::string_view(argv[2]) == "cached";
    std::string html = "<html><body>";
    for (int i = 0; i < 50; ++i) html += "<script src='/script/" + std::to_string(i) + ".js'></script>";
    html += "</body></html>";
    std::vector<SubdomainJsTarget> targets;
    for (int i = 0; i < 32; ++i) {
        targets.push_back({"http://localhost:" + std::to_string(port) + "/page/" + std::to_string(i),
                           cached ? std::optional<std::string>(html) : std::nullopt});
    }
    SubdomainJsOptions options;
    options.workers = workers;
    options.budget_ms = 30000;
    const auto result = scrape_js_subdomains(targets, "localhost", options);
    const auto& p = result.progress;
    const nlohmann::json output = {
        {"candidates", result.names},
        {"progress", {{"pages_attempted", p.pages_attempted}, {"pages_processed", p.pages_processed},
                      {"cached_pages", p.cached_pages}, {"scripts_total", p.scripts_total},
                      {"scripts_completed", p.scripts_completed}, {"candidates", p.candidates},
                      {"budget_exhausted", p.budget_exhausted}}},
        {"warnings", g_result.warnings}, {"errors", g_result.errors}};
    std::cout << output.dump() << '\n';
}
