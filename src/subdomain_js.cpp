#include "subdomain_common.hpp"
#include "dns_response.hpp"
#include "../include/thread_pool.hpp"
#include <curl/curl.h>
#include <algorithm>
#include <cctype>
#include <future>
#include <memory>
#include <sstream>

namespace {
using Clock = std::chrono::steady_clock;
using Url = std::unique_ptr<CURLU, decltype(&curl_url_cleanup)>;
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    return first == std::string::npos ? "" : value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}
std::optional<std::string> part(CURLU* url, CURLUPart field) {
    char* raw = nullptr;
    if (curl_url_get(url, field, &raw, 0) != CURLUE_OK) return std::nullopt;
    std::unique_ptr<char, decltype(&curl_free)> value(raw, curl_free);
    return std::string(value.get());
}
std::optional<std::string> safe_url(const std::string& value, const std::string& base, const std::string& domain) {
    if (value.empty() || value.size() > 8192 || value.find('\0') != std::string::npos || value.find('\\') != std::string::npos) return std::nullopt;
    Url url(curl_url(), curl_url_cleanup);
    if (!url || (!base.empty() && curl_url_set(url.get(), CURLUPART_URL, base.c_str(), 0) != CURLUE_OK) ||
        curl_url_set(url.get(), CURLUPART_URL, value.c_str(), 0) != CURLUE_OK) return std::nullopt;
    const auto scheme = part(url.get(), CURLUPART_SCHEME);
    const auto host = part(url.get(), CURLUPART_HOST);
    const auto root = dns_response::name_key(domain);
    if (!scheme || (lower(*scheme) != "http" && lower(*scheme) != "https") || !host ||
        part(url.get(), CURLUPART_USER) || part(url.get(), CURLUPART_PASSWORD) || part(url.get(), CURLUPART_OPTIONS) ||
        !dns_response::valid_name(root)) return std::nullopt;
    const auto normalized = dns_response::name_key(*host);
    if (!dns_response::valid_name(normalized) || (normalized != root && !normalize_subdomain_name(normalized, root))) return std::nullopt;
    if (curl_url_set(url.get(), CURLUPART_HOST, normalized.c_str(), 0) != CURLUE_OK ||
        curl_url_set(url.get(), CURLUPART_FRAGMENT, nullptr, 0) != CURLUE_OK) return std::nullopt;
    const auto result = part(url.get(), CURLUPART_URL);
    if (!result || result->size() > 8192) return std::nullopt;
    return result;
}
// Reject duplicate and folded fields; retain only the final response header block.
std::optional<std::string> header(const std::string& headers, const std::string& name) {
    std::istringstream input(headers);
    std::string line, value;
    bool found = false, malformed = false;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.rfind("HTTP/", 0) == 0) { found = false; malformed = false; value.clear(); continue; }
        if (line.empty()) continue;
        if (line.front() == ' ' || line.front() == '\t') { malformed = true; continue; }
        const auto colon = line.find(':');
        if (colon == std::string::npos) { malformed = true; continue; }
        if (lower(line.substr(0, colon)) == name) {
            if (found) malformed = true;
            found = true; value = trim(line.substr(colon + 1));
        }
    }
    if (!found || malformed || value.empty()) return std::nullopt;
    return value;
}
bool has_header(const std::string& headers, const std::string& name) {
    std::istringstream input(headers); std::string line;
    while (std::getline(input, line)) {
        const auto colon = line.find(':');
        if (colon != std::string::npos && lower(trim(line.substr(0, colon))) == name) return true;
    }
    return false;
}
struct Fetched { CurlResponse response; std::string url; bool rejected_redirect = false; };
Fetched fetch(std::string url, const std::string& domain, std::size_t redirects, Clock::time_point deadline) {
    std::set<std::string> seen;
    for (std::size_t hop = 0; !g_cancel_token.cancelled && Clock::now() < deadline; ++hop) {
        if (!seen.insert(url).second) return {{}, "", true};
        auto response = libcurl_get_deadline(url, deadline);
        const auto status = response.http_code;
        if (status != 301 && status != 302 && status != 303 && status != 307 && status != 308) return {std::move(response), url};
        if (hop >= redirects || !response.headers_complete) return {{}, "", true};
        const auto location = header(response.headers, "location");
        if (!location) return {{}, "", true};
        const auto next = safe_url(*location, url, domain);
        if (!next) return {{}, "", true};
        url = *next;
    }
    return {};
}
}

bool is_html_response(const CurlResponse& response) {
    if (!response.success || response.http_code < 200 || response.http_code >= 300 || !response.headers_complete || !response.body_complete) return false;
    if (has_header(response.headers, "content-type")) {
        const auto type = header(response.headers, "content-type");
        if (!type) return false;
        const auto media = lower(trim(type->substr(0, type->find(';'))));
        return media == "text/html" || media == "application/xhtml+xml";
    }
    auto text = lower(trim(response.body.substr(0, 512)));
    for (const auto* tag : {"<!doctype html", "<html", "<head", "<body", "<title", "<script", "<!--"})
        if (text.rfind(tag, 0) == 0) return true;
    return false;
}

SubdomainJsResult scrape_js_subdomains(const std::vector<SubdomainJsTarget>& targets, const std::string& domain,
    const SubdomainJsOptions& options, const std::function<void(const SubdomainJsProgress&)>& callback) {
    SubdomainJsResult result;
    auto& p = result.progress;
    const auto workers = static_cast<std::size_t>(std::clamp(options.workers, 1, 8));
    const auto page_limit = std::min<std::size_t>(options.page_limit, 32);
    const auto attempt_limit = std::min<std::size_t>(options.page_attempt_limit, 64);
    const auto script_limit = std::min<std::size_t>(options.script_limit, 50);
    const auto candidate_limit = std::min<std::size_t>(options.candidate_limit, 5000);
    const auto redirect_limit = std::min<std::size_t>(options.redirect_limit, 3);
    const auto deadline = Clock::now() + std::chrono::milliseconds(std::clamp(options.budget_ms, 1, 300000));
    auto notify = [&] { p.candidates = result.names.size(); if (callback) callback(p); };
    auto expired = [&] { if (Clock::now() >= deadline) p.budget_exhausted = true; return p.budget_exhausted || g_cancel_token.cancelled.load(); };
    notify();
    if (targets.empty() || !page_limit || !attempt_limit || !script_limit || !candidate_limit || g_cancel_token.cancelled)
        return result;
    std::set<std::string> pages, script_seen;
    std::vector<std::string> scripts;
    std::size_t index = 0;
    bool script_limited = false, candidate_limited = false;
    std::size_t rejected_redirects = 0;
    ThreadPool pool(workers);
    while (index < targets.size() && p.pages_processed < page_limit && p.pages_attempted < attempt_limit && !expired()) {
        struct Page { std::string url; bool cached; std::future<Fetched> future; std::optional<std::string> html; };
        std::vector<Page> batch;
        while (index < targets.size() && batch.size() < workers && p.pages_attempted < attempt_limit &&
               p.pages_processed + batch.size() < page_limit && !expired()) {
            const auto& target = targets[index++];
            const auto url = safe_url(target.url, "", domain);
            if (!url || !pages.insert(*url).second) continue;
            ++p.pages_attempted;
            const bool cached = target.html && target.html->size() <= 1024 * 1024;
            Page page{*url, cached, {}, cached ? target.html : std::nullopt};
            if (!cached) page.future = pool.submit([url = *url, domain, redirect_limit, deadline] { return fetch(url, domain, redirect_limit, deadline); });
            batch.push_back(std::move(page));
        }
        for (auto& page : batch) {
            Fetched got;
            if (!page.cached) got = page.future.get();
            if (got.rejected_redirect) ++rejected_redirects;
            if (expired()) continue;
            if (!page.cached && !is_html_response(got.response)) continue;
            ++p.pages_processed;
            if (page.cached) ++p.cached_pages;
            const auto& base = page.cached ? page.url : got.url;
            const auto& html = page.cached ? *page.html : got.response.body;
            for (const auto& raw : extract_script_urls(html, base, domain, 50)) {
                const auto url = safe_url(raw, base, domain);
                if (!url || script_seen.count(*url)) continue;
                if (scripts.size() >= script_limit) { script_limited = true; continue; }
                script_seen.insert(*url); scripts.push_back(*url);
            }
        }
        p.scripts_total = scripts.size(); notify();
    }
    std::size_t script_index = 0;
    while (script_index < scripts.size() && result.names.size() < candidate_limit && !expired()) {
        std::vector<std::future<Fetched>> batch;
        while (script_index < scripts.size() && batch.size() < workers && !expired()) {
            const auto url = scripts[script_index++];
            batch.push_back(pool.submit([url, domain, redirect_limit, deadline] { return fetch(url, domain, redirect_limit, deadline); }));
        }
        for (auto& future : batch) {
            auto got = future.get(); ++p.scripts_completed;
            if (got.rejected_redirect) ++rejected_redirects;
            if (expired() || !got.response.success || !got.response.body_complete || got.response.http_code < 200 || got.response.http_code >= 300) continue;
            std::set<std::string> extracted;
            extract_subs(got.response.body, domain, extracted);
            for (const auto& name : extracted) {
                if (expired()) break;
                if (result.names.count(name)) continue;
                if (result.names.size() >= candidate_limit) { candidate_limited = true; break; }
                result.names.insert(name);
            }
        }
        notify();
    }
    if (index < targets.size() && !g_cancel_token.cancelled && (p.pages_processed >= page_limit || p.pages_attempted >= attempt_limit))
        subdomain_warning("JS discovery page or attempt limit reached; remaining pages skipped");
    if (script_limited) subdomain_warning("JS discovery script limit reached; remaining scripts skipped");
    if (candidate_limited || (script_index < scripts.size() && result.names.size() >= candidate_limit)) subdomain_warning("JS discovery candidate limit reached; remaining candidates skipped");
    if (p.budget_exhausted) subdomain_warning("JS discovery time budget exhausted; remaining work skipped");
    if (rejected_redirects) subdomain_warning("JS discovery skipped " + std::to_string(rejected_redirects) +
        " redirects with invalid scope, headers, loops or hop limits");
    notify();
    return result;
}
