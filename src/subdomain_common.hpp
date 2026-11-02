#pragma once

#include "../include/dark_nexus.hpp"
#include <functional>
#include <chrono>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

struct CurlResponse : SubdomainHttpObservation {
    std::string headers;
    std::string body;
    std::vector<SubdomainHttpObservation> attempts;
};

struct SubdomainJsTarget { std::string url; std::optional<std::string> html; };
struct SubdomainJsOptions {
    int workers = 4, budget_ms = 30000;
    std::size_t page_limit = 32, page_attempt_limit = 64, script_limit = 50,
                candidate_limit = 5000, redirect_limit = 3;
};
struct SubdomainJsProgress {
    std::size_t pages_attempted = 0, pages_processed = 0, cached_pages = 0,
                scripts_completed = 0, scripts_total = 0, candidates = 0;
    bool budget_exhausted = false;
};
struct SubdomainJsResult { std::set<std::string> names; SubdomainJsProgress progress; };
bool is_html_response(const CurlResponse& response);
SubdomainJsResult scrape_js_subdomains(const std::vector<SubdomainJsTarget>& targets,
    const std::string& domain, const SubdomainJsOptions& options = {},
    const std::function<void(const SubdomainJsProgress&)>& progress = {});
CurlResponse libcurl_get_deadline(const std::string& url, std::chrono::steady_clock::time_point deadline);

enum class SubdomainHttpMode { Verified, TargetProbe };
void subdomain_warning(const std::string& message);
std::string sanitize_subdomain_text(const std::string& value, std::size_t limit = 512);
std::optional<std::string> normalize_subdomain_name(const std::string& candidate, const std::string& domain);

struct WAFInfo  { std::string name, confidence; };
struct TechInfo { std::vector<std::string> stack; std::string cms, language, session_cookie; };

extern thread_local std::mt19937 tl_rng;

void http_jitter();
CurlResponse libcurl_get(const std::string& url,
                         const std::string& host_hdr,
                         const std::string& ua,
                         int timeout_s = 5,
                         const std::vector<std::string>& extra_headers = {},
                         SubdomainHttpMode mode = SubdomainHttpMode::Verified);
CurlResponse libcurl_post(const std::string& url, const std::string& ua, int timeout_s,
                         const std::vector<std::string>& headers, const std::string& body,
                         const std::string& credentials = "");
CurlResponse fast_probe(const std::string& sub, int timeout_s, bool head = false,
                        const std::vector<std::string>& addresses = {});
long fast_check(const std::string& sub, int timeout_s);
WAFInfo detect_waf(const std::string& hdrs, const std::string& body, const std::string& cookies);
TechInfo detect_tech(const std::string& headers, const std::string& body, const std::string& cookies);
std::string parse_title(const std::string& body);

void extract_subs(const std::string& text, const std::string& domain, std::set<std::string>& out);
std::set<std::string> extract_script_urls(const std::string& html, const std::string& base_url,
                                          const std::string& domain, std::size_t limit = 50);
std::vector<std::string> doh_query(const std::string& hostname,
                                   const std::string& type = "A",
                                   std::string* prov = nullptr);
std::string auto_find_wordlist();
std::optional<std::string> normalize_wordlist_candidate_to_fqdn(
    const std::string& line,
    const std::string& scan_domain);
const std::vector<std::string>& builtin_wordlist();
void for_each_permutation_candidate(const std::set<std::string>& found,
                                    const std::string& domain,
                                    const std::function<void(std::string&&)>& emit);
std::vector<std::string> generate_permutations(const std::set<std::string>& found,
                                               const std::string& domain);

void passive_crtsh(const std::string& domain, std::set<std::string>& out);
void passive_hackertarget(const std::string& domain, std::set<std::string>& out);
void passive_alienvault(const std::string& d, std::set<std::string>& out);
void passive_urlscan(const std::string& d, std::set<std::string>& out);
void passive_rapiddns(const std::string& d, std::set<std::string>& out);
void passive_threatcrowd(const std::string& d, std::set<std::string>& out);
void passive_dnsdumpster(const std::string& domain, std::set<std::string>& out);
void passive_virustotal(const std::string& d, std::set<std::string>& out);
void passive_securitytrails(const std::string& d, std::set<std::string>& out);
void passive_shodan(const std::string& d, std::set<std::string>& out);
void passive_censys(const std::string& d, std::set<std::string>& out);
void dns_extra_records(const std::string& domain, std::set<std::string>& out);
