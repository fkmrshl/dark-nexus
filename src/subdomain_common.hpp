#pragma once

#include "../include/dark_nexus.hpp"
#include <functional>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

struct CurlResponse {
    std::string headers;
    std::string body;
    long        http_code = 0;
};

struct WAFInfo  { std::string name, confidence; };
struct TechInfo { std::vector<std::string> stack; std::string cms, language, session_cookie; };

extern thread_local std::mt19937 tl_rng;

void http_jitter();
CurlResponse libcurl_get(const std::string& url,
                         const std::string& host_hdr,
                         const std::string& ua,
                         int timeout_s = 5,
                         const std::vector<std::string>& extra_headers = {});
CurlResponse fast_probe(const std::string& sub, int timeout_s);
long fast_check(const std::string& sub, int timeout_s);
WAFInfo detect_waf(const std::string& hdrs, const std::string& body, const std::string& cookies);
TechInfo detect_tech(const std::string& headers, const std::string& body, const std::string& cookies);
std::string parse_title(const std::string& body);

void extract_subs(const std::string& text, const std::string& domain, std::set<std::string>& out);
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
