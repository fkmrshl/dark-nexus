#include "../include/dark_nexus.hpp"
#include "../include/dns_engine.hpp"
#include "subdomain_common.hpp"
#include "atomic_file.hpp"
#include "dns_query.hpp"
#include <curl/curl.h>
#include <fstream>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <cctype>
#include <cstdint>
#include <optional>
#include <exception>
#include <filesystem>
#include <nlohmann/json.hpp>
#include "../include/security.hpp"
#include "../include/user_agents.hpp"

template<typename T>
class PipelineQueue {
    std::deque<T>           q_;
    mutable std::mutex      mtx_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::condition_variable idle_;
    bool                    closed_   = false;
    size_t                  active_   = 0;
    const size_t            max_size_;
public:
    explicit PipelineQueue(size_t n = 200000) : max_size_(n) {}

    bool push(T item) {
        std::unique_lock<std::mutex> lk(mtx_);
        while (q_.size() >= max_size_ && !closed_ && !g_cancel_token.cancelled)
            not_full_.wait_for(lk, std::chrono::milliseconds(50));
        if (closed_ || g_cancel_token.cancelled) return false;
        q_.push_back(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    bool pop(T& item) {
        std::unique_lock<std::mutex> lk(mtx_);
        while (q_.empty() && !closed_ && !g_cancel_token.cancelled)
            not_empty_.wait_for(lk, std::chrono::milliseconds(50));
        if (q_.empty() || g_cancel_token.cancelled) return false;
        item = std::move(q_.front());
        q_.pop_front();
        active_++;
        not_full_.notify_one();
        return true;
    }

    void task_done() {
        std::unique_lock<std::mutex> lk(mtx_);
        if (active_ == 0) return;
        active_--;
        if (q_.empty() && active_ == 0) idle_.notify_all();
    }

    void wait_idle() {
        std::unique_lock<std::mutex> lk(mtx_);
        while (!q_.empty() || active_ != 0) {
            if (g_cancel_token.cancelled) { q_.clear(); not_full_.notify_all(); }
            if (q_.empty() && active_ == 0) break;
            idle_.wait_for(lk, std::chrono::milliseconds(50));
        }
    }

    void close() {
        { std::lock_guard<std::mutex> lk(mtx_); closed_ = true; }
        not_empty_.notify_all();
        not_full_.notify_all();
        idle_.notify_all();
    }

    void abort() {
        { std::lock_guard<std::mutex> lk(mtx_); closed_ = true; q_.clear(); }
        not_empty_.notify_all();
        not_full_.notify_all();
        idle_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return q_.size();
    }
};

class CurlGlobalGuard {
    bool initialized_;
public:
    CurlGlobalGuard() : initialized_(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK) {
        if (!initialized_) throw std::runtime_error("cannot initialize HTTP library");
    }
    ~CurlGlobalGuard() { if (initialized_) curl_global_cleanup(); }
    CurlGlobalGuard(const CurlGlobalGuard&) = delete;
    CurlGlobalGuard& operator=(const CurlGlobalGuard&) = delete;
};

struct DnsPending {
    std::size_t              result_index = 0;
};

template<class T>
class PipelineJoinGuard {
    PipelineQueue<T>& queue_;
    std::vector<std::thread>& threads_;
    int exceptions_ = std::uncaught_exceptions();
public:
    PipelineJoinGuard(PipelineQueue<T>& queue, std::vector<std::thread>& threads)
        : queue_(queue), threads_(threads) {}
    ~PipelineJoinGuard() {
        if (std::uncaught_exceptions() > exceptions_) g_cancel_token.cancelled = true;
        queue_.abort();
        for (auto& thread : threads_) if (thread.joinable()) thread.join();
    }
};

static void subdomain_error(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_result_mtx);
    if (g_result.errors.size() < 64) g_result.errors.push_back(InputGuard::sanitize_output(message, 2048));
}

static std::string server_from_headers(const std::string& headers) {
    std::string server;
    std::size_t start = 0;
    while (start < headers.size()) {
        const auto newline = headers.find('\n', start);
        const auto end = newline == std::string::npos ? headers.size() : newline;
        if (headers.compare(start, 5, "HTTP/") == 0) server.clear();
        static constexpr char name[] = "server:";
        bool matches = end - start >= sizeof(name) - 1;
        for (std::size_t i = 0; matches && i < sizeof(name) - 1; ++i)
            matches = std::tolower(static_cast<unsigned char>(headers[start + i])) == name[i];
        if (matches) {
            auto first = start + sizeof(name) - 1;
            auto last = end;
            while (first < last && std::isspace(static_cast<unsigned char>(headers[first]))) ++first;
            while (last > first && std::isspace(static_cast<unsigned char>(headers[last - 1]))) --last;
            server = sanitize_subdomain_text(headers.substr(first, std::min(last - first, std::size_t{256})), 80);
        }
        if (newline == std::string::npos) break;
        start = newline + 1;
    }
    return server;
}

thread_local std::mt19937 tl_rng{std::random_device{}()};

struct SubResult {
    std::string sub, cname, http_code, server, title, source, doh_fallback;
    std::vector<std::string> ips, ipv6;
    WAFInfo  waf;
    TechInfo tech;
    bool wildcard_match = false;
    std::string dns_status = "resolved";
    bool takeover_possible = false;
    std::size_t report_index = 0;
};

struct TakeoverSig { std::string cname_pattern, service; std::vector<std::string> fingerprints; };

static const std::vector<TakeoverSig>& takeover_db() {
    static const std::vector<TakeoverSig> db = {
        {"github.io",         "GitHub Pages",  {"There isn't a GitHub Pages site here"}},
        {"herokuapp.com",     "Heroku",         {"No such app"}},
        {"azurewebsites.net", "Azure App Svc",  {"404 Web Site not found"}},
        {"cloudfront.net",    "CloudFront",     {"ERROR: The request could not be satisfied"}},
        {"s3.amazonaws.com",  "AWS S3",         {"NoSuchBucket"}},
        {"s3-website",        "AWS S3 Website", {"NoSuchBucket"}},
        {"myshopify.com",     "Shopify",        {"Sorry, this shop is currently unavailable"}},
        {"ghost.io",          "Ghost",          {"The thing you were looking for is no longer here"}},
        {"wordpress.com",     "WordPress",      {"Do you want to register"}},
        {"pantheon.io",       "Pantheon",       {"404 error unknown site"}},
        {"zendesk.com",       "Zendesk",        {"Help Center Closed"}},
        {"readme.io",         "ReadMe",         {"Project doesnt exist"}},
        {"readme.com",        "ReadMe",         {"Project doesnt exist"}},
        {"surge.sh",          "Surge",          {"project not found"}},
        {"bitbucket.io",      "Bitbucket",      {"Repository not found"}},
        {"netlify.app",       "Netlify",        {"Not Found - Request ID"}},
        {"vercel.app",        "Vercel",         {"DEPLOYMENT_NOT_FOUND"}},
        {"fly.dev",           "Fly.io",         {"404 Not Found"}},
        {"render.com",        "Render",         {"There's nothing here, yet"}},
        {"pages.dev",         "CF Pages",       {"There's nothing here, yet"}},
        {"webflow.io",        "Webflow",        {"The page you are looking for doesn't exist"}},
        {"hubspot.com",       "HubSpot",        {"does not exist"}},
        {"uservoice.com",     "UserVoice",      {"This UserVoice subdomain is currently available"}},
        {"statuspage.io",     "Statuspage",     {"page not found"}},
        {"freshdesk.com",     "Freshdesk",      {"There is no helpdesk here"}},
        {"fastly.net",        "Fastly",         {"Fastly error: unknown domain"}},
        {"squarespace.com",   "Squarespace",    {"You need to assign a Custom Domain"}},
        {"wixsite.com",       "Wix",            {"doesn't exist"}},
        {"acquia-sites.com",  "Acquia",         {"Web Site Not Configured"}},
    };
    return db;
}

static std::string takeover_validate(const std::string& sub,
                                     const std::vector<std::string>& fingerprints) {
    auto lower = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return std::tolower(c); });
        return value;
    };
    for (const auto& url : {"https://" + sub, "http://" + sub}) {
        if (g_cancel_token.cancelled) return "CANCELLED";
        const auto response = libcurl_get(url, sub, random_ua(), 5);
        if (response.http_code <= 0) continue;
        const auto body = lower(response.body), headers = lower(response.headers);
        for (const auto& fingerprint : fingerprints) {
            const auto text = lower(fingerprint);
            if (body.find(text) != std::string::npos || headers.find(text) != std::string::npos)
                return "FINGERPRINT_MATCH";
        }
        return response.http_code == 404 ? "POSSIBLE" : "LIVE";
    }
    return "UNREACHABLE";
}

static nlohmann::json result_row(const SubResult& r) {
    return {{"subdomain", r.sub}, {"source", r.source}, {"ipv4", r.ips}, {"ipv6", r.ipv6},
        {"cname", r.cname}, {"http_code", r.http_code}, {"server", r.server}, {"title", r.title},
        {"waf", r.waf.name}, {"language", r.tech.language}, {"cms", r.tech.cms},
        {"stack", r.tech.stack}, {"doh_fallback", r.doh_fallback},
        {"wildcard_match", r.wildcard_match}, {"dns_status", r.dns_status},
        {"takeover_possible", r.takeover_possible}};
}

static std::string json_text(const nlohmann::json& value) {
    return value.dump(2, ' ', false, nlohmann::json::error_handler_t::replace) + '\n';
}

static void export_results(const std::vector<SubResult>& results, const std::string& domain) {
    nlohmann::json output = nlohmann::json::array();
    for (const auto& result : results) output.push_back(result_row(result));
    std::ostringstream csv;
    csv << "subdomain,ipv4,cname,http_code,server,title,waf,language,cms,source,ipv6,wildcard_match,takeover_possible,dns_status\r\n";
    auto join = [](const std::vector<std::string>& values) {
        std::string text;
        for (const auto& value : values) { if (!text.empty()) text += ' '; text += value; }
        return text;
    };
    auto quote = [](const std::string& text) {
        std::string escaped = "\"";
        for (char c : text) { if (c == '"') escaped += '"'; escaped += c; }
        return escaped + '"';
    };
    for (const auto& r : results)
        csv << quote(r.sub) << ',' << quote(join(r.ips)) << ',' << quote(r.cname) << ','
            << quote(r.http_code) << ',' << quote(r.server) << ',' << quote(r.title) << ','
            << quote(r.waf.name) << ',' << quote(r.tech.language) << ',' << quote(r.tech.cms) << ','
            << quote(r.source) << ',' << quote(join(r.ipv6)) << ',' << (r.wildcard_match ? "true" : "false")
            << ',' << (r.takeover_possible ? "true" : "false") << ',' << quote(r.dns_status) << "\r\n";
    for (const auto& report : std::vector<std::pair<std::string, std::string>>{
            {domain + "_subdomains.json", json_text(output)}, {domain + "_subdomains.csv", csv.str()}}) {
        std::string error;
        if (!write_atomic_file(report.first, report.second, error)) subdomain_error(error);
        else std::cout << "  saved " << report.first << '\n';
    }
}

static std::string checkpoint_timestamp_utc() {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    if (gmtime_s(&tm, &now) != 0) return std::to_string(static_cast<long long>(now));
#else
    if (gmtime_r(&now, &tm) == nullptr) return std::to_string(static_cast<long long>(now));
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

static bool write_checkpoint_json(const std::vector<SubResult>& results,
                                  const std::string& domain,
                                  const std::string& filename,
                                  std::string& error)
{
    try {
        nlohmann::json result_rows = nlohmann::json::array();
        for (const auto& result : results) {
            auto row = result_row(result);
            row["ips"] = result.ips;
            result_rows.push_back(std::move(row));
        }

        nlohmann::json output = {
            {"type", "subdomain_checkpoint"},
            {"partial", true},
            {"domain", domain},
            {"saved_at", checkpoint_timestamp_utc()},
            {"count", results.size()},
            {"resolved_count", std::count_if(results.begin(), results.end(),
                [](const auto& row) { return row.dns_status == "resolved"; })},
            {"candidate_count", std::count_if(results.begin(), results.end(),
                [](const auto& row) { return row.dns_status != "resolved"; })},
            {"results", std::move(result_rows)}
        };

        return write_atomic_file(filename, json_text(output), error);
    } catch (const std::exception& ex) {
        error = ex.what();
        return false;
    }
}

static void scrape_js_subdomains(const std::vector<std::string>& targets,
                                 const std::string& domain, std::set<std::string>& out) {
    std::set<std::string> urls;
    std::size_t pages = 0;
    for (const auto& sub : targets) {
        if (g_cancel_token.cancelled) return;
        if (pages++ >= 32) { subdomain_warning("JS discovery page limit of 32 reached"); break; }
        const auto response = libcurl_get("https://" + sub, sub, random_ua(), 5);
        if (response.http_code < 200 || response.http_code >= 300) continue;
        for (const auto& url : extract_script_urls(response.body, "https://" + sub + "/", domain)) {
            urls.insert(url);
            if (urls.size() >= 50) break;
        }
        if (urls.size() >= 50) { subdomain_warning("JS discovery script limit of 50 reached"); break; }
    }
    for (const auto& url : urls) {
        if (g_cancel_token.cancelled) return;
        const auto response = libcurl_get(url, "", random_ua(), 5);
        if (response.http_code >= 200 && response.http_code < 300) extract_subs(response.body, domain, out);
    }
}

static std::string auto_find_resolvers() {
    const char* h_env = getenv("HOME");
    std::string h = h_env ? h_env : "/root";
    for (auto& p : std::vector<std::string>{
        "./resolvers.txt","./resolvers_trusted.txt",
        h+"/resolvers.txt",
        "/usr/share/wordlists/resolvers.txt",
        "/opt/resolvers.txt",
    }) { if (access(p.c_str(), F_OK)==0) return p; }
    return "";
}

void subdomain_scan(const std::string& domain,
                    const std::string& wordlist_path,
                    int max_threads,
                    bool run_permutations,
                    bool deep_passive,
                    bool do_enrich,
                    bool use_deep_passive_sources,
                    bool passive_only,
                    std::optional<SubdomainFeatures> requested_features)
{
    std::string scan_domain = domain;
    std::transform(scan_domain.begin(), scan_domain.end(), scan_domain.begin(),
                   [](unsigned char ch){ return static_cast<char>(std::tolower(ch)); });
    if (!scan_domain.empty() && scan_domain.back() == '.') scan_domain.pop_back();
    if (!dns_query::valid_name(scan_domain)) throw std::runtime_error("invalid scan domain");
    if (g_cancel_token.cancelled) return;
    auto features = requested_features.value_or(SubdomainFeatures{
        do_enrich, do_enrich && deep_passive, do_enrich && deep_passive,
        do_enrich && deep_passive, do_enrich && deep_passive});
    if (!do_enrich) features = {false, false, false, false, false, features.full_addresses};
    features.tech = features.tech && features.http;
    features.js = features.js && features.http && !passive_only;
    features.service_hints = features.service_hints && features.http && features.cname;
    const bool enrich_active = features.http || features.cname;

    print_header("SUBDOMAIN SCAN // " + scan_domain);
    const auto value_color = terminal::style(terminal::Style::Value);
    auto print_addresses = [&](const char* label, const std::vector<std::string>& addresses) {
        if (addresses.empty()) return;
        std::cout << "    " << value_color << label << ":  " << addresses.front() << RESET;
        if (!features.full_addresses && addresses.size() > 1)
            std::cout << DIM << " (+" << addresses.size() - 1 << ")" << RESET;
        std::cout << '\n';
        if (features.full_addresses)
            for (std::size_t i = 1; i < addresses.size(); ++i)
                std::cout << "           " << value_color << addresses[i] << RESET << '\n';
    };
    CurlGlobalGuard curl_guard;

    auto& dns = DnsEngine::get();
    dns.clear_cache();

    print_section("RESOLVER SETUP");
    std::string resolver_path = auto_find_resolvers();
    if (!resolver_path.empty()) {
        dns.load_resolvers(resolver_path);
    } else {
        std::cout << "  using built-in DNS resolvers; optional resolvers.txt is read from the working directory\n";
    }

    const int HTTP_WORKERS = enrich_active ? std::clamp(max_threads, 1, 512) : 1;
    const int HTTP_TIMEOUT = deep_passive ? 5 : 3;
    const int DNS_BATCH_SIZE = 10000;
    const int DNS_CONCURRENCY = deep_passive ? 2000 : 1000;

    std::cout << BLOOD_RED << "  [*] mode: " << WHITE << (deep_passive ? "DEEP" : "FAST")
              << BLOOD_RED << " | enrichment workers: " << WHITE << HTTP_WORKERS
              << BLOOD_RED << " | DNS batch: " << WHITE << DNS_BATCH_SIZE
              << BLOOD_RED << " | DNS concurrency: " << WHITE << DNS_CONCURRENCY
              << BLOOD_RED << " | DNS channels: " << WHITE << dns.channel_count()
              << BLOOD_RED << " | resolver pool: " << WHITE << dns.resolver_count() << "\n" << RESET;

    print_section("WORDLIST");
    std::ifstream wordlist_stream;
    bool stream_file_wordlist = false;
    if (!passive_only && !wordlist_path.empty()) {
            std::error_code error;
            if (!std::filesystem::is_regular_file(wordlist_path, error))
                throw std::runtime_error("wordlist must be a readable regular file: " + wordlist_path);
            wordlist_stream.open(wordlist_path);
            if (wordlist_stream.is_open()) {
                stream_file_wordlist = true;
                std::cout << BLOOD_RED << "  [*] streaming: " << WHITE
                          << wordlist_path << "\n" << RESET;
            } else {
                throw std::runtime_error("cannot read wordlist: " + wordlist_path);
            }
    }
    if (passive_only) {
        std::cout << "  disabled by --passive-only\n";
    } else if (!stream_file_wordlist) {
        std::cout << BLOOD_RED << "  [*] builtin (" << WHITE << builtin_wordlist().size()
                  << BLOOD_RED << " words)\n" << RESET;
    }

    print_section("WILDCARD CHECK");
    struct NormalizedIpSet {
        std::vector<std::string> ips;
    };

    auto normalize_ip_set = [](std::vector<std::string> ips) {
        std::sort(ips.begin(), ips.end());
        ips.erase(std::unique(ips.begin(), ips.end()), ips.end());
        return NormalizedIpSet{std::move(ips)};
    };

    auto random_dns_token = []() {
        static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        std::string token;
        token.reserve(12);
        for (int i=0; i<12; i++) token += alphabet[tl_rng() % (sizeof(alphabet)-1)];
        return token;
    };

    enum class WildcardState { Clear, Wildcard, Unknown };
    std::unordered_map<std::string, WildcardState> wildcard_scopes;
    constexpr std::size_t max_wildcard_scopes = 64;
    auto scope_for = [](const std::string& host) { return host.substr(host.find('.') + 1); };
    bool scope_limit_warned = false;
    auto prepare_scopes = [&](const std::vector<std::string>& parents) {
        std::map<std::string, std::vector<std::string>> pending;
        std::vector<std::string> probes;
        for (const auto& parent : parents) {
            if (g_cancel_token.cancelled) break;
            if (wildcard_scopes.count(parent)) continue;
            if (wildcard_scopes.size() >= max_wildcard_scopes) {
                if (!scope_limit_warned) {
                    scope_limit_warned = true;
                    subdomain_warning("Wildcard scope limit of 64 reached; unchecked branches remain uncertain and generated candidates are skipped");
                }
                continue;
            }
            wildcard_scopes.emplace(parent, WildcardState::Unknown);
            std::vector<std::string> names;
            const int count = parent == scan_domain ? 6 : 3;
            for (int i = 0; i < count; ++i) {
                auto name = "dnxwc-" + random_dns_token() + "." + parent;
                if (!dns_query::valid_name(name)) break;
                names.push_back(std::move(name));
            }
            if (names.size() != static_cast<std::size_t>(count)) {
                subdomain_warning("Wildcard scope cannot be probed within the DNS name length limit; branch remains uncertain");
                continue;
            }
            probes.insert(probes.end(), names.begin(), names.end());
            pending.emplace(parent, std::move(names));
        }
        if (probes.empty() || g_cancel_token.cancelled) return;
        const auto answers = dns.resolve_batch_checked(probes, 64, 5000);
        for (const auto& [parent, names] : pending) {
            std::size_t positive = 0;
            bool incomplete = false;
            for (const auto& probe : names) {
                const auto answer = answers.find(probe);
                if (answer == answers.end()) { incomplete = true; continue; }
                incomplete = incomplete || answer->second.failed;
                if (!answer->second.ipv4.empty() || !answer->second.ipv6.empty()) ++positive;
            }
            const auto state = positive >= 2 ? WildcardState::Wildcard :
                positive == 0 && !incomplete ? WildcardState::Clear : WildcardState::Unknown;
            wildcard_scopes.at(parent) = state;
            if (state == WildcardState::Wildcard) {
                subdomain_warning("Wildcard DNS detected under " + parent +
                    "; generated names are skipped regardless of address rotation, independent names remain uncertain");
            } else if (state == WildcardState::Unknown) {
                subdomain_warning("Wildcard DNS check incomplete or inconsistent under " + parent +
                    "; generated names are skipped and independent names remain uncertain");
            }
        }
    };
    prepare_scopes({scan_domain});
    const auto root_wildcard = wildcard_scopes.count(scan_domain) ?
        wildcard_scopes.at(scan_domain) : WildcardState::Unknown;
    std::cout << "  " << (root_wildcard == WildcardState::Wildcard ? "wildcard DNS detected; generated names in this branch will be skipped" :
        root_wildcard == WildcardState::Unknown ? "wildcard check inconclusive; generated names in this branch will be skipped" :
        "no wildcard observed in completed root probes") << '\n';

    print_section("PASSIVE ENUM");
    if (g_cancel_token.cancelled) return;
    std::set<std::string> passive_subs;

    std::cout << BLOOD_RED << "  [*] " << WHITE << "crt.sh" << BLOOD_RED << "...\n" << RESET;
    passive_crtsh(scan_domain, passive_subs);
    std::cout << BLOOD_RED << "  [+] crt.sh +" << WHITE << passive_subs.size() << "\n" << RESET;

    if (use_deep_passive_sources) {

        struct PassiveTask { std::string name; std::function<void(std::set<std::string>&)> fn; };
        std::vector<PassiveTask> tasks = {
            {"HackerTarget",   [&](std::set<std::string>& o){ passive_hackertarget(scan_domain,o); }},
            {"AlienVault OTX", [&](std::set<std::string>& o){ passive_alienvault(scan_domain,o); }},
            {"urlscan.io",     [&](std::set<std::string>& o){ passive_urlscan(scan_domain,o); }},
            {"RapidDNS",       [&](std::set<std::string>& o){ passive_rapiddns(scan_domain,o); }},
            {"ThreatCrowd",    [&](std::set<std::string>& o){ passive_threatcrowd(scan_domain,o); }},
            {"DNSDumpster",    [&](std::set<std::string>& o){ passive_dnsdumpster(scan_domain,o); }},
            {"MX/TXT/NS/SRV", [&](std::set<std::string>& o){ dns_extra_records(scan_domain,o); }},
        };
        if (getenv("VT_API_KEY"))     tasks.push_back({"VirusTotal",     [&](std::set<std::string>& o){ passive_virustotal(scan_domain,o); }});
        if (getenv("ST_API_KEY"))     tasks.push_back({"SecurityTrails", [&](std::set<std::string>& o){ passive_securitytrails(scan_domain,o); }});
        if (getenv("SHODAN_API_KEY")) tasks.push_back({"Shodan",         [&](std::set<std::string>& o){ passive_shodan(scan_domain,o); }});
        if (getenv("CENSYS_API_ID"))  tasks.push_back({"Censys",         [&](std::set<std::string>& o){ passive_censys(scan_domain,o); }});

        std::vector<std::pair<std::string, std::set<std::string>>> results_per_source(tasks.size());
        ThreadPool passive_pool(std::min<std::size_t>(tasks.size(), 12));
        std::vector<std::future<void>> passive_futures;
        for (size_t i=0; i<tasks.size(); i++) {
            passive_futures.push_back(passive_pool.submit([&,i](){
                if (g_cancel_token.cancelled) return;
                try { tasks[i].fn(results_per_source[i].second); }
                catch (const std::exception& error) {
                    subdomain_warning(tasks[i].name + ": " + error.what());
                }
                results_per_source[i].first = tasks[i].name;
                std::lock_guard<std::mutex> lk(g_print_mtx);
                std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(18)
                          << tasks[i].name << BLOOD_RED << "+" << WHITE
                          << results_per_source[i].second.size() << "\n" << RESET;
            }));
        }
        for (auto& future : passive_futures) future.get();

        for (auto& [name, subs] : results_per_source)
            for (auto& s : subs) passive_subs.insert(s);
    }
    {
        std::set<std::string> normalized;
        for (const auto& candidate : passive_subs)
            if (auto name = normalize_subdomain_name(candidate, scan_domain)) normalized.insert(*name);
        passive_subs = std::move(normalized);
    }
    std::cout << BLOOD_RED << "  [=] total passive: " << WHITE << passive_subs.size() << "\n" << RESET;

    std::mutex state_mtx;
    std::vector<SubResult>  results;
    std::unordered_map<std::string, std::size_t> result_indices;
    std::atomic<int> found_count{0}, dns_checked{0}, doh_used{0};
    std::unordered_set<std::string> passive_set_uset(passive_subs.begin(), passive_subs.end());
    std::unordered_set<std::string> derived_dedup(passive_set_uset.begin(), passive_set_uset.end());
    auto current_found_size = [&]() {
        return static_cast<std::size_t>(found_count.load());
    };
    auto format_elapsed_seconds = [](std::chrono::steady_clock::duration elapsed) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(1) << std::chrono::duration<double>(elapsed).count();
        return ss.str();
    };
    auto format_rate = [](double rate) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(1) << rate;
        return ss.str();
    };
    std::mutex checkpoint_mtx;
    const auto checkpoint_interval = std::chrono::seconds(60);
    std::chrono::steady_clock::time_point last_checkpoint_attempt;
    size_t last_checkpoint_count = 0;
    const std::string checkpoint_file = scan_domain + "_subdomains_checkpoint.json";
    auto maybe_write_checkpoint = [&](bool force, const std::string& reason) {
        std::vector<SubResult> snapshot;
        bool checkpoint_ok = false;
        bool should_log = false;
        std::string checkpoint_error;
        size_t snapshot_count = 0;

        {
            std::lock_guard<std::mutex> ck(checkpoint_mtx);
            auto now = std::chrono::steady_clock::now();
            if (!force && last_checkpoint_attempt.time_since_epoch().count() != 0 &&
                now - last_checkpoint_attempt < checkpoint_interval) {
                return;
            }
            last_checkpoint_attempt = now;

            {
                std::lock_guard<std::mutex> lk(state_mtx);
                if (!force && results.empty()) return;
                snapshot_count = results.size();
                if (!force && snapshot_count == last_checkpoint_count) return;
                snapshot = results;
            }

            checkpoint_ok = write_checkpoint_json(snapshot, scan_domain,
                                                  checkpoint_file, checkpoint_error);
            if (checkpoint_ok) last_checkpoint_count = snapshot_count;
            should_log = true;
        }

        if (!should_log) return;
        std::lock_guard<std::mutex> lk(g_print_mtx);
        if (checkpoint_ok) {
            std::cout << BLOOD_RED << "  [checkpoint] saved " << WHITE << snapshot_count
                      << BLOOD_RED << " results -> " << WHITE << checkpoint_file
                      << BLOOD_RED << " (" << WHITE << reason << BLOOD_RED << ")\n" << RESET;
        } else {
            subdomain_warning("checkpoint failed: " + checkpoint_error);
            std::cout << BLOOD_RED << "  [!] checkpoint failed: " << WHITE
                      << checkpoint_error << BLOOD_RED << " (" << WHITE
                      << reason << BLOOD_RED << ")\n" << RESET;
        }
    };

    auto entry_from_result = [](const SubResult& result) {
        SubEntry entry;
        entry.sub = result.sub; entry.ips = result.ips; entry.ipv6 = result.ipv6;
        entry.cname = result.cname; entry.http_code = result.http_code;
        entry.server = result.server; entry.title = result.title; entry.source = result.source;
        entry.waf = result.waf.name; entry.language = result.tech.language; entry.cms = result.tech.cms;
        entry.wildcard_match = result.wildcard_match; entry.takeover_possible = result.takeover_possible;
        entry.dns_status = result.dns_status;
        return entry;
    };
    std::atomic<std::size_t> wildcard_filtered{0};
    std::size_t unchecked_filtered = 0;
    auto report_rows = [&](const SubResult& result) -> std::vector<SubEntry>& {
        return result.dns_status == "resolved" ? g_result.subdomains : g_result.subdomain_candidates;
    };
    auto retain_dns = [&](const std::string& host, const DnsLookupResult& answer,
                          const std::string& provider, const std::string& source_hint) -> std::optional<std::size_t> {
        const auto normalized = normalize_subdomain_name(host, scan_domain);
        if (!normalized || *normalized != host || (answer.ipv4.empty() && answer.ipv6.empty())) return std::nullopt;
        std::lock_guard<std::mutex> lock(state_mtx);
        const auto previous = result_indices.find(host);
        if (previous != result_indices.end()) {
            auto& result = results.at(previous->second);
            result.ips.insert(result.ips.end(), answer.ipv4.begin(), answer.ipv4.end());
            result.ipv6.insert(result.ipv6.end(), answer.ipv6.begin(), answer.ipv6.end());
            result.ips = normalize_ip_set(std::move(result.ips)).ips;
            result.ipv6 = normalize_ip_set(std::move(result.ipv6)).ips;
            if (source_hint == "brute" && passive_set_uset.count(host)) result.source = "both";
            if (!provider.empty()) result.doh_fallback = provider;
            std::lock_guard<std::mutex> report_lock(g_result_mtx);
            report_rows(result).at(result.report_index) = entry_from_result(result);
            return std::nullopt;
        }
        SubResult result;
        result.sub = host; result.ips = answer.ipv4; result.ipv6 = answer.ipv6;
        result.ips = normalize_ip_set(std::move(result.ips)).ips;
        result.ipv6 = normalize_ip_set(std::move(result.ipv6)).ips;
        const auto scope = wildcard_scopes.find(scope_for(host));
        const auto classification = scope == wildcard_scopes.end() ? WildcardState::Unknown : scope->second;
        result.wildcard_match = classification == WildcardState::Wildcard;
        result.dns_status = result.wildcard_match ? "wildcard" :
            classification == WildcardState::Clear ? "resolved" : "uncertain";
        const bool passive = passive_set_uset.count(host) != 0;
        result.source = passive && source_hint == "brute" ? "both" : passive ? "passive" : source_hint;
        result.doh_fallback = provider;
        {
            std::lock_guard<std::mutex> report_lock(g_result_mtx);
            auto& rows = report_rows(result);
            result.report_index = rows.size();
            rows.push_back(entry_from_result(result));
        }
        const bool resolved = result.dns_status == "resolved";
        const auto index = results.size();
        results.push_back(std::move(result));
        result_indices.emplace(host, index);
        if (!resolved) return std::nullopt;
        ++found_count;
        return index;
    };
    auto process_resolved = [&](std::size_t index) {
        if (g_cancel_token.cancelled) return;
        SubResult result;
        { std::lock_guard<std::mutex> lock(state_mtx); result = results.at(index); }
        const auto& sub = result.sub;
        if (enrich_active && !g_cancel_token.cancelled) {
            if (features.cname) result.cname = dns.resolve_cname(sub);
            if (g_cancel_token.cancelled) return;
            if (features.http) http_jitter();
            if (g_cancel_token.cancelled) return;
            if (features.http && (deep_passive || features.tech)) {
                auto response = fast_probe(sub, HTTP_TIMEOUT);
                if (response.http_code > 0) {
                    result.http_code = std::to_string(response.http_code);
                    result.server = server_from_headers(response.headers);
                    result.title = parse_title(response.body);
                    if (features.tech) {
                        result.waf = detect_waf(response.headers, response.body, response.headers);
                        result.tech = detect_tech(response.headers, response.body, response.headers);
                    }
                }
            } else if (features.http) {
                const auto code = fast_check(sub, HTTP_TIMEOUT);
                if (code > 0) result.http_code = std::to_string(code);
            }
        }
        result.server = sanitize_subdomain_text(result.server, 80);
        result.title = sanitize_subdomain_text(result.title, 512);
        {
            std::lock_guard<std::mutex> lock(state_mtx);
            const auto& current = results.at(index);
            result.ips = current.ips; result.ipv6 = current.ipv6;
            result.wildcard_match = current.wildcard_match;
            result.dns_status = current.dns_status;
            result.source = current.source; result.doh_fallback = current.doh_fallback;
            results.at(index) = result;
            std::lock_guard<std::mutex> report_lock(g_result_mtx);
            g_result.subdomains.at(result.report_index) = entry_from_result(result);
        }
        std::lock_guard<std::mutex> print_lock(g_print_mtx);
        std::cout << "  " << BOLD << sub << RESET;
        if (!result.http_code.empty())
            std::cout << "  HTTP:" << value_color << result.http_code << RESET;
        std::cout << DIM << " (" << result.source << ")" << RESET << '\n';
        print_addresses("IPv4", result.ips);
        print_addresses("IPv6", result.ipv6);
        if (!result.cname.empty())
            std::cout << "    " << value_color << "CNAME: " << result.cname << RESET << '\n';
    };

    print_section("ASYNC DNS + DoH → PIPELINE HTTP");
    std::cout << BLOOD_RED << "  wordlist: " << WHITE
              << (passive_only ? "disabled" : stream_file_wordlist ? "streaming" : "builtin")
              << BLOOD_RED << " | passive: " << WHITE << passive_subs.size()
              << BLOOD_RED << " | enrichment workers: " << WHITE << HTTP_WORKERS
              << BLOOD_RED << " | DNS batch: " << WHITE << DNS_BATCH_SIZE
              << BLOOD_RED << " | DNS concurrency: " << WHITE << DNS_CONCURRENCY
              << BLOOD_RED << " | pipeline ON\n\n" << RESET;

    PipelineQueue<DnsPending> http_pipe(1024);

    std::vector<std::thread> http_threads;
    http_threads.reserve(HTTP_WORKERS);
    PipelineJoinGuard<DnsPending> join_http(http_pipe, http_threads);
    for (int i=0; i<HTTP_WORKERS; i++) {
        http_threads.emplace_back([&](){
            struct TaskDoneGuard {
                PipelineQueue<DnsPending>& pipe;
                explicit TaskDoneGuard(PipelineQueue<DnsPending>& p) : pipe(p) {}
                ~TaskDoneGuard() { pipe.task_done(); }
                TaskDoneGuard(const TaskDoneGuard&) = delete;
                TaskDoneGuard& operator=(const TaskDoneGuard&) = delete;
            };
            DnsPending item;
            while (http_pipe.pop(item)) {
                TaskDoneGuard done(http_pipe);
                try { process_resolved(item.result_index); }
                catch (const std::exception& error) { subdomain_error("subdomain enrichment: " + std::string(error.what())); }
                catch (...) { subdomain_error("subdomain enrichment failed with an unknown exception"); }
            }
        });
    }

    std::size_t doh_attempts = 0;
    auto resolve_and_queue_batch = [&](const std::vector<std::string>& input,
                                       const std::string& source_hint,
                                       bool allow_passive_doh,
                                       const std::string& resolved_doh_provider) {
        if (input.empty() || g_cancel_token.cancelled) return;
        std::vector<std::string> parents;
        parents.reserve(input.size());
        for (const auto& host : input) parents.push_back(scope_for(host));
        prepare_scopes(parents);
        std::vector<std::string> batch;
        batch.reserve(input.size());
        for (const auto& host : input) {
            if (g_cancel_token.cancelled) break;
            const auto cached = wildcard_scopes.find(scope_for(host));
            const auto scope = cached == wildcard_scopes.end() ? WildcardState::Unknown : cached->second;
            const bool independent = source_hint != "brute" || passive_set_uset.count(host) ||
                resolved_doh_provider == "js";
            if (!independent && scope != WildcardState::Clear) {
                if (scope == WildcardState::Wildcard) ++wildcard_filtered;
                else ++unchecked_filtered;
                continue;
            }
            batch.push_back(host);
        }
        if (batch.empty() || g_cancel_token.cancelled) return;
        auto answers = dns.resolve_batch_checked(batch, DNS_CONCURRENCY);
        std::vector<DnsPending> pending;
        std::size_t failed = 0;
        std::string failure_example;
        for (const auto& host : batch) {
            const auto it = answers.find(host);
            if (it == answers.end()) {
                if (!g_cancel_token.cancelled) { ++failed; failure_example = "missing DNS result for " + host; }
                continue;
            }
            auto& answer = it->second;
            ++dns_checked;
            if (answer.failed && !g_cancel_token.cancelled) {
                ++failed;
                if (failure_example.empty()) failure_example = host + ": " + answer.error;
            }
            if (const auto index = retain_dns(host, answer, resolved_doh_provider, source_hint))
                pending.push_back({*index});
        }
        if (failed) subdomain_error("DNS lookup failed for " + std::to_string(failed) +
            " candidates in a batch: " + failure_example);
        for (auto& item : pending) {
            if (g_cancel_token.cancelled) break;
            if (enrich_active) { if (!http_pipe.push(std::move(item))) break; }
        }
        if (!allow_passive_doh || g_cancel_token.cancelled) return;
        std::vector<std::string> fallback;
        for (const auto& host : batch) {
            const auto it = answers.find(host);
            if (it == answers.end() || !it->second.failed || !it->second.ipv4.empty() ||
                !it->second.ipv6.empty() || !passive_set_uset.count(host)) continue;
            if (doh_attempts >= 500) {
                subdomain_warning("DoH fallback limit of 500 candidates reached; remaining fallbacks skipped");
                break;
            }
            ++doh_attempts;
            fallback.push_back(host);
        }
        if (fallback.empty()) return;
        ThreadPool pool(std::min<std::size_t>(fallback.size(), 16));
        std::vector<std::future<void>> futures;
        for (const auto& host : fallback) futures.push_back(pool.submit([&, host] {
            if (g_cancel_token.cancelled) return;
            std::string provider_a, provider_aaaa;
            DnsLookupResult answer;
            answer.ipv4 = doh_query(host, "A", &provider_a);
            if (!g_cancel_token.cancelled) answer.ipv6 = doh_query(host, "AAAA", &provider_aaaa);
            std::string provider = answer.ipv4.empty() ? "" : provider_a;
            if (!answer.ipv6.empty() && !provider_aaaa.empty() && provider_aaaa != provider) {
                if (!provider.empty()) provider += ',';
                provider += provider_aaaa;
            }
            const auto index = retain_dns(host, answer, provider, "passive");
            if (!answer.ipv4.empty() || !answer.ipv6.empty()) ++doh_used;
            if (!index) return;
            if (enrich_active && !g_cancel_token.cancelled)
                http_pipe.push({*index});
        }));
        for (auto& future : futures) future.get();
    };

    if (!g_cancel_token.cancelled && !passive_subs.empty()) {
        std::cout << "  resolving " << passive_subs.size() << " passive candidates first...\n";
        std::vector<std::string> passive_batch;
        passive_batch.reserve(DNS_BATCH_SIZE);
        for (const auto& sub : passive_subs) {
            if (g_cancel_token.cancelled) break;
            passive_batch.push_back(sub);
            if (passive_batch.size() >= static_cast<std::size_t>(DNS_BATCH_SIZE)) {
                resolve_and_queue_batch(passive_batch, "passive", true, "");
                passive_batch.clear();
            }
        }
        if (!g_cancel_token.cancelled)
            resolve_and_queue_batch(passive_batch, "passive", true, "");
    }

    std::vector<std::string> wordlist_batch;
    wordlist_batch.reserve(DNS_BATCH_SIZE);
    std::unordered_set<std::string> wordlist_batch_dedup;
    wordlist_batch_dedup.reserve(DNS_BATCH_SIZE * 2);
    uint64_t candidates_seen = 0;
    uint64_t candidates_queued = 0;
    uint64_t candidates_skipped = 0;
    uint64_t wordlist_batches = 0;

    auto flush_wordlist_batch = [&]() {
        if (wordlist_batch.empty()) return;
        const size_t batch_size = wordlist_batch.size();
        auto batch_start = std::chrono::steady_clock::now();
        resolve_and_queue_batch(wordlist_batch, "brute", false, "");
        auto elapsed = std::chrono::steady_clock::now() - batch_start;
        double elapsed_seconds = std::chrono::duration<double>(elapsed).count();
        double rate = elapsed_seconds > 0.0 ? (double)batch_size / elapsed_seconds : 0.0;
        wordlist_batches++;
        wordlist_batch.clear();
        wordlist_batch_dedup.clear();
        {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << BLOOD_RED << "  [dns] wordlist batch " << WHITE << wordlist_batches
                      << BLOOD_RED << " size=" << WHITE << batch_size
                      << BLOOD_RED << " elapsed=" << WHITE << format_elapsed_seconds(elapsed) << BLOOD_RED << "s rate=" << WHITE << format_rate(rate) << BLOOD_RED << "/s"
                      << BLOOD_RED << " processed=" << WHITE << candidates_seen
                      << BLOOD_RED << " queued=" << WHITE << candidates_queued
                      << BLOOD_RED << " skipped=" << WHITE << candidates_skipped
                      << BLOOD_RED << " pipe=" << WHITE << http_pipe.size()
                      << BLOOD_RED << " found=" << WHITE << found_count.load()
                      << RESET << '\n' << std::flush;
        }
        maybe_write_checkpoint(false, "wordlist-batch");
    };

    auto queue_wordlist_candidate = [&](const std::string& line) {
        candidates_seen++;
        auto fqdn = normalize_wordlist_candidate_to_fqdn(line, scan_domain);
        if (!fqdn || !wordlist_batch_dedup.insert(*fqdn).second) {
            candidates_skipped++;
            return;
        }
        wordlist_batch.push_back(std::move(*fqdn));
        candidates_queued++;
        if ((int)wordlist_batch.size() >= DNS_BATCH_SIZE) flush_wordlist_batch();
    };

    if (passive_only) {
        std::lock_guard<std::mutex> print_lock(g_print_mtx);
        std::cout << "  generated discovery disabled by --passive-only\n";
    } else if (stream_file_wordlist) {
        std::string line;
        while (!g_cancel_token.cancelled && std::getline(wordlist_stream, line)) {
            queue_wordlist_candidate(line);
        }
        if (wordlist_stream.bad()) {
            subdomain_error("error while reading wordlist: " + wordlist_path);
        }
        if (!g_cancel_token.cancelled && candidates_queued == 0) {
            subdomain_error("explicit wordlist contains no valid candidates: " + wordlist_path);
        }
    } else {
        for (const auto& word : builtin_wordlist()) {
            if (g_cancel_token.cancelled) break;
            queue_wordlist_candidate(word);
        }
    }
    if (!g_cancel_token.cancelled) flush_wordlist_batch();
    {
        std::lock_guard<std::mutex> lk(g_print_mtx);
        std::cout << "\n" << BLOOD_RED << "  [=] wordlist processed=" << WHITE << candidates_seen
                  << BLOOD_RED << " queued=" << WHITE << candidates_queued
                  << BLOOD_RED << " skipped=" << WHITE << candidates_skipped
                  << BLOOD_RED << " batches=" << WHITE << wordlist_batches << "\n" << RESET;
    }

    std::set<std::string> found_snapshot;
    if (run_permutations && !passive_only && !g_cancel_token.cancelled) {
        {
            std::lock_guard<std::mutex> print_lock(g_print_mtx);
            std::cout << BLOOD_RED << "  [*] waiting for base enrichment pipeline...\n" << RESET;
        }
        http_pipe.wait_idle();
        maybe_write_checkpoint(true, "base-idle");
        std::lock_guard<std::mutex> lk(state_mtx);
        for (const auto& result : results)
            if (result.dns_status == "resolved") found_snapshot.insert(result.sub);
        constexpr std::size_t max_seeds = 64;
        if (found_snapshot.size() > max_seeds) {
            found_snapshot.erase(std::next(found_snapshot.begin(), max_seeds), found_snapshot.end());
            subdomain_warning("Permutation seed limit of 64 reached; remaining resolved names are not expanded");
        }
    }
    if (run_permutations && !found_snapshot.empty() && !g_cancel_token.cancelled) {
        print_section("PERMUTATION ENGINE");
        std::cout << BLOOD_RED << "  [*] streaming permutations resolving...\n" << RESET;
        std::vector<std::string> perm_batch;
        perm_batch.reserve(static_cast<size_t>(DNS_BATCH_SIZE));
        size_t perm_generated = 0;
        size_t perm_queued = 0;
        size_t perm_batches = 0;
        bool permutation_limit = false;

        auto flush_perm_batch = [&]() {
            if (perm_batch.empty() || g_cancel_token.cancelled) return;
            const size_t batch_index = perm_batches + 1;
            const size_t batch_size = perm_batch.size();
            {
                std::lock_guard<std::mutex> lk(g_print_mtx);
                std::cout << BLOOD_RED << "  [perm-dns] batch " << WHITE << batch_index
                          << BLOOD_RED << " size=" << WHITE << batch_size
                          << BLOOD_RED << " started...\n" << RESET << std::flush;
            }
            auto batch_start = std::chrono::steady_clock::now();
            resolve_and_queue_batch(perm_batch, "brute", false, "");
            auto elapsed = std::chrono::steady_clock::now() - batch_start;
            perm_batches++;
            size_t pipe_size = http_pipe.size();
            size_t found_size = current_found_size();
            {
                std::lock_guard<std::mutex> lk(g_print_mtx);
                std::cout << BLOOD_RED << "  [perm-dns] batch " << WHITE << batch_index
                          << BLOOD_RED << " size=" << WHITE << batch_size
                          << BLOOD_RED << " done elapsed=" << WHITE << format_elapsed_seconds(elapsed)
                          << BLOOD_RED << "s pipe=" << WHITE << pipe_size
                          << BLOOD_RED << " found=" << WHITE << found_size << "\n" << RESET;
            }
            perm_batch.clear();
            maybe_write_checkpoint(false, "permutation-batch");
        };

        for_each_permutation_candidate(found_snapshot, scan_domain, [&](std::string&& candidate) {
            perm_generated++;
            if (g_cancel_token.cancelled) return;
            if (perm_queued >= 5000) { permutation_limit = true; return; }
            if (!normalize_subdomain_name(candidate, scan_domain)) return;
            if (derived_dedup.insert(candidate).second) {
                perm_batch.push_back(std::move(candidate));
                perm_queued++;
                if (perm_batch.size() >= static_cast<size_t>(DNS_BATCH_SIZE)) flush_perm_batch();
            }
        });
        if (permutation_limit)
            subdomain_warning("Permutation candidate limit of 5000 reached; remaining generated variants were skipped");
        if (!g_cancel_token.cancelled) flush_perm_batch();
        {
            std::lock_guard<std::mutex> print_lock(g_print_mtx);
            std::cout << BLOOD_RED << "  [=] permutations generated=" << WHITE << perm_generated
                      << BLOOD_RED << " queued=" << WHITE << perm_queued
                      << BLOOD_RED << " batches=" << WHITE << perm_batches << "\n" << RESET;
        }
    }

    std::vector<std::string> js_targets;
    if (features.js && !g_cancel_token.cancelled) {
        size_t pipe_size = http_pipe.size();
        size_t found_size = current_found_size();
        {
            std::lock_guard<std::mutex> print_lock(g_print_mtx);
            std::cout << BLOOD_RED << "  [*] waiting for enrichment pipeline..."
                      << BLOOD_RED << " pipe=" << WHITE << pipe_size
                      << BLOOD_RED << " found=" << WHITE << found_size << "\n" << RESET;
        }
        http_pipe.wait_idle();
        maybe_write_checkpoint(true, "permutation-idle");
        {
            std::lock_guard<std::mutex> lk(state_mtx);
            js_targets.reserve(results.size());
            for (const auto& r : results) {
                if (r.dns_status == "resolved" && !r.http_code.empty() && r.http_code != "0")
                    js_targets.push_back(r.sub);
            }
        }
        std::cout << BLOOD_RED << "  [*] JS targets: " << WHITE << js_targets.size() << "\n" << RESET;
    }
    if (features.js && !js_targets.empty() && !g_cancel_token.cancelled) {
        print_section("JS SCRAPING");
        std::set<std::string> js_subs;
        scrape_js_subdomains(js_targets, scan_domain, js_subs);
        std::vector<std::string> new_js;
        for (auto& s : js_subs) {
            if (derived_dedup.insert(s).second) new_js.push_back(s);
        }
        std::cout << BLOOD_RED << "  [*] " << WHITE << new_js.size()
                  << BLOOD_RED << " new JS candidates resolving...\n" << RESET;
        if (!new_js.empty()) {
            int total_batches = ((int)new_js.size() + DNS_BATCH_SIZE - 1) / DNS_BATCH_SIZE;
            for (int bs=0; bs<(int)new_js.size() && !g_cancel_token.cancelled; bs+=DNS_BATCH_SIZE) {
                int be = std::min(bs+DNS_BATCH_SIZE, (int)new_js.size());
                int batch_index = bs / DNS_BATCH_SIZE + 1;
                std::vector<std::string> batch(new_js.begin()+bs, new_js.begin()+be);
                {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    std::cout << BLOOD_RED << "  [js-dns] batch " << WHITE << batch_index
                              << BLOOD_RED << "/" << WHITE << total_batches
                              << BLOOD_RED << " size=" << WHITE << batch.size()
                              << BLOOD_RED << " started...\n" << RESET << std::flush;
                }
                auto batch_start = std::chrono::steady_clock::now();
                resolve_and_queue_batch(batch, "brute", false, "js");
                auto elapsed = std::chrono::steady_clock::now() - batch_start;
                size_t pipe_size = http_pipe.size();
                size_t found_size = current_found_size();
                {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    std::cout << BLOOD_RED << "  [js-dns] batch " << WHITE << batch_index
                              << BLOOD_RED << "/" << WHITE << total_batches
                              << BLOOD_RED << " size=" << WHITE << batch.size()
                              << BLOOD_RED << " done elapsed=" << WHITE << format_elapsed_seconds(elapsed)
                              << BLOOD_RED << "s pipe=" << WHITE << pipe_size
                              << BLOOD_RED << " found=" << WHITE << found_size << "\n" << RESET;
                }
                maybe_write_checkpoint(false, "js-batch");
            }
        }
    }

    maybe_write_checkpoint(true, "dns-complete");
    {
        std::lock_guard<std::mutex> print_lock(g_print_mtx);
        std::cout << "\n" << BLOOD_RED << "  [*] DNS done. Waiting for "
                  << http_pipe.size() << " pending enrichments...\n" << RESET;
    }
    http_pipe.close();
    for (auto& t : http_threads) t.join();

    if (wildcard_filtered.load())
        subdomain_warning("Filtered " + std::to_string(wildcard_filtered.load()) +
            " generated candidates matching wildcard DNS; shared-address names may require independent verification");
    if (unchecked_filtered)
        subdomain_warning("Skipped " + std::to_string(unchecked_filtered) +
            " generated candidates in branches with inconclusive wildcard checks");
    const auto candidate_count = results.size() - static_cast<std::size_t>(found_count.load());
    if (candidate_count)
        subdomain_warning(std::to_string(candidate_count) +
            " independent DNS observations remain uncertain; see subdomain_candidates and module dns_status fields");

    std::cout << "\n";

    {
        std::lock_guard<std::mutex> lk(state_mtx);
        std::sort(results.begin(), results.end(),
                  [](const SubResult& a, const SubResult& b){ return a.sub < b.sub; });
    }

    print_section("SUMMARY");
    if (!features.full_addresses && std::any_of(results.begin(), results.end(), [](const auto& row) {
            return row.dns_status == "resolved" && (row.ips.size() > 1 || row.ipv6.size() > 1);
        }))
        std::cout << "  Addresses: first per family (+N); use --full-addresses to display every address.\n";
    std::cout << "\n" << BLOOD_RED << BOLD
              << "  " << std::left << std::setw(42) << "SUBDOMAIN"
              << std::setw(16) << "IPv4" << std::setw(6) << "v6"
              << std::setw(8)  << "HTTP" << std::setw(16) << "WAF"
              << std::setw(12) << "TECH" << "TITLE\n"
              << "  " << std::string(108,'-') << "\n" << RESET;

    int cnt_cname=0, cnt_waf=0, cnt_ipv6=0;
    std::map<std::string,int> server_stats, waf_stats, lang_stats, cms_stats, source_stats;

    for (auto& r : results) {
        if (r.dns_status != "resolved") continue;
        std::cout << BLOOD_RED << "  " << WHITE << std::left << std::setw(42) << r.sub;
        if (!r.ips.empty())  std::cout << value_color << std::setw(16) << r.ips[0] << RESET;
        else                 std::cout << DIM << std::setw(16) << "-" << RESET;
        if (!r.ipv6.empty()) { std::cout << value_color << std::setw(6) << "v6" << RESET; cnt_ipv6++; }
        else                   std::cout << DIM << std::setw(6) << "-" << RESET;
        if (!r.http_code.empty() && r.http_code!="0")
            std::cout << value_color << std::setw(8) << r.http_code << RESET;
        else std::cout << DIM << std::setw(8) << "-" << RESET;
        if (!r.waf.name.empty()) {
            std::string wn=r.waf.name; if(wn.size()>14) wn=wn.substr(0,14);
            std::cout << value_color << std::setw(16) << wn << RESET; cnt_waf++;
        } else { std::cout << DIM << std::setw(16) << "-" << RESET; }
        std::string ts=r.tech.language; if(!r.tech.cms.empty()) ts+="/"+r.tech.cms;
        if (ts.size()>12) ts=ts.substr(0,12);
        std::cout << (ts.empty() ? DIM : value_color) << std::setw(12) << (ts.empty()?"-":ts) << RESET;
        std::cout << WHITE << sanitize(r.title) << RESET << "\n";
        if (r.ips.size() > 1) print_addresses("IPv4", r.ips);
        if (!r.cname.empty()) { std::cout << "    -> " << value_color << "CNAME: " << r.cname << RESET << "\n"; cnt_cname++; }
        if (!r.ipv6.empty()) print_addresses("IPv6", r.ipv6);
        if (!r.tech.stack.empty()) { std::cout << "    -> stack: " << value_color; for (auto& s:r.tech.stack) std::cout<<s<<" "; std::cout<<RESET<<"\n"; }
        if (!r.server.empty()) server_stats[r.server]++;
        if (!r.waf.name.empty()) waf_stats[r.waf.name]++;
        if (!r.tech.language.empty()) lang_stats[r.tech.language]++;
        if (!r.tech.cms.empty()) cms_stats[r.tech.cms]++;
        source_stats[r.source]++;
    }

    print_section("STATISTICS");
    std::cout << "  [resolved names]  " << value_color << found_count.load() << RESET << '\n';
    std::cout << "  [uncertain names] " << (candidate_count ? YELLOW : DIM) << candidate_count << RESET
              << " (excluded from resolved names)\n";
    std::cout << "  [dns checked]     " << value_color << dns_checked.load() << RESET << '\n';
    std::cout << "  [DoH fallbacks]   " << value_color << doh_used.load() << RESET << '\n';
    std::cout << "  [with CNAME]      " << value_color << cnt_cname << RESET << '\n';
    std::cout << "  [with IPv6]       " << value_color << cnt_ipv6 << RESET << '\n';
    std::cout << "  [behind WAF]      " << value_color << cnt_waf << RESET << '\n';
    std::cout << "  [wildcard scopes] " << std::count_if(wildcard_scopes.begin(), wildcard_scopes.end(),
        [](const auto& scope) { return scope.second == WildcardState::Wildcard; }) << '\n';
    std::cout << BLOOD_RED << "  [wildcard filtered] " << WHITE << wildcard_filtered.load() << "\n" << RESET;
    std::cout << "  [unchecked skipped] " << unchecked_filtered << '\n';
    std::cout << BLOOD_RED << "  [enrich workers]  " << WHITE << HTTP_WORKERS           << "\n" << RESET;

    auto print_dist=[&](const std::map<std::string,int>& m, const std::string& label){
        if (m.empty()) return;
        std::cout << BLOOD_RED << "\n  [" << WHITE << label << BLOOD_RED << "]\n" << RESET;
        std::vector<std::pair<std::string,int>> v(m.begin(),m.end());
        std::sort(v.begin(),v.end(),[](auto& a,auto& b){return a.second>b.second;});
        for (auto& [k,cnt]:v)
            std::cout << "    " << value_color << std::left << std::setw(30) << k
                      << RESET << value_color << cnt << RESET << '\n';
    };
    print_dist(source_stats,"sources");
    print_dist(waf_stats,"WAF");
    print_dist(lang_stats,"languages");
    print_dist(cms_stats,"CMS");
    print_dist(server_stats,"server distribution");

    if (features.service_hints && !g_cancel_token.cancelled) {
        print_section("CNAME SERVICE HINTS");
        std::size_t inspected = 0;
        for (auto& result : results) {
            if (g_cancel_token.cancelled) break;
            if (result.dns_status != "resolved") continue;
            if (result.cname.empty()) continue;
            if (inspected >= 64) { subdomain_warning("CNAME service inspection limit of 64 reached"); break; }
            for (const auto& signature : takeover_db()) {
                const auto& name = result.cname;
                const auto& pattern = signature.cname_pattern;
                const bool matches = name == pattern || (name.size() > pattern.size() &&
                    name.compare(name.size() - pattern.size(), pattern.size(), pattern) == 0 &&
                    name[name.size() - pattern.size() - 1] == '.');
                if (!matches) continue;
                ++inspected;
                const auto answers = dns.resolve_batch_checked({name}, 2, 5000);
                if (g_cancel_token.cancelled) break;
                const auto answer = answers.find(name);
                std::string status = "UNKNOWN";
                if (answer != answers.end() && !answer->second.failed) {
                    status = answer->second.ipv4.empty() && answer->second.ipv6.empty() ?
                        "DNS_NO_ADDRESS" : takeover_validate(result.sub, signature.fingerprints);
                }
                result.takeover_possible = status == "FINGERPRINT_MATCH" || status == "POSSIBLE" || status == "DNS_NO_ADDRESS";
                {
                    std::lock_guard<std::mutex> report_lock(g_result_mtx);
                    g_result.subdomains.at(result.report_index).takeover_possible = result.takeover_possible;
                }
                std::cout << "  " << result.sub << " -> " << value_color << name << RESET
                          << " (" << value_color << signature.service << RESET << "): "
                          << YELLOW << status << RESET << "; manual verification required\n";
                break;
            }
        }
    }
    maybe_write_checkpoint(true, g_cancel_token.cancelled ? "cancelled" : "complete");
    {
        std::lock_guard<std::mutex> report_lock(g_result_mtx);
        std::sort(g_result.subdomains.begin(), g_result.subdomains.end(),
                  [](const auto& a, const auto& b) { return a.sub < b.sub; });
        std::sort(g_result.subdomain_candidates.begin(), g_result.subdomain_candidates.end(),
                  [](const auto& a, const auto& b) { return a.sub < b.sub; });
    }

    print_section("EXPORT");
    {
        std::lock_guard<std::mutex> lk(state_mtx);
        export_results(results, scan_domain);
    }

    LOG_INFO("subdomain_scan","done domain="+scan_domain
        +" resolved="+std::to_string(found_count.load())
        +" uncertain="+std::to_string(candidate_count)
        +" doh="+std::to_string(doh_used.load())
        +" workers="+std::to_string(HTTP_WORKERS));
}
