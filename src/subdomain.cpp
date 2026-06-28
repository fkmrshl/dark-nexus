#include "../include/dark_nexus.hpp"
#include "../include/dns_engine.hpp"
#include "subdomain_common.hpp"
#include <curl/curl.h>
#include <fstream>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <cctype>
#include <cstdint>
#include <optional>
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
        not_full_.wait(lk, [&]{ return q_.size() < max_size_ || closed_; });
        if (closed_) return false;
        q_.push_back(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    bool pop(T& item) {
        std::unique_lock<std::mutex> lk(mtx_);
        not_empty_.wait(lk, [&]{ return !q_.empty() || closed_; });
        if (q_.empty()) return false;
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
        idle_.wait(lk, [&]{ return q_.empty() && active_ == 0; });
    }

    void close() {
        { std::lock_guard<std::mutex> lk(mtx_); closed_ = true; }
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
    CurlGlobalGuard() : initialized_(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK) {}
    ~CurlGlobalGuard() { if (initialized_) curl_global_cleanup(); }
    CurlGlobalGuard(const CurlGlobalGuard&) = delete;
    CurlGlobalGuard& operator=(const CurlGlobalGuard&) = delete;
};

struct DnsPending {
    std::string              sub;
    std::vector<std::string> ips;
    std::string              doh_provider;
    std::string              source_hint;
};

static RateLimiter subdomain_rl(50000.0);
thread_local std::mt19937 tl_rng{std::random_device{}()};

struct SubResult {
    std::string sub, cname, http_code, server, title, source, doh_fallback;
    std::vector<std::string> ips, ipv6;
    WAFInfo  waf;
    TechInfo tech;
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
                                     const std::vector<std::string>& fingerprints)
{
    auto lc=[](std::string s){std::transform(s.begin(),s.end(),s.begin(),::tolower);return s;};
    for (auto& url : {"https://"+sub, "http://"+sub}) {
        auto resp = libcurl_get(url, sub, "Mozilla/5.0 (compatible; Validator/1.0)", 8);
        if (resp.body.empty() && resp.headers.empty()) continue;
        std::string bl=lc(resp.body), hl=lc(resp.headers);
        for (auto& fp : fingerprints) {
            std::string fpl=lc(fp);
            if (bl.find(fpl)!=std::string::npos || hl.find(fpl)!=std::string::npos) return "CONFIRMED";
        }
        if (resp.http_code==404 || resp.http_code==0) return "POSSIBLE";
        return "LIVE";
    }
    return "UNREACHABLE";
}

static void export_results(const std::vector<SubResult>& results, const std::string& domain) {
    {
        std::string fname = domain+"_subdomains.json";
        nlohmann::json output = nlohmann::json::array();
        for (const auto& r : results) {
            output.push_back({
                {"subdomain", r.sub},
                {"source", r.source},
                {"ipv4", r.ips},
                {"ipv6", r.ipv6},
                {"cname", r.cname},
                {"http_code", r.http_code},
                {"server", r.server},
                {"title", r.title},
                {"waf", r.waf.name},
                {"language", r.tech.language},
                {"cms", r.tech.cms},
                {"stack", r.tech.stack},
                {"doh_fallback", r.doh_fallback}
            });
        }
        std::ofstream f(fname);
        f << output.dump(2) << '\n';
        std::cout<<BLOOD_RED<<"  [+] JSON: "<<WHITE<<fname<<"\n"<<RESET;
    }
    {
        std::string fname = domain+"_subdomains.csv";
        std::ofstream f(fname);
        f<<"subdomain,ipv4,cname,http_code,server,title,waf,language,cms,source\r\n";
        auto js=[](const std::vector<std::string>& v){std::string s;for(auto& x:v){if(!s.empty())s+=" ";s+=x;}return s;};
        auto q=[](const std::string& s){
            if (s.find_first_of(",\"\r\n") == std::string::npos) return s;
            std::string escaped;
            escaped.reserve(s.size()+2);
            for (char ch : s) {
                if (ch=='\"') escaped.push_back('\"');
                escaped.push_back(ch);
            }
            return "\""+escaped+"\"";
        };
        for (auto& r : results) {
            f<<q(r.sub)<<","<<q(js(r.ips))<<","<<q(r.cname)<<","<<q(r.http_code)<<","
             <<q(r.server)<<","<<q(r.title)<<","<<q(r.waf.name)<<","
             <<q(r.tech.language)<<","<<q(r.tech.cms)<<","<<q(r.source)<<"\r\n";
        }
        std::cout<<BLOOD_RED<<"  [+] CSV:  "<<WHITE<<fname<<"\n"<<RESET;
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
        for (const auto& r : results) {
            result_rows.push_back({
                {"subdomain", r.sub},
                {"ips", r.ips},
                {"ipv6", r.ipv6},
                {"cname", r.cname},
                {"http_code", r.http_code},
                {"server", r.server},
                {"title", r.title},
                {"source", r.source},
                {"waf", r.waf.name},
                {"language", r.tech.language},
                {"cms", r.tech.cms},
                {"stack", r.tech.stack},
                {"doh_fallback", r.doh_fallback}
            });
        }

        nlohmann::json output = {
            {"type", "subdomain_checkpoint"},
            {"partial", true},
            {"domain", domain},
            {"saved_at", checkpoint_timestamp_utc()},
            {"count", results.size()},
            {"results", std::move(result_rows)}
        };

        const std::string tmp_filename = filename + ".tmp";
        std::ofstream f(tmp_filename);
        if (!f.is_open()) {
            error = "cannot open " + tmp_filename;
            return false;
        }
        f << output.dump(2) << '\n';
        if (!f.good()) {
            error = "write failed for " + tmp_filename;
            f.close();
            return false;
        }
        f.close();
        if (!f) {
            error = "close failed for " + tmp_filename;
            return false;
        }
        if (std::rename(tmp_filename.c_str(), filename.c_str()) != 0) {
            error = "rename failed for " + tmp_filename + " -> " + filename;
            return false;
        }
        return true;
    } catch (const std::exception& ex) {
        error = ex.what();
        return false;
    }
}

static void scrape_js_subdomains(const std::vector<std::string>& targets,
                                 const std::string& domain,
                                 std::set<std::string>& out)
{
    std::set<std::string> js_urls;
    for (auto& sub : targets) {
        auto resp = libcurl_get("http://"+sub, sub, random_ua(), 8);
        if (resp.body.empty()) continue;
        std::regex re_js("(?:src|href)=['\"]([^'\"]+\\.js[^'\"]*)['\"]", std::regex::icase);
        std::sregex_iterator it(resp.body.begin(), resp.body.end(), re_js), end;
        for (; it!=end; ++it) {
            std::string src=(*it)[1].str();
            if (src.substr(0,4)=="http") js_urls.insert(src);
            else if (src[0]=='/') js_urls.insert("http://"+sub+src);
        }
    }
    int scraped=0;
    for (auto& url : js_urls) {
        if (scraped++>50) break;
        auto resp = libcurl_get(url, "", random_ua(), 6);
        if (!resp.body.empty()) extract_subs(resp.body, domain, out);
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
                    bool do_enrich)
{
    std::string scan_domain = domain;
    std::transform(scan_domain.begin(), scan_domain.end(), scan_domain.begin(),
                   [](unsigned char ch){ return static_cast<char>(std::tolower(ch)); });

    print_header("SUBDOMAIN SCAN // " + scan_domain);
    CurlGlobalGuard curl_guard;

    auto& dns = DnsEngine::get();
    dns.clear_cache();

    print_section("RESOLVER SETUP");
    std::string resolver_path = auto_find_resolvers();
    if (!resolver_path.empty()) {
        dns.load_resolvers(resolver_path);
    } else {
        std::cout << BLOOD_RED << "  [*] using builtin resolvers (16)\n" << RESET;
        std::cout << BLOOD_RED << "  [!] tip: put resolvers.txt in current dir for 5-10x speedup\n"
                  << WHITE    << "      get it: curl -o resolvers.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt\n"
                  << RESET;
    }

    const int HTTP_WORKERS = std::clamp(max_threads, 1, do_enrich ? 512 : 50);
    const int HTTP_TIMEOUT = deep_passive ? 5 : 3;
    const int DNS_BATCH_SIZE = 10000;
    const int DNS_CONCURRENCY = deep_passive ? 2000 : 1000;
    const std::unordered_set<std::string> no_doh_allow;

    std::cout << BLOOD_RED << "  [*] mode: " << WHITE << (deep_passive ? "DEEP" : "FAST")
              << BLOOD_RED << " | HTTP workers: " << WHITE << HTTP_WORKERS
              << BLOOD_RED << " | DNS batch: " << WHITE << DNS_BATCH_SIZE
              << BLOOD_RED << " | DNS concurrency: " << WHITE << DNS_CONCURRENCY
              << BLOOD_RED << " | DNS channels: " << WHITE << dns.channel_count()
              << BLOOD_RED << " | resolver pool: " << WHITE << dns.resolver_count() << "\n" << RESET;

    print_section("WORDLIST");
    std::ifstream wordlist_stream;
    bool stream_file_wordlist = false;
    if (!wordlist_path.empty()) {
        if (!InputGuard::is_safe_path(wordlist_path)) {
            std::cout << BLOOD_RED << "  [!] unsafe wordlist path, using builtin list: "
                      << WHITE << wordlist_path << "\n" << RESET;
        } else {
            wordlist_stream.open(wordlist_path);
            if (wordlist_stream.is_open()) {
                stream_file_wordlist = true;
                std::cout << BLOOD_RED << "  [*] streaming: " << WHITE
                          << wordlist_path << "\n" << RESET;
            } else {
                std::cout << BLOOD_RED << "  [!] cannot open wordlist, using builtin list: "
                          << WHITE << wordlist_path << "\n" << RESET;
            }
        }
    }
    if (!stream_file_wordlist) {
        std::cout << BLOOD_RED << "  [*] builtin (" << WHITE << builtin_wordlist().size()
                  << BLOOD_RED << " words)\n" << RESET;
    }

    print_section("WILDCARD CHECK");
    struct NormalizedIpSet {
        std::vector<std::string> ips;
        std::string              signature;
    };
    struct WildcardFingerprint {
        bool active = false;
        std::unordered_set<std::string> ip_union;
        std::unordered_map<std::string, size_t> ip_frequency;
        std::unordered_set<std::string> signatures;
        std::vector<std::string> probes;
        size_t positive_probes = 0;
    };

    auto normalize_ip_set = [](std::vector<std::string> ips) {
        std::sort(ips.begin(), ips.end());
        ips.erase(std::unique(ips.begin(), ips.end()), ips.end());
        std::string signature;
        for (const auto& ip : ips) {
            if (!signature.empty()) signature.push_back('|');
            signature += ip;
        }
        return NormalizedIpSet{std::move(ips), std::move(signature)};
    };

    auto random_dns_token = []() {
        static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        std::string token;
        token.reserve(12);
        for (int i=0; i<12; i++) token += alphabet[tl_rng() % (sizeof(alphabet)-1)];
        return token;
    };

    WildcardFingerprint wildcard_fp;
    {
        auto& probes = wildcard_fp.probes;
        const auto one_label_token = random_dns_token();
        const auto two_label_token = random_dns_token();
        const auto parent_token = random_dns_token();
        probes.reserve(12);
        for (int i=0; i<8; i++) {
            probes.push_back("dnxwc-" + one_label_token + "-" + std::to_string(i) + "." + scan_domain);
        }
        for (int i=0; i<4; i++) {
            probes.push_back("dnxwc-" + two_label_token + "-" + std::to_string(i) +
                             ".dnxwc-" + parent_token + "." + scan_domain);
        }
        auto wc = dns.resolve_batch(probes, 10, &no_doh_allow);
        for (auto& [h,ips] : wc) {
            auto normalized = normalize_ip_set(std::move(ips));
            if (normalized.ips.empty()) continue;
            wildcard_fp.positive_probes++;
            for (const auto& ip : normalized.ips) {
                wildcard_fp.ip_union.insert(ip);
                wildcard_fp.ip_frequency[ip]++;
            }
            wildcard_fp.signatures.insert(std::move(normalized.signature));
        }
        wildcard_fp.active = wildcard_fp.positive_probes >= 2;
    }
    if (wildcard_fp.active) {
        std::cout << BLOOD_RED << "  [!] wildcard DNS detected: "
                  << WHITE << wildcard_fp.positive_probes << "/" << wildcard_fp.probes.size()
                  << BLOOD_RED << " probes positive, " << WHITE << wildcard_fp.ip_union.size()
                  << BLOOD_RED << " IPs, " << WHITE << wildcard_fp.signatures.size()
                  << BLOOD_RED << " signatures\n" << RESET;
    } else {
        std::cout << BLOOD_RED << "  [+] no wildcard\n" << RESET;
    }

    auto looks_like_wildcard = [&](const std::vector<std::string>& candidate_ips,
                                   const WildcardFingerprint& fp) {
        if (!fp.active || candidate_ips.empty()) return false;
        auto normalized = normalize_ip_set(candidate_ips);
        if (normalized.ips.empty()) return false;
        if (fp.signatures.count(normalized.signature)) return true;
        for (const auto& ip : normalized.ips)
            if (!fp.ip_union.count(ip)) return false;
        return true;
    };

    print_section("PASSIVE ENUM");
    std::set<std::string> passive_subs;
    std::mutex passive_mtx;

    std::cout << BLOOD_RED << "  [*] " << WHITE << "crt.sh" << BLOOD_RED << "...\n" << RESET;
    passive_crtsh(scan_domain, passive_subs);
    std::cout << BLOOD_RED << "  [+] crt.sh +" << WHITE << passive_subs.size() << "\n" << RESET;

    if (deep_passive) {

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
        std::vector<std::thread> passive_threads;
        passive_threads.reserve(tasks.size());

        for (size_t i=0; i<tasks.size(); i++) {
            passive_threads.emplace_back([&,i](){
                tasks[i].fn(results_per_source[i].second);
                results_per_source[i].first = tasks[i].name;
                std::lock_guard<std::mutex> lk(g_print_mtx);
                std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(18)
                          << tasks[i].name << BLOOD_RED << "+" << WHITE
                          << results_per_source[i].second.size() << "\n" << RESET;
            });
        }
        for (auto& t : passive_threads) t.join();

        for (auto& [name, subs] : results_per_source)
            for (auto& s : subs) passive_subs.insert(s);
    }
    std::cout << BLOOD_RED << "  [=] total passive: " << WHITE << passive_subs.size() << "\n" << RESET;

    std::mutex state_mtx;
    std::vector<SubResult>  results;
    std::set<std::string>   found_set;
    std::atomic<int> found_count{0}, dns_checked{0}, doh_used{0};
    std::unordered_set<std::string> passive_set_uset(passive_subs.begin(), passive_subs.end());
    std::unordered_set<std::string> derived_dedup(passive_set_uset.begin(), passive_set_uset.end());
    auto current_found_size = [&]() {
        std::lock_guard<std::mutex> lk(state_mtx);
        return found_set.size();
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
                if (results.empty()) return;
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
            std::cout << BLOOD_RED << "  [!] checkpoint failed: " << WHITE
                      << checkpoint_error << BLOOD_RED << " (" << WHITE
                      << reason << BLOOD_RED << ")\n" << RESET;
        }
    };

    auto process_resolved = [&](const std::string& sub,
                                std::vector<std::string> ips,
                                const std::string& doh_provider,
                                const std::string& source_hint)
    {

        if (looks_like_wildcard(ips, wildcard_fp)) {
            dns_checked++;
            return;
        }

        { std::lock_guard<std::mutex> lk(state_mtx); if (!found_set.insert(sub).second) return; }

        std::sort(ips.begin(), ips.end());
        ips.erase(std::unique(ips.begin(), ips.end()), ips.end());

        std::vector<std::string> ipv6;
        std::string cname, http_code, server_hdr, page_title;
        WAFInfo waf; TechInfo tech;

        if (do_enrich) {

            if (deep_passive) {
                ipv6 = dns.resolve_aaaa(sub);
            }

            if (deep_passive) {
                cname = dns.resolve_cname(sub);
            }

            http_jitter();

            if (deep_passive) {

                auto resp = fast_probe(sub, HTTP_TIMEOUT);
                if (resp.http_code > 0) {
                    http_code = std::to_string(resp.http_code);
                    std::smatch ms;
                    std::regex re_srv("(?:^|\n)[Ss]erver:\\s*([^\r\n]+)");
                    if (std::regex_search(resp.headers, ms, re_srv)) {
                        server_hdr = ms[1].str();
                        if (server_hdr.size()>40) server_hdr=server_hdr.substr(0,40);
                    }
                    page_title = parse_title(resp.body);
                    if (!resp.headers.empty()) {
                        std::string cookies;
                        std::regex re_ck("(?:^|\n)[Ss]et-[Cc]ookie:\\s*([^\r\n]+)");
                        std::sregex_iterator ci(resp.headers.begin(), resp.headers.end(), re_ck), ce;
                        for (; ci!=ce; ++ci) cookies += (*ci)[1].str()+";";
                        waf  = detect_waf(resp.headers, resp.body, cookies);
                        tech = detect_tech(resp.headers, resp.body, cookies);
                    }
                }
            } else {

                long code = fast_check(sub, HTTP_TIMEOUT);
                if (code > 0) http_code = std::to_string(code);
            }
        }

        bool fp = passive_set_uset.count(sub) > 0;
        std::string source;
        if (fp && source_hint == "brute") source = "both";
        else if (source_hint == "passive") source = "passive";
        else if (fp) source = "passive";
        else source = "brute";

        SubResult sr;
        sr.sub=sub; sr.ips=ips; sr.ipv6=ipv6; sr.cname=cname;
        sr.http_code=http_code; sr.server=server_hdr; sr.title=page_title;
        sr.source=source; sr.waf=waf; sr.tech=tech; sr.doh_fallback=doh_provider;

        found_count++;
        {
            std::lock_guard<std::mutex> lk(state_mtx);
            results.push_back(sr);
            SubEntry se;
            se.sub=sr.sub; se.ips=sr.ips; se.cname=sr.cname;
            se.http_code=sr.http_code; se.server=sr.server;
            se.waf=sr.waf.name; se.language=sr.tech.language;
            se.cms=sr.tech.cms; se.source=sr.source; se.title=sr.title;
            { std::lock_guard<std::mutex> rlk(g_result_mtx); g_result.subdomains.push_back(se); }
        }
        {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << "\r" << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(42) << sub;
            for (auto& ip : ips) std::cout << WHITE << ip << " ";
            if (!ipv6.empty())   std::cout << BLOOD_RED << "[v6:" << WHITE << ipv6[0] << BLOOD_RED << "] ";
            if (!cname.empty())  std::cout << BLOOD_RED << "CNAME:" << WHITE << cname << " ";
            if (!http_code.empty() && http_code!="0") std::cout << BLOOD_RED << "HTTP:" << WHITE << http_code << " ";
            if (!server_hdr.empty())    std::cout << BLOOD_RED << "[" << WHITE << server_hdr << BLOOD_RED << "] ";
            if (!waf.name.empty())      std::cout << BLOOD_RED << "WAF:" << WHITE << waf.name << " ";
            if (!tech.language.empty()) std::cout << BLOOD_RED << tech.language << " ";
            if (!tech.cms.empty())      std::cout << BLOOD_RED << tech.cms << " ";
            if (!doh_provider.empty())  std::cout << BLOOD_RED << "[DoH:" << WHITE << doh_provider << BLOOD_RED << "]";
            std::cout << BLOOD_RED << " (" << WHITE << source << BLOOD_RED << ")" << RESET << "\n";
        }
    };

    print_section("ASYNC DNS + DoH → PIPELINE HTTP");
    std::cout << BLOOD_RED << "  wordlist: " << WHITE
              << (stream_file_wordlist ? "streaming" : "builtin")
              << BLOOD_RED << " | passive: " << WHITE << passive_subs.size()
              << BLOOD_RED << " | HTTP workers: " << WHITE << HTTP_WORKERS
              << BLOOD_RED << " | DNS batch: " << WHITE << DNS_BATCH_SIZE
              << BLOOD_RED << " | DNS concurrency: " << WHITE << DNS_CONCURRENCY
              << BLOOD_RED << " | pipeline ON\n\n" << RESET;

    PipelineQueue<DnsPending> http_pipe(500000);

    std::vector<std::thread> http_threads;
    http_threads.reserve(HTTP_WORKERS);
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
                process_resolved(item.sub, std::move(item.ips),
                                 item.doh_provider, item.source_hint);
            }
        });
    }

    auto resolve_and_queue_batch = [&](const std::vector<std::string>& batch,
                                       const std::string& source_hint,
                                       bool allow_passive_doh,
                                       const std::string& resolved_doh_provider)
    {
        if (batch.empty()) return;
        const auto* doh_allow = allow_passive_doh ? &passive_set_uset : &no_doh_allow;
        auto dns_res = dns.resolve_batch(batch, DNS_CONCURRENCY, doh_allow);

        std::vector<std::string> doh_queue;
        for (auto& [host,ips] : dns_res) {
            if (!ips.empty()) {
                http_pipe.push({host, std::move(ips), resolved_doh_provider, source_hint});
            } else if (allow_passive_doh && passive_set_uset.count(host)) {
                doh_queue.push_back(host);
            } else {
                dns_checked++;
            }
        }

        if (!doh_queue.empty()) {
            ThreadPool doh_pool(std::min((int)doh_queue.size(), 32));
            std::vector<std::future<void>> dfuts;
            for (auto& host : doh_queue) {
                dfuts.push_back(doh_pool.submit([&, h=host](){
                    subdomain_rl.acquire();
                    std::string provider;
                    auto ips = doh_query(h, "A", &provider);
                    if (!ips.empty()) {
                        doh_used++;
                        http_pipe.push({h, std::move(ips), provider, "passive"});
                    }
                    else dns_checked++;
                }));
            }
            for (auto& f : dfuts) f.get();
        }
    };

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
            std::cout << BLOOD_RED << "\r  [dns] wordlist batch " << WHITE << wordlist_batches
                      << BLOOD_RED << " size=" << WHITE << batch_size
                      << BLOOD_RED << " elapsed=" << WHITE << format_elapsed_seconds(elapsed) << BLOOD_RED << "s rate=" << WHITE << format_rate(rate) << BLOOD_RED << "/s"
                      << BLOOD_RED << " processed=" << WHITE << candidates_seen
                      << BLOOD_RED << " queued=" << WHITE << candidates_queued
                      << BLOOD_RED << " skipped=" << WHITE << candidates_skipped
                      << BLOOD_RED << " pipe=" << WHITE << http_pipe.size()
                      << BLOOD_RED << " found=" << WHITE << found_count.load()
                      << "    " << RESET << std::flush;
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

    if (stream_file_wordlist) {
        std::string line;
        while (!g_cancel_token.cancelled && std::getline(wordlist_stream, line)) {
            queue_wordlist_candidate(line);
        }
        if (wordlist_stream.bad()) {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << "\n" << BLOOD_RED << "  [!] error while reading wordlist: "
                      << WHITE << wordlist_path << "\n" << RESET;
        }
        if (!g_cancel_token.cancelled && candidates_queued == 0) {
            std::cout << BLOOD_RED << "  [!] no valid wordlist candidates, using builtin list\n" << RESET;
            for (const auto& word : builtin_wordlist()) queue_wordlist_candidate(word);
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

    if (!g_cancel_token.cancelled && !passive_subs.empty()) {
        std::cout << BLOOD_RED << "  [*] resolving " << WHITE << passive_subs.size()
                  << BLOOD_RED << " passive candidates...\n" << RESET;
        std::vector<std::string> passive_batch;
        passive_batch.reserve(DNS_BATCH_SIZE);
        for (const auto& sub : passive_subs) {
            if (g_cancel_token.cancelled) break;
            if (sub == scan_domain) continue;
            passive_batch.push_back(sub);
            if ((int)passive_batch.size() >= DNS_BATCH_SIZE) {
                resolve_and_queue_batch(passive_batch, "passive", true, "");
                passive_batch.clear();
            }
        }
        if (!g_cancel_token.cancelled) {
            resolve_and_queue_batch(passive_batch, "passive", true, "");
        }
    }

    std::set<std::string> found_snapshot;
    if (run_permutations && !g_cancel_token.cancelled) {
        std::cout << BLOOD_RED << "  [*] waiting for base HTTP pipeline...\n" << RESET;
        http_pipe.wait_idle();
        maybe_write_checkpoint(true, "base-idle");
        std::lock_guard<std::mutex> lk(state_mtx);
        found_snapshot = found_set;
    }
    if (run_permutations && !found_snapshot.empty() && !g_cancel_token.cancelled) {
        print_section("PERMUTATION ENGINE");
        std::cout << BLOOD_RED << "  [*] streaming permutations resolving...\n" << RESET;
        std::vector<std::string> perm_batch;
        perm_batch.reserve(static_cast<size_t>(DNS_BATCH_SIZE));
        size_t perm_generated = 0;
        size_t perm_queued = 0;
        size_t perm_batches = 0;

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
            if (derived_dedup.insert(candidate).second) {
                perm_batch.push_back(std::move(candidate));
                perm_queued++;
                if (perm_batch.size() >= static_cast<size_t>(DNS_BATCH_SIZE)) flush_perm_batch();
            }
        });
        if (!g_cancel_token.cancelled) flush_perm_batch();
        std::cout << BLOOD_RED << "  [=] permutations generated=" << WHITE << perm_generated
                  << BLOOD_RED << " queued=" << WHITE << perm_queued
                  << BLOOD_RED << " batches=" << WHITE << perm_batches << "\n" << RESET;
        std::cout << BLOOD_RED << "  [+] permutations queued\n" << RESET;
    }

    std::vector<std::string> js_targets;
    if (do_enrich && deep_passive && !g_cancel_token.cancelled) {
        size_t pipe_size = http_pipe.size();
        size_t found_size = current_found_size();
        std::cout << BLOOD_RED << "  [*] waiting for permutation HTTP pipeline..."
                  << BLOOD_RED << " pipe=" << WHITE << pipe_size
                  << BLOOD_RED << " found=" << WHITE << found_size << "\n" << RESET;
        http_pipe.wait_idle();
        maybe_write_checkpoint(true, "permutation-idle");
        {
            std::lock_guard<std::mutex> lk(state_mtx);
            js_targets.reserve(results.size());
            for (const auto& r : results) {
                if (!r.http_code.empty() && r.http_code != "0") js_targets.push_back(r.sub);
            }
        }
        std::cout << BLOOD_RED << "  [*] JS targets: " << WHITE << js_targets.size() << "\n" << RESET;
    }
    if (do_enrich && deep_passive && !js_targets.empty() && !g_cancel_token.cancelled) {
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
    std::cout << "\n" << BLOOD_RED << "  [*] DNS done. Waiting for "
              << http_pipe.size() << " pending HTTP enrichments...\n" << RESET;
    http_pipe.close();
    for (auto& t : http_threads) t.join();

    std::cout << "\n";

    {
        std::lock_guard<std::mutex> lk(state_mtx);
        std::sort(results.begin(), results.end(),
                  [](const SubResult& a, const SubResult& b){ return a.sub < b.sub; });
    }

    print_section("SUMMARY");
    std::cout << "\n" << BLOOD_RED << BOLD
              << "  " << std::left << std::setw(42) << "SUBDOMAIN"
              << std::setw(16) << "IPv4" << std::setw(6) << "v6"
              << std::setw(8)  << "HTTP" << std::setw(16) << "WAF"
              << std::setw(12) << "TECH" << "TITLE\n"
              << "  " << std::string(108,'-') << "\n" << RESET;

    int cnt_cname=0, cnt_waf=0, cnt_ipv6=0;
    std::map<std::string,int> server_stats, waf_stats, lang_stats, cms_stats, source_stats;

    for (auto& r : results) {
        std::cout << BLOOD_RED << "  " << WHITE << std::left << std::setw(42) << r.sub;
        if (!r.ips.empty())  std::cout << WHITE << std::setw(16) << r.ips[0];
        else                 std::cout << BLOOD_RED << std::setw(16) << "-";
        if (!r.ipv6.empty()) { std::cout << WHITE << std::setw(6) << "v6"; cnt_ipv6++; }
        else                   std::cout << BLOOD_RED << std::setw(6) << "-";
        if (!r.http_code.empty() && r.http_code!="0") std::cout << BLOOD_RED << std::setw(8) << r.http_code;
        else                                           std::cout << BLOOD_RED << std::setw(8) << "-";
        if (!r.waf.name.empty()) {
            std::string wn=r.waf.name; if(wn.size()>14) wn=wn.substr(0,14);
            std::cout << BLOOD_RED << std::setw(16) << wn; cnt_waf++;
        } else { std::cout << BLOOD_RED << std::setw(16) << "-"; }
        std::string ts=r.tech.language; if(!r.tech.cms.empty()) ts+="/"+r.tech.cms;
        if (ts.size()>12) ts=ts.substr(0,12);
        std::cout << BLOOD_RED << std::setw(12) << (ts.empty()?"-":ts);
        std::cout << WHITE << sanitize(r.title) << RESET << "\n";
        if (!r.cname.empty()) { std::cout << BLOOD_RED << "    -> CNAME: " << WHITE << r.cname << RESET << "\n"; cnt_cname++; }
        if (!r.ipv6.empty())  { std::cout << BLOOD_RED << "    -> IPv6:  " << WHITE; for (auto& a:r.ipv6) std::cout<<a<<" "; std::cout<<RESET<<"\n"; }
        if (!r.tech.stack.empty()) { std::cout << BLOOD_RED << "    -> stack: " << WHITE; for (auto& s:r.tech.stack) std::cout<<s<<" "; std::cout<<RESET<<"\n"; }
        if (!r.server.empty()) server_stats[r.server]++;
        if (!r.waf.name.empty()) waf_stats[r.waf.name]++;
        if (!r.tech.language.empty()) lang_stats[r.tech.language]++;
        if (!r.tech.cms.empty()) cms_stats[r.tech.cms]++;
        source_stats[r.source]++;
    }

    print_section("STATISTICS");
    std::cout << BLOOD_RED << "  [total found]     " << WHITE << results.size()        << "\n" << RESET;
    std::cout << BLOOD_RED << "  [dns checked]     " << WHITE << dns_checked.load()    << "\n" << RESET;
    std::cout << BLOOD_RED << "  [DoH fallbacks]   " << WHITE << doh_used.load()       << "\n" << RESET;
    std::cout << BLOOD_RED << "  [with CNAME]      " << WHITE << cnt_cname             << "\n" << RESET;
    std::cout << BLOOD_RED << "  [with IPv6]       " << WHITE << cnt_ipv6              << "\n" << RESET;
    std::cout << BLOOD_RED << "  [behind WAF]      " << WHITE << cnt_waf               << "\n" << RESET;
    std::cout << BLOOD_RED << "  [wildcard]        " << WHITE << (wildcard_fp.active?"YES":"no") << "\n" << RESET;
    std::cout << BLOOD_RED << "  [HTTP workers]    " << WHITE << HTTP_WORKERS           << "\n" << RESET;

    auto print_dist=[](const std::map<std::string,int>& m, const std::string& label){
        if (m.empty()) return;
        std::cout << BLOOD_RED << "\n  [" << WHITE << label << BLOOD_RED << "]\n" << RESET;
        std::vector<std::pair<std::string,int>> v(m.begin(),m.end());
        std::sort(v.begin(),v.end(),[](auto& a,auto& b){return a.second>b.second;});
        for (auto& [k,cnt]:v)
            std::cout<<BLOOD_RED<<"    "<<std::left<<std::setw(30)<<k<<WHITE<<cnt<<"\n"<<RESET;
    };
    print_dist(source_stats,"sources");
    print_dist(waf_stats,"WAF");
    print_dist(lang_stats,"languages");
    print_dist(cms_stats,"CMS");
    print_dist(server_stats,"server distribution");

    print_section("TAKEOVER CANDIDATES");
    bool any_takeover=false;
    int confirmed_count=0, possible_count=0;
    std::vector<std::future<void>> to_futs;
    std::mutex to_mtx;
    ThreadPool to_pool(std::min(20, (int)results.size()+1));

    {
        std::lock_guard<std::mutex> lk(state_mtx);
        for (auto& r : results) {
            if (r.cname.empty()) continue;
            std::string cl=r.cname;
            std::transform(cl.begin(),cl.end(),cl.begin(),::tolower);
            for (auto& sig : takeover_db()) {
                if (cl.find(sig.cname_pattern)==std::string::npos) continue;
                any_takeover=true;
                std::string sub_c=r.sub, cname_c=r.cname, svc_c=sig.service;
                std::vector<std::string> fps_c=sig.fingerprints;
                to_futs.push_back(to_pool.submit([&,sub_c,cname_c,svc_c,fps_c](){
                    std::string dns_check=resolve(cname_c);
                    std::string status;
                    if (dns_check.empty()) status="DANGLING_DNS";
                    else status=takeover_validate(sub_c, fps_c);
                    std::lock_guard<std::mutex> lk2(to_mtx);
                    if (status=="CONFIRMED") {
                        confirmed_count++;
                        std::cout<<BLOOD_RED<<BOLD<<"  [!!!] CONFIRMED TAKEOVER: "<<WHITE<<sub_c<<"\n"
                                 <<BLOOD_RED<<"        CNAME:   "<<WHITE<<cname_c<<"\n"
                                 <<BLOOD_RED<<"        SERVICE: "<<WHITE<<svc_c<<"\n"<<RESET;
                    } else if (status=="DANGLING_DNS"||status=="POSSIBLE") {
                        possible_count++;
                        std::cout<<BLOOD_RED<<"  [?]   POSSIBLE: "<<WHITE<<sub_c
                                 <<BLOOD_RED<<" → "<<WHITE<<cname_c
                                 <<BLOOD_RED<<" ("<<WHITE<<svc_c<<BLOOD_RED<<") — "<<WHITE<<status<<"\n"<<RESET;
                    } else {
                        std::cout<<BLOOD_RED<<"  [-]   "<<WHITE<<sub_c<<BLOOD_RED<<" → "<<WHITE<<cname_c
                                 <<BLOOD_RED<<" LIVE\n"<<RESET;
                    }
                }));
                break;
            }
        }
    }
    for (auto& f : to_futs) f.get();
    if (!any_takeover) std::cout<<BLOOD_RED<<"  no CNAME-based candidates\n"<<RESET;
    else {
        std::cout<<"\n"<<BLOOD_RED<<"  [!!!] CONFIRMED: "<<WHITE<<confirmed_count<<"\n"
                 <<BLOOD_RED<<"  [?]   POSSIBLE:  "<<WHITE<<possible_count<<"\n"<<RESET;
    }

    print_section("EXPORT");
    {
        std::lock_guard<std::mutex> lk(state_mtx);
        export_results(results, scan_domain);
    }

    LOG_INFO("subdomain_scan","done domain="+scan_domain
        +" found="+std::to_string(results.size())
        +" doh="+std::to_string(doh_used.load())
        +" workers="+std::to_string(HTTP_WORKERS));
}
