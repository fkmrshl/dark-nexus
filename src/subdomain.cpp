#include "../include/dark_nexus.hpp"
#include "../include/dns_engine.hpp"
#include <curl/curl.h>
#include <fstream>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include "../include/security.hpp"
#include "../include/user_agents.hpp"

template<typename T>
class PipelineQueue {
    std::deque<T>           q_;
    mutable std::mutex      mtx_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    bool                    closed_   = false;
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
        not_full_.notify_one();
        return true;
    }

    void close() {
        { std::lock_guard<std::mutex> lk(mtx_); closed_ = true; }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return q_.size();
    }
};

struct DnsPending {
    std::string              sub;
    std::vector<std::string> ips;
    std::string              doh_provider;
};

static RateLimiter subdomain_rl(50000.0);
static thread_local std::mt19937 tl_rng{std::random_device{}()};

static void http_jitter() {
    std::uniform_int_distribution<int> d(5, 40);
    std::this_thread::sleep_for(std::chrono::milliseconds(d(tl_rng)));
}

struct CurlResponse {
    std::string headers;
    std::string body;
    long        http_code = 0;
};

static size_t curl_hdr_cb(char* buf, size_t sz, size_t n, void* ud) {
    static_cast<CurlResponse*>(ud)->headers.append(buf, sz*n);
    return sz*n;
}

static size_t curl_body_cb(char* buf, size_t sz, size_t n, void* ud) {
    auto* r = static_cast<CurlResponse*>(ud);
    size_t bytes = sz*n;
    if (r->body.size() < 50000) {
        size_t take = std::min(bytes, 50000 - r->body.size());
        r->body.append(buf, take);
    }
    return bytes;
}

static CurlResponse libcurl_get(const std::string& url,
                                const std::string& host_hdr,
                                const std::string& ua,
                                int timeout_s = 5,
                                const std::vector<std::string>& extra_headers = {})
{
    CurlResponse resp;
    CURL* c = curl_easy_init();
    if (!c) return resp;
    struct curl_slist* hdrs = nullptr;
    if (!host_hdr.empty()) hdrs = curl_slist_append(hdrs, ("Host: "+host_hdr).c_str());
    for (auto& h : extra_headers)   hdrs = curl_slist_append(hdrs, h.c_str());
    curl_easy_setopt(c, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(c, CURLOPT_USERAGENT,     ua.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER,0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST,0L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION,1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS,     3L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,       (long)timeout_s);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL,      1L);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION,curl_hdr_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA,    &resp);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_body_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,     &resp);
    curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp.http_code);
    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    return resp;
}

static CurlResponse fast_probe(const std::string& sub, int timeout_s) {
    auto r = libcurl_get("https://"+sub, sub, random_ua(), timeout_s);
    if (r.http_code > 0) return r;
    return libcurl_get("http://"+sub, sub, random_ua(), timeout_s);
}

static long fast_check(const std::string& sub, int timeout_s) {
    CURL* c = curl_easy_init();
    if (!c) return 0;
    long code = 0;
    std::string url = "https://" + sub;
    curl_easy_setopt(c, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(c, CURLOPT_USERAGENT,     random_ua().c_str());
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER,0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST,0L);
    curl_easy_setopt(c, CURLOPT_NOBODY,        1L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION,1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS,     2L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,       (long)timeout_s);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL,      1L);
    curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    if (code > 0) return code;

    c = curl_easy_init();
    if (!c) return 0;
    url = "http://" + sub;
    curl_easy_setopt(c, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(c, CURLOPT_USERAGENT,     random_ua().c_str());
    curl_easy_setopt(c, CURLOPT_NOBODY,        1L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION,1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS,     2L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,       (long)timeout_s);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL,      1L);
    curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    return code;
}

struct WAFInfo  { std::string name, confidence; };
struct TechInfo { std::vector<std::string> stack; std::string cms, language, session_cookie; };

static const std::vector<struct WAFSig>& waf_db();
static WAFInfo  detect_waf(const std::string& hdrs, const std::string& body, const std::string& cookies);
static TechInfo detect_tech(const std::string& headers, const std::string& body, const std::string& cookies);

struct WAFSig {
    std::string name, confidence;
    std::vector<std::pair<std::string,std::string>> headers;
    std::vector<std::string> cookies, body_kw;
};

static const std::vector<WAFSig>& waf_db() {
    static const std::vector<WAFSig> db = {
        {"Cloudflare",  "high",{{"server","cloudflare"},{"cf-ray",""},{"cf-cache-status",""}},{"__cfduid","cf_clearance"},{}},
        {"Akamai",      "high",{{"x-check-cacheable",""},{"akamai-origin-hop",""},{"x-akamai-transformed",""}},{"ak_bmsc","bm_sz"},{"AkamaiGHost"}},
        {"AWS WAF",     "high",{{"x-amzn-requestid",""},{"x-amz-cf-id",""},{"x-amzn-trace-id",""}},{},{"Access Denied"}},
        {"Imperva",     "high",{{"x-iinfo",""},{"x-cdn","Incapsula"}},{"incap_ses","visid_incap"},{"Incapsula incident"}},
        {"F5 BIG-IP",   "high",{{"x-wa-info",""},{"server","BigIP"}},{"BIGipServer","F5_ST"},{}},
        {"Sucuri",      "high",{{"x-sucuri-id",""},{"x-sucuri-cache",""},{"server","Sucuri"}},{},{"Sucuri WebSite Firewall"}},
        {"Barracuda",   "medium",{{"server","barracuda"}},{"barra_counter_session"},{"Barracuda Web Application Firewall"}},
        {"ModSecurity", "medium",{{"x-mod-security-message",""}},{},{"ModSecurity","NOYB"}},
        {"Fortinet",    "high",{{"x-waf-event-info",""}},{"FORTIWAFSID"},{"FortiGate","FortiWEB"}},
        {"Citrix ADC",  "medium",{{"via","NS-CACHE"}},{"NSC_"},{}},
        {"DDoS-Guard",  "medium",{{"server","ddos-guard"}},{},{"DDoS-Guard"}},
        {"Qrator",      "medium",{{"server","qrator"}},{},{}},
        {"Wallarm",     "medium",{{"x-wallarm-node",""}},{},{}},
        {"Reblaze",     "medium",{{"x-reblaze-protection",""}},{"rbzid"},{}},
        {"Fastly",      "low",{{"x-fastly-request-id",""},{"x-varnish",""},{"via","varnish"}},{},{}},
        {"StackPath",   "medium",{{"x-sp-url",""},{"server","StackPath"}},{},{}},
    };
    return db;
}

static WAFInfo detect_waf(const std::string& hdrs, const std::string& body, const std::string& cookies) {
    auto lc = [](std::string s){ std::transform(s.begin(),s.end(),s.begin(),::tolower); return s; };
    std::string h=lc(hdrs), b=lc(body), c=lc(cookies);
    for (auto& sig : waf_db()) {
        int score=0, max=0;
        for (auto& [hn,hv] : sig.headers) {
            max++;
            std::string hnl=lc(hn), hvl=lc(hv);
            if (hvl.empty()) { if (h.find(hnl+":") != std::string::npos) score++; }
            else             { if (h.find(hvl) != std::string::npos) score++; }
        }
        for (auto& ck : sig.cookies) { max++; if (c.find(lc(ck)) != std::string::npos) score++; }
        for (auto& kw : sig.body_kw) { max++; if (b.find(lc(kw)) != std::string::npos) score++; }
        if (max > 0 && float(score)/float(max) >= 0.5f) return {sig.name, sig.confidence};
    }
    return {};
}

static TechInfo detect_tech(const std::string& headers, const std::string& body, const std::string& cookies) {
    TechInfo info;
    auto lc = [](std::string s){ std::transform(s.begin(),s.end(),s.begin(),::tolower); return s; };
    std::string h=lc(headers), b=lc(body), c=lc(cookies);
    if      (h.find("x-powered-by: php")      != std::string::npos) { info.language="PHP";     info.stack.push_back("PHP"); }
    else if (h.find("x-powered-by: asp.net")  != std::string::npos) { info.language="C#/.NET"; info.stack.push_back("ASP.NET"); }
    else if (h.find("x-powered-by: express")  != std::string::npos) { info.language="Node.js"; info.stack.push_back("Express"); }
    else if (h.find("x-powered-by: next.js")  != std::string::npos) { info.language="Node.js"; info.stack.push_back("Next.js"); }
    if      (c.find("phpsessid")         != std::string::npos) { info.session_cookie="PHPSESSID";  if(info.language.empty()) info.language="PHP"; }
    else if (c.find("jsessionid")        != std::string::npos) { info.session_cookie="JSESSIONID"; info.language="Java"; info.stack.push_back("Java/Servlet"); }
    else if (c.find("asp.net_sessionid") != std::string::npos) { info.session_cookie="ASP.NET_Session"; if(info.language.empty()) info.language="C#/.NET"; }
    else if (c.find("laravel_session")   != std::string::npos) { info.stack.push_back("Laravel"); if(info.language.empty()) info.language="PHP"; }
    else if (c.find("csrftoken")         != std::string::npos) { info.stack.push_back("Django"); if(info.language.empty()) info.language="Python"; }
    else if (c.find("_rails")            != std::string::npos) { info.stack.push_back("Rails"); if(info.language.empty()) info.language="Ruby"; }
    if      (h.find("server: nginx")             != std::string::npos) info.stack.push_back("nginx");
    else if (h.find("server: apache")            != std::string::npos) info.stack.push_back("Apache");
    else if (h.find("server: microsoft-iis")     != std::string::npos) { info.stack.push_back("IIS"); if(info.language.empty()) info.language="C#/.NET"; }
    else if (h.find("server: litespeed")         != std::string::npos) info.stack.push_back("LiteSpeed");
    else if (h.find("server: openresty")         != std::string::npos) info.stack.push_back("OpenResty");
    else if (h.find("server: caddy")             != std::string::npos) info.stack.push_back("Caddy");
    else if (h.find("server: gunicorn")          != std::string::npos) { info.stack.push_back("Gunicorn"); if(info.language.empty()) info.language="Python"; }
    if (b.find("wp-content")  != std::string::npos) info.cms="WordPress";
    else if (b.find("joomla") != std::string::npos) info.cms="Joomla";
    else if (b.find("drupal") != std::string::npos || h.find("x-drupal-cache") != std::string::npos) info.cms="Drupal";
    else if (b.find("cdn.shopify") != std::string::npos)  info.cms="Shopify";
    else if (b.find("ghost-url")   != std::string::npos)  info.cms="Ghost";
    else if (b.find("magento")     != std::string::npos)  info.cms="Magento";
    else if (b.find("bitrix")      != std::string::npos)  info.cms="Bitrix";
    if (b.find("__react")    != std::string::npos) info.stack.push_back("React");
    if (b.find("__vue__")    != std::string::npos) info.stack.push_back("Vue.js");
    if (b.find("ng-version") != std::string::npos) info.stack.push_back("Angular");
    if (b.find("__next")     != std::string::npos) info.stack.push_back("Next.js");
    if (b.find("jquery")     != std::string::npos) info.stack.push_back("jQuery");
    if (h.find("x-amz-")    != std::string::npos) info.stack.push_back("AWS");
    if (h.find("x-ms-")     != std::string::npos) info.stack.push_back("Azure");
    if (h.find("x-goog-")   != std::string::npos) info.stack.push_back("GCP");
    std::sort(info.stack.begin(), info.stack.end());
    info.stack.erase(std::unique(info.stack.begin(), info.stack.end()), info.stack.end());
    return info;
}

static void extract_subs(const std::string& text, const std::string& domain, std::set<std::string>& out) {
    std::string pat = "([a-zA-Z0-9_\\-]+(?:\\.[a-zA-Z0-9_\\-]+)*\\."+domain+")";
    std::regex re(pat, std::regex::icase);
    std::sregex_iterator it(text.begin(), text.end(), re), end;
    for (; it != end; ++it) {
        std::string h = (*it)[1].str();
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
        if (h.size() > domain.size() && h.substr(h.size()-domain.size()) == domain) out.insert(h);
    }
}

static void passive_crtsh(const std::string& domain, std::set<std::string>& out) {
    auto body = safe_curl("https://crt.sh/?q=%25."+domain+"&output=json", 20);
    if (body.empty()) return;
    std::regex re("\"(?:common_name|name_value)\"\\s*:\\s*\"([^\"]+)\"");
    std::sregex_iterator it(body.begin(), body.end(), re), end;
    for (; it != end; ++it) {
        std::string val = (*it)[1].str();
        std::istringstream vss(val); std::string part;
        while (std::getline(vss, part, '\n')) {
            if (part.size()>2 && part[0]=='*' && part[1]=='.') part=part.substr(2);
            std::transform(part.begin(),part.end(),part.begin(),::tolower);
            if (part.size()>domain.size() && part.substr(part.size()-domain.size())==domain) out.insert(part);
        }
    }
}
static void passive_hackertarget(const std::string& domain, std::set<std::string>& out) {
    auto body = safe_curl("https://api.hackertarget.com/hostsearch/?q="+domain, 15);
    if (body.empty() || body.find("error")!=std::string::npos) return;
    std::istringstream ss(body); std::string line;
    while (std::getline(ss, line)) {
        auto c = line.find(',');
        if (c==std::string::npos) continue;
        std::string sub = line.substr(0, c);
        std::transform(sub.begin(),sub.end(),sub.begin(),::tolower);
        if (sub.size()>domain.size() && sub.substr(sub.size()-domain.size())==domain) out.insert(sub);
    }
}
static void passive_alienvault(const std::string& d, std::set<std::string>& out)   { auto b=safe_curl("https://otx.alienvault.com/api/v1/indicators/domain/"+d+"/passive_dns",15); if(!b.empty()){extract_subs(b,d,out);} }
static void passive_urlscan(const std::string& d, std::set<std::string>& out)      { auto b=safe_curl("https://urlscan.io/api/v1/search/?q=domain:"+d+"&size=200",15); if(!b.empty()){extract_subs(b,d,out);} }
static void passive_rapiddns(const std::string& d, std::set<std::string>& out)     { auto b=safe_curl("https://rapiddns.io/subdomain/"+d+"?full=1&down=1",15); if(!b.empty()){extract_subs(b,d,out);} }
static void passive_threatcrowd(const std::string& d, std::set<std::string>& out)  { auto b=safe_curl("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+d,15); if(!b.empty()){extract_subs(b,d,out);} }

static void passive_dnsdumpster(const std::string& domain, std::set<std::string>& out) {
    CURL* c = curl_easy_init(); if (!c) return;
    std::string get_body, post_body;
    auto cb = +[](char* p, size_t s, size_t n, void* u) -> size_t { static_cast<std::string*>(u)->append(p, s*n); return s*n; };
    curl_easy_setopt(c, CURLOPT_URL, "https://dnsdumpster.com/");
    curl_easy_setopt(c, CURLOPT_USERAGENT, random_ua().c_str());
    curl_easy_setopt(c, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &get_body);
    if (curl_easy_perform(c) != CURLE_OK) { curl_easy_cleanup(c); return; }
    std::regex re_c("csrfmiddlewaretoken.*?value=['\"]([^'\"]+)['\"]", std::regex::icase);
    std::smatch m;
    if (!std::regex_search(get_body, m, re_c)) { curl_easy_cleanup(c); return; }
    std::string post_data = "csrfmiddlewaretoken="+m[1].str()+"&targetip="+domain+"&user=free";
    struct curl_slist* hdrs = curl_slist_append(nullptr, "Referer: https://dnsdumpster.com/");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &post_body);
    if (curl_easy_perform(c) == CURLE_OK && !post_body.empty()) extract_subs(post_body, domain, out);
    curl_slist_free_all(hdrs); curl_easy_cleanup(c);
}
static void passive_virustotal(const std::string& d, std::set<std::string>& out) {
    const char* k = getenv("VT_API_KEY"); if (!k||!*k) return;
    auto resp = libcurl_get("https://www.virustotal.com/api/v3/domains/"+d+"/subdomains?limit=40", "", random_ua(), 15, {"x-apikey: "+std::string(k)});
    if (resp.body.empty()) return; extract_subs(resp.body, d, out);
    std::regex re_c("\"cursor\"\\s*:\\s*\"([^\"]+)\""); std::smatch mc;
    if (std::regex_search(resp.body, mc, re_c)) {
        auto resp2 = libcurl_get("https://www.virustotal.com/api/v3/domains/"+d+"/subdomains?limit=40&cursor="+mc[1].str(), "", random_ua(), 15, {"x-apikey: "+std::string(k)});
        if (!resp2.body.empty()) extract_subs(resp2.body, d, out);
    }
}
static void passive_securitytrails(const std::string& d, std::set<std::string>& out) {
    const char* k = getenv("ST_API_KEY"); if (!k||!*k) return;
    auto resp = libcurl_get("https://api.securitytrails.com/v1/domain/"+d+"/subdomains?children_only=false&include_inactive=true", "", random_ua(), 15, {"apikey: "+std::string(k), "Accept: application/json"});
    if (!resp.body.empty()) extract_subs(resp.body, d, out);
}
static void passive_shodan(const std::string& d, std::set<std::string>& out) {
    const char* k = getenv("SHODAN_API_KEY"); if (!k||!*k) return;
    auto resp = libcurl_get("https://api.shodan.io/dns/domain/"+d+"?key="+std::string(k), "", random_ua(), 15);
    if (!resp.body.empty()) extract_subs(resp.body, d, out);
}
static void passive_censys(const std::string& d, std::set<std::string>& out) {
    const char* ai = getenv("CENSYS_API_ID"); const char* as_ = getenv("CENSYS_API_SECRET");
    if (!ai||!*ai||!as_||!*as_) return;
    CURL* c = curl_easy_init(); if (!c) return;
    std::string body;
    auto cb = +[](char* p, size_t s, size_t n, void* u) -> size_t { static_cast<std::string*>(u)->append(p, s*n); return s*n; };
    struct curl_slist* hdrs = curl_slist_append(nullptr, "Content-Type: application/json");
    std::string auth = std::string(ai)+":"+std::string(as_);
    std::string post = "{\"q\":\""+d+"\",\"fields\":[\"parsed.names\"],\"flatten\":true}";
    curl_easy_setopt(c, CURLOPT_URL, "https://search.censys.io/api/v1/search/certificates");
    curl_easy_setopt(c, CURLOPT_USERAGENT, random_ua().c_str());
    curl_easy_setopt(c, CURLOPT_USERPWD, auth.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, post.c_str());
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    if (curl_easy_perform(c) == CURLE_OK && !body.empty()) extract_subs(body, d, out);
    curl_slist_free_all(hdrs); curl_easy_cleanup(c);
}

static void dns_extra_records(const std::string& domain, std::set<std::string>& out) {
    for (auto& type : {"MX","TXT","NS","SRV"}) {
        auto res = safe_exec({"dig","+short","+time=5","+tries=2",domain,type}, 8);
        if (res.empty()) continue;
        extract_subs(res, domain, out);
        for (auto& line : split_lines(res)) {
            std::transform(line.begin(), line.end(), line.begin(), ::tolower);
            while (!line.empty() && line.back()=='.') line.pop_back();
            if (line.size()>domain.size() && line.substr(line.size()-domain.size())==domain) out.insert(line);
        }
    }
}

static std::vector<std::string> doh_query(const std::string& hostname,
                                          const std::string& type = "A",
                                          std::string* prov = nullptr)
{
    if (!InputGuard::is_valid_host(hostname)) return {};
    const std::vector<std::pair<std::string,std::string>> providers = {
        {"cloudflare", "https://cloudflare-dns.com/dns-query?name="+hostname+"&type="+type},
        {"google",     "https://dns.google/resolve?name="+hostname+"&type="+type},
    };
    for (auto& [name, url] : providers) {
        auto resp = libcurl_get(url, "", random_ua(), 6, {"Accept: application/dns-json"});
        if (resp.body.empty()) continue;
        std::vector<std::string> addrs;
        std::regex re("\"data\"\\s*:\\s*\"([0-9a-fA-F.:]+)\"");
        std::sregex_iterator it(resp.body.begin(), resp.body.end(), re), end;
        for (; it != end; ++it) {
            std::string a = (*it)[1].str();
            if (a.find('.')!=std::string::npos || a.find(':')!=std::string::npos) addrs.push_back(a);
        }
        if (!addrs.empty()) { if (prov) *prov = name; return addrs; }
    }
    return {};
}

std::string auto_find_wordlist() {
    std::vector<char> buf(256, 0); std::string loc_res;
    FILE* pipe = popen("locate best-dns-wordlist.txt 2>/dev/null | head -n 1", "r");
    if (pipe) {
        if (fgets(buf.data(), (int)buf.size(), pipe)) loc_res = buf.data();
        pclose(pipe);
        if (!loc_res.empty()) {
            if (loc_res.back()=='\n') loc_res.pop_back();
            if (access(loc_res.c_str(), F_OK)==0) return loc_res;
        }
    }
    const char* h_env = getenv("HOME");
    std::string h = h_env ? h_env : "/root";
    for (auto& p : std::vector<std::string>{
        "./best-dns-wordlist.txt",
        h+"/best-dns-wordlist.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-500000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-500000.txt",
        "/opt/SecLists/Discovery/DNS/subdomains-top1million-500000.txt",
        "/opt/wordlists/best-dns-wordlist.txt",
        h+"/wordlists/subdomains-top1million-500000.txt",
    }) { if (access(p.c_str(), F_OK)==0) return p; }
    return "";
}

static std::vector<std::string> load_wordlist_file(const std::string& path) {
    if (!InputGuard::is_safe_path(path)) return {};
    std::vector<std::string> words;
    std::ifstream f(path);
    if (!f.is_open()) return words;
    words.reserve(10000000);
    std::string line;
    while (std::getline(f, line)) {
        auto s = line.find_first_not_of(" \t\r\n");
        if (s==std::string::npos) continue;
        line = line.substr(s);
        auto e = line.find_last_not_of(" \t\r\n");
        if (e!=std::string::npos) line = line.substr(0, e+1);
        if (line.empty() || line[0]=='#') continue;
        auto dot = line.find('.');
        words.push_back(dot==std::string::npos ? line : line.substr(0, dot));
    }
    return words;
}

static const std::vector<std::string>& builtin_wordlist() {
    static const std::vector<std::string> wl = {
        "www","mail","ftp","admin","api","dev","test","staging","blog","shop",
        "cdn","static","vpn","remote","portal","app","m","mobile","secure",
        "login","dashboard","panel","cpanel","webmail","smtp","pop","imap",
        "store","web","cloud","media","video","img","images","assets","forum",
        "news","support","help","docs","wiki","status","git","gitlab","jenkins",
        "jira","beta","alpha","demo","sandbox","uat","qa","stage","preprod",
        "prod","production","server","server1","server2","host","node","edge",
        "lb","proxy","cache","gateway","relay","backup","old","new","ns1","ns2",
        "ns3","ns4","dns","dns1","dns2","mx","mx1","mx2","mail2","mail3",
        "www1","www2","www3","web1","web2","ftp2","pop3","smtp2","exchange",
        "owa","outlook","office","sso","auth","oauth","ldap","intranet",
        "extranet","internal","external","corp","corporate","manage","console",
        "cms","wp","wordpress","joomla","drupal","magento","crm","erp","hr",
        "billing","pay","payment","checkout","autodiscover","autoconfig","whm",
        "plesk","directadmin","doc","kb","knowledge","learning","lms","edu",
        "upload","download","file","files","share","transfer","data","archive",
        "mirror","repo","repository","pkg","packages","npm","pip","gem","maven",
        "docker","registry","k8s","kube","kubernetes","swarm","ecs","lambda",
        "functions","serverless","run","compute","batch","job","jobs","worker",
        "workers","task","tasks","queue","mq","amqp","rabbit","kafka",
        "db","db1","db2","db3","db4","db5","database","sql","mysql","postgres",
        "pgsql","postgresql","mongo","mongodb","redis","memcached","elastic",
        "elasticsearch","es","solr","cassandra","mariadb","oracle","mssql",
        "neo4j","couchdb","dynamodb","influxdb","clickhouse","rds","aurora",
        "grafana","kibana","prometheus","nagios","zabbix","datadog","splunk",
        "sentry","newrelic","uptime","monitor","ci","cd","build","deploy",
        "release","argocd","vault","consul","traefik","envoy","waf","firewall",
        "cert","pki","acme","rabbitmq","nats","events","stream","websocket",
        "ws","hook","webhooks","s3","minio","storage","blob","bucket",
        "cdn1","cdn2","origin","edge1","edge2","api1","api2","api3","gw",
        "core","mgmt","management","noc","ipmi","ilo","ntp","log","logs",
        "analytics","metrics","stats","telemetry","jaeger","zipkin",
        "us","eu","ap","us-east","us-west","eu-west","eu-central",
        "dev1","dev2","test1","test2","stg","prd","canary","green","blue",
        "accounts","signup","register","reset","token","callback","redirect",
        "preview","draft","temp","debug","health","healthz","readyz","ping",
        "v1","v2","v3","graphql","rest","grpc","int","internal","private",
        "dc","dc1","dc2","ldaps","radius","chat","xmpp","voip","sip",
        "app1","app2","app3","backend","frontend","service","services","micro",
    };
    return wl;
}

static std::vector<std::string> generate_permutations(const std::set<std::string>& found,
                                                      const std::string& domain)
{
    static const std::vector<std::string> affixes = {
        "1","2","3","4","old","new","dev","test","stg","prod","api","app",
        "backend","internal","admin","v2","v3","beta","alpha","legacy","tmp",
        "uat","qa","staging","preprod","corp","int","secure","cloud"
    };
    std::set<std::string> perms;
    for (auto& sub : found) {
        std::string label = sub;
        auto dot = sub.find('.');
        if (dot!=std::string::npos) label = sub.substr(0, dot);
        if (label.empty()) continue;
        for (auto& af : affixes) {
            perms.insert(label+"-"+af+"."+domain);
            perms.insert(label+af+"."+domain);
            perms.insert(af+"-"+label+"."+domain);
            perms.insert(af+label+"."+domain);
        }
    }
    return {perms.begin(), perms.end()};
}

struct SubResult {
    std::string sub, cname, http_code, server, title, source, doh_fallback;
    std::vector<std::string> ips, ipv6;
    WAFInfo  waf;
    TechInfo tech;
};

static std::string parse_title(const std::string& body) {
    std::regex re_t("<title[^>]*>([^<]{1,100})</title>", std::regex::icase);
    std::smatch mt;
    if (!std::regex_search(body, mt, re_t)) return "";
    std::string t = mt[1].str();
    auto a = t.find_first_not_of(" \t\r\n");
    auto z = t.find_last_not_of(" \t\r\n");
    if (a==std::string::npos) return "";
    t = t.substr(a, z-a+1);
    if (t.size()>60) t = t.substr(0,60)+"...";
    return t;
}

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
        std::ofstream f(fname); f << "[\n";
        auto arr_s=[](const std::vector<std::string>& v){
            std::string s="["; for(size_t j=0;j<v.size();j++){if(j)s+=",";s+="\""+v[j]+"\"";}return s+"]";
        };
        for (size_t i=0; i<results.size(); i++) {
            auto& r=results[i];
            f<<"  {\n"
             <<"    \"subdomain\": \""<<r.sub<<"\",\n"
             <<"    \"source\": \""<<r.source<<"\",\n"
             <<"    \"ipv4\": "<<arr_s(r.ips)<<",\n"
             <<"    \"ipv6\": "<<arr_s(r.ipv6)<<",\n"
             <<"    \"cname\": \""<<r.cname<<"\",\n"
             <<"    \"http_code\": \""<<r.http_code<<"\",\n"
             <<"    \"server\": \""<<r.server<<"\",\n"
             <<"    \"title\": \""<<r.title<<"\",\n"
             <<"    \"waf\": \""<<r.waf.name<<"\",\n"
             <<"    \"language\": \""<<r.tech.language<<"\",\n"
             <<"    \"cms\": \""<<r.tech.cms<<"\",\n"
             <<"    \"stack\": "<<arr_s(r.tech.stack)<<",\n"
             <<"    \"doh_fallback\": \""<<r.doh_fallback<<"\"\n"
             <<"  }"<<(i+1<results.size()?",":"")<<"\n";
        }
        f<<"]\n";
        std::cout<<BLOOD_RED<<"  [+] JSON: "<<WHITE<<fname<<"\n"<<RESET;
    }
    {
        std::string fname = domain+"_subdomains.csv";
        std::ofstream f(fname);
        f<<"subdomain,ipv4,cname,http_code,server,title,waf,language,cms,source\r\n";
        auto js=[](const std::vector<std::string>& v){std::string s;for(auto& x:v){if(!s.empty())s+=" ";s+=x;}return s;};
        auto q=[](const std::string& s){return s.find(',')!=std::string::npos?"\""+s+"\"":s;};
        for (auto& r : results) {
            f<<r.sub<<","<<q(js(r.ips))<<","<<r.cname<<","<<r.http_code<<","
             <<q(r.server)<<","<<q(r.title)<<","<<r.waf.name<<","
             <<r.tech.language<<","<<r.tech.cms<<","<<r.source<<"\r\n";
        }
        std::cout<<BLOOD_RED<<"  [+] CSV:  "<<WHITE<<fname<<"\n"<<RESET;
    }
}

static void scrape_js_subdomains(const std::vector<SubResult>& found,
                                 const std::string& domain,
                                 std::set<std::string>& out)
{
    std::set<std::string> js_urls;
    for (auto& r : found) {
        if (r.http_code.empty() || r.http_code=="0") continue;
        auto resp = libcurl_get("http://"+r.sub, r.sub, random_ua(), 8);
        if (resp.body.empty()) continue;
        std::regex re_js("(?:src|href)=['\"]([^'\"]+\\.js[^'\"]*)['\"]", std::regex::icase);
        std::sregex_iterator it(resp.body.begin(), resp.body.end(), re_js), end;
        for (; it!=end; ++it) {
            std::string src=(*it)[1].str();
            if (src.substr(0,4)=="http") js_urls.insert(src);
            else if (src[0]=='/') js_urls.insert("http://"+r.sub+src);
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
                    int ,
                    bool run_permutations,
                    bool deep_passive,
                    bool do_enrich)
{
    print_header("SUBDOMAIN SCAN // " + domain);
    curl_global_init(CURL_GLOBAL_ALL);

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

    const int HTTP_WORKERS = do_enrich ? 200 : 50;
    const int HTTP_TIMEOUT = deep_passive ? 5 : 3;
    const int DNS_BATCH_SIZE = deep_passive ? 50000 : 10000;

    std::cout << BLOOD_RED << "  [*] mode: " << WHITE << (deep_passive ? "DEEP" : "FAST")
              << BLOOD_RED << " | HTTP workers: " << WHITE << HTTP_WORKERS
              << BLOOD_RED << " | DNS batch: " << WHITE << DNS_BATCH_SIZE
              << BLOOD_RED << " | DNS channels: " << WHITE << "16 × 1000\n" << RESET;

    print_section("WORDLIST");
    std::vector<std::string> wordlist;
    if (!wordlist_path.empty()) {
        wordlist = load_wordlist_file(wordlist_path);
        if (!wordlist.empty())
            std::cout << BLOOD_RED << "  [+] " << WHITE << wordlist.size()
                      << BLOOD_RED << " words: " << WHITE << wordlist_path << "\n" << RESET;
    }
    if (wordlist.empty()) {
        wordlist = builtin_wordlist();
        std::cout << BLOOD_RED << "  [*] builtin (" << WHITE << wordlist.size() << BLOOD_RED << " words)\n" << RESET;
    }

    print_section("WILDCARD CHECK");
    std::unordered_set<std::string> wildcard_ips;
    std::atomic<bool> has_wildcard{false};
    {
        std::vector<std::string> probes;
        for (int i=0; i<5; i++) {
            std::string s;
            for (int j=0; j<16; j++) s += char('a'+tl_rng()%26);
            probes.push_back(s+"."+domain);
        }
        auto wc = dns.resolve_batch(probes, 10);
        for (auto& [h,ips] : wc)
            for (auto& ip : ips) { has_wildcard=true; wildcard_ips.insert(ip); }
    }
    if (has_wildcard) {
        std::cout << BLOOD_RED << "  [!] wildcard detected:";
        for (auto& ip : wildcard_ips) std::cout << WHITE << " " << ip;
        std::cout << BLOOD_RED << " — filtering ON\n" << RESET;
    } else {
        std::cout << BLOOD_RED << "  [+] no wildcard\n" << RESET;
    }

    print_section("PASSIVE ENUM");
    std::set<std::string> passive_subs;
    std::mutex passive_mtx;

    std::cout << BLOOD_RED << "  [*] " << WHITE << "crt.sh" << BLOOD_RED << "...\n" << RESET;
    passive_crtsh(domain, passive_subs);
    std::cout << BLOOD_RED << "  [+] crt.sh +" << WHITE << passive_subs.size() << "\n" << RESET;

    if (deep_passive) {

        struct PassiveTask { std::string name; std::function<void(std::set<std::string>&)> fn; };
        std::vector<PassiveTask> tasks = {
            {"HackerTarget",   [&](std::set<std::string>& o){ passive_hackertarget(domain,o); }},
            {"AlienVault OTX", [&](std::set<std::string>& o){ passive_alienvault(domain,o); }},
            {"urlscan.io",     [&](std::set<std::string>& o){ passive_urlscan(domain,o); }},
            {"RapidDNS",       [&](std::set<std::string>& o){ passive_rapiddns(domain,o); }},
            {"ThreatCrowd",    [&](std::set<std::string>& o){ passive_threatcrowd(domain,o); }},
            {"DNSDumpster",    [&](std::set<std::string>& o){ passive_dnsdumpster(domain,o); }},
            {"MX/TXT/NS/SRV", [&](std::set<std::string>& o){ dns_extra_records(domain,o); }},
        };
        if (getenv("VT_API_KEY"))     tasks.push_back({"VirusTotal",     [&](std::set<std::string>& o){ passive_virustotal(domain,o); }});
        if (getenv("ST_API_KEY"))     tasks.push_back({"SecurityTrails", [&](std::set<std::string>& o){ passive_securitytrails(domain,o); }});
        if (getenv("SHODAN_API_KEY")) tasks.push_back({"Shodan",         [&](std::set<std::string>& o){ passive_shodan(domain,o); }});
        if (getenv("CENSYS_API_ID"))  tasks.push_back({"Censys",         [&](std::set<std::string>& o){ passive_censys(domain,o); }});

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

    std::unordered_set<std::string> dedup;
    dedup.reserve(wordlist.size() + passive_subs.size() + 1000);
    std::vector<std::string> all_subs;
    all_subs.reserve(wordlist.size() + passive_subs.size());

    for (auto& w : wordlist) {
        std::string full = w+"."+domain;
        if (dedup.insert(full).second) all_subs.push_back(full);
    }
    for (auto& s : passive_subs) {
        if (s!=domain && dedup.insert(s).second) all_subs.push_back(s);
    }
    int total_hosts = (int)all_subs.size();

    std::mutex state_mtx;
    std::vector<SubResult>  results;
    std::set<std::string>   found_set;
    std::unordered_map<std::string,std::string> seen_ip_primary;
    std::atomic<int> found_count{0}, dns_checked{0}, doh_used{0}, ip_dedup_hits{0};
    std::unordered_set<std::string> wordlist_set(wordlist.begin(), wordlist.end());
    std::unordered_set<std::string> passive_set_uset(passive_subs.begin(), passive_subs.end());
    std::unordered_set<std::string> passive_set_copy = passive_set_uset;

    auto process_resolved = [&](const std::string& sub,
                                std::vector<std::string> ips,
                                const std::string& doh_provider)
    {

        if (has_wildcard) {
            bool all_wc = true;
            for (auto& ip : ips) { if (!wildcard_ips.count(ip)) { all_wc=false; break; } }
            if (all_wc) { dns_checked++; return; }
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
                auto co = safe_exec({"dig","+short","+time=1","+tries=1",sub,"CNAME"}, 2);
                if (!co.empty()) {
                    auto lines = split_lines(co);
                    if (!lines.empty()) {
                        cname = lines[0];
                        while (!cname.empty() && cname.back()=='.') cname.pop_back();
                    }
                }
            }

            std::string primary_ip = ips.empty() ? "" : ips[0];
            std::string seen_sub;
            {
                std::lock_guard<std::mutex> lk(state_mtx);
                auto it = seen_ip_primary.find(primary_ip);
                if (it!=seen_ip_primary.end()) { seen_sub=it->second; }
                else { seen_ip_primary[primary_ip]=sub; }
            }

            if (!seen_sub.empty() && !primary_ip.empty()) {
                ip_dedup_hits++;
                std::lock_guard<std::mutex> lk(state_mtx);
                for (auto& r : results) {
                    if (r.sub==seen_sub) {
                        http_code=r.http_code; server_hdr=r.server;
                        page_title=r.title; waf=r.waf; tech=r.tech;
                        break;
                    }
                }
            } else {
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
        }

        bool fp = passive_set_uset.count(sub) > 0;
        std::string prefix = sub.size()>domain.size()+1 ? sub.substr(0, sub.size()-domain.size()-1) : sub;
        bool fw = wordlist_set.count(prefix) > 0;
        std::string source = (fp&&fw) ? "both" : fp ? "passive" : "brute";

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
    std::cout << BLOOD_RED << "  total: " << WHITE << total_hosts << BLOOD_RED << " subdomains | "
              << WHITE << HTTP_WORKERS << BLOOD_RED << " HTTP workers | pipeline ON\n\n" << RESET;

    PipelineQueue<DnsPending> http_pipe(500000);

    std::vector<std::thread> http_threads;
    http_threads.reserve(HTTP_WORKERS);
    for (int i=0; i<HTTP_WORKERS; i++) {
        http_threads.emplace_back([&](){
            DnsPending item;
            while (http_pipe.pop(item)) {
                process_resolved(item.sub, item.ips, item.doh_provider);
            }
        });
    }

    const std::unordered_set<std::string>* passive_ptr = &passive_set_copy;

    for (int bs=0; bs<total_hosts && !g_cancel_token.cancelled; bs+=DNS_BATCH_SIZE) {
        int be = std::min(bs+DNS_BATCH_SIZE, total_hosts);
        std::vector<std::string> batch(all_subs.begin()+bs, all_subs.begin()+be);

        int batch_num = bs/DNS_BATCH_SIZE+1;
        int total_batches = (total_hosts+DNS_BATCH_SIZE-1)/DNS_BATCH_SIZE;
        {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << BLOOD_RED << "\r  [dns] " << batch_num << "/" << total_batches
                      << " (" << batch.size() << " hosts) pipe=" << http_pipe.size()
                      << " found=" << found_count.load() << "    " << RESET << std::flush;
        }

        auto dns_res = dns.resolve_batch(batch, 2000, passive_ptr);

        std::vector<std::string> doh_queue;

        for (auto& [host,ips] : dns_res) {
            if (!ips.empty()) {

                http_pipe.push({host, ips, ""});
            } else if (passive_set_uset.count(host)) {
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
                    if (!ips.empty()) { doh_used++; http_pipe.push({h, ips, provider}); }
                    else dns_checked++;
                }));
            }
            for (auto& f : dfuts) f.get();
        }

        draw_progress(be, total_hosts, "dns " + std::to_string(found_count.load())+" found");
    }

    if (run_permutations && !found_set.empty() && !g_cancel_token.cancelled) {
        print_section("PERMUTATION ENGINE");
        auto perms = generate_permutations(found_set, domain);
        std::vector<std::string> new_perms;
        new_perms.reserve(perms.size());
        for (auto& p : perms) {
            if (dedup.insert(p).second) new_perms.push_back(p);
        }
        std::cout << BLOOD_RED << "  [*] " << WHITE << new_perms.size()
                  << BLOOD_RED << " permutations resolving...\n" << RESET;
        if (!new_perms.empty()) {
            for (int bs=0; bs<(int)new_perms.size() && !g_cancel_token.cancelled; bs+=DNS_BATCH_SIZE) {
                int be = std::min(bs+DNS_BATCH_SIZE, (int)new_perms.size());
                std::vector<std::string> batch(new_perms.begin()+bs, new_perms.begin()+be);
                auto pres = dns.resolve_batch(batch, 2000);
                for (auto& [h,ips] : pres) {
                    if (!ips.empty()) http_pipe.push({h, ips, ""});
                    else dns_checked++;
                }
            }
        }
        std::cout << BLOOD_RED << "  [+] permutations queued\n" << RESET;
    }

    if (do_enrich && deep_passive && !results.empty() && !g_cancel_token.cancelled) {
        print_section("JS SCRAPING");
        std::set<std::string> js_subs;
        {
            std::lock_guard<std::mutex> lk(state_mtx);
            scrape_js_subdomains(results, domain, js_subs);
        }
        std::vector<std::string> new_js;
        for (auto& s : js_subs) {
            if (dedup.insert(s).second) new_js.push_back(s);
        }
        std::cout << BLOOD_RED << "  [*] " << WHITE << new_js.size()
                  << BLOOD_RED << " new JS candidates resolving...\n" << RESET;
        if (!new_js.empty()) {
            auto jres = dns.resolve_batch(new_js, 2000);
            for (auto& [h,ips] : jres) {
                if (!ips.empty()) http_pipe.push({h, ips, "js"});
                else dns_checked++;
            }
        }
    }

    std::cout << "\n" << BLOOD_RED << "  [*] DNS done. Waiting for "
              << http_pipe.size() << " pending HTTP enrichments...\n" << RESET;
    http_pipe.close();
    for (auto& t : http_threads) t.join();

    curl_global_cleanup();
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
    std::cout << BLOOD_RED << "  [IP dedup hits]   " << WHITE << ip_dedup_hits.load()  << "\n" << RESET;
    std::cout << BLOOD_RED << "  [with CNAME]      " << WHITE << cnt_cname             << "\n" << RESET;
    std::cout << BLOOD_RED << "  [with IPv6]       " << WHITE << cnt_ipv6              << "\n" << RESET;
    std::cout << BLOOD_RED << "  [behind WAF]      " << WHITE << cnt_waf               << "\n" << RESET;
    std::cout << BLOOD_RED << "  [wildcard]        " << WHITE << (has_wildcard.load()?"YES":"no") << "\n" << RESET;
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
        export_results(results, domain);
    }

    LOG_INFO("subdomain_scan","done domain="+domain
        +" found="+std::to_string(results.size())
        +" doh="+std::to_string(doh_used.load())
        +" workers="+std::to_string(HTTP_WORKERS));
}
