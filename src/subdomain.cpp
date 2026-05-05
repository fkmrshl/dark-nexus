#include "../include/dark_nexus.hpp"
#include "../include/dns_engine.hpp"
#include <curl/curl.h>
#include <fstream>
#include <random>
#include <unordered_map>
#include "../include/security.hpp"

static RateLimiter subdomain_rl(50000.0);
static std::atomic<int>        g_http_slots{15};
static std::mutex              g_http_mtx;
static std::condition_variable g_http_cv;

static void http_acquire() {
    std::unique_lock<std::mutex> lk(g_http_mtx);
    g_http_cv.wait(lk, []{ return g_http_slots.load() > 0; });
    --g_http_slots;
}

static void http_release() {
    ++g_http_slots;
    g_http_cv.notify_one();
}

struct HttpSlotGuard {
    HttpSlotGuard()                                = default;
    ~HttpSlotGuard()                               { if (acquired_) { http_release(); } }
    void acquire()                                 { http_acquire(); acquired_ = true; }
    HttpSlotGuard(const HttpSlotGuard&)            = delete;
    HttpSlotGuard& operator=(const HttpSlotGuard&) = delete;
private:
    bool acquired_ = false;
};

static thread_local std::mt19937 tl_rng{std::random_device{}()};

static void http_jitter() {
    std::uniform_int_distribution<int> d(10, 80);
    std::this_thread::sleep_for(std::chrono::milliseconds(d(tl_rng)));
}

static const std::string& random_ua() {
    static const std::vector<std::string> pool = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "curl/8.7.1",
        "python-requests/2.31.0",
    };
    std::uniform_int_distribution<size_t> d(0, pool.size()-1);
    return pool[d(tl_rng)];
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
                                int timeout_s = 6)
{
    CurlResponse resp;
    CURL* c = curl_easy_init();
    if (!c) { return resp; }
    struct curl_slist* hdrs = nullptr;
    if (!host_hdr.empty()) {
        hdrs = curl_slist_append(hdrs, ("Host: "+host_hdr).c_str());
    }
    curl_easy_setopt(c, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(c, CURLOPT_USERAGENT,      ua.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS,      3L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,        (long)timeout_s);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL,       1L);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, curl_hdr_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA,     &resp);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,  curl_body_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,      &resp);
    curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp.http_code);
    if (hdrs) { curl_slist_free_all(hdrs); }
    curl_easy_cleanup(c);
    return resp;
}

static long libcurl_check(const std::string& url, const std::string& ua, int timeout_s = 3) {
    CURL* c = curl_easy_init();
    if (!c) { return 0; }
    long code = 0;
    curl_easy_setopt(c, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(c, CURLOPT_USERAGENT,     ua.c_str());
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
    return code;
}

struct WAFInfo  { std::string name, confidence; };
struct TechInfo { std::vector<std::string> stack; std::string cms, language, session_cookie; };
struct SubResult {
    std::string sub, cname, http_code, server, title, source, doh_fallback;
    std::vector<std::string> ips, ipv6;
    WAFInfo  waf;
    TechInfo tech;
};

std::string auto_find_wordlist() {
    std::vector<char> buf(256, 0); std::string loc_res;
    FILE* pipe = popen("locate best-dns-wordlist.txt 2>/dev/null | head -n 1", "r");
    if (pipe) {
        if (fgets(buf.data(), (int)buf.size(), pipe)) { loc_res = buf.data(); }
        pclose(pipe);
        if (!loc_res.empty()) {
            if (loc_res.back() == '\n') { loc_res.pop_back(); }
            if (access(loc_res.c_str(), F_OK) == 0) { return loc_res; }
        }
    }
    const char* h_env = getenv("HOME");
    std::string h = h_env ? h_env : "/root";
    for (auto& p : std::vector<std::string>{
        "./best-dns-wordlist.txt",
         h+"/best-dns-wordlist.txt",
         h+"/wordlists/best-dns-wordlist.txt",
         "/usr/share/wordlists/best-dns-wordlist.txt",
         "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
         "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
         "/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt",
         "/opt/wordlists/best-dns-wordlist.txt",
    }) {
        if (access(p.c_str(), F_OK) == 0) { return p; }
    }
    return "";
}

static std::vector<std::string> load_wordlist_file(const std::string& path) {
    if (!InputGuard::is_safe_path(path)) return {};
    std::vector<std::string> words;
    std::ifstream f(path);
    if (!f.is_open()) { return words; }
    std::string line;
    while (std::getline(f, line)) {
        auto s = line.find_first_not_of(" \t\r\n");
        if (s == std::string::npos) { continue; }
        line = line.substr(s);
        auto e = line.find_last_not_of(" \t\r\n");
        if (e != std::string::npos) { line = line.substr(0, e+1); }
        if (line.empty() || line[0] == '#') { continue; }
        auto dot = line.find('.');
        words.push_back(dot == std::string::npos ? line : line.substr(0, dot));
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

static void extract_subs(const std::string& text, const std::string& domain, std::set<std::string>& out) {
    std::string pat = "([a-zA-Z0-9_\\-]+(?:\\.[a-zA-Z0-9_\\-]+)*\\."+domain+")";
    std::regex re(pat, std::regex::icase);
    std::sregex_iterator it(text.begin(), text.end(), re), end;
    for (; it != end; ++it) {
        std::string h = (*it)[1].str();
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
        if (h.size() > domain.size() && h.substr(h.size()-domain.size()) == domain) {
            out.insert(h);
        }
    }
}

static void passive_crtsh(const std::string& domain, std::set<std::string>& out) {
    auto body = safe_curl("https://crt.sh/?q=%25."+domain+"&output=json", 20);
    if (body.empty()) { return; }
    std::regex re("\"(?:common_name|name_value)\"\\s*:\\s*\"([^\"]+)\"");
    std::sregex_iterator it(body.begin(), body.end(), re), end;
    for (; it != end; ++it) {
        std::string val = (*it)[1].str();
        std::istringstream vss(val); std::string part;
        while (std::getline(vss, part, '\n')) {
            if (part.size() > 2 && part[0] == '*' && part[1] == '.') { part = part.substr(2); }
            std::transform(part.begin(), part.end(), part.begin(), ::tolower);
            if (part.size() > domain.size() && part.substr(part.size()-domain.size()) == domain) {
                out.insert(part);
            }
        }
    }
}

static void passive_hackertarget(const std::string& domain, std::set<std::string>& out) {
    auto body = safe_curl("https://api.hackertarget.com/hostsearch/?q="+domain, 15);
    if (body.empty() || body.find("error") != std::string::npos) { return; }
    std::istringstream ss(body); std::string line;
    while (std::getline(ss, line)) {
        auto c = line.find(',');
        if (c == std::string::npos) { continue; }
        std::string sub = line.substr(0, c);
        std::transform(sub.begin(), sub.end(), sub.begin(), ::tolower);
        if (sub.size() > domain.size() && sub.substr(sub.size()-domain.size()) == domain) {
            out.insert(sub);
        }
    }
}

static void passive_alienvault(const std::string& d, std::set<std::string>& out)   { auto b=safe_curl("https://otx.alienvault.com/api/v1/indicators/domain/"+d+"/passive_dns",15); if(!b.empty()){extract_subs(b,d,out);} }
static void passive_urlscan(const std::string& d, std::set<std::string>& out)      { auto b=safe_curl("https://urlscan.io/api/v1/search/?q=domain:"+d+"&size=200",15); if(!b.empty()){extract_subs(b,d,out);} }
static void passive_rapiddns(const std::string& d, std::set<std::string>& out)     { auto b=safe_curl("https://rapiddns.io/subdomain/"+d+"?full=1&down=1",15); if(!b.empty()){extract_subs(b,d,out);} }
static void passive_threatcrowd(const std::string& d, std::set<std::string>& out)  { auto b=safe_curl("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+d,15); if(!b.empty()){extract_subs(b,d,out);} }

static void passive_dnsdumpster(const std::string& domain, std::set<std::string>& out) {
    auto cr = safe_exec({"curl","-s","--max-time","10","-c","/tmp/dnsdump_cookies.txt","https://dnsdumpster.com/"}, 12);
    std::regex re_c("csrfmiddlewaretoken.*?value=['\"]([^'\"]+)['\"]", std::regex::icase);
    std::smatch m;
    if (!std::regex_search(cr, m, re_c)) { return; }
    auto b = safe_exec({"curl","-s","--max-time","20",
        "-b","/tmp/dnsdump_cookies.txt","-c","/tmp/dnsdump_cookies.txt",
        "-H","Referer: https://dnsdumpster.com/",
        "-d","csrfmiddlewaretoken="+m[1].str()+"&targetip="+domain+"&user=free",
                       "https://dnsdumpster.com/"}, 22);
    if (!b.empty()) { extract_subs(b, domain, out); }
}

static void passive_virustotal(const std::string& d, std::set<std::string>& out) {
    const char* k = getenv("VT_API_KEY"); if (!k||!*k) { return; }
    auto b = safe_exec({"curl","-s","--max-time","15","-H",std::string("x-apikey: ")+k,
        "https://www.virustotal.com/api/v3/domains/"+d+"/subdomains?limit=40"}, 18);
    if (b.empty()) { return; }
    extract_subs(b, d, out);
    std::regex re_c("\"cursor\"\\s*:\\s*\"([^\"]+)\""); std::smatch mc;
    if (std::regex_search(b, mc, re_c)) {
        auto b2 = safe_exec({"curl","-s","--max-time","15","-H",std::string("x-apikey: ")+k,
            "https://www.virustotal.com/api/v3/domains/"+d+"/subdomains?limit=40&cursor="+mc[1].str()}, 18);
        if (!b2.empty()) { extract_subs(b2, d, out); }
    }
}

static void passive_securitytrails(const std::string& d, std::set<std::string>& out) {
    const char* k = getenv("ST_API_KEY"); if (!k||!*k) { return; }
    auto b = safe_exec({"curl","-s","--max-time","15","-H",std::string("apikey: ")+k,
        "-H","Accept: application/json",
        "https://api.securitytrails.com/v1/domain/"+d+"/subdomains?children_only=false&include_inactive=true"}, 18);
    if (!b.empty()) { extract_subs(b, d, out); }
}

static void passive_shodan(const std::string& d, std::set<std::string>& out) {
    const char* k = getenv("SHODAN_API_KEY"); if (!k||!*k) { return; }
    auto b = safe_exec({"curl","-s","--max-time","15","https://api.shodan.io/dns/domain/"+d+"?key="+std::string(k)}, 18);
    if (!b.empty()) { extract_subs(b, d, out); }
}

static void passive_censys(const std::string& d, std::set<std::string>& out) {
    const char* ai = getenv("CENSYS_API_ID"); const char* as = getenv("CENSYS_API_SECRET");
    if (!ai||!*ai||!as||!*as) { return; }
    auto b = safe_exec({"curl","-s","--max-time","15","-u",std::string(ai)+":"+std::string(as),
        "-H","Content-Type: application/json",
        "-d","{\"q\":\""+d+"\",\"fields\":[\"parsed.names\"],\"flatten\":true}",
        "https://search.censys.io/api/v1/search/certificates"}, 18);
    if (!b.empty()) { extract_subs(b, d, out); }
}

static void dns_extra_records(const std::string& domain, std::set<std::string>& out) {
    for (auto& type : {"MX","TXT","NS","SRV"}) {
        auto res = safe_exec({"dig","+short","+time=5","+tries=2",domain,type}, 8);
        if (res.empty()) { continue; }
        extract_subs(res, domain, out);
        for (auto& line : split_lines(res)) {
            std::transform(line.begin(), line.end(), line.begin(), ::tolower);
            while (!line.empty() && line.back() == '.') { line.pop_back(); }
            if (line.size() > domain.size() && line.substr(line.size()-domain.size()) == domain) {
                out.insert(line);
            }
        }
    }
    auto axfr = safe_exec({"dig","axfr",domain,"@ns1."+domain,"+time=5"}, 10);
    if (!axfr.empty() && axfr.find("Transfer failed") == std::string::npos) {
        extract_subs(axfr, domain, out);
    }
}

static void scrape_js_subdomains(const std::vector<SubResult>& found,
                                 const std::string& domain,
                                 std::set<std::string>& out)
{
    std::set<std::string> js_urls;
    for (auto& r : found) {
        if (r.http_code.empty() || r.http_code == "0") { continue; }
        std::string base = "http://"+r.sub;
        auto resp = libcurl_get(base, r.sub, random_ua(), 8);
        if (resp.body.empty()) { continue; }
        std::regex re_js("(?:src|href)=['\"]([^'\"]+\\.js[^'\"]*)['\"]", std::regex::icase);
        std::sregex_iterator it(resp.body.begin(), resp.body.end(), re_js), end;
        for (; it != end; ++it) {
            std::string src = (*it)[1].str();
            if (src.substr(0,4) == "http") { js_urls.insert(src); }
            else if (src[0] == '/') { js_urls.insert(base+src); }
            else { js_urls.insert(base+"/"+src); }
        }
    }
    int scraped = 0;
    for (auto& url : js_urls) {
        if (scraped++ > 50) { break; }
        auto resp = libcurl_get(url, "", random_ua(), 6);
        if (!resp.body.empty()) { extract_subs(resp.body, domain, out); }
    }
}

static std::vector<std::string> doh_query(const std::string& hostname,
                                          const std::string& type = "A",
                                          std::string* prov = nullptr)
{
    const std::vector<std::pair<std::string,std::string>> providers = {
        {"cloudflare","https://cloudflare-dns.com/dns-query?name="+hostname+"&type="+type},
        {"google",    "https://dns.google/resolve?name="+hostname+"&type="+type},
    };
    for (auto& [name,url] : providers) {
        auto resp = safe_exec({"curl","-s","--max-time","6","-H","Accept: application/dns-json",url}, 8);
        if (resp.empty()) { continue; }
        std::vector<std::string> addrs;
        std::regex re("\"data\"\\s*:\\s*\"([0-9a-fA-F.:]+)\"");
        std::sregex_iterator it(resp.begin(), resp.end(), re), end;
        for (; it != end; ++it) {
            std::string a = (*it)[1].str();
            if (a.find('.') != std::string::npos || a.find(':') != std::string::npos) {
                addrs.push_back(a);
            }
        }
        if (!addrs.empty()) {
            if (prov) { *prov = name; }
            return addrs;
        }
    }
    return {};
}

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
            if (hvl.empty()) {
                if (h.find(hnl+":") != std::string::npos) { score++; }
            } else {
                if (h.find(hvl) != std::string::npos) { score++; }
            }
        }
        for (auto& ck : sig.cookies) { max++; if (c.find(lc(ck)) != std::string::npos) { score++; } }
        for (auto& kw : sig.body_kw) { max++; if (b.find(lc(kw)) != std::string::npos) { score++; } }
        if (max > 0 && float(score)/float(max) >= 0.5f) { return {sig.name, sig.confidence}; }
    }
    return {};
}

static TechInfo detect_tech(const std::string& headers, const std::string& body, const std::string& cookies) {
    TechInfo info;
    auto lc = [](std::string s){ std::transform(s.begin(),s.end(),s.begin(),::tolower); return s; };
    std::string h=lc(headers), b=lc(body), c=lc(cookies);
    if (h.find("x-powered-by: php") != std::string::npos) {
        info.language="PHP"; std::regex re("x-powered-by: php/([0-9\\.]+)"); std::smatch m;
        info.stack.push_back(std::regex_search(h,m,re) ? "PHP/"+m[1].str() : "PHP");
    } else if (h.find("x-powered-by: asp.net") != std::string::npos) { info.language="C#/.NET"; info.stack.push_back("ASP.NET"); }
    else if (h.find("x-powered-by: express") != std::string::npos)   { info.language="Node.js"; info.stack.push_back("Express"); }
    else if (h.find("x-powered-by: next.js") != std::string::npos)   { info.language="Node.js"; info.stack.push_back("Next.js"); }
    if (c.find("phpsessid") != std::string::npos)        { info.session_cookie="PHPSESSID"; if(info.language.empty()){info.language="PHP";} }
    else if (c.find("jsessionid") != std::string::npos)  { info.session_cookie="JSESSIONID"; info.language="Java"; info.stack.push_back("Java/Servlet"); }
    else if (c.find("asp.net_sessionid") != std::string::npos) { info.session_cookie="ASP.NET_Session"; if(info.language.empty()){info.language="C#/.NET";} }
    else if (c.find("laravel_session") != std::string::npos)   { info.session_cookie="laravel_session"; info.stack.push_back("Laravel"); if(info.language.empty()){info.language="PHP";} }
    else if (c.find("csrftoken") != std::string::npos)   { info.stack.push_back("Django"); if(info.language.empty()){info.language="Python";} }
    else if (c.find("rack.session") != std::string::npos){ info.stack.push_back("Ruby/Rack"); if(info.language.empty()){info.language="Ruby";} }
    else if (c.find("_rails") != std::string::npos)      { info.stack.push_back("Rails"); if(info.language.empty()){info.language="Ruby";} }
    if (h.find("server: nginx") != std::string::npos)             { info.stack.push_back("nginx"); }
    else if (h.find("server: apache") != std::string::npos)        { info.stack.push_back("Apache"); }
    else if (h.find("server: microsoft-iis") != std::string::npos) { info.stack.push_back("IIS"); if(info.language.empty()){info.language="C#/.NET";} }
    else if (h.find("server: litespeed") != std::string::npos)     { info.stack.push_back("LiteSpeed"); }
    else if (h.find("server: openresty") != std::string::npos)     { info.stack.push_back("OpenResty"); }
    else if (h.find("server: caddy") != std::string::npos)         { info.stack.push_back("Caddy"); }
    else if (h.find("server: gunicorn") != std::string::npos)      { info.stack.push_back("Gunicorn"); if(info.language.empty()){info.language="Python";} }
    else if (h.find("server: uvicorn") != std::string::npos)       { info.stack.push_back("Uvicorn"); if(info.language.empty()){info.language="Python";} }
    if (b.find("wp-content") != std::string::npos)   { info.cms="WordPress"; }
    else if (b.find("joomla") != std::string::npos)   { info.cms="Joomla"; }
    else if (b.find("drupal") != std::string::npos || h.find("x-drupal-cache") != std::string::npos) { info.cms="Drupal"; }
    else if (b.find("cdn.shopify") != std::string::npos)  { info.cms="Shopify"; }
    else if (b.find("ghost-url") != std::string::npos)    { info.cms="Ghost"; }
    else if (b.find("magento") != std::string::npos || c.find("mage-") != std::string::npos) { info.cms="Magento"; }
    else if (b.find("bitrix") != std::string::npos)  { info.cms="Bitrix"; }
    else if (b.find("typo3") != std::string::npos)   { info.cms="TYPO3"; }
    if (b.find("__react")    != std::string::npos) { info.stack.push_back("React"); }
    if (b.find("__vue__")    != std::string::npos) { info.stack.push_back("Vue.js"); }
    if (b.find("ng-version") != std::string::npos) { info.stack.push_back("Angular"); }
    if (b.find("__next")     != std::string::npos) { info.stack.push_back("Next.js"); }
    if (b.find("nuxt")       != std::string::npos) { info.stack.push_back("Nuxt.js"); }
    if (b.find("jquery")     != std::string::npos) { info.stack.push_back("jQuery"); }
    if (h.find("x-amz-")    != std::string::npos) { info.stack.push_back("AWS"); }
    if (h.find("x-ms-")     != std::string::npos) { info.stack.push_back("Azure"); }
    if (h.find("x-goog-")   != std::string::npos) { info.stack.push_back("GCP"); }
    std::sort(info.stack.begin(), info.stack.end());
    info.stack.erase(std::unique(info.stack.begin(), info.stack.end()), info.stack.end());
    return info;
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
        if (dot != std::string::npos) { label = sub.substr(0, dot); }
        if (label.empty()) { continue; }
        for (auto& af : affixes) {
            perms.insert(label+"-"+af+"."+domain);
            perms.insert(label+af+"."+domain);
            perms.insert(af+"-"+label+"."+domain);
            perms.insert(af+label+"."+domain);
        }
    }
    return {perms.begin(), perms.end()};
}

struct TakeoverSig {
    std::string cname_pattern;
    std::string service;
    std::vector<std::string> fingerprints;
};

static const std::vector<TakeoverSig>& takeover_db() {
    static const std::vector<TakeoverSig> db = {
        {"github.io",          "GitHub Pages",    {"There isn't a GitHub Pages site here","For root URLs"}},
        {"herokuapp.com",      "Heroku",           {"No such app","herokucdn.com/error-pages/no-such-app"}},
        {"azurewebsites.net",  "Azure App Svc",    {"404 Web Site not found","Microsoft Azure App Service"}},
        {"cloudfront.net",     "CloudFront",       {"Bad request","ERROR: The request could not be satisfied"}},
        {"s3.amazonaws.com",   "AWS S3",           {"NoSuchBucket","The specified bucket does not exist"}},
        {"s3-website",         "AWS S3 Website",   {"NoSuchBucket","The specified bucket does not exist"}},
        {"myshopify.com",      "Shopify",          {"Sorry, this shop is currently unavailable","Only one step"}},
        {"ghost.io",           "Ghost",            {"The thing you were looking for is no longer here"}},
        {"wordpress.com",      "WordPress",        {"Do you want to register","doesn't exist"}},
        {"pantheon.io",        "Pantheon",         {"The gods are wise","404 error unknown site"}},
        {"zendesk.com",        "Zendesk",          {"Help Center Closed","this page does not exist"}},
        {"readme.io",          "ReadMe",           {"Project doesnt exist","We couldn't find that page"}},
        {"readme.com",         "ReadMe",           {"Project doesnt exist","We couldn't find that page"}},
        {"surge.sh",           "Surge",            {"project not found"}},
        {"bitbucket.io",       "Bitbucket",        {"Repository not found"}},
        {"netlify.app",        "Netlify",          {"Not Found - Request ID","page not found"}},
        {"vercel.app",         "Vercel",           {"The deployment could not be found","DEPLOYMENT_NOT_FOUND"}},
        {"fly.dev",            "Fly.io",           {"404 Not Found","fly.io"}},
        {"render.com",         "Render",           {"There's nothing here, yet"}},
        {"pages.dev",          "CF Pages",         {"There's nothing here, yet"}},
        {"webflow.io",         "Webflow",          {"The page you are looking for doesn't exist"}},
        {"hubspot.com",        "HubSpot",          {"does not exist","This page no longer exists"}},
        {"uservoice.com",      "UserVoice",        {"This UserVoice subdomain is currently available"}},
        {"statuspage.io",      "Statuspage",       {"page not found","Statuspage"}},
        {"freshdesk.com",      "Freshdesk",        {"There is no helpdesk here","this helpdesk does not exist"}},
        {"intercom.io",        "Intercom",         {"This page is reserved for artistic"}},
        {"unbounce.com",       "Unbounce",         {"The requested URL was not found"}},
        {"myjetbrains.com",    "JetBrains",        {"is not a registered InCloud YouTrack"}},
        {"kinsta-cloud.com",   "Kinsta",           {"No Site For Domain"}},
        {"launchrock.com",     "Launchrock",       {"It looks like you may have taken a wrong turn"}},
        {"feedpress.me",       "FeedPress",        {"The feed has not been found"}},
        {"teamwork.com",       "Teamwork",         {"Teamwork Projects doesn't allow"}},
        {"smartjobboard.com",  "SmartJobBoard",    {"This job board website is either expired"}},
        {"fastly.net",         "Fastly",           {"Fastly error: unknown domain"}},
        {"squarespace.com",    "Squarespace",      {"You need to assign a Custom Domain"}},
        {"wixsite.com",        "Wix",              {"doesn't exist","This website is no longer published"}},
        {"acquia-sites.com",   "Acquia",           {"Web Site Not Configured"}},
    };
    return db;
}

static std::string takeover_validate(const std::string& sub,
                                     const std::string& /*cname*/,
                                     const std::string& /*service*/,
                                     const std::vector<std::string>& fingerprints)
{
    auto lc = [](std::string s){ std::transform(s.begin(),s.end(),s.begin(),::tolower); return s; };

    for (auto& url : {"https://"+sub, "http://"+sub}) {
        auto resp = libcurl_get(url, sub, "Mozilla/5.0 (compatible; Validator/1.0)", 8);
        if (resp.body.empty() && resp.headers.empty()) { continue; }
        std::string body_lc = lc(resp.body);
        std::string hdrs_lc = lc(resp.headers);
        for (auto& fp : fingerprints) {
            std::string fpl = lc(fp);
            if (body_lc.find(fpl) != std::string::npos ||
                hdrs_lc.find(fpl) != std::string::npos) {
                return "CONFIRMED";
                }
        }
        if (resp.http_code == 404 || resp.http_code == 0) {
            return "POSSIBLE";
        }
        return "LIVE";
    }
    return "UNREACHABLE";
}

static const std::vector<std::pair<std::string,std::string>> s = {
    {"github.io","GitHub Pages"},{"herokuapp.com","Heroku"},
    {"azurewebsites.net","Azure"},{"cloudfront.net","CloudFront"},
    {"s3.amazonaws.com","AWS S3"},{"s3-website","AWS S3 Website"},
    {"shopify.com","Shopify"},{"myshopify.com","Shopify"},
    {"ghost.io","Ghost"},{"wordpress.com","WordPress"},
    {"pantheon.io","Pantheon"},{"zendesk.com","Zendesk"},
    {"readme.io","ReadMe"},{"readme.com","ReadMe"},
    {"surge.sh","Surge"},{"bitbucket.io","Bitbucket"},
    {"netlify.app","Netlify"},{"vercel.app","Vercel"},
    {"fly.dev","Fly.io"},{"render.com","Render"},
    {"pages.dev","Cloudflare Pages"},{"fastly.net","Fastly"},
    {"squarespace.com","Squarespace"},{"wixsite.com","Wix"},
    {"webflow.io","Webflow"},{"hubspot.com","HubSpot"},
    {"helpscoutdocs.com","HelpScout"},{"uservoice.com","UserVoice"},
    {"statuspage.io","Statuspage"},{"freshdesk.com","Freshdesk"},
    {"intercom.io","Intercom"},{"kajabi.com","Kajabi"},
    {"pingdom.com","Pingdom"},{"unbounce.com","Unbounce"},
    {"myjetbrains.com","JetBrains"},{"acquia-sites.com","Acquia"},
    {"kinsta-cloud.com","Kinsta"},{"cargo.site","Cargo"},
    {"launchrock.com","Launchrock"},{"feedpress.me","FeedPress"},
    {"uberflip.com","Uberflip"},{"teamwork.com","Teamwork"},
    {"airee.ru","Airee"},{"smartjobboard.com","SmartJobBoard"},
};

static void export_results(const std::vector<SubResult>& results, const std::string& domain) {
    {
        std::string fname = domain+"_subdomains.json";
        std::ofstream f(fname); f << "[\n";
        for (size_t i = 0; i < results.size(); i++) {
            auto& r = results[i];
            auto arr_s = [](const std::vector<std::string>& v) {
                std::string s="["; for(size_t j=0;j<v.size();j++){if(j){s+=",";}s+="\""+v[j]+"\"";} return s+"]";
            };
            f << "  {\n"
            << "    \"subdomain\": \""      << r.sub              << "\",\n"
            << "    \"source\": \""         << r.source           << "\",\n"
            << "    \"ipv4\": "             << arr_s(r.ips)       << ",\n"
            << "    \"ipv6\": "             << arr_s(r.ipv6)      << ",\n"
            << "    \"cname\": \""          << r.cname            << "\",\n"
            << "    \"http_code\": \""      << r.http_code        << "\",\n"
            << "    \"server\": \""         << r.server           << "\",\n"
            << "    \"title\": \""          << r.title            << "\",\n"
            << "    \"waf\": \""            << r.waf.name         << "\",\n"
            << "    \"waf_confidence\": \"" << r.waf.confidence   << "\",\n"
            << "    \"language\": \""       << r.tech.language    << "\",\n"
            << "    \"cms\": \""            << r.tech.cms         << "\",\n"
            << "    \"stack\": "            << arr_s(r.tech.stack)<< ",\n"
            << "    \"doh_fallback\": \""   << r.doh_fallback     << "\"\n"
            << "  }";
            if (i+1 < results.size()) { f << ","; }
            f << "\n";
        }
        f << "]\n";
        std::cout << BLOOD_RED << "  [+] JSON: " << WHITE << fname << "\n" << RESET;
    }
    {
        std::string fname = domain+"_subdomains.csv";
        std::ofstream f(fname);
        f << "subdomain,ipv4,ipv6,cname,http_code,server,title,waf,language,cms,stack,source,doh_fallback\n";
        for (auto& r : results) {
            auto js=[](const std::vector<std::string>& v){std::string s;for(auto& x:v){if(!s.empty()){s+=" ";}s+=x;}return s;};
            auto q=[](const std::string& s){return s.find(',')!=std::string::npos?"\""+s+"\"":s;};
            f << r.sub<<","<<q(js(r.ips))<<","<<q(js(r.ipv6))<<","<<r.cname<<","
            << r.http_code<<","<<q(r.server)<<","<<q(r.title)<<","
            << r.waf.name<<","<<r.tech.language<<","<<r.tech.cms<<","
            << q(js(r.tech.stack))<<","<<r.source<<","<<r.doh_fallback<<"\n";
        }
        std::cout << BLOOD_RED << "  [+] CSV:  " << WHITE << fname << "\n" << RESET;
    }
}

static std::string parse_title(const std::string& body) {
    std::regex re_t("<title[^>]*>([^<]{1,100})</title>", std::regex::icase);
    std::smatch mt;
    if (!std::regex_search(body, mt, re_t)) { return ""; }
    std::string t = mt[1].str();
    auto a = t.find_first_not_of(" \t\r\n");
    auto z = t.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) { return ""; }
    t = t.substr(a, z-a+1);
    if (t.size() > 60) { t = t.substr(0, 60)+"..."; }
    return t;
}

void subdomain_scan(const std::string& domain,
                    const std::string& wordlist_path,
                    int max_threads,
                    bool run_permutations,
                    bool deep_passive,
                    bool do_enrich)
{
    print_header("SUBDOMAIN SCAN // " + domain);
    g_http_slots.store(15);
    curl_global_init(CURL_GLOBAL_ALL);

    auto& dns = DnsEngine::get();
    dns.clear_cache();

    print_section("WORDLIST");
    std::vector<std::string> wordlist;
    if (!wordlist_path.empty()) {
        wordlist = load_wordlist_file(wordlist_path);
        if (!wordlist.empty()) {
            std::cout << BLOOD_RED << "  [+] " << WHITE << wordlist.size() << BLOOD_RED << " words loaded: " << WHITE << wordlist_path << "\n" << RESET;
        }
    }
    if (wordlist.empty()) {
        wordlist = builtin_wordlist();
        std::cout << BLOOD_RED << "  [*] builtin wordlist (" << WHITE << wordlist.size() << BLOOD_RED << " words)\n" << RESET;
    }
    std::cout << BLOOD_RED << "  [*] engine: DnsEngine | " << WHITE << std::thread::hardware_concurrency()
    << BLOOD_RED << " channels | 40+ resolvers | io_uring auto\n" << RESET;
    std::cout << BLOOD_RED << "  [*] enrich: " << WHITE
    << (do_enrich ? "ON  | libcurl | slots: 15 | UA: random | jitter: 10-80ms"
    : "OFF | DNS only")
    << "\n" << RESET;

    print_section("WILDCARD CHECK");
    std::set<std::string> wildcard_ips;
    std::atomic<bool> has_wildcard{false};
    {
        std::vector<std::string> probes;
        for (int i = 0; i < 5; i++) {
            std::string s;
            for (int j = 0; j < 16; j++) { s += char('a'+tl_rng()%26); }
            probes.push_back(s+"."+domain);
        }
        auto wc = dns.resolve_batch(probes, 10);
        for (auto& [h,ips] : wc) {
            for (auto& ip : ips) { has_wildcard = true; wildcard_ips.insert(ip); }
        }
    }
    if (has_wildcard) {
        std::cout << BLOOD_RED << "  [!] wildcard ->";
        for (auto& ip : wildcard_ips) { std::cout << WHITE << " " << ip; }
        std::cout << BLOOD_RED << "\n  [!] filtering ON\n" << RESET;
    } else {
        std::cout << BLOOD_RED << "  [+] no wildcard\n" << RESET;
    }

    print_section("PASSIVE ENUM");
    std::set<std::string> passive_subs;
    size_t before;
    auto run_source = [&](const std::string& name, auto fn) {
        std::cout << BLOOD_RED << "  [*] " << WHITE << name << BLOOD_RED << "...\n" << RESET;
        before = passive_subs.size(); fn();
        std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(18) << name
        << BLOOD_RED << "+" << WHITE << (passive_subs.size()-before) << "\n" << RESET;
    };

    run_source("crt.sh",         [&](){ passive_crtsh(domain, passive_subs); });
    if (deep_passive) {
        run_source("HackerTarget",   [&](){ passive_hackertarget(domain, passive_subs); });
        run_source("AlienVault OTX", [&](){ passive_alienvault(domain, passive_subs); });
        run_source("urlscan.io",     [&](){ passive_urlscan(domain, passive_subs); });
        run_source("RapidDNS",       [&](){ passive_rapiddns(domain, passive_subs); });
        run_source("ThreatCrowd",    [&](){ passive_threatcrowd(domain, passive_subs); });
        run_source("DNSDumpster",    [&](){ passive_dnsdumpster(domain, passive_subs); });
        if (getenv("VT_API_KEY"))     { run_source("VirusTotal",     [&](){ passive_virustotal(domain, passive_subs); }); }
        if (getenv("ST_API_KEY"))     { run_source("SecurityTrails", [&](){ passive_securitytrails(domain, passive_subs); }); }
        if (getenv("SHODAN_API_KEY")) { run_source("Shodan",         [&](){ passive_shodan(domain, passive_subs); }); }
        if (getenv("CENSYS_API_ID"))  { run_source("Censys",         [&](){ passive_censys(domain, passive_subs); }); }
        run_source("MX/TXT/NS/SRV",  [&](){ dns_extra_records(domain, passive_subs); });
    }
    std::cout << BLOOD_RED << "  [=] total passive: " << WHITE << passive_subs.size() << "\n" << RESET;

    std::set<std::string> dedup;
    std::vector<std::string> all_subs;
    for (auto& w : wordlist) {
        std::string full = w+"."+domain;
        if (dedup.insert(full).second) { all_subs.push_back(full); }
    }
    for (auto& s : passive_subs) {
        if (s != domain && dedup.insert(s).second) { all_subs.push_back(s); }
    }

    int total_hosts = (int)all_subs.size();

    print_section("ASYNC DNS + DoH BRUTEFORCE");
    std::cout << BLOOD_RED << "  checking " << WHITE << total_hosts << BLOOD_RED << " subdomains"
    << " (" << WHITE << wordlist.size() << BLOOD_RED << " wordlist + " << WHITE << passive_subs.size() << BLOOD_RED << " passive)"
    << " via DnsEngine + DoH fallback...\n\n" << RESET;

    const int DNS_BATCH = 5000;
    const int DOH_MAX   = 5000;

    std::mutex mtx;
    std::vector<SubResult> results;
    std::set<std::string> found_set;
    std::unordered_map<std::string,std::string> seen_ip_primary;
    std::atomic<int> found_count{0}, dns_checked{0}, doh_used{0}, ip_dedup_hits{0};

    ThreadPool pool(std::min(max_threads, total_hosts > 0 ? total_hosts : 1));

    auto process_resolved = [&](const std::string& sub,
                                std::vector<std::string> ips,
                                const std::string& doh_provider)
    {
        dns_checked++;
        if (ips.empty()) { return; }
        if (has_wildcard && ips.size() == 1 && wildcard_ips.count(ips[0])) { return; }
        { std::lock_guard<std::mutex> lk(mtx); if (!found_set.insert(sub).second) { return; } }

        std::sort(ips.begin(), ips.end());
        ips.erase(std::unique(ips.begin(), ips.end()), ips.end());

        std::vector<std::string> ipv6;
        std::string cname, http_code, server_hdr, page_title;
        WAFInfo waf; TechInfo tech;

        if (do_enrich) {
            ipv6 = dns.resolve_aaaa(sub);

            auto co = safe_exec({"dig","+short","+time=2","+tries=1",sub,"CNAME"}, 4);
            if (!co.empty()) {
                auto lines = split_lines(co);
                if (!lines.empty()) {
                    cname = lines[0];
                    while (!cname.empty() && cname.back() == '.') { cname.pop_back(); }
                }
            }

            std::string primary_ip = ips.empty() ? "" : ips[0];
            std::string seen_sub;
            {
                std::lock_guard<std::mutex> lk(mtx);
                auto it = seen_ip_primary.find(primary_ip);
                if (it != seen_ip_primary.end()) {
                    seen_sub = it->second;
                } else {
                    seen_ip_primary[primary_ip] = sub;
                }
            }

            if (!seen_sub.empty() && !primary_ip.empty()) {
                ip_dedup_hits++;
                std::lock_guard<std::mutex> lk(mtx);
                for (auto& r : results) {
                    if (r.sub == seen_sub) {
                        http_code  = r.http_code;
                        server_hdr = r.server;
                        page_title = r.title;
                        waf        = r.waf;
                        tech       = r.tech;
                        break;
                    }
                }
            } else {
                HttpSlotGuard sg;
                sg.acquire();
                http_jitter();

                long code_https = libcurl_check("https://"+sub, random_ua(), 3);
                long code_http  = libcurl_check("http://"+sub,  random_ua(), 3);

                std::string grab_url;
                if (code_https > 0) { grab_url = "https://"+sub; }
                    else if (code_http > 0) { grab_url = "http://"+sub; }

                        if (!grab_url.empty()) {
                            auto resp = libcurl_get(grab_url, sub, random_ua(), 6);
                            if (resp.http_code > 0) { http_code = std::to_string(resp.http_code); }
                            std::smatch ms;
                            std::regex re_srv("(?:^|\n)[Ss]erver:\\s*([^\r\n]+)");
                            if (std::regex_search(resp.headers, ms, re_srv)) {
                                server_hdr = ms[1].str();
                                if (server_hdr.size() > 40) { server_hdr = server_hdr.substr(0, 40); }
                            }
                            page_title = parse_title(resp.body);
                            if (!resp.headers.empty()) {
                                std::string cookies;
                                std::regex re_ck("(?:^|\n)[Ss]et-[Cc]ookie:\\s*([^\r\n]+)");
                                std::sregex_iterator ci(resp.headers.begin(), resp.headers.end(), re_ck), ce;
                                for (; ci != ce; ++ci) { cookies += (*ci)[1].str()+";"; }
                                waf  = detect_waf(resp.headers, resp.body, cookies);
                                tech = detect_tech(resp.headers, resp.body, cookies);
                            }
                        }
            }
        }

        bool fp = passive_subs.count(sub) > 0;
        std::string prefix = sub.substr(0, sub.size()-domain.size()-1);
        bool fw = std::find(wordlist.begin(), wordlist.end(), prefix) != wordlist.end();
        std::string source = (fp&&fw) ? "both" : fp ? "passive" : "brute";

        SubResult sr;
        sr.sub=sub; sr.ips=ips; sr.ipv6=ipv6; sr.cname=cname;
        sr.http_code=http_code; sr.server=server_hdr; sr.title=page_title;
        sr.source=source; sr.waf=waf; sr.tech=tech; sr.doh_fallback=doh_provider;

        found_count++;
        {
            std::lock_guard<std::mutex> lk(mtx);
            results.push_back(sr);
            g_result.subdomains.push_back(sub);
        }
        {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << "\r" << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(42) << sub;
            for (auto& ip : ips) { std::cout << WHITE << ip << " "; }
            if (!ipv6.empty())   { std::cout << BLOOD_RED << "[v6:" << WHITE << ipv6[0] << BLOOD_RED << "] "; }
            if (!cname.empty())  { std::cout << BLOOD_RED << "CNAME:" << WHITE << cname << " "; }
            if (!http_code.empty() && http_code != "0") { std::cout << BLOOD_RED << "HTTP:" << BLOOD_RED << http_code << " "; }
            if (!server_hdr.empty())    { std::cout << BLOOD_RED << "[" << BLOOD_RED << server_hdr << BLOOD_RED << "] "; }
            if (!waf.name.empty())      { std::cout << BLOOD_RED << "WAF:" << BLOOD_RED << waf.name << " "; }
            if (!tech.language.empty()) { std::cout << BLOOD_RED << tech.language << " "; }
            if (!tech.cms.empty())      { std::cout << BLOOD_RED << tech.cms << " "; }
            if (!doh_provider.empty())  { std::cout << BLOOD_RED << " [DoH:" << WHITE << doh_provider << BLOOD_RED << "]"; }
            std::cout << BLOOD_RED << " (" << WHITE << source << BLOOD_RED << ")" << RESET << "\n";
        }
    };

    for (int bs = 0; bs < total_hosts; bs += DNS_BATCH) {
        int be = std::min(bs+DNS_BATCH, total_hosts);
        std::vector<std::string> batch(all_subs.begin()+bs, all_subs.begin()+be);

        std::cout << BLOOD_RED << "\r  [dns] batch " << WHITE << (bs/DNS_BATCH+1) << BLOOD_RED << "/"
        << WHITE << ((total_hosts+DNS_BATCH-1)/DNS_BATCH)
        << BLOOD_RED << " (" << WHITE << batch.size() << BLOOD_RED << " hosts) via DnsEngine...    " << RESET << std::flush;

        auto dns_res = dns.resolve_batch(batch, 1500);
        std::vector<std::future<void>> futs;
        std::vector<std::string> doh_queue;

        for (auto& [host,ips] : dns_res) {
            if (!ips.empty()) {
                futs.push_back(pool.submit([&,h=host,i=ips]() mutable {
                    process_resolved(h, i, "");
                }));
            } else {
                doh_queue.push_back(host);
            }
        }
        for (auto& f : futs) { f.get(); }

        if (!doh_queue.empty()) {
            if ((int)doh_queue.size() > DOH_MAX) {
                std::cout << BLOOD_RED << "  [!] DoH queue: " << WHITE << doh_queue.size()
                << BLOOD_RED << ", capping at " << WHITE << DOH_MAX << "\n" << RESET;
                doh_queue.resize(DOH_MAX);
            }
            std::vector<std::future<void>> dfuts;
            for (auto& host : doh_queue) {
                dfuts.push_back(pool.submit([&,h=host]() {
                    subdomain_rl.acquire();
                    std::string provider;
                    auto ips = doh_query(h, "A", &provider);
                    if (!ips.empty()) { doh_used++; process_resolved(h, ips, provider); }
                    else { dns_checked++; }
                }));
            }
            for (auto& f : dfuts) { f.get(); }
        }
        draw_progress(be, total_hosts, std::to_string(found_count.load())+" found");
    }

    if (run_permutations && !found_set.empty()) {
        print_section("PERMUTATION ENGINE");
        auto perms = generate_permutations(found_set, domain);
        std::vector<std::string> new_perms;
        for (auto& p : perms) {
            if (!dedup.count(p)) { new_perms.push_back(p); dedup.insert(p); }
        }
        std::cout << BLOOD_RED << "  [*] " << WHITE << new_perms.size() << BLOOD_RED << " permutations from "
        << WHITE << found_set.size() << BLOOD_RED << " found\n" << RESET;
        if (!new_perms.empty()) {
            auto pres = dns.resolve_batch(new_perms, 1500);
            std::vector<std::future<void>> pfuts;
            for (auto& [h,ips] : pres) {
                if (!ips.empty()) {
                    pfuts.push_back(pool.submit([&,hc=h,ic=ips]() mutable {
                        process_resolved(hc, ic, "");
                    }));
                } else {
                    dns_checked++;
                }
            }
            for (auto& f : pfuts) { f.get(); }
            std::cout << BLOOD_RED << "  [+] permutations done\n" << RESET;
        }
    }

    if (do_enrich && deep_passive && !results.empty()) {
        print_section("JS SCRAPING");
        std::set<std::string> js_subs;
        scrape_js_subdomains(results, domain, js_subs);
        std::vector<std::string> new_js;
        for (auto& s : js_subs) {
            if (!dedup.count(s)) { new_js.push_back(s); dedup.insert(s); }
        }
        std::cout << BLOOD_RED << "  [*] " << WHITE << js_subs.size() << BLOOD_RED << " candidates in JS, resolving "
        << WHITE << new_js.size() << BLOOD_RED << " new...\n" << RESET;
        if (!new_js.empty()) {
            auto jres = dns.resolve_batch(new_js, 1500);
            std::vector<std::future<void>> jfuts;
            for (auto& [h,ips] : jres) {
                if (!ips.empty()) {
                    jfuts.push_back(pool.submit([&,hc=h,ic=ips]() mutable {
                        process_resolved(hc, ic, "js");
                    }));
                } else {
                    dns_checked++;
                }
            }
            for (auto& f : jfuts) { f.get(); }
            std::cout << BLOOD_RED << "  [+] JS scraping done\n" << RESET;
        }
    }

    curl_global_cleanup();
    std::cout << "\n";
    std::sort(results.begin(), results.end(),
              [](const SubResult& a, const SubResult& b){ return a.sub < b.sub; });

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
        if (!r.ips.empty())  { std::cout << WHITE << std::setw(16) << r.ips[0]; }
        else                 { std::cout << BLOOD_RED << std::setw(16) << "-"; }
        if (!r.ipv6.empty()) { std::cout << WHITE << std::setw(6)  << "v6"; cnt_ipv6++; }
        else                 { std::cout << BLOOD_RED << std::setw(6)  << "-"; }
        if (!r.http_code.empty() && r.http_code != "0") { std::cout << BLOOD_RED << std::setw(8) << r.http_code; }
        else                                             { std::cout << BLOOD_RED << std::setw(8) << "-"; }
        if (!r.waf.name.empty()) {
            std::string wn = r.waf.name;
            if (wn.size() > 14) { wn = wn.substr(0, 14); }
            std::cout << BLOOD_RED << std::setw(16) << wn; cnt_waf++;
        } else { std::cout << BLOOD_RED << std::setw(16) << "-"; }
        std::string ts = r.tech.language;
        if (!r.tech.cms.empty()) { ts += "/"+r.tech.cms; }
        if (ts.size() > 12) { ts = ts.substr(0, 12); }
        std::cout << BLOOD_RED << std::setw(12) << (ts.empty() ? "-" : ts);
        std::cout << WHITE << sanitize(r.title) << RESET << "\n";
        if (!r.cname.empty()) { std::cout << BLOOD_RED << "    -> CNAME: " << WHITE << r.cname << RESET << "\n"; cnt_cname++; }
        if (!r.ipv6.empty())  { std::cout << BLOOD_RED << "    -> IPv6:  " << WHITE; for (auto& a:r.ipv6){std::cout<<a<<" ";} std::cout<<RESET<<"\n"; }
        if (!r.tech.stack.empty()) { std::cout << BLOOD_RED << "    -> stack: " << BLOOD_RED; for (auto& s:r.tech.stack){std::cout<<s<<" ";} std::cout<<RESET<<"\n"; }
        if (r.ips.size() > 1) { std::cout << BLOOD_RED << "    -> also:  " << WHITE; for (size_t j=1;j<r.ips.size();j++){std::cout<<r.ips[j]<<" ";} std::cout<<RESET<<"\n"; }
        if (!r.server.empty())        { server_stats[r.server]++; }
        if (!r.waf.name.empty())      { waf_stats[r.waf.name]++; }
        if (!r.tech.language.empty()) { lang_stats[r.tech.language]++; }
        if (!r.tech.cms.empty())      { cms_stats[r.tech.cms]++; }
        source_stats[r.source]++;
    }

    print_section("STATISTICS");
    std::cout << BLOOD_RED << "  [total found]     " << WHITE << results.size()       << "\n" << RESET;
    std::cout << BLOOD_RED << "  [dns checked]     " << WHITE << dns_checked.load()   << "\n" << RESET;
    std::cout << BLOOD_RED << "  [DoH fallbacks]   " << WHITE << doh_used.load()      << "\n" << RESET;
    std::cout << BLOOD_RED << "  [IP dedup hits]   " << WHITE << ip_dedup_hits.load() << "\n" << RESET;
    std::cout << BLOOD_RED << "  [with CNAME]      " << WHITE << cnt_cname            << "\n" << RESET;
    std::cout << BLOOD_RED << "  [with IPv6]       " << WHITE << cnt_ipv6             << "\n" << RESET;
    std::cout << BLOOD_RED << "  [behind WAF]      " << WHITE << cnt_waf              << "\n" << RESET;
    std::cout << BLOOD_RED << "  [enrich mode]     " << WHITE << (do_enrich ? "ON" : "OFF") << "\n" << RESET;
    std::cout << BLOOD_RED << "  [wildcard]        " << WHITE << (has_wildcard.load() ? "YES" : "no") << "\n" << RESET;

    auto print_dist = [](const std::map<std::string,int>& m, const std::string& label) {
        if (m.empty()) { return; }
        std::cout << BLOOD_RED << "\n  [" << WHITE << label << BLOOD_RED << "]\n" << RESET;
        std::vector<std::pair<std::string,int>> v(m.begin(), m.end());
        std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.second > b.second; });
        for (auto& [k,cnt] : v) {
            std::cout << BLOOD_RED << "    " << BLOOD_RED << std::left << std::setw(30) << k << WHITE << cnt << "\n" << RESET;
        }
    };
    print_dist(source_stats, "sources");
    print_dist(waf_stats,    "WAF distribution");
    print_dist(lang_stats,   "languages");
    print_dist(cms_stats,    "CMS");
    print_dist(server_stats, "server distribution");

    print_section("TAKEOVER CANDIDATES");
    bool any_takeover = false;
    int confirmed_count = 0, possible_count = 0;

    std::vector<std::future<void>> to_futs;
    std::mutex to_mtx;

    for (auto& r : results) {
        if (r.cname.empty()) { continue; }
        std::string cl = r.cname;
        std::transform(cl.begin(), cl.end(), cl.begin(), ::tolower);

        for (auto& sig : takeover_db()) {
            if (cl.find(sig.cname_pattern) == std::string::npos) { continue; }

            any_takeover = true;
            std::string sub_copy  = r.sub;
            std::string cname_copy = r.cname;
            std::string svc_copy  = sig.service;
            std::vector<std::string> fps_copy = sig.fingerprints;

            to_futs.push_back(pool.submit([&, sub_copy, cname_copy, svc_copy, fps_copy]() {
                std::string dns_check = resolve(cname_copy);
                std::string status;

                if (dns_check.empty()) {
                    status = "DANGLING_DNS";
                } else {
                    status = takeover_validate(sub_copy, cname_copy, svc_copy, fps_copy);
                }

                std::lock_guard<std::mutex> lk(to_mtx);
                if (status == "CONFIRMED") {
                    confirmed_count++;
                    std::cout << BLOOD_RED << BOLD
                    << "  [!!!] CONFIRMED TAKEOVER: " << WHITE << sub_copy << "\n"
                    << BLOOD_RED << "        CNAME:   " << WHITE << cname_copy << "\n"
                    << BLOOD_RED << "        SERVICE: " << WHITE << svc_copy << "\n"
                    << BLOOD_RED << "        STATUS:  " << WHITE << "fingerprint matched — register the service to claim\n"
                    << RESET;
                } else if (status == "DANGLING_DNS" || status == "POSSIBLE") {
                    possible_count++;
                    std::cout << BLOOD_RED
                    << "  [?]   POSSIBLE TAKEOVER: " << WHITE << sub_copy << "\n"
                    << BLOOD_RED << "        CNAME:   " << WHITE << cname_copy << "\n"
                    << BLOOD_RED << "        SERVICE: " << WHITE << svc_copy << "\n"
                    << BLOOD_RED << "        STATUS:  " << WHITE << status << BLOOD_RED << " — verify manually\n"
                    << RESET;
                } else {
                    std::cout << BLOOD_RED
                    << "  [-]   " << WHITE << sub_copy << BLOOD_RED << " -> " << WHITE << cname_copy
                    << BLOOD_RED << " (" << WHITE << svc_copy << BLOOD_RED << ") LIVE — not vulnerable\n"
                    << RESET;
                }
            }));
            break;
        }
    }
    for (auto& f : to_futs) { f.get(); }

    if (!any_takeover) {
        std::cout << BLOOD_RED << "  no takeover candidates found\n" << RESET;
    } else {
        std::cout << "\n"
        << BLOOD_RED << "  [!!!] CONFIRMED: " << WHITE << confirmed_count << "\n" << RESET
        << BLOOD_RED << "  [?]   POSSIBLE:  " << WHITE << possible_count  << "\n" << RESET;
    }

    print_section("EXPORT");
    export_results(results, domain);

    LOG_INFO("subdomain_scan", "done domain="+domain
    +" found="+std::to_string(results.size())
    +" doh="+std::to_string(doh_used.load()));
}
