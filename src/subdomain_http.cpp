#include "subdomain_common.hpp"
#include "../include/user_agents.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <curl/curl.h>
#include <regex>
#include <thread>
#include <utility>

void http_jitter() {
    std::uniform_int_distribution<int> d(5, 40);
    std::this_thread::sleep_for(std::chrono::milliseconds(d(tl_rng)));
}

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

CurlResponse libcurl_get(const std::string& url,
                         const std::string& host_hdr,
                         const std::string& ua,
                         int timeout_s,
                         const std::vector<std::string>& extra_headers)
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

CurlResponse fast_probe(const std::string& sub, int timeout_s) {
    auto r = libcurl_get("https://"+sub, sub, random_ua(), timeout_s);
    if (r.http_code > 0) return r;
    return libcurl_get("http://"+sub, sub, random_ua(), timeout_s);
}

long fast_check(const std::string& sub, int timeout_s) {
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

WAFInfo detect_waf(const std::string& hdrs, const std::string& body, const std::string& cookies) {
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

TechInfo detect_tech(const std::string& headers, const std::string& body, const std::string& cookies) {
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

std::string parse_title(const std::string& body) {
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
