#include "subdomain_common.hpp"
#include "../include/user_agents.hpp"
#include <algorithm>
#include <cstdlib>
#include <curl/curl.h>
#include <regex>
#include <sstream>

void passive_crtsh(const std::string& domain, std::set<std::string>& out) {
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

void passive_hackertarget(const std::string& domain, std::set<std::string>& out) {
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

void passive_alienvault(const std::string& d, std::set<std::string>& out)   { auto b=safe_curl("https://otx.alienvault.com/api/v1/indicators/domain/"+d+"/passive_dns",15); if(!b.empty()){extract_subs(b,d,out);} }
void passive_urlscan(const std::string& d, std::set<std::string>& out)      { auto b=safe_curl("https://urlscan.io/api/v1/search/?q=domain:"+d+"&size=200",15); if(!b.empty()){extract_subs(b,d,out);} }
void passive_rapiddns(const std::string& d, std::set<std::string>& out)     { auto b=safe_curl("https://rapiddns.io/subdomain/"+d+"?full=1&down=1",15); if(!b.empty()){extract_subs(b,d,out);} }
void passive_threatcrowd(const std::string& d, std::set<std::string>& out)  { auto b=safe_curl("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+d,15); if(!b.empty()){extract_subs(b,d,out);} }

void passive_dnsdumpster(const std::string& domain, std::set<std::string>& out) {
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

void passive_virustotal(const std::string& d, std::set<std::string>& out) {
    const char* k = getenv("VT_API_KEY");
    if (!k || !*k) return;

    auto resp = libcurl_get(
        "https://www.virustotal.com/api/v3/domains/" + d + "/subdomains?limit=40",
        "", random_ua(), 15, {"x-apikey: " + std::string(k)});
    if (resp.body.empty()) return;

    extract_subs(resp.body, d, out);

    std::regex re_c("\"cursor\"\\s*:\\s*\"([^\"]+)\"");
    std::smatch mc;
    if (!std::regex_search(resp.body, mc, re_c)) return;

    auto resp2 = libcurl_get(
        "https://www.virustotal.com/api/v3/domains/" + d + "/subdomains?limit=40&cursor=" + mc[1].str(),
        "", random_ua(), 15, {"x-apikey: " + std::string(k)});
    if (resp2.body.empty()) return;

    extract_subs(resp2.body, d, out);
}

void passive_securitytrails(const std::string& d, std::set<std::string>& out) {
    const char* k = getenv("ST_API_KEY"); if (!k||!*k) return;
    auto resp = libcurl_get("https://api.securitytrails.com/v1/domain/"+d+"/subdomains?children_only=false&include_inactive=true", "", random_ua(), 15, {"apikey: "+std::string(k), "Accept: application/json"});
    if (!resp.body.empty()) extract_subs(resp.body, d, out);
}

void passive_shodan(const std::string& d, std::set<std::string>& out) {
    const char* k = getenv("SHODAN_API_KEY"); if (!k||!*k) return;
    auto resp = libcurl_get("https://api.shodan.io/dns/domain/"+d+"?key="+std::string(k), "", random_ua(), 15);
    if (!resp.body.empty()) extract_subs(resp.body, d, out);
}

void passive_censys(const std::string& d, std::set<std::string>& out) {
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

void dns_extra_records(const std::string& domain, std::set<std::string>& out) {
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
