#include "subdomain_common.hpp"
#include "../include/security.hpp"
#include "../include/user_agents.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <chrono>
#include <curl/curl.h>
#include <cstring>
#include <limits>
#include <memory>
#include <nlohmann/json.hpp>
#include <thread>
#include <utility>

std::string sanitize_subdomain_text(const std::string& value, std::size_t limit) {
    auto single_line = value;
    for (auto& byte : single_line) if (byte == '\n' || byte == '\r' || byte == '\t') byte = ' ';
    const auto clean = InputGuard::sanitize_output(single_line, limit);
    const auto encoded = nlohmann::json(clean).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    auto text = nlohmann::json::parse(encoded).get<std::string>();
    if (text.size() > limit) {
        text.resize(limit);
        while (!text.empty() && (static_cast<unsigned char>(text.back()) & 0xc0) == 0x80) text.pop_back();
        if (!text.empty() && static_cast<unsigned char>(text.back()) >= 0xc0) text.pop_back();
    }
    return text;
}

void subdomain_warning(const std::string& message) {
    if (g_cancel_token.cancelled.load(std::memory_order_relaxed)) return;
    const auto text = sanitize_subdomain_text(message, 1024);
    std::lock_guard<std::mutex> lock(g_result_mtx);
    if (g_result.warnings.size() >= 64 || std::find(g_result.warnings.begin(), g_result.warnings.end(), text) != g_result.warnings.end()) return;
    g_result.warnings.push_back(text);
}

void http_jitter() {
    std::uniform_int_distribution<int> delay(5, 40);
    if (!g_cancel_token.cancelled.load(std::memory_order_relaxed))
        std::this_thread::sleep_for(std::chrono::milliseconds(delay(tl_rng)));
}

namespace {
struct Transfer {
    CurlResponse response;
    std::size_t body_limit = 1024 * 1024, header_limit = 64 * 1024;
    std::size_t body_bytes = 0, header_bytes = 0;
    bool target = false, final_header_block = false;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

bool transfer_stopped(Transfer& transfer) {
    if (g_cancel_token.cancelled.load(std::memory_order_relaxed)) {
        transfer.response.cancelled = true;
        return true;
    }
    if (transfer.deadline && std::chrono::steady_clock::now() >= *transfer.deadline) {
        transfer.response.timed_out = true;
        return true;
    }
    return false;
}

std::size_t body_callback(char* data, std::size_t size, std::size_t count, void* opaque) {
    auto& transfer = *static_cast<Transfer*>(opaque);
    if (size && count > std::numeric_limits<std::size_t>::max() / size) { transfer.response.truncated = true; return 0; }
    const auto bytes = size * count;
    if (transfer_stopped(transfer)) return 0;
    const auto available = transfer.body_limit - transfer.body_bytes;
    const auto captured = std::min(bytes, available);
    if (bytes > available && !transfer.target) { transfer.response.truncated = true; return 0; }
    try { transfer.response.body.append(data, captured); }
    catch (...) { transfer.response.callback_failed = true; return 0; }
    transfer.body_bytes += captured;
    if (captured != bytes) { transfer.response.truncated = true; return 0; }
    return bytes;
}

std::size_t header_callback(char* data, std::size_t size, std::size_t count, void* opaque) {
    auto& transfer = *static_cast<Transfer*>(opaque);
    if (size && count > std::numeric_limits<std::size_t>::max() / size) { transfer.response.truncated = true; transfer.response.headers_complete = false; return 0; }
    const auto bytes = size * count;
    if (transfer_stopped(transfer)) return 0;
    if (bytes > transfer.header_limit - transfer.header_bytes) { transfer.response.truncated = true; transfer.response.headers_complete = false; return 0; }
    transfer.header_bytes += bytes;
    const bool status_line = bytes >= 5 && std::memcmp(data, "HTTP/", 5) == 0;
    // Trailer fields are bounded but must not replace the original response metadata.
    if (transfer.response.headers_complete && !status_line) return bytes;
    if (status_line) {
        transfer.response.headers.clear();
        transfer.response.body.clear();
        transfer.response.headers_complete = false;
        const auto* space = static_cast<const char*>(std::memchr(data, ' ', bytes));
        transfer.final_header_block = space && static_cast<std::size_t>(space - data) + 3 < bytes &&
            ((space[1] >= '2' && space[1] <= '9') || (space[1] == '1' && space[2] == '0' && space[3] == '1'));
    }
    try { transfer.response.headers.append(data, bytes); }
    catch (...) { transfer.response.callback_failed = true; transfer.response.headers_complete = false; return 0; }
    if ((bytes == 2 && data[0] == '\r' && data[1] == '\n') || (bytes == 1 && data[0] == '\n'))
        transfer.response.headers_complete = transfer.final_header_block;
    return bytes;
}

int progress_callback(void* opaque, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    return transfer_stopped(*static_cast<Transfer*>(opaque)) ? 1 : 0;
}

CurlResponse request(const std::string& url, const std::string& host, const std::string& ua, int timeout_s,
                     const std::vector<std::string>& headers, SubdomainHttpMode mode,
                     const std::string* post = nullptr, const std::string& credentials = "", bool head = false,
                     std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt,
                     const std::vector<std::string>& addresses = {}) {
    Transfer transfer;
    transfer.deadline = deadline;
    transfer.response.requested_url = url;
    transfer.response.method = post ? "POST" : head ? "HEAD" : "GET";
    if (mode == SubdomainHttpMode::TargetProbe) { transfer.body_limit = 50000; transfer.target = true; }
    if (g_cancel_token.cancelled.load(std::memory_order_relaxed)) {
        transfer.response.cancelled = true;
        transfer.response.error = "cancelled";
        return transfer.response;
    }
    if (!InputGuard::is_safe_url(url) || (!host.empty() && !InputGuard::is_valid_host(host))) {
        transfer.response.error = "invalid HTTP URL or host";
        return transfer.response;
    }
    long timeout_ms = static_cast<long>(std::clamp(timeout_s, 1, 60)) * 1000;
    if (deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            *deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) {
            transfer.response.timed_out = true;
            transfer.response.transport_code = static_cast<int>(CURLE_OPERATION_TIMEDOUT);
            transfer.response.error = "HTTP deadline exceeded";
            return transfer.response;
        }
        timeout_ms = static_cast<long>(std::min<long long>(timeout_ms, remaining));
    }
    // Lists must outlive the easy handle that references them.
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> fields(nullptr, &curl_slist_free_all);
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> resolve(nullptr, &curl_slist_free_all);
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> owner(curl_easy_init(), &curl_easy_cleanup);
    CURL* handle = owner.get();
    if (!handle) { transfer.response.error = "cannot initialize HTTP client"; return transfer.response; }
    for (const auto& header : headers) {
        if (header.find_first_of("\r\n") != std::string::npos || header.find('\0') != std::string::npos) {
            transfer.response.error = "invalid HTTP header";
            return transfer.response;
        }
        auto* next = curl_slist_append(fields.get(), header.c_str());
        if (!next) {
            transfer.response.error = "cannot allocate HTTP headers";
            return transfer.response;
        }
        fields.release();
        fields.reset(next);
    }
    if (!addresses.empty()) {
        if (addresses.size() > 256) { transfer.response.error = "too many pinned addresses"; return transfer.response; }
        std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> parsed(curl_url(), &curl_url_cleanup);
        if (!parsed || curl_url_set(parsed.get(), CURLUPART_URL, url.c_str(), 0) != CURLUE_OK) {
            transfer.response.error = "cannot parse pinned URL"; return transfer.response;
        }
        char* raw_host = nullptr;
        char* raw_port = nullptr;
        const auto host_status = curl_url_get(parsed.get(), CURLUPART_HOST, &raw_host, 0);
        const auto port_status = curl_url_get(parsed.get(), CURLUPART_PORT, &raw_port, CURLU_DEFAULT_PORT);
        std::unique_ptr<char, decltype(&curl_free)> url_host(raw_host, &curl_free), url_port(raw_port, &curl_free);
        if (host_status != CURLUE_OK || port_status != CURLUE_OK || !url_host || !url_port) {
            transfer.response.error = "cannot parse pinned URL host or port"; return transfer.response;
        }
        // Pinned probes require a DNS name: libcurl can bypass resolve entries for IP literals.
        std::string hostname(url_host.get());
        if (hostname.size() >= 2 && hostname.front() == '[' && hostname.back() == ']')
            hostname = hostname.substr(1, hostname.size() - 2);
        unsigned char host_bytes[16];
        if (inet_pton(AF_INET, hostname.c_str(), host_bytes) == 1 ||
            inet_pton(AF_INET6, hostname.c_str(), host_bytes) == 1) {
            transfer.response.error = "pinned HTTP request requires a DNS hostname"; return transfer.response;
        }
        std::string entry = std::string(url_host.get()) + ":" + url_port.get() + ":";
        for (std::size_t i = 0; i < addresses.size(); ++i) {
            unsigned char bytes[16];
            const auto& address = addresses[i];
            if (address.find('\0') != std::string::npos) { transfer.response.error = "invalid pinned address"; return transfer.response; }
            const bool ipv4 = inet_pton(AF_INET, address.c_str(), bytes) == 1;
            const bool ipv6 = inet_pton(AF_INET6, address.c_str(), bytes) == 1;
            if (!ipv4 && !ipv6) { transfer.response.error = "invalid pinned address"; return transfer.response; }
            if (i) entry += ',';
            entry += ipv6 ? "[" + address + "]" : address;
        }
        resolve.reset(curl_slist_append(nullptr, entry.c_str()));
        if (!resolve || curl_easy_setopt(handle, CURLOPT_RESOLVE, resolve.get()) != CURLE_OK ||
            curl_easy_setopt(handle, CURLOPT_PROXY, "") != CURLE_OK) {
            transfer.response.error = "cannot configure pinned HTTP request"; return transfer.response;
        }
        transfer.response.dns_pinned = true;
    }
    curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(handle, CURLOPT_USERAGENT, ua.c_str());
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, fields.get());
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(handle, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
    curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 3L);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
    curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, std::min(timeout_ms, 3000L));
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    if (!head && mode == SubdomainHttpMode::Verified) curl_easy_setopt(handle, CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(transfer.body_limit));
    curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(handle, CURLOPT_HEADERDATA, &transfer);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, body_callback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &transfer);
    curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(handle, CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(handle, CURLOPT_XFERINFODATA, &transfer);
    if (head) curl_easy_setopt(handle, CURLOPT_NOBODY, 1L);
    if (post) {
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, post->data());
        curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(post->size()));
    }
    if (!credentials.empty()) curl_easy_setopt(handle, CURLOPT_USERPWD, credentials.c_str());
    const auto result = curl_easy_perform(handle);
    transfer.response.transport_code = static_cast<int>(result);
    transfer.response.cancelled = transfer.response.cancelled || g_cancel_token.cancelled.load(std::memory_order_relaxed);
    transfer.response.timed_out = transfer.response.timed_out || result == CURLE_OPERATION_TIMEDOUT;
    transfer.response.truncated = transfer.response.truncated || result == CURLE_FILESIZE_EXCEEDED;
    long code = 0;
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &code);
    char* effective = nullptr;
    if (curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &effective) == CURLE_OK && effective)
        transfer.response.effective_url = effective;
    char* primary_ip = nullptr;
    if (curl_easy_getinfo(handle, CURLINFO_PRIMARY_IP, &primary_ip) == CURLE_OK && primary_ip)
        transfer.response.primary_ip = primary_ip;
    if (code == 101 || code >= 200) transfer.response.http_code = code;
    transfer.response.body_complete = result == CURLE_OK && !transfer.response.cancelled &&
        !transfer.response.truncated && !transfer.response.callback_failed && transfer.response.headers_complete;
    transfer.response.success = transfer.response.body_complete && code >= 200 && code < 300;
    if (!transfer.response.body_complete) {
        transfer.response.error = transfer.response.cancelled ? "cancelled" : transfer.response.callback_failed ? "cannot buffer HTTP response" :
            transfer.response.timed_out && deadline ? "HTTP deadline exceeded" :
            transfer.response.truncated ? "HTTP response exceeded the capture limit" :
            result != CURLE_OK ? curl_easy_strerror(result) : "incomplete HTTP headers";
    }
    return transfer.response;
}
}

CurlResponse libcurl_get(const std::string& url, const std::string& host, const std::string& ua, int timeout_s,
                         const std::vector<std::string>& headers, SubdomainHttpMode mode) {
    return request(url, host, ua, timeout_s, headers, mode);
}

CurlResponse libcurl_get_deadline(const std::string& url, std::chrono::steady_clock::time_point deadline) {
    return request(url, "", random_ua(), 5, {}, SubdomainHttpMode::Verified, nullptr, "", false, deadline);
}

CurlResponse libcurl_post(const std::string& url, const std::string& ua, int timeout_s,
                          const std::vector<std::string>& headers, const std::string& body,
                          const std::string& credentials) {
    return request(url, "", ua, timeout_s, headers, SubdomainHttpMode::Verified, &body, credentials);
}

CurlResponse fast_probe(const std::string& sub, int timeout_s, bool head, const std::vector<std::string>& addresses) {
    auto host = sub;
    const auto colon = host.rfind(':');
    if (colon != std::string::npos && host.find(':') == colon) host.resize(colon);
    auto response = request("https://" + sub, host, random_ua(), timeout_s, {}, SubdomainHttpMode::TargetProbe, nullptr, "", head, std::nullopt, addresses);
    std::vector<SubdomainHttpObservation> attempts;
    attempts.push_back(response);
    if (!response.http_code && !response.cancelled) {
        response = request("http://" + sub, host, random_ua(), timeout_s, {}, SubdomainHttpMode::TargetProbe, nullptr, "", head, std::nullopt, addresses);
        attempts.push_back(response);
    }
    response.attempts = std::move(attempts);
    if (!response.cancelled && !response.body_complete)
        subdomain_warning("HTTP enrichment for " + sub + ": " + response.error);
    return response;
}

long fast_check(const std::string& sub, int timeout_s) {
    return fast_probe(sub, timeout_s, true).http_code;
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
    auto lc = [](std::string s){ std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){ return static_cast<char>(std::tolower(c)); }); return s; };
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
    auto lc = [](std::string s){ std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){ return static_cast<char>(std::tolower(c)); }); return s; };
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
    auto lower = body.substr(0, 50000);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    auto start = lower.find("<title");
    if (start == std::string::npos || start + 6 >= lower.size() ||
        (lower[start + 6] != '>' && !std::isspace(static_cast<unsigned char>(lower[start + 6])))) return "";
    start = lower.find('>', start + 6);
    if (start == std::string::npos) return "";
    const auto end = lower.find("</title>", start + 1);
    if (end == std::string::npos) return "";
    std::string t = body.substr(start + 1, end - start - 1);
    auto a = t.find_first_not_of(" \t\r\n");
    auto z = t.find_last_not_of(" \t\r\n");
    if (a==std::string::npos) return "";
    t = t.substr(a, z-a+1);
    const bool shortened = t.size() > 60;
    return sanitize_subdomain_text(t, 60) + (shortened ? "..." : "");
}
