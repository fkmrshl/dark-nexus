#include "subdomain_common.hpp"
#include "environment.hpp"
#include "dns_response.hpp"
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include "../include/security.hpp"
#include "../include/user_agents.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>
#include <unistd.h>
#include <utility>

std::optional<std::string> normalize_subdomain_name(const std::string& value, const std::string& domain) {
    auto candidate = value;
    const auto first = candidate.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return std::nullopt;
    candidate = candidate.substr(first, candidate.find_last_not_of(" \t\r\n") - first + 1);
    if (candidate.rfind("*.", 0) == 0) candidate.erase(0, 2);
    candidate = dns_response::name_key(candidate);
    const auto root = dns_response::name_key(domain);
    if (!dns_response::valid_name(candidate) || !dns_response::valid_name(root)) return std::nullopt;
    const auto suffix = "." + root;
    if (candidate.size() <= suffix.size() || candidate.compare(candidate.size() - suffix.size(), suffix.size(), suffix) != 0)
        return std::nullopt;
    return candidate;
}

void extract_subs(const std::string& text, const std::string& domain, std::set<std::string>& out) {
    std::string token;
    bool overlong = false;
    auto consume = [&]() {
        if (!overlong) if (const auto normalized = normalize_subdomain_name(token, domain)) out.insert(*normalized);
        token.clear();
        overlong = false;
    };
    for (unsigned char c : text) {
        if (g_cancel_token.cancelled.load(std::memory_order_relaxed)) return;
        if (out.size() >= 50000) { subdomain_warning("Passive candidate limit of 50000 reached; additional names were skipped"); return; }
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '.' || c == '-' || c == '_' || c == '*') {
            if (token.size() < 255) token += static_cast<char>(c);
            else overlong = true;
        }
        else consume();
    }
    consume();
}

std::set<std::string> extract_script_urls(const std::string& html, const std::string& base_url,
                                          const std::string& domain, std::size_t limit) {
    std::set<std::string> output;
    limit = std::min<std::size_t>(limit, 50);
    if (!limit || g_cancel_token.cancelled) return output;
    using Url = std::unique_ptr<CURLU, decltype(&curl_url_cleanup)>;
    auto part = [](CURLU* url, CURLUPart field) -> std::optional<std::string> {
        char* raw = nullptr;
        if (curl_url_get(url, field, &raw, 0) != CURLUE_OK) return std::nullopt;
        std::unique_ptr<char, decltype(&curl_free)> value(raw, curl_free);
        return std::string(value.get());
    };
    const auto root = dns_response::name_key(domain);
    auto allowed = [&](CURLU* url) {
        auto scheme = part(url, CURLUPART_SCHEME);
        const auto host = part(url, CURLUPART_HOST);
        if (scheme) std::transform(scheme->begin(), scheme->end(), scheme->begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        return scheme && (*scheme == "http" || *scheme == "https") && host &&
            dns_response::valid_name(dns_response::name_key(*host)) &&
            (dns_response::name_key(*host) == root || normalize_subdomain_name(*host, root)) &&
            !part(url, CURLUPART_USER) && !part(url, CURLUPART_PASSWORD);
    };
    Url base(curl_url(), curl_url_cleanup);
    if (!dns_response::valid_name(root) || !base ||
        base_url.find('\0') != std::string::npos ||
        curl_url_set(base.get(), CURLUPART_URL, base_url.c_str(), 0) != CURLUE_OK || !allowed(base.get()))
        return output;
    auto add = [&](std::size_t start, std::size_t end) {
        if (end - start > 8192) return;
        auto value = html.substr(start, end - start);
        const auto first = value.find_first_not_of(" \t\r\n\f");
        if (first == std::string::npos) return;
        value = value.substr(first, value.find_last_not_of(" \t\r\n\f") - first + 1);
        std::string decoded;
        decoded.reserve(value.size());
        for (std::size_t i = 0; i < value.size(); ++i) {
            if (value.compare(i, 5, "&amp;") == 0) { decoded += '&'; i += 4; }
            else decoded += value[i];
        }
        if (decoded.find('\0') != std::string::npos || decoded.find('\\') != std::string::npos) return;
        Url url(curl_url_dup(base.get()), curl_url_cleanup);
        if (!url || curl_url_set(url.get(), CURLUPART_URL, decoded.c_str(), 0) != CURLUE_OK || !allowed(url.get())) return;
        const auto path = part(url.get(), CURLUPART_PATH);
        if (!path || path->size() < 3) return;
        auto extension = path->substr(path->size() - 3);
        std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        if (extension != ".js") return;
        const auto host = part(url.get(), CURLUPART_HOST);
        const auto normalized_host = dns_response::name_key(*host);
        if (curl_url_set(url.get(), CURLUPART_HOST, normalized_host.c_str(), 0) != CURLUE_OK ||
            curl_url_set(url.get(), CURLUPART_FRAGMENT, nullptr, 0) != CURLUE_OK) return;
        if (const auto resolved = part(url.get(), CURLUPART_URL)) output.insert(*resolved);
    };
    constexpr std::size_t max_html = 1024 * 1024;
    const auto size = std::min(html.size(), max_html);
    const std::string_view input(html.data(), size);
    if (html.size() > max_html) subdomain_warning("JS discovery HTML capture exceeded 1 MiB; remaining input skipped");
    auto whitespace = [](unsigned char ch) { return std::isspace(ch) != 0; };
    auto name_char = [](unsigned char ch) { return std::isalnum(ch) || ch == '-' || ch == '_' || ch == ':'; };
    std::size_t cursor = 0;
    while (cursor < size && output.size() < limit && !g_cancel_token.cancelled) {
        cursor = input.find('<', cursor);
        if (cursor == std::string::npos || cursor >= size) break;
        if (input.compare(cursor, 4, "<!--") == 0) {
            const auto end = input.find("-->", cursor + 4);
            if (end == std::string::npos || end >= size) break;
            cursor = end + 3;
            continue;
        }
        ++cursor;
        if (cursor >= size || !std::isalpha(static_cast<unsigned char>(html[cursor]))) continue;
        while (cursor < size && name_char(static_cast<unsigned char>(html[cursor]))) ++cursor;
        while (cursor < size && html[cursor] != '>' && html[cursor] != '<' &&
               output.size() < limit && !g_cancel_token.cancelled) {
            if (whitespace(static_cast<unsigned char>(html[cursor])) || html[cursor] == '/') { ++cursor; continue; }
            const auto start = cursor;
            while (cursor < size && name_char(static_cast<unsigned char>(html[cursor]))) ++cursor;
            if (cursor == start) { ++cursor; continue; }
            auto name = html.substr(start, cursor - start);
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            while (cursor < size && whitespace(static_cast<unsigned char>(html[cursor]))) ++cursor;
            if (cursor >= size || html[cursor] != '=') continue;
            ++cursor;
            while (cursor < size && whitespace(static_cast<unsigned char>(html[cursor]))) ++cursor;
            if (cursor >= size) break;
            const char quote = html[cursor] == '\'' || html[cursor] == '"' ? html[cursor++] : '\0';
            const auto value_start = cursor;
            if (quote) {
                cursor = input.find(quote, cursor);
                if (cursor == std::string::npos || cursor >= size) { cursor = size; break; }
            } else {
                while (cursor < size && !whitespace(static_cast<unsigned char>(html[cursor])) &&
                       html[cursor] != '>' && html[cursor] != '<') ++cursor;
            }
            if (name == "src" || name == "href") add(value_start, cursor);
            if (quote) ++cursor;
        }
        if (cursor < size && html[cursor] == '>') ++cursor;
    }
    return output;
}

std::vector<std::string> doh_query(const std::string& hostname, const std::string& type, std::string* provider) {
    if (provider) provider->clear();
    if (!dns_response::valid_name(hostname) || (type != "A" && type != "AAAA") || g_cancel_token.cancelled.load()) return {};
    for (const auto& entry : std::vector<std::pair<std::string, std::string>>{
            {"cloudflare", "https://cloudflare-dns.com/dns-query?name=" + hostname + "&type=" + type},
            {"google", "https://dns.google/resolve?name=" + hostname + "&type=" + type}}) {
        if (g_cancel_token.cancelled.load()) break;
        const auto response = libcurl_get(entry.second, "", random_ua(), 6, {"Accept: application/dns-json"});
        if (response.cancelled) break;
        if (!response.success) {
            subdomain_warning("DoH " + entry.first + ": " + (response.error.empty() ? "HTTP " + std::to_string(response.http_code) : response.error));
            continue;
        }
        const auto answer = dns_response::parse_doh_response(response.body, hostname, type == "A" ? 1 : 28);
        if (!answer.valid) { subdomain_warning("DoH " + entry.first + ": " + answer.error); continue; }
        if (provider) *provider = entry.first;
        return answer.addresses;
    }
    return {};
}

std::string auto_find_wordlist() {
    return environment::find_wordlist(environment::current());
}

std::optional<std::string> normalize_wordlist_candidate_to_fqdn(
    const std::string& line,
    const std::string& scan_domain)
{
    auto first = line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return std::nullopt;
    auto last = line.find_last_not_of(" \t\r\n");
    std::string candidate = line.substr(first, last-first+1);
    if (candidate.empty() || candidate.front() == '#') return std::nullopt;

    std::transform(candidate.begin(), candidate.end(), candidate.begin(),
                   [](unsigned char ch){ return static_cast<char>(std::tolower(ch)); });
    if (!candidate.empty() && candidate.back() == '.') candidate.pop_back();
    if (candidate.empty() || candidate == scan_domain) return std::nullopt;

    const std::string suffix = "." + scan_domain;
    std::string fqdn;
    if (candidate.size() >= suffix.size() &&
        candidate.compare(candidate.size()-suffix.size(), suffix.size(), suffix) == 0) {
        fqdn = std::move(candidate);
    } else {
        fqdn = candidate + suffix;
    }

    if (fqdn == scan_domain || !InputGuard::is_valid_host(fqdn)) return std::nullopt;
    return fqdn;
}

const std::vector<std::string>& builtin_wordlist() {
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

void for_each_permutation_candidate(const std::set<std::string>& found,
                                    const std::string& domain,
                                    const std::function<void(std::string&&)>& emit)
{
    static const std::vector<std::string> affixes = {
        "1","2","3","4","old","new","dev","test","stg","prod","api","app",
        "backend","internal","admin","v2","v3","beta","alpha","legacy","tmp",
        "uat","qa","staging","preprod","corp","int","secure","cloud"
    };
    for (auto& sub : found) {
        if (g_cancel_token.cancelled.load()) return;
        const auto seed = normalize_subdomain_name(sub, domain);
        if (!seed) continue;
        const auto dot = seed->find('.');
        const auto label = seed->substr(0, dot);
        const auto parent_suffix = seed->substr(dot);
        for (auto& af : affixes) {
            if (g_cancel_token.cancelled.load()) return;
            for (auto& candidate : {label+"-"+af+parent_suffix, label+af+parent_suffix,
                    af+"-"+label+parent_suffix, af+label+parent_suffix})
                if (const auto normalized = normalize_subdomain_name(candidate, domain)) emit(std::string(*normalized));
        }
    }
}

std::vector<std::string> generate_permutations(const std::set<std::string>& found,
                                               const std::string& domain)
{
    std::set<std::string> perms;
    for_each_permutation_candidate(found, domain, [&](std::string&& candidate) {
        perms.insert(std::move(candidate));
    });
    return {perms.begin(), perms.end()};
}
