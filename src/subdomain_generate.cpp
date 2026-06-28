#include "subdomain_common.hpp"
#include "../include/security.hpp"
#include "../include/user_agents.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <regex>
#include <unistd.h>
#include <utility>

static std::string regex_escape(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() * 2);
    for (char ch : value) {
        switch (ch) {
            case '\\': case '^': case '$': case '.': case '|': case '?': case '*':
            case '+': case '(': case ')': case '[': case ']': case '{': case '}':
                escaped.push_back('\\');
                break;
            default:
                break;
        }
        escaped.push_back(ch);
    }
    return escaped;
}

void extract_subs(const std::string& text, const std::string& domain, std::set<std::string>& out) {
    std::string pat = "([a-zA-Z0-9_\\-]+(?:\\.[a-zA-Z0-9_\\-]+)*\\."+regex_escape(domain)+")";
    std::regex re(pat, std::regex::icase);
    std::sregex_iterator it(text.begin(), text.end(), re), end;
    for (; it != end; ++it) {
        std::string h = (*it)[1].str();
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
        if (h.size() > domain.size() && h.substr(h.size()-domain.size()) == domain) out.insert(h);
    }
}

std::vector<std::string> doh_query(const std::string& hostname,
                                   const std::string& type,
                                   std::string* prov)
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

static bool is_safe_readable_wordlist_path(const std::string& path) {
    if (path.empty()) return false;
    if (path.find("..") != std::string::npos) return false;
    if (path.find('\0') != std::string::npos) return false;
    for (unsigned char ch : path) {
        bool alnum = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
        if (alnum || ch == '_' || ch == '-' || ch == '.' || ch == '/') continue;
        return false;
    }
    return access(path.c_str(), R_OK) == 0;
}

std::string auto_find_wordlist() {
    const char* h_env = getenv("HOME");
    std::string h = h_env ? h_env : "/root";
    for (auto& p : std::vector<std::string>{
        "./best-dns-wordlist.txt",
        "best-dns-wordlist.txt",
        "/usr/share/wordlists/dark-nexus/best-dns-wordlist.txt",
        h+"/best-dns-wordlist.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-500000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-500000.txt",
        "/opt/SecLists/Discovery/DNS/subdomains-top1million-500000.txt",
        "/opt/wordlists/best-dns-wordlist.txt",
        h+"/wordlists/subdomains-top1million-500000.txt",
    }) { if (is_safe_readable_wordlist_path(p)) return p; }
    std::vector<char> buf(4096, 0); std::string loc_res;
    FILE* pipe = popen("locate best-dns-wordlist.txt 2>/dev/null | head -n 1", "r");
    if (pipe) {
        if (fgets(buf.data(), (int)buf.size(), pipe)) loc_res = buf.data();
        pclose(pipe);
        if (!loc_res.empty()) {
            if (loc_res.back()=='\n') loc_res.pop_back();
            if (is_safe_readable_wordlist_path(loc_res)) return loc_res;
        }
    }
    return "";
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
        std::string label = sub;
        auto dot = sub.find('.');
        if (dot!=std::string::npos) label = sub.substr(0, dot);
        if (label.empty()) continue;
        for (auto& af : affixes) {
            emit(label+"-"+af+"."+domain);
            emit(label+af+"."+domain);
            emit(af+"-"+label+"."+domain);
            emit(af+label+"."+domain);
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
