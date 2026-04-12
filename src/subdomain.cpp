#include "../include/dark_nexus.hpp"


struct WAFInfo {
    std::string name;
    std::string confidence;  
};

struct TechInfo {
    std::vector<std::string> stack;
    std::string cms;
    std::string language;
    std::string session_cookie;
};

struct SubResult {
    std::string sub;
    std::vector<std::string> ips;
    std::vector<std::string> ipv6;
    std::string cname, http_code, server, title;
    std::vector<uint16_t> open_ports;
    std::string source;
    WAFInfo waf;
    TechInfo tech;
    bool wildcard = false;
    std::string doh_fallback;
};


static std::vector<std::string> load_wordlist_file(const std::string& path) {
    std::vector<std::string> words;
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << RED << "  [!] wordlist not found: " << path << RESET << "\n";
        return words;
    }
    std::string line;
    while (std::getline(f, line)) {
        auto s = line.find_first_not_of(" \t\r\n");
        if (s == std::string::npos) continue;
        line = line.substr(s);
        auto e = line.find_last_not_of(" \t\r\n");
        if (e != std::string::npos) line = line.substr(0, e + 1);
        if (line.empty() || line[0] == '#') continue;
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


static void passive_crtsh(const std::string& domain, std::set<std::string>& out) {
    auto body = safe_curl("https://crt.sh/?q=%25." + domain + "&output=json", 20);
    if (body.empty()) return;
    std::regex re("\"(?:common_name|name_value)\"\\s*:\\s*\"([^\"]+)\"");
    std::sregex_iterator it(body.begin(), body.end(), re), end;
    for (; it != end; ++it) {
        std::string val = (*it)[1].str();
        std::istringstream vss(val);
        std::string part;
        while (std::getline(vss, part, '\n')) {
            if (part.size() > 2 && part[0]=='*' && part[1]=='.')
                part = part.substr(2);
            std::transform(part.begin(), part.end(), part.begin(), ::tolower);
            if (part.size() > domain.size() &&
                part.substr(part.size() - domain.size()) == domain)
                out.insert(part);
        }
    }
}

static void passive_hackertarget(const std::string& domain, std::set<std::string>& out) {
    auto body = safe_curl("https://api.hackertarget.com/hostsearch/?q=" + domain, 15);
    if (body.empty() || body.find("error") != std::string::npos) return;
    std::istringstream ss(body);
    std::string line;
    while (std::getline(ss, line)) {
        auto comma = line.find(',');
        if (comma == std::string::npos) continue;
        std::string sub = line.substr(0, comma);
        std::transform(sub.begin(), sub.end(), sub.begin(), ::tolower);
        if (sub.size() > domain.size() &&
            sub.substr(sub.size() - domain.size()) == domain)
            out.insert(sub);
    }
}

static void passive_alienvault(const std::string& domain, std::set<std::string>& out) {
    auto body = safe_curl(
        "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns", 15);
    if (body.empty()) return;
    std::regex re("\"hostname\"\\s*:\\s*\"([^\"]+)\"");
    std::sregex_iterator it(body.begin(), body.end(), re), end;
    for (; it != end; ++it) {
        std::string h = (*it)[1].str();
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
        if (h.size() > domain.size() &&
            h.substr(h.size() - domain.size()) == domain)
            out.insert(h);
    }
}

static void passive_urlscan(const std::string& domain, std::set<std::string>& out) {
    auto body = safe_curl(
        "https://urlscan.io/api/v1/search/?q=domain:" + domain + "&size=200", 15);
    if (body.empty()) return;
    for (auto field : {"\"domain\"", "\"hostname\""}) {
        std::string pat = std::string(field) + "\\s*:\\s*\"([^\"]+\\." + domain + ")\"";
        std::regex re(pat);
        std::sregex_iterator it(body.begin(), body.end(), re), end;
        for (; it != end; ++it) {
            std::string h = (*it)[1].str();
            std::transform(h.begin(), h.end(), h.begin(), ::tolower);
            out.insert(h);
        }
    }
}

static void passive_rapiddns(const std::string& domain, std::set<std::string>& out) {
    auto body = safe_curl("https://rapiddns.io/subdomain/" + domain + "?full=1&down=1", 15);
    if (body.empty()) return;
    std::string pat = "([a-z0-9_\\-]+(?:\\.[a-z0-9_\\-]+)*\\." + domain + ")";
    std::regex re(pat);
    std::sregex_iterator it(body.begin(), body.end(), re), end;
    for (; it != end; ++it) {
        std::string h = (*it)[1].str();
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
        out.insert(h);
    }
}


static std::vector<std::string> doh_query(
    const std::string& hostname,
    const std::string& type = "A",
    std::string* provider_out = nullptr)
{
    const std::vector<std::pair<std::string,std::string>> providers = {
        {"cloudflare", "https://cloudflare-dns.com/dns-query?name=" + hostname + "&type=" + type},
        {"google",     "https://dns.google/resolve?name="           + hostname + "&type=" + type},
    };
    for (auto& [name, url] : providers) {
        auto resp = safe_exec({"curl","-s","--max-time","6",
                               "-H","Accept: application/dns-json", url}, 8);
        if (resp.empty()) continue;
        std::vector<std::string> addrs;
        std::regex re("\"data\"\\s*:\\s*\"([0-9a-fA-F.:]+)\"");
        std::sregex_iterator it(resp.begin(), resp.end(), re), end;
        for (; it != end; ++it) {
            std::string addr = (*it)[1].str();
            if (addr.find('.') != std::string::npos ||
                addr.find(':') != std::string::npos)
                addrs.push_back(addr);
        }
        if (!addrs.empty()) {
            if (provider_out) *provider_out = name;
            return addrs;
        }
    }
    return {};
}

static std::vector<std::string> resolve_aaaa(const std::string& hostname) {
    auto out = safe_exec({"dig","+short","+time=3","+tries=1",hostname,"AAAA"}, 5);
    std::vector<std::string> addrs;
    if (out.empty()) return addrs;
    for (auto& line : split_lines(out))
        if (!line.empty() && line.find(':') != std::string::npos)
            addrs.push_back(line);
    return addrs;
}


static const std::vector<std::string> DEFAULT_RESOLVERS = {
    "8.8.8.8","8.8.4.4",
    "1.1.1.1","1.0.0.1",
    "9.9.9.9","149.112.112.112",
    "208.67.222.222","208.67.220.220",
    "64.6.64.6","64.6.65.6",
};

struct AresCtx {
    std::string hostname;
    std::vector<std::string>* ips;
    std::atomic<int>* pending;
};

static void ares_cb(void* arg, int status, int, struct hostent* host) {
    auto* ctx = static_cast<AresCtx*>(arg);
    if (status == ARES_SUCCESS && host)
        for (int i = 0; host->h_addr_list[i]; i++) {
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, host->h_addr_list[i], buf, sizeof(buf));
            ctx->ips->push_back(std::string(buf));
        }
    ctx->pending->fetch_sub(1);
    delete ctx;
}

static std::unordered_map<std::string, std::vector<std::string>>
async_resolve_batch(const std::vector<std::string>& hosts,
                    const std::vector<std::string>& resolvers = DEFAULT_RESOLVERS,
                    int concurrency = 5000)
{
    std::unordered_map<std::string, std::vector<std::string>> results;
    for (auto& h : hosts) results[h];

    ares_library_init(ARES_LIB_INIT_ALL);
    struct ares_options opts{};
    opts.timeout = 2000; opts.tries = 2;
    ares_channel channel;
    if (ares_init_options(&channel, &opts, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES) != ARES_SUCCESS) {
        ares_library_cleanup(); return results;
    }
    std::string csv;
    for (size_t i = 0; i < resolvers.size(); i++) { if(i) csv+=","; csv+=resolvers[i]; }
    ares_set_servers_csv(channel, csv.c_str());

    std::atomic<int> pending{0};
    size_t sent = 0, total = hosts.size();
    while (sent < total || pending.load() > 0) {
        while (sent < total && pending.load() < concurrency) {
            const std::string& h = hosts[sent++];
            pending.fetch_add(1);
            ares_gethostbyname(channel, h.c_str(), AF_INET, ares_cb,
                               new AresCtx{h, &results[h], &pending});
        }
        fd_set rfds, wfds;
        FD_ZERO(&rfds); FD_ZERO(&wfds);
        int nfds = ares_fds(channel, &rfds, &wfds);
        if (nfds == 0) {
            if (pending.load() > 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        struct timeval tv{};
        auto* tvp = ares_timeout(channel, nullptr, &tv);
        select(nfds, &rfds, &wfds, nullptr, tvp);
        ares_process(channel, &rfds, &wfds);
    }
    ares_destroy(channel);
    ares_library_cleanup();
    return results;
}


struct WAFSig {
    std::string name, confidence;
    std::vector<std::pair<std::string,std::string>> headers;
    std::vector<std::string> cookies;
    std::vector<std::string> body_kw;
};

static const std::vector<WAFSig>& waf_db() {
    static const std::vector<WAFSig> db = {
        {"Cloudflare",      "high",
            {{"server","cloudflare"},{"cf-ray",""},{"cf-cache-status",""}},
            {"__cfduid","cf_clearance"}, {}},
        {"Akamai",          "high",
            {{"x-check-cacheable",""},{"akamai-origin-hop",""},{"x-akamai-transformed",""}},
            {"ak_bmsc","bm_sz"}, {"AkamaiGHost"}},
        {"AWS WAF",         "high",
            {{"x-amzn-requestid",""},{"x-amz-cf-id",""},{"x-amzn-trace-id",""}},
            {}, {"Access Denied"}},
        {"Imperva",         "high",
            {{"x-iinfo",""},{"x-cdn","Incapsula"}},
            {"incap_ses","visid_incap"}, {"Incapsula incident"}},
        {"F5 BIG-IP",       "high",
            {{"x-wa-info",""},{"server","BigIP"}},
            {"BIGipServer","F5_ST"}, {}},
        {"Sucuri",          "high",
            {{"x-sucuri-id",""},{"x-sucuri-cache",""},{"server","Sucuri"}},
            {}, {"Sucuri WebSite Firewall"}},
        {"Barracuda",       "medium",
            {{"server","barracuda"}},
            {"barra_counter_session"}, {"Barracuda Web Application Firewall"}},
        {"ModSecurity",     "medium",
            {{"x-mod-security-message",""}},
            {}, {"ModSecurity","NOYB"}},
        {"Fortinet",        "high",
            {{"x-waf-event-info",""}},
            {"FORTIWAFSID"}, {"FortiGate","FortiWEB"}},
        {"Citrix ADC",      "medium",
            {{"via","NS-CACHE"}},
            {"NSC_"}, {}},
        {"DDoS-Guard",      "medium",
            {{"server","ddos-guard"}}, {}, {"DDoS-Guard"}},
        {"Qrator",          "medium",
            {{"server","qrator"}}, {}, {}},
        {"Wallarm",         "medium",
            {{"x-wallarm-node",""}}, {}, {}},
        {"Reblaze",         "medium",
            {{"x-reblaze-protection",""}}, {"rbzid"}, {}},
        {"Fastly/Varnish",  "low",
            {{"x-fastly-request-id",""},{"x-varnish",""},{"via","varnish"}}, {}, {}},
        {"StackPath",       "medium",
            {{"x-sp-url",""},{"server","StackPath"}}, {}, {}},
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
            else              { if (h.find(hvl)     != std::string::npos) score++; }
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

    if (h.find("x-powered-by: php")     != std::string::npos) { info.language="PHP";
        std::regex re("x-powered-by: php/([0-9\\.]+)"); std::smatch m;
        info.stack.push_back(std::regex_search(h,m,re) ? "PHP/"+m[1].str() : "PHP"); }
    else if (h.find("x-powered-by: asp.net") != std::string::npos)
        { info.language="C#/.NET"; info.stack.push_back("ASP.NET"); }
    else if (h.find("x-powered-by: express") != std::string::npos)
        { info.language="Node.js"; info.stack.push_back("Express"); }
    else if (h.find("x-powered-by: next.js") != std::string::npos)
        { info.language="Node.js"; info.stack.push_back("Next.js"); }

    if      (c.find("phpsessid")              != std::string::npos)
        { info.session_cookie="PHPSESSID";       if(info.language.empty()) info.language="PHP"; }
    else if (c.find("jsessionid")             != std::string::npos)
        { info.session_cookie="JSESSIONID";      info.language="Java"; info.stack.push_back("Java/Servlet"); }
    else if (c.find("asp.net_sessionid")      != std::string::npos)
        { info.session_cookie="ASP.NET_Session"; if(info.language.empty()) info.language="C#/.NET"; }
    else if (c.find("laravel_session")        != std::string::npos)
        { info.session_cookie="laravel_session"; info.stack.push_back("Laravel");
          if(info.language.empty()) info.language="PHP"; }
    else if (c.find("csrftoken")              != std::string::npos)
        { info.stack.push_back("Django");         if(info.language.empty()) info.language="Python"; }
    else if (c.find("rack.session")           != std::string::npos)
        { info.stack.push_back("Ruby/Rack");      if(info.language.empty()) info.language="Ruby"; }
    else if (c.find("_rails")                 != std::string::npos)
        { info.stack.push_back("Rails");          if(info.language.empty()) info.language="Ruby"; }

    if      (h.find("server: nginx")          != std::string::npos) info.stack.push_back("nginx");
    else if (h.find("server: apache")         != std::string::npos) info.stack.push_back("Apache");
    else if (h.find("server: microsoft-iis")  != std::string::npos)
        { info.stack.push_back("IIS"); if(info.language.empty()) info.language="C#/.NET"; }
    else if (h.find("server: litespeed")      != std::string::npos) info.stack.push_back("LiteSpeed");
    else if (h.find("server: openresty")      != std::string::npos) info.stack.push_back("OpenResty");
    else if (h.find("server: caddy")          != std::string::npos) info.stack.push_back("Caddy");
    else if (h.find("server: gunicorn")       != std::string::npos)
        { info.stack.push_back("Gunicorn"); if(info.language.empty()) info.language="Python"; }
    else if (h.find("server: uvicorn")        != std::string::npos)
        { info.stack.push_back("Uvicorn");  if(info.language.empty()) info.language="Python"; }

    if      (b.find("wp-content")   != std::string::npos) { info.cms="WordPress"; }
    else if (b.find("joomla")        != std::string::npos) { info.cms="Joomla"; }
    else if (b.find("drupal")        != std::string::npos ||
             h.find("x-drupal-cache")!= std::string::npos) { info.cms="Drupal"; }
    else if (b.find("cdn.shopify")   != std::string::npos) { info.cms="Shopify"; }
    else if (b.find("ghost-url")     != std::string::npos) { info.cms="Ghost"; }
    else if (b.find("magento")       != std::string::npos ||
             c.find("mage-")         != std::string::npos) { info.cms="Magento"; }
    else if (b.find("bitrix")        != std::string::npos) { info.cms="Bitrix"; }
    else if (b.find("typo3")         != std::string::npos) { info.cms="TYPO3"; }

    if (b.find("__react")  != std::string::npos) info.stack.push_back("React");
    if (b.find("__vue__")  != std::string::npos) info.stack.push_back("Vue.js");
    if (b.find("ng-version")!= std::string::npos) info.stack.push_back("Angular");
    if (b.find("__next")   != std::string::npos) info.stack.push_back("Next.js");
    if (b.find("nuxt")     != std::string::npos) info.stack.push_back("Nuxt.js");
    if (b.find("jquery")   != std::string::npos) info.stack.push_back("jQuery");

    if (h.find("x-amz-")  != std::string::npos) info.stack.push_back("AWS");
    if (h.find("x-ms-")   != std::string::npos) info.stack.push_back("Azure");
    if (h.find("x-goog-") != std::string::npos) info.stack.push_back("GCP");

    std::sort(info.stack.begin(), info.stack.end());
    info.stack.erase(std::unique(info.stack.begin(), info.stack.end()), info.stack.end());
    return info;
}


static std::vector<std::string> generate_permutations(
    const std::set<std::string>& found, const std::string& domain)
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
        if (dot != std::string::npos) label = sub.substr(0, dot);
        if (label.empty()) continue;
        for (auto& af : affixes) {
            perms.insert(label + "-" + af + "." + domain);
            perms.insert(label + af       + "." + domain);
            perms.insert(af + "-" + label + "." + domain);
            perms.insert(af + label       + "." + domain);
        }
    }
    return {perms.begin(), perms.end()};
}


static const std::vector<std::pair<std::string,std::string>>& takeover_sigs() {
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
    return s;
}


static void export_results(const std::vector<SubResult>& results, const std::string& domain) {
    {
        std::string fname = domain + "_subdomains.json";
        std::ofstream f(fname);
        f << "[\n";
        for (size_t i = 0; i < results.size(); i++) {
            auto& r = results[i];
            auto arr_str = [&](const std::vector<std::string>& v) {
                std::string s = "[";
                for (size_t j=0;j<v.size();j++) { if(j) s+=","; s+="\""+v[j]+"\""; }
                return s + "]";
            };
            auto arr_u16 = [&](const std::vector<uint16_t>& v) {
                std::string s = "[";
                for (size_t j=0;j<v.size();j++) { if(j) s+=","; s+=std::to_string(v[j]); }
                return s + "]";
            };
            f << "  {\n"
              << "    \"subdomain\": \""      << r.sub          << "\",\n"
              << "    \"source\": \""         << r.source       << "\",\n"
              << "    \"ipv4\": "             << arr_str(r.ips) << ",\n"
              << "    \"ipv6\": "             << arr_str(r.ipv6)<< ",\n"
              << "    \"cname\": \""          << r.cname        << "\",\n"
              << "    \"http_code\": \""      << r.http_code    << "\",\n"
              << "    \"server\": \""         << r.server       << "\",\n"
              << "    \"title\": \""          << r.title        << "\",\n"
              << "    \"open_ports\": "       << arr_u16(r.open_ports) << ",\n"
              << "    \"waf\": \""            << r.waf.name     << "\",\n"
              << "    \"waf_confidence\": \"" << r.waf.confidence << "\",\n"
              << "    \"language\": \""       << r.tech.language<< "\",\n"
              << "    \"cms\": \""            << r.tech.cms     << "\",\n"
              << "    \"stack\": "            << arr_str(r.tech.stack) << ",\n"
              << "    \"doh_fallback\": \""   << r.doh_fallback << "\"\n"
              << "  }";
            if (i+1 < results.size()) f << ",";
            f << "\n";
        }
        f << "]\n";
        std::cout << GREEN << "  [+] JSON: " << fname << "\n" << RESET;
    }
    {
        std::string fname = domain + "_subdomains.csv";
        std::ofstream f(fname);
        f << "subdomain,ipv4,ipv6,cname,http_code,server,title,ports,waf,language,cms,stack,source,doh_fallback\n";
        for (auto& r : results) {
            auto join_s = [](const std::vector<std::string>& v) {
                std::string s; for (auto& x:v){if(!s.empty())s+=" ";s+=x;} return s; };
            auto join_p = [](const std::vector<uint16_t>& v) {
                std::string s; for (auto x:v){if(!s.empty())s+=" ";s+=std::to_string(x);} return s; };
            auto q = [](const std::string& s) {
                return s.find(',')!=std::string::npos ? "\""+s+"\"" : s; };
            f << r.sub                    << ","
              << q(join_s(r.ips))         << ","
              << q(join_s(r.ipv6))        << ","
              << r.cname                  << ","
              << r.http_code              << ","
              << q(r.server)              << ","
              << q(r.title)               << ","
              << q(join_p(r.open_ports))  << ","
              << r.waf.name               << ","
              << r.tech.language          << ","
              << r.tech.cms               << ","
              << q(join_s(r.tech.stack))  << ","
              << r.source                 << ","
              << r.doh_fallback           << "\n";
        }
        std::cout << GREEN << "  [+] CSV:  " << fname << "\n" << RESET;
    }
}


void subdomain_scan(const std::string& domain,
                    const std::string& wordlist_path,
                    int max_threads,
                    bool run_permutations,
                    bool deep_passive)
{
    print_header("SUBDOMAIN SCAN // " + domain);

    const std::vector<uint16_t> SCAN_PORTS = {
        80,443,8080,8443,8000,8888,3000,5000,9090,9443,8081,8082,4443,2083,2087,10000
    };

    print_section("WORDLIST");
    std::vector<std::string> wordlist;
    if (!wordlist_path.empty()) {
        wordlist = load_wordlist_file(wordlist_path);
        if (!wordlist.empty())
            std::cout << GREEN << "  [+] " << wordlist.size() << " words: " << wordlist_path << "\n" << RESET;
    }
    if (wordlist.empty()) {
        wordlist = builtin_wordlist();
        std::cout << CYAN << "  [*] builtin wordlist (" << wordlist.size() << " words)\n" << RESET;
    }

    print_section("WILDCARD CHECK");
    std::set<std::string> wildcard_ips;
    std::atomic<bool> has_wildcard{false};
    {
        std::mt19937 rng(std::random_device{}());
        std::vector<std::string> probes;
        for (int i = 0; i < 5; i++) {
            std::string s;
            for (int j = 0; j < 16; j++) s += char('a' + rng() % 26);
            probes.push_back(s + "." + domain);
        }
        auto wc = async_resolve_batch(probes, DEFAULT_RESOLVERS, 10);
        for (auto& [h, ips] : wc)
            for (auto& ip : ips) { has_wildcard = true; wildcard_ips.insert(ip); }
    }
    if (has_wildcard) {
        std::cout << YELLOW << "  [!] wildcard ->";
        for (auto& ip : wildcard_ips) std::cout << " " << ip;
        std::cout << "\n  [!] filtering ON\n" << RESET;
    } else {
        std::cout << GREEN << "  [+] no wildcard\n" << RESET;
    }

    print_section("PASSIVE ENUM");
    std::set<std::string> passive_subs;
    size_t before;

    std::cout << YELLOW << "  [*] crt.sh...\n" << RESET;
    passive_crtsh(domain, passive_subs);
    std::cout << CYAN << "  [+] crt.sh:        " << passive_subs.size() << "\n" << RESET;

    if (deep_passive) {
        before = passive_subs.size();
        std::cout << YELLOW << "  [*] HackerTarget...\n" << RESET;
        passive_hackertarget(domain, passive_subs);
        std::cout << CYAN << "  [+] hackertarget:  +" << (passive_subs.size()-before) << "\n" << RESET;

        before = passive_subs.size();
        std::cout << YELLOW << "  [*] AlienVault OTX...\n" << RESET;
        passive_alienvault(domain, passive_subs);
        std::cout << CYAN << "  [+] alienvault:    +" << (passive_subs.size()-before) << "\n" << RESET;

        before = passive_subs.size();
        std::cout << YELLOW << "  [*] urlscan.io...\n" << RESET;
        passive_urlscan(domain, passive_subs);
        std::cout << CYAN << "  [+] urlscan.io:    +" << (passive_subs.size()-before) << "\n" << RESET;

        before = passive_subs.size();
        std::cout << YELLOW << "  [*] RapidDNS...\n" << RESET;
        passive_rapiddns(domain, passive_subs);
        std::cout << CYAN << "  [+] rapiddns:      +" << (passive_subs.size()-before) << "\n" << RESET;
    }
    std::cout << GREEN << "  [=] total passive: " << passive_subs.size() << "\n" << RESET;

    std::set<std::string> dedup;
    std::vector<std::string> all_subs;
    for (auto& w : wordlist) {
        std::string full = w + "." + domain;
        if (dedup.insert(full).second) all_subs.push_back(full);
    }
    for (auto& s : passive_subs)
        if (s != domain && dedup.insert(s).second) all_subs.push_back(s);

    int total_hosts = (int)all_subs.size();

    print_section("ASYNC DNS + DoH BRUTEFORCE");
    std::cout << YELLOW << "  checking " << total_hosts << " subdomains"
              << " (" << wordlist.size() << " wordlist + "
              << passive_subs.size() << " passive) via c-ares + DoH fallback...\n\n" << RESET;

    const int DNS_BATCH       = 100000;
    const int DNS_CONCURRENCY = 5000;

    std::mutex mtx;
    std::vector<SubResult> results;
    std::set<std::string> found_set;
    std::atomic<int> found_count{0}, dns_checked{0}, doh_used{0};

    ThreadPool pool(std::min(max_threads, total_hosts > 0 ? total_hosts : 1));

    auto process_resolved = [&](const std::string& sub,
                                 std::vector<std::string> ips,
                                 const std::string& doh_provider)
    {
        dns_checked++;
        if (ips.empty()) return;
        if (has_wildcard && ips.size() == 1 && wildcard_ips.count(ips[0])) return;

        { std::lock_guard<std::mutex> lk(mtx);
          if (!found_set.insert(sub).second) return; }

        std::vector<std::string> ipv6 = resolve_aaaa(sub);

        std::sort(ips.begin(), ips.end());
        ips.erase(std::unique(ips.begin(), ips.end()), ips.end());

        std::string cname;
        auto co = safe_exec({"dig","+short","+time=2","+tries=1",sub,"CNAME"}, 4);
        if (!co.empty()) {
            auto lines = split_lines(co);
            if (!lines.empty()) {
                cname = lines[0];
                while (!cname.empty() && cname.back() == '.') cname.pop_back();
            }
        }

        std::vector<uint16_t> open_ports;
        for (auto port : SCAN_PORTS)
            if (tcp_probe(ips[0], port, 300)) open_ports.push_back(port);

        std::string http_code, server_hdr, page_title;
        std::string full_headers, full_body, cookies;

        auto http_grab = [&](const std::string& url) {
            auto raw = safe_exec({"curl","-s","--max-time","6",
                                  "-A","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                                  "-H","Host: " + sub,
                                  "-k","-L","--max-redirs","3","-D","-","--",url}, 8);
            if (raw.empty()) return;
            auto sep = raw.find("\r\n\r\n");
            if (sep == std::string::npos) sep = raw.find("\n\n");
            if (sep != std::string::npos) {
                full_headers = raw.substr(0, sep);
                full_body    = raw.substr(sep);
                if (full_body.size() > 50000) full_body = full_body.substr(0, 50000);
            } else { full_headers = raw; }

            std::regex re_code("HTTP/[0-9\\.]+ ([0-9]{3})");
            std::smatch mc;
            if (std::regex_search(full_headers, mc, re_code)) http_code = mc[1].str();

            std::regex re_srv("(?:^|\n)[Ss]erver:\\s*([^\r\n]+)");
            std::smatch ms;
            if (std::regex_search(full_headers, ms, re_srv)) {
                server_hdr = ms[1].str();
                if (server_hdr.size() > 40) server_hdr = server_hdr.substr(0, 40);
            }

            std::regex re_ck("(?:^|\n)[Ss]et-[Cc]ookie:\\s*([^\r\n]+)");
            std::sregex_iterator ci(full_headers.begin(), full_headers.end(), re_ck), ce;
            for (; ci != ce; ++ci) cookies += (*ci)[1].str() + ";";

            std::regex re_t("<title[^>]*>([^<]{1,100})</title>", std::regex::icase);
            std::smatch mt;
            if (std::regex_search(full_body, mt, re_t)) {
                page_title = mt[1].str();
                auto a = page_title.find_first_not_of(" \t\r\n");
                auto z = page_title.find_last_not_of(" \t\r\n");
                if (a != std::string::npos) page_title = page_title.substr(a, z-a+1);
                if (page_title.size() > 60) page_title = page_title.substr(0,60)+"...";
            }
        };

        bool has_443 = std::find(open_ports.begin(),open_ports.end(),443)!=open_ports.end();
        bool has_80  = std::find(open_ports.begin(),open_ports.end(),80) !=open_ports.end();
        if (has_443) http_grab("https://" + sub);
        else if (has_80) http_grab("http://" + sub);

        WAFInfo waf;
        TechInfo tech;
        if (!full_headers.empty()) {
            waf  = detect_waf(full_headers, full_body, cookies);
            tech = detect_tech(full_headers, full_body, cookies);
        }

        bool fp = passive_subs.count(sub) > 0;
        std::string prefix = sub.substr(0, sub.size() - domain.size() - 1);
        bool fw = std::find(wordlist.begin(), wordlist.end(), prefix) != wordlist.end();
        std::string source = (fp&&fw) ? "both" : fp ? "passive" : "brute";

        SubResult sr;
        sr.sub=sub; sr.ips=ips; sr.ipv6=ipv6; sr.cname=cname;
        sr.http_code=http_code; sr.server=server_hdr; sr.title=page_title;
        sr.open_ports=open_ports; sr.source=source;
        sr.waf=waf; sr.tech=tech; sr.doh_fallback=doh_provider;

        found_count++;
        { std::lock_guard<std::mutex> lk(mtx);
          results.push_back(sr);
          g_result.subdomains.push_back(sub); }

        { std::lock_guard<std::mutex> lk(g_print_mtx);
          std::cout << "\r" << GREEN << "  [+] " << std::left << std::setw(42) << sub;
          for (auto& ip : ips)  std::cout << CYAN   << ip << " ";
          if (!ipv6.empty())    std::cout << YELLOW << "[v6:" << ipv6[0] << "] ";
          if (!cname.empty())   std::cout << YELLOW << "CNAME:" << cname << " ";
          if (!http_code.empty() && http_code!="000")
                                std::cout << MAGENTA<< "HTTP:"  << http_code << " ";
          if (!server_hdr.empty()) std::cout << GRAY<< "["  << server_hdr << "] ";
          if (!waf.name.empty())   std::cout << RED << "WAF:" << waf.name << " ";
          if (!tech.language.empty()) std::cout << CYAN << tech.language << " ";
          if (!tech.cms.empty())   std::cout << YELLOW << tech.cms << " ";
          if (!open_ports.empty()) {
              std::cout << CYAN << "ports:";
              for (auto p : open_ports) std::cout << p << ",";
          }
          if (!doh_provider.empty()) std::cout << DIM << " [DoH:" << doh_provider << "]";
          std::cout << DIM << " (" << source << ")" << RESET << "\n"; }
    };

    for (int bs = 0; bs < total_hosts; bs += DNS_BATCH) {
        int be = std::min(bs + DNS_BATCH, total_hosts);
        std::vector<std::string> batch(all_subs.begin()+bs, all_subs.begin()+be);

        std::cout << CYAN << "\r  [dns] batch "
                  << (bs/DNS_BATCH+1) << "/" << ((total_hosts+DNS_BATCH-1)/DNS_BATCH)
                  << " (" << batch.size() << " hosts)...    " << RESET << std::flush;

        auto dns_res = async_resolve_batch(batch, DEFAULT_RESOLVERS, DNS_CONCURRENCY);

        std::vector<std::future<void>> futs;
        std::vector<std::string> doh_queue;

        for (auto& [host, ips] : dns_res) {
            if (!ips.empty())
                futs.push_back(pool.submit([&,h=host,i=ips]() mutable {
                    process_resolved(h, i, ""); }));
            else
                doh_queue.push_back(host);
        }
        for (auto& f : futs) f.get();

        if (!doh_queue.empty()) {
            std::vector<std::future<void>> dfuts;
            for (auto& host : doh_queue)
                dfuts.push_back(pool.submit([&, h=host]() {
                    std::string provider;
                    auto ips = doh_query(h, "A", &provider);
                    if (!ips.empty()) { doh_used++; process_resolved(h, ips, provider); }
                    else dns_checked++;
                }));
            for (auto& f : dfuts) f.get();
        }

        draw_progress(be, total_hosts, std::to_string(found_count.load()) + " found");
    }

    if (run_permutations && !found_set.empty()) {
        print_section("PERMUTATION ENGINE");
        auto perms = generate_permutations(found_set, domain);
        std::vector<std::string> new_perms;
        for (auto& p : perms)
            if (!dedup.count(p)) { new_perms.push_back(p); dedup.insert(p); }

        std::cout << YELLOW << "  [*] " << new_perms.size()
                  << " permutations from " << found_set.size() << " found\n" << RESET;

        if (!new_perms.empty()) {
            auto pres = async_resolve_batch(new_perms, DEFAULT_RESOLVERS, DNS_CONCURRENCY);
            std::vector<std::future<void>> pfuts;
            for (auto& [h, ips] : pres)
                if (!ips.empty())
                    pfuts.push_back(pool.submit([&,hc=h,ic=ips]() mutable {
                        process_resolved(hc, ic, ""); }));
                else dns_checked++;
            for (auto& f : pfuts) f.get();
            std::cout << GREEN << "  [+] permutations done\n" << RESET;
        }
    }

    std::cout << "\n";

    std::sort(results.begin(), results.end(), [](const SubResult& a, const SubResult& b) {
        return a.sub < b.sub;
    });

    print_section("SUMMARY");
    std::cout << "\n" << BOLD << WHITE
              << "  " << std::left
              << std::setw(42) << "SUBDOMAIN"
              << std::setw(16) << "IPv4"
              << std::setw(6)  << "v6"
              << std::setw(8)  << "HTTP"
              << std::setw(14) << "PORTS"
              << std::setw(16) << "WAF"
              << std::setw(12) << "TECH"
              << "TITLE\n"
              << "  " << std::string(120, '-') << "\n" << RESET;

    int cnt_https=0,cnt_http=0,cnt_cname=0,cnt_waf=0,cnt_ipv6=0;
    std::map<std::string,int> server_stats,waf_stats,lang_stats,cms_stats,source_stats;

    for (auto& r : results) {
        std::cout << GREEN << "  " << std::left << std::setw(42) << r.sub;
        if (!r.ips.empty())  std::cout << CYAN   << std::setw(16) << r.ips[0];
        else                 std::cout << GRAY   << std::setw(16) << "-";
        if (!r.ipv6.empty()){ std::cout << YELLOW<< std::setw(6)  << "v6"; cnt_ipv6++; }
        else                  std::cout << GRAY  << std::setw(6)  << "-";
        if (!r.http_code.empty() && r.http_code!="000")
            std::cout << MAGENTA << std::setw(8) << r.http_code;
        else std::cout << GRAY << std::setw(8) << "-";
        if (!r.open_ports.empty()) {
            std::string ps;
            for (auto p:r.open_ports){if(!ps.empty())ps+=",";ps+=std::to_string(p);}
            if (ps.size()>12) ps=ps.substr(0,12)+"..";
            std::cout << CYAN << std::setw(14) << ps;
        } else std::cout << GRAY << std::setw(14) << "-";
        if (!r.waf.name.empty()) {
            std::string wn=r.waf.name; if(wn.size()>14)wn=wn.substr(0,14);
            std::cout << RED  << std::setw(16) << wn; cnt_waf++;
        } else std::cout << GRAY << std::setw(16) << "-";
        std::string ts = r.tech.language;
        if (!r.tech.cms.empty()) ts += "/"+r.tech.cms;
        if (ts.size()>12) ts=ts.substr(0,12);
        std::cout << (ts.empty() ? GRAY : CYAN) << std::setw(12) << (ts.empty()? "-":ts);
        std::cout << WHITE << sanitize(r.title) << RESET << "\n";

        if (!r.cname.empty())
            std::cout << YELLOW << "    -> CNAME: " << r.cname << RESET << "\n", cnt_cname++;
        if (!r.ipv6.empty()) {
            std::cout << CYAN << "    -> IPv6:  ";
            for (auto& a:r.ipv6) std::cout << a << " ";
            std::cout << RESET << "\n";
        }
        if (!r.tech.stack.empty()) {
            std::cout << GRAY << "    -> stack: ";
            for (auto& s:r.tech.stack) std::cout << s << " ";
            std::cout << RESET << "\n";
        }
        if (r.ips.size()>1) {
            std::cout << GRAY << "    -> also: ";
            for (size_t j=1;j<r.ips.size();j++) std::cout<<r.ips[j]<<" ";
            std::cout << RESET << "\n";
        }

        bool h443=std::find(r.open_ports.begin(),r.open_ports.end(),443)!=r.open_ports.end();
        bool h80 =std::find(r.open_ports.begin(),r.open_ports.end(),80) !=r.open_ports.end();
        if (h443) cnt_https++;
        if (h80&&!h443) cnt_http++;
        if (!r.server.empty())       server_stats[r.server]++;
        if (!r.waf.name.empty())     waf_stats[r.waf.name]++;
        if (!r.tech.language.empty())lang_stats[r.tech.language]++;
        if (!r.tech.cms.empty())     cms_stats[r.tech.cms]++;
        source_stats[r.source]++;
    }

    print_section("STATISTICS");
    std::cout << CYAN << "  [total found]     " << WHITE  << results.size()     << "\n" << RESET;
    std::cout << CYAN << "  [checked]         " << WHITE  << dns_checked.load() << "\n" << RESET;
    std::cout << CYAN << "  [DoH fallbacks]   " << YELLOW << doh_used.load()    << "\n" << RESET;
    std::cout << CYAN << "  [HTTPS (443)]     " << GREEN  << cnt_https          << "\n" << RESET;
    std::cout << CYAN << "  [HTTP only (80)]  " << YELLOW << cnt_http           << "\n" << RESET;
    std::cout << CYAN << "  [with CNAME]      " << WHITE  << cnt_cname          << "\n" << RESET;
    std::cout << CYAN << "  [with IPv6]       " << CYAN   << cnt_ipv6           << "\n" << RESET;
    std::cout << CYAN << "  [behind WAF]      " << RED    << cnt_waf            << "\n" << RESET;
    std::cout << CYAN << "  [wildcard]        " << (has_wildcard.load() ? RED "YES" : GREEN "no") << "\n" << RESET;

    auto print_dist = [](const std::map<std::string,int>& m, const std::string& label) {
        if (m.empty()) return;
        std::cout << CYAN << "\n  [" << label << "]\n" << RESET;
        std::vector<std::pair<std::string,int>> v(m.begin(),m.end());
        std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
        for (auto& [k,c]:v)
            std::cout << GRAY << "    " << std::left << std::setw(30) << k
                      << CYAN << c << "\n" << RESET;
    };
    print_dist(source_stats, "sources");
    print_dist(waf_stats,    "WAF distribution");
    print_dist(lang_stats,   "languages");
    print_dist(cms_stats,    "CMS");
    print_dist(server_stats, "server distribution");

    print_section("TAKEOVER CANDIDATES");
    bool any_takeover = false;
    for (auto& r : results) {
        if (r.cname.empty()) continue;
        std::string cl = r.cname;
        std::transform(cl.begin(),cl.end(),cl.begin(),::tolower);
        for (auto& [sig,name] : takeover_sigs()) {
            if (cl.find(sig) != std::string::npos) {
                std::string tip = resolve(r.cname);
                if (tip.empty())
                    std::cout << RED    << "  [!!!] " << r.sub << " -> " << r.cname
                              << " (" << name << ") -- DANGLING! possible takeover\n" << RESET;
                else
                    std::cout << YELLOW << "  [?]   " << r.sub << " -> " << r.cname
                              << " (" << name << ") -- resolves, verify manually\n" << RESET;
                any_takeover = true; break;
            }
        }
    }
    if (!any_takeover) std::cout << GREEN << "  no obvious takeover candidates\n" << RESET;

    print_section("EXPORT");
    export_results(results, domain);

    LOG_INFO("subdomain_scan", "done domain="+domain+
             " found="+std::to_string(results.size())+
             " doh="+std::to_string(doh_used.load()));
}
