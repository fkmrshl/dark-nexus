#include "../include/dark_nexus.hpp"

void subdomain_scan(const std::string& domain) {
    print_header("SUBDOMAIN SCAN // " + domain);

    const int MAX_THREADS = 200;
    const std::vector<uint16_t> SCAN_PORTS = {
        80,443,8080,8443,8000,8888,3000,5000,9090,9443,8081,8082,4443,2083,2087,10000
    };

    struct SubResult {
        std::string sub;
        std::vector<std::string> ips;
        std::string cname, http_code, server, title;
        std::vector<uint16_t> open_ports;
        std::string source;
        bool wildcard = false;
    };

    std::mutex mtx;
    std::vector<SubResult> results;
    std::set<std::string> found_set;
    std::atomic<int> checked{0}, found_count{0};
    std::atomic<bool> has_wildcard{false};
    std::set<std::string> wildcard_ips;

    static const std::vector<std::string> wordlist = {
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
        "docker","registry","k8s","kube","kubernetes","swarm","mesos","ecs",
        "lambda","functions","serverless","run","compute","batch","job","jobs",
        "worker","workers","task","tasks","queue","mq","amqp","rabbit","kafka",
        "db","db1","db2","db3","db4","db5","database","sql","mysql","postgres",
        "pgsql","postgresql","mongo","mongodb","redis","memcached","memcache",
        "elastic","elasticsearch","es","solr","lucene","cassandra",
        "mariadb","oracle","mssql","sqlserver","neo4j","graph",
        "couchdb","couchbase","dynamodb","influxdb","influx",
        "clickhouse","timescale","rds","aurora",
        "grafana","kibana","prometheus","nagios","zabbix","datadog","splunk",
        "sentry","newrelic","pagerduty","opsgenie","uptime","monitor",
        "ci","cd","build","deploy","release","argocd","terraform","ansible",
        "puppet","chef","vault","consul","nomad","traefik","envoy","istio",
        "waf","firewall","ids","ips","scan","pentest","bounty","security",
        "cert","certs","pki","ca","ocsp","crl","acme","letsencrypt",
        "rabbitmq","nats","pulsar","eventbus","events","stream","streams",
        "websocket","ws","wss","socket","hook","hooks","webhook","webhooks",
        "mx3","mx4","mail4","mail5","mailgw","spam","antispam","dkim","dmarc",
        "postfix","sendmail","zimbra","roundcube","horde",
        "s3","minio","storage","blob","bucket","assets1","assets2","static1",
        "static2","cdn1","cdn2","origin","edge1","edge2","media1","media2",
        "api1","api2","api3","gw","gw1","gw2","router","switch","fw","fw1",
        "core","core1","core2","mgmt","management","noc","oob","ipmi","ilo",
        "bmc","kvm","pdu","ups","ntp","time","log","logs","syslog","audit",
        "analytics","metrics","stats","telemetry","trace","tracing","jaeger","zipkin",
        "us","eu","ap","us-east","us-west","eu-west","eu-central","ap-south",
        "dev1","dev2","test1","test2","stg","stg1","stg2","prd","prd1","prd2",
        "canary","green","blue","primary","secondary","failover","dr",
        "accounts","account","signup","register","reset","password","token",
        "callback","redirect","connect","link","go","click","track","pixel",
        "preview","draft","temp","tmp","debug","info","health","healthz",
        "readyz","livez","ping","echo","version","v1","v2","v3","graphql",
        "rest","soap","rpc","grpc","proto","ws","sse","poll"
    };

    print_section("WILDCARD CHECK");
    std::string wc_test = "randomnxdomain7742test." + domain;
    std::string wc_ip = resolve(wc_test);
    if (!wc_ip.empty()) {
        has_wildcard = true;
        wildcard_ips.insert(wc_ip);
        std::string wc_test2 = "anotherfake9981nx." + domain;
        std::string wc_ip2 = resolve(wc_test2);
        if (!wc_ip2.empty()) wildcard_ips.insert(wc_ip2);
        std::cout << YELLOW << "  [!] wildcard DNS detected -> " << wc_ip;
        if (!wc_ip2.empty() && wc_ip2 != wc_ip) std::cout << ", " << wc_ip2;
        std::cout << "\n  [!] filtering wildcard results\n" << RESET;
    } else {
        std::cout << GREEN << "  [+] no wildcard DNS\n" << RESET;
    }

    print_section("PASSIVE ENUM (crt.sh)");
    std::cout << YELLOW << "  querying certificate transparency logs...\n" << RESET;

    std::set<std::string> passive_subs;
    auto crt_body = safe_curl("https://crt.sh/?q=%25." + domain + "&output=json", 15);
    if (!crt_body.empty()) {
        std::regex re_name("\"(?:common_name|name_value)\"\\s*:\\s*\"([^\"]+)\"");
        std::sregex_iterator it(crt_body.begin(), crt_body.end(), re_name), end;
        for (; it != end; ++it) {
            std::string val = (*it)[1].str();
            std::istringstream vss(val);
            std::string part;
            while (std::getline(vss, part, '\n')) {
                if (part.size() > 2 && part[0] == '*' && part[1] == '.')
                    part = part.substr(2);
                std::transform(part.begin(), part.end(), part.begin(), ::tolower);
                if (part.size() > domain.size() &&
                    part.substr(part.size() - domain.size()) == domain &&
                    (part[part.size() - domain.size() - 1] == '.' ||
                     part.size() == domain.size()))
                    passive_subs.insert(part);
                if (part == domain) passive_subs.insert(part);
            }
        }
        std::cout << GREEN << "  [+] crt.sh returned " << passive_subs.size() << " unique names\n" << RESET;
    } else {
        std::cout << GRAY << "  [-] crt.sh unavailable or empty\n" << RESET;
    }

    std::vector<std::string> all_subs;
    std::set<std::string> dedup;

    for (auto& w : wordlist) {
        std::string full = w + "." + domain;
        if (dedup.insert(full).second) all_subs.push_back(full);
    }
    for (auto& s : passive_subs) {
        if (s != domain && dedup.insert(s).second) all_subs.push_back(s);
    }

    int total = all_subs.size();
    print_section("BRUTE FORCE + RESOLVE");
    std::cout << YELLOW << "  checking " << total << " subdomains (" << wordlist.size()
              << " wordlist + " << passive_subs.size() << " passive)...\n\n" << RESET;

    ThreadPool pool(std::min(MAX_THREADS, total));
    std::vector<std::future<void>> futs;
    futs.reserve(total);

    for (int i = 0; i < total; i++) {
        futs.push_back(pool.submit([&, i] {
            const std::string& sub = all_subs[i];

            addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            int rc = getaddrinfo(sub.c_str(), nullptr, &hints, &res);
            checked++;

            if (rc != 0 || !res) {
                if (checked % 200 == 0) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(checked, total, std::to_string(found_count.load()) + " found");
                }
                return;
            }

            std::vector<std::string> ips;
            for (addrinfo* p = res; p; p = p->ai_next) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, buf, sizeof(buf));
                std::string ipstr = buf;
                if (std::find(ips.begin(), ips.end(), ipstr) == ips.end())
                    ips.push_back(ipstr);
            }
            freeaddrinfo(res);

            if (has_wildcard && ips.size() == 1 && wildcard_ips.count(ips[0])) {
                if (checked % 200 == 0) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(checked, total, std::to_string(found_count.load()) + " found");
                }
                return;
            }

            std::string cname;
            auto cname_out = safe_exec({"dig","+short","+time=2","+tries=1",sub,"CNAME"}, 4);
            if (!cname_out.empty()) {
                auto lines = split_lines(cname_out);
                if (!lines.empty()) {
                    cname = lines[0];
                    while (!cname.empty() && cname.back() == '.') cname.pop_back();
                }
            }

            std::vector<uint16_t> open_ports;
            for (auto port : SCAN_PORTS)
                if (tcp_probe(ips[0], port, 300)) open_ports.push_back(port);

            std::string http_code, server_hdr, page_title;

            auto http_check = [&](const std::string& url) {
                auto resp = safe_exec({"curl","-s","--max-time","4","-o","/dev/null",
                                       "-w","%{http_code}|%{redirect_url}",
                                       "-A","Mozilla/5.0",
                                       "-H","Host: " + sub,
                                       "-k","-L","--",url}, 6);
                if (!resp.empty()) {
                    auto pipe_pos = resp.find('|');
                    http_code = (pipe_pos != std::string::npos) ? resp.substr(0, pipe_pos) : resp;
                    http_code.erase(std::remove_if(http_code.begin(), http_code.end(), ::isspace), http_code.end());
                }
            };

            auto grab_info = [&](const std::string& url) {
                auto body = safe_exec({"curl","-s","--max-time","4",
                                       "-A","Mozilla/5.0",
                                       "-H","Host: " + sub,
                                       "-k","-D","-","--",url}, 6);
                if (!body.empty()) {
                    std::regex re_srv("^[Ss]erver:\\s*(.+)", std::regex::multiline);
                    std::smatch m;
                    if (std::regex_search(body, m, re_srv)) {
                        server_hdr = m[1].str();
                        while (!server_hdr.empty() && (server_hdr.back() == '\r' || server_hdr.back() == '\n'))
                            server_hdr.pop_back();
                        if (server_hdr.size() > 40) server_hdr = server_hdr.substr(0, 40);
                    }
                    std::regex re_title("<title[^>]*>([^<]+)</title>", std::regex::icase);
                    if (std::regex_search(body, m, re_title)) {
                        page_title = m[1].str();
                        while (!page_title.empty() && (page_title.front() == ' ' || page_title.front() == '\n'))
                            page_title.erase(page_title.begin());
                        while (!page_title.empty() && (page_title.back() == ' ' || page_title.back() == '\n'))
                            page_title.pop_back();
                        if (page_title.size() > 50) page_title = page_title.substr(0, 50) + "...";
                    }
                }
            };

            bool has_443 = std::find(open_ports.begin(), open_ports.end(), 443) != open_ports.end();
            bool has_80  = std::find(open_ports.begin(), open_ports.end(), 80)  != open_ports.end();

            if (has_443) { http_check("https://" + sub); grab_info("https://" + sub); }
            else if (has_80) { http_check("http://" + sub); grab_info("http://" + sub); }

            bool from_passive = passive_subs.count(sub) > 0;
            std::string prefix = sub.substr(0, sub.size() - domain.size() - 1);
            bool from_wordlist = std::find(wordlist.begin(), wordlist.end(), prefix) != wordlist.end();
            std::string source;
            if (from_passive && from_wordlist) source = "both";
            else if (from_passive) source = "crt.sh";
            else source = "brute";

            SubResult sr;
            sr.sub = sub; sr.ips = ips; sr.cname = cname;
            sr.http_code = http_code; sr.server = server_hdr;
            sr.title = page_title; sr.open_ports = open_ports; sr.source = source;

            found_count++;
            {
                std::lock_guard<std::mutex> lk(mtx);
                results.push_back(sr);
                found_set.insert(sub);
                g_result.subdomains.push_back(sub);
            }

            {
                std::lock_guard<std::mutex> lk(g_print_mtx);
                std::cout << "\r" << GREEN << "  [+] " << std::left << std::setw(40) << sub;
                for (auto& ip : ips) std::cout << CYAN << ip << " ";
                if (!cname.empty()) std::cout << YELLOW << "CNAME:" << cname << " ";
                if (!http_code.empty() && http_code != "000")
                    std::cout << MAGENTA << "HTTP:" << http_code << " ";
                if (!server_hdr.empty()) std::cout << GRAY << "[" << server_hdr << "] ";
                if (!open_ports.empty()) {
                    std::cout << CYAN << "ports:";
                    for (auto p : open_ports) std::cout << p << ",";
                }
                std::cout << DIM << " (" << source << ")" << RESET << "\n";
            }

            if (checked % 100 == 0) {
                std::lock_guard<std::mutex> lk(g_print_mtx);
                draw_progress(checked, total, std::to_string(found_count.load()) + " found");
            }
        }));
    }

    for (auto& f : futs) f.get();
    draw_progress(total, total, std::to_string(found_count.load()) + " found");
    std::cout << "\n";

    std::sort(results.begin(), results.end(), [](const SubResult& a, const SubResult& b) {
        return a.sub < b.sub;
    });

    print_section("SUMMARY");
    std::cout << "\n" << BOLD << WHITE
              << "  " << std::left << std::setw(40) << "SUBDOMAIN"
              << std::setw(18) << "IP"
              << std::setw(8)  << "HTTP"
              << std::setw(10) << "PORTS"
              << "SERVER / TITLE\n"
              << "  " << std::string(95, '-') << "\n" << RESET;

    int cnt_https = 0, cnt_http = 0, cnt_cname = 0;
    std::map<std::string, int> server_stats;

    for (auto& r : results) {
        std::cout << GREEN << "  " << std::left << std::setw(40) << r.sub;

        if (!r.ips.empty()) std::cout << CYAN << std::setw(18) << r.ips[0];
        else                std::cout << GRAY << std::setw(18) << "-";

        if (!r.http_code.empty() && r.http_code != "000")
            std::cout << MAGENTA << std::setw(8) << r.http_code;
        else
            std::cout << GRAY << std::setw(8) << "-";

        if (!r.open_ports.empty()) {
            std::string ps;
            for (auto p : r.open_ports) {
                if (!ps.empty()) ps += ",";
                ps += std::to_string(p);
            }
            if (ps.size() > 7) ps = ps.substr(0, 7) + "..";
            std::cout << CYAN << std::setw(8) << ps;
        }

        std::cout << WHITE << sanitize(r.title) << RESET << "\n";

        if (!r.cname.empty()) {
            std::cout << YELLOW << "    -> CNAME: " << r.cname << RESET << "\n";
            cnt_cname++;
        }
        if (r.ips.size() > 1) {
            std::cout << GRAY << "    -> also: ";
            for (size_t j = 1; j < r.ips.size(); j++) std::cout << r.ips[j] << " ";
            std::cout << RESET << "\n";
        }

        bool h443 = std::find(r.open_ports.begin(), r.open_ports.end(), 443) != r.open_ports.end();
        bool h80  = std::find(r.open_ports.begin(), r.open_ports.end(), 80)  != r.open_ports.end();
        if (h443) cnt_https++;
        if (h80 && !h443) cnt_http++;
        if (!r.server.empty()) server_stats[r.server]++;
    }

    print_section("STATISTICS");
    std::cout << CYAN << "  [total found]     " << WHITE << results.size() << "\n" << RESET;
    std::cout << CYAN << "  [checked]         " << WHITE << total << "\n" << RESET;
    std::cout << CYAN << "  [HTTPS (443)]     " << GREEN  << cnt_https << "\n" << RESET;
    std::cout << CYAN << "  [HTTP only (80)]  " << YELLOW << cnt_http  << "\n" << RESET;
    std::cout << CYAN << "  [with CNAME]      " << WHITE  << cnt_cname << "\n" << RESET;
    std::cout << CYAN << "  [wildcard]        " << (has_wildcard.load() ? RED "YES" : GREEN "no") << "\n" << RESET;

    if (!server_stats.empty()) {
        std::cout << CYAN << "\n  [server distribution]\n" << RESET;
        std::vector<std::pair<std::string,int>> sorted_srv(server_stats.begin(), server_stats.end());
        std::sort(sorted_srv.begin(), sorted_srv.end(),
                  [](const std::pair<std::string,int>& a, const std::pair<std::string,int>& b) {
                      return a.second > b.second;
                  });
        for (auto& kv : sorted_srv)
            std::cout << GRAY << "    " << std::left << std::setw(30) << kv.first
                      << CYAN << kv.second << "\n" << RESET;
    }

    print_section("TAKEOVER CANDIDATES");
    static const std::vector<std::pair<std::string,std::string>> takeover_sigs = {
        {"github.io",        "GitHub Pages"},
        {"herokuapp.com",    "Heroku"},
        {"azurewebsites.net","Azure"},
        {"cloudfront.net",   "CloudFront"},
        {"s3.amazonaws.com", "AWS S3"},
        {"shopify.com",      "Shopify"},
        {"ghost.io",         "Ghost"},
        {"wordpress.com",    "WordPress"},
        {"pantheon.io",      "Pantheon"},
        {"zendesk.com",      "Zendesk"},
        {"readme.io",        "ReadMe"},
        {"surge.sh",         "Surge"},
        {"bitbucket.io",     "Bitbucket"},
        {"netlify.app",      "Netlify"},
        {"vercel.app",       "Vercel"},
        {"fly.dev",          "Fly.io"},
        {"render.com",       "Render"},
        {"pages.dev",        "Cloudflare Pages"},
    };
    bool any_takeover = false;
    for (auto& r : results) {
        if (r.cname.empty()) continue;
        std::string cl = r.cname;
        std::transform(cl.begin(), cl.end(), cl.begin(), ::tolower);
        for (auto& sig : takeover_sigs) {
            if (cl.find(sig.first) != std::string::npos) {
                std::string tip = resolve(r.cname);
                if (tip.empty())
                    std::cout << RED << "  [!!!] " << r.sub << " -> CNAME " << r.cname
                              << " (" << sig.second << ") -- DANGLING! possible takeover\n" << RESET;
                else
                    std::cout << YELLOW << "  [?]   " << r.sub << " -> CNAME " << r.cname
                              << " (" << sig.second << ") -- resolves, verify manually\n" << RESET;
                any_takeover = true;
                break;
            }
        }
    }
    if (!any_takeover) std::cout << GREEN << "  no obvious takeover candidates\n" << RESET;

    LOG_INFO("subdomain_scan", "done domain=" + domain + " found=" + std::to_string(results.size()));
}
