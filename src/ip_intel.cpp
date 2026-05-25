#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

void ip_intel(const std::string& ip) {
    print_header("IP INTELLIGENCE // " + ip);
    g_result.target=ip; g_result.start_time=now_str();

    print_section("GEOLOCATION");
    std::cout<<BLOOD_RED<<"  fetching...\n"<<RESET;
    if (!InputGuard::is_valid_ipv4(ip) && !InputGuard::is_valid_ipv6(ip)) {
        std::cout << BLOOD_RED << "  invalid ip\n" << RESET;
        return;
    }
    std::string body = safe_curl("http://ip-api.com/json/" + ip + "?fields=...");

    if(!body.empty()){
        auto g=[&](const std::string& k){return json_val(body,k);};
        if(g("status")!="fail"){
            print_row("ip",      g("query").empty()?ip:g("query"));
            print_row("country", g("country")+" ("+g("countryCode")+")");
            print_row("region",  g("regionName"));
            print_row("city",    g("city"));
            print_row("zip",     g("zip"));
            print_row("coords",  g("lat")+", "+g("lon"));
            print_row("timezone",g("timezone"));
            print_section("NETWORK");
            print_row("isp",     g("isp"));
            print_row("org",     g("org"));
            print_row("as",      g("as"));
            print_row("as name", g("asname"));
            print_row("hostname",g("reverse"));
            print_section("FLAGS");
            auto proxy=g("proxy"), hosting=g("hosting"), mobile=g("mobile");
            std::cout<<BLOOD_RED<<"  [proxy/vpn]    "<<WHITE<<(proxy=="true"?"YES  detected":"no")<<"\n";
            std::cout<<BLOOD_RED<<"  [hosting/dc]   "<<WHITE<<(hosting=="true"?"yes - datacenter":"no - residential")<<"\n";
            std::cout<<BLOOD_RED<<"  [mobile]       "<<WHITE<<(mobile=="true"?"yes":"no")<<"\n";

            {
                std::lock_guard<std::mutex> lk(g_result_mtx);
                g_result.geo_country=g("country"); g_result.geo_city=g("city");
                g_result.geo_isp=g("isp"); g_result.geo_as=g("as");
                g_result.proxy=(proxy=="true"); g_result.hosting=(hosting=="true");
            }

            auto lat=g("lat"), lon=g("lon");
            if(!lat.empty()) std::cout<<"\n"<<BLOOD_RED<<"  map: "<<WHITE<<"https://maps.google.com/?q="<<lat<<","<<lon<<"\n"<<RESET;
        }
    }

    print_section("REVERSE DNS");
    auto rdns=safe_exec({"host",ip},5);
    std::cout<<(rdns.empty()?std::string(BLOOD_RED)+"  none\n"+RESET:std::string(WHITE)+rdns+RESET);

    print_section("ASN / BGP");
    auto bgp=safe_exec({"whois","-h","whois.radb.net",ip},8);
    if(bgp.empty()){std::cout<<BLOOD_RED<<"  no bgp info\n"<<RESET;}
    else{
        std::istringstream ss(bgp); std::string line; int c=0;
        while(std::getline(ss,line)&&c<6){
            if(line.find("route:")!=std::string::npos||line.find("origin:")!=std::string::npos||line.find("descr:")!=std::string::npos){
                auto col=line.find(':');
                if(col!=std::string::npos)
                    std::cout<<BLOOD_RED<<"  ["<<std::left<<std::setw(8)<<line.substr(0,col)<<"] "<<WHITE<<sanitize(line.substr(col+1))<<"\n";
                c++;
            }
        }
    }

    print_section("ABUSE CONTACTS");
    auto whois=safe_exec({"whois",ip},10);
    if(!whois.empty()){
        std::istringstream ss(whois); std::string line; int c=0;
        std::vector<std::string> want={"OrgAbuseEmail","abuse","OrgName","Phone"};
        while(std::getline(ss,line)&&c<8){
            std::string ll=line;
            std::transform(ll.begin(),ll.end(),ll.begin(),::tolower);
            for(auto& w:want){
                std::string wl=w;
                std::transform(wl.begin(),wl.end(),wl.begin(),::tolower);
                if(ll.find(wl)!=std::string::npos){
                    auto col=line.find(':');
                    if(col!=std::string::npos)
                        std::cout<<BLOOD_RED<<"  ["<<std::left<<std::setw(16)<<line.substr(0,col)<<"] "<<WHITE<<sanitize(line.substr(col+1))<<RESET<<"\n";
                    c++; break;
                }
            }
        }
    }

    print_section("BLACKLIST");
    std::vector<std::string> lists={"zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net","b.barracudacentral.org"};
    std::string pts[4]; int pi=0; std::string tmp;
    for(char ch:ip){if(ch=='.'){pts[pi++]=tmp;tmp="";}else tmp+=ch;} pts[pi]=tmp;
    std::string rev=pts[3]+"."+pts[2]+"."+pts[1]+"."+pts[0];
    for(auto& bl:lists){
        if (g_cancel_token.cancelled) break;
        std::string hit=resolve(rev+"."+bl);
        std::cout<<BLOOD_RED<<"  ["<<std::left<<std::setw(28)<<bl<<"] "<<WHITE<<(hit.empty()?"clean":"LISTED")<<RESET<<"\n";
    }

    print_section("OPEN PORTS (quick)");
    std::vector<int> top={21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,27017};
    std::cout<<BLOOD_RED<<BOLD<<"  PORT        SERVICE         RISK      BANNER\n  "<<std::string(65,'-')<<"\n"<<RESET;
    bool any=false;
    for(int p:top){
        if (g_cancel_token.cancelled) break;
        if (!tcp_probe(ip, p, 600)) continue;
        any = true;
        std::string b=banner(ip,p), s=svc(p);
        std::cout<<WHITE<<"  "<<std::left<<std::setw(12)<<p<<std::setw(16)<<s<<std::setw(10)<<risk_label(p)<<sanitize(b.size()>40?b.substr(0,40):b)<<"\n";
        g_result.open_ports.push_back({p,s});
    }
    if(!any) std::cout<<BLOOD_RED<<"  top ports closed\n"<<RESET;

    if(!g_cancel_token.cancelled && tcp_probe(ip,443,500)){
        print_section("SSL CERTIFICATE");
        auto cert = safe_exec({"sh","-c",
            "echo Q | openssl s_client -connect " +
            InputGuard::sanitize_output(ip) + ":443 -servername " +
            InputGuard::sanitize_output(ip) + " 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null"}, 10);
        if(cert.empty()) std::cout<<BLOOD_RED<<"  could not fetch cert\n"<<RESET;
        else{
            std::istringstream ss(cert); std::string l;
            while(std::getline(ss,l)) std::cout<<WHITE<<"  "<<sanitize(l)<<"\n";
        }
    }
    LOG_INFO("ip_intel","done target="+ip);
}
