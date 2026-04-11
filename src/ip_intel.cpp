#include "../include/dark_nexus.hpp"

void ip_intel(const std::string& ip) {
    print_header("IP INTELLIGENCE // " + ip);
    g_result.target=ip; g_result.timestamp=now_str();

    print_section("GEOLOCATION");
    std::cout<<YELLOW<<"  fetching...\n"<<RESET;
    std::string body=safe_curl(
        "http://ip-api.com/json/"+ip+
        "?fields=status,message,country,countryCode,regionName,"
        "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query");

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
            std::cout<<CYAN<<"  [proxy/vpn]    "<<(proxy=="true"?RED "YES  detected":GREEN "no")<<RESET<<"\n";
            std::cout<<CYAN<<"  [hosting/dc]   "<<(hosting=="true"?YELLOW "yes - datacenter":GREEN "no - residential")<<RESET<<"\n";
            std::cout<<CYAN<<"  [mobile]       "<<RESET<<(mobile=="true"?"yes":"no")<<"\n";
            g_result.geo_country=g("country"); g_result.geo_city=g("city");
            g_result.geo_isp=g("isp"); g_result.geo_as=g("as");
            g_result.proxy=proxy=="true"; g_result.hosting=hosting=="true";
            auto lat=g("lat"), lon=g("lon");
            if(!lat.empty()) std::cout<<"\n"<<YELLOW<<"  map: https://maps.google.com/?q="<<lat<<","<<lon<<"\n"<<RESET;
        }
    }

    print_section("REVERSE DNS");
    auto rdns=safe_exec({"host",ip},5);
    std::cout<<(rdns.empty()?std::string(GRAY)+"  none\n"+RESET:GREEN+rdns+RESET);

    print_section("ASN / BGP");
    auto bgp=safe_exec({"whois","-h","whois.radb.net",ip},8);
    if(bgp.empty()){std::cout<<GRAY<<"  no bgp info\n"<<RESET;}
    else{
        std::istringstream ss(bgp); std::string line; int c=0;
        while(std::getline(ss,line)&&c<6){
            if(line.find("route:")!=std::string::npos||line.find("origin:")!=std::string::npos||line.find("descr:")!=std::string::npos){
                auto col=line.find(':');
                if(col!=std::string::npos)
                    std::cout<<CYAN<<"  ["<<std::left<<std::setw(8)<<line.substr(0,col)<<"] "<<RESET<<sanitize(line.substr(col+1))<<"\n";
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
                        std::cout<<CYAN<<"  ["<<std::left<<std::setw(16)<<line.substr(0,col)<<"] "<<YELLOW<<sanitize(line.substr(col+1))<<RESET<<"\n";
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
        std::string hit=resolve(rev+"."+bl);
        std::cout<<CYAN<<"  ["<<std::left<<std::setw(28)<<bl<<"] "<<(hit.empty()?GREEN "clean":RED "LISTED")<<RESET<<"\n";
    }

    print_section("OPEN PORTS (quick)");
    std::vector<int> top={21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,27017};
    std::cout<<BOLD<<WHITE<<"  PORT        SERVICE         RISK      BANNER\n  "<<std::string(65,'-')<<"\n"<<RESET;
    bool any=false;
    for(int p:top){
        if (!tcp_probe(ip, p, 600)) continue; 
any = true;
        std::string b=banner(ip,p), s=svc(p);
        std::cout<<GREEN<<"  "<<std::left<<std::setw(12)<<p<<WHITE<<std::setw(16)<<s<<std::setw(10)<<risk_label(p)<<GRAY<<(b.size()>40?b.substr(0,40):b)<<RESET<<"\n";
        g_result.open_ports.push_back({p,s});
    }
    if(!any) std::cout<<GRAY<<"  top ports closed\n"<<RESET;

    if(tcp_probe(ip,443,500)){
        print_section("SSL CERTIFICATE");
        auto cert=safe_exec({"sh","-c",
            "echo Q | openssl s_client -connect "+ip+":443 -servername "+ip+
            " 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null"},10);
        if(cert.empty()) std::cout<<GRAY<<"  could not fetch cert\n"<<RESET;
        else{
            std::istringstream ss(cert); std::string l;
            while(std::getline(ss,l)) std::cout<<CYAN<<"  "<<sanitize(l)<<RESET<<"\n";
        }
    }
    LOG_INFO("ip_intel","done target="+ip);
}
