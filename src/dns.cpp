#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

static RateLimiter dns_rl(5.0);
void dns_lookup(const std::string& domain) {
    print_header("DNS LOOKUP // " + domain);

    std::cout<<BLOOD_RED<<"\n  -- A / AAAA / PTR --\n"<<RESET;
    auto fut_a    = std::async(std::launch::async, dig_short, domain, "A",    6);
    auto fut_aaaa = std::async(std::launch::async, dig_short, domain, "AAAA", 6);
    auto a_ips    = split_lines(fut_a.get());
    auto aaaa_ips = split_lines(fut_aaaa.get());

    for(auto& ip:a_ips){
        std::string ptr=ptr_lookup(ip);
        std::cout<<BLOOD_RED<<"  [A]    "<<WHITE<<std::left<<std::setw(18)<<sanitize(ip);
        if(!ptr.empty()) std::cout<<BLOOD_RED<<"  PTR -> "<<WHITE<<sanitize(ptr);
        std::cout<<RESET<<"\n";
    }
    for(auto& ip:aaaa_ips) std::cout<<BLOOD_RED<<"  [AAAA] "<<WHITE<<sanitize(ip)<<RESET<<"\n";
    if(a_ips.empty()&&aaaa_ips.empty()) std::cout<<BLOOD_RED<<"  no A/AAAA records\n"<<RESET;

    std::vector<std::string> types={"MX","NS","TXT","CNAME","SOA","CAA","SRV"};
    auto fetch=[&](const std::string& t)->std::pair<std::string,std::string>{
        return {t, dig_full(domain, t)};
    };
    std::vector<std::future<std::pair<std::string,std::string>>> futs;
    futs.reserve(types.size());
    for(auto& t:types) futs.push_back(std::async(std::launch::async,fetch,t));

    std::cout<<BLOOD_RED<<"\n  -- Records --\n"<<RESET;
    for(auto& f:futs){
        auto [t,out]=f.get();
        std::cout<<"\n"<<BLOOD_RED<<"  ["<<WHITE<<t<<BLOOD_RED<<"]:\n"<<RESET;
        if(out.empty()) std::cout<<BLOOD_RED<<"  none\n"<<RESET;
        else std::cout<<WHITE<<sanitize(out)<<RESET;
    }

    std::cout<<BLOOD_RED<<"\n  -- SPF --\n"<<RESET;
    auto txt=dig_short(domain,"TXT",6);
    bool spf_found=false;
    for(auto& line:split_lines(txt)){
        if(line.find("v=spf1")!=std::string::npos){
            std::cout<<BLOOD_RED<<"  [SPF] "<<WHITE<<sanitize(line)<<RESET<<"\n";
            spf_found=true;
            std::regex re_inc(R"(include:(\S+)|redirect=(\S+))");
            std::smatch m; std::string s=line;
            while(std::regex_search(s,m,re_inc)){
                std::string inc=m[1].matched?m[1].str():m[2].str();
                std::cout<<BLOOD_RED<<"    -> "<<WHITE<<sanitize(inc)<<RESET<<"\n";
                auto sub=dig_short(inc,"TXT",5);
                if(!sub.empty()) std::cout<<WHITE<<"    "<<sanitize(sub)<<RESET<<"\n";
                s=m.suffix();
            }
        }
    }
    if(!spf_found) std::cout<<BLOOD_RED<<"  [!] no SPF -- email spoofing may be possible\n"<<RESET;

    std::cout<<BLOOD_RED<<"\n  -- DMARC --\n"<<RESET;
    auto dmarc=dig_full("_dmarc."+domain,"TXT",5);
    if(dmarc.empty()) std::cout<<BLOOD_RED<<"  [-] no DMARC\n"<<RESET;
    else std::cout<<WHITE<<sanitize(dmarc)<<RESET;

    std::cout<<BLOOD_RED<<"\n  -- DNSSEC --\n"<<RESET;
    auto ds=dig_short(domain,"DS",5);
    auto dnskey=dig_short(domain,"DNSKEY",5);
    if(!ds.empty()||!dnskey.empty()) std::cout<<BLOOD_RED<<"  [+] "<<WHITE<<"DNSSEC enabled\n"<<RESET;
    else std::cout<<BLOOD_RED<<"  [-] DNSSEC not detected\n"<<RESET;

    std::cout<<BLOOD_RED<<"\n  -- Zone Transfer (AXFR) --\n"<<RESET;
    auto ns_raw=dig_short(domain,"NS",6);
    for(auto ns:split_lines(ns_raw)){
        while(!ns.empty()&&(ns.back()=='.'||ns.back()=='\n')) ns.pop_back();
        if(ns.empty()) continue;
        std::cout<<BLOOD_RED<<"  trying "<<WHITE<<sanitize(ns)<<RESET<<"\n";
        dns_rl.acquire();
        auto zt=safe_exec({"dig","axfr","@"+ns,domain},10);
        if(zt.empty()||zt.find("Transfer failed")!=std::string::npos||zt.find("REFUSED")!=std::string::npos)
            std::cout<<WHITE<<"    refused (secure)\n"<<RESET;
        else
            std::cout<<BLOOD_RED<<"  [!!!] ZONE TRANSFER SUCCEEDED on "<<WHITE<<sanitize(ns)<<BLOOD_RED<<"!\n"<<WHITE<<sanitize(zt)<<RESET;
    }

    LOG_INFO("dns_lookup","done domain="+domain);
}

void whois_lookup(const std::string& target) {
    print_header("WHOIS // " + target);
    std::vector<std::string> keys={
        "Domain","Registrar","Created","Updated","Expir","Name Server",
        "CIDR","NetRange","OrgName","Country","RegDate","NetName",
        "inetnum","netname","descr","origin","Email","Phone","Address"
    };
    dns_rl.acquire();
    auto raw=safe_exec({"whois",target},10);
    if(raw.empty()){std::cout<<BLOOD_RED<<"  install: sudo apt install whois\n"<<RESET;return;}
    std::istringstream ss(raw); std::string line;
    while(std::getline(ss,line)){
        if(line.empty()||line[0]=='%'||line[0]=='#') continue;
        for(auto& k:keys){
            std::string ll=line, kl=k;
            std::transform(ll.begin(),ll.end(),ll.begin(),::tolower);
            std::transform(kl.begin(),kl.end(),kl.begin(),::tolower);
            if(ll.find(kl)==std::string::npos) continue;
            auto c=line.find(':');
            if(c!=std::string::npos)
                std::cout<<BLOOD_RED<<"  ["<<std::left<<std::setw(16)<<line.substr(0,c)<<"] "<<WHITE<<sanitize(line.substr(c+1))<<RESET<<"\n";
            break;
        }
    }
}

void site_lookup(const std::string& raw) {
    print_header("SITE -> IP // " + raw);
    std::string s=raw;
    for(auto& p:{"https://","http://","www."})
        if(s.size()>=strlen(p)&&s.substr(0,strlen(p))==p) s=s.substr(strlen(p));
        for(char sep:{'/',  '?','#',':'}) {auto p=s.find(sep);if(p!=std::string::npos) s=s.substr(0,p);}
        while(!s.empty()&&(s.back()==' '||s.back()==10||s.back()==13)) s.pop_back();
        if(!valid_target(s)){std::cout<<BLOOD_RED<<"  invalid input\n"<<RESET;return;}
        std::cout<<BLOOD_RED<<"  resolving "<<WHITE<<s<<BLOOD_RED<<"...\n"<<RESET;
        std::string ip=resolve(s);
        if(ip.empty()){std::cout<<BLOOD_RED<<"  could not resolve\n"<<RESET;return;}
        std::cout<<BLOOD_RED<<"  "<<WHITE<<s<<BLOOD_RED<<" -> "<<WHITE<<ip<<"\n"<<RESET;
        ip_intel(ip);
}
