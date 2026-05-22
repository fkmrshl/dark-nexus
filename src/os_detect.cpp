#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"
#include <mutex>
#include <atomic>

void os_detect(const std::string& ip) {
    print_header("ADVANCED OS DETECTION // " + ip);

    struct Check {
        int port; const char* name; const char* cat;
        int w_win, w_lin, w_bsd, w_net;
    };
    static const std::vector<Check> checks = {
        {22,  "SSH",        "remote",   1, 10,  8,  5},
        {23,  "Telnet",     "remote",   2,  1,  1, 10},
        {80,  "HTTP",       "web",      5,  7,  5,  3},
        {111, "RPCBind",    "unix",     0,  9,  8,  0},
        {135, "MSRPC",      "windows", 10,  0,  0,  0},
        {139, "NetBIOS-NS", "windows", 10,  1,  0,  0},
        {161, "SNMP",       "monitor",  5,  4,  3, 10},
        {443, "HTTPS",      "web",      5,  7,  5,  3},
        {445, "SMB",        "windows", 10,  2,  1,  0},
        {3389,"RDP",        "windows", 10,  0,  0,  0},
        {5432,"PostgreSQL", "db",       2,  9,  7,  0},
        {5985,"WinRM",      "windows", 10,  0,  0,  0},
        {6379,"Redis",      "db",       1,  9,  5,  0},
    };

    struct Result { int port; std::string name, cat, bnr; bool open; int w[4]; std::string extra; };
    std::vector<Result> results(checks.size());
    ThreadPool pool(checks.size());
    std::vector<std::future<void>> futs; futs.reserve(checks.size());

    std::atomic<bool> tcp_fp_done{false};
    std::string tcp_fp;

    for (int i=0;i<(int)checks.size();i++) {
        futs.push_back(pool.submit([&,i]{
            const auto& c=checks[i];
            bool ok=tcp_probe(ip,c.port,800);
            std::string b, ext;
            if(ok) {
                b=smart_banner(ip,c.port,1000);

                // Deep Inspections
                if (c.port == 445) {
                    std::string smb = smb_os_probe(ip, 1000);
                    if (!smb.empty()) ext = "Native OS: " + smb;
                } else if (c.port == 80 || c.port == 443) {
                    std::string http = analyze_http_headers(ip, c.port, 1000);
                    if (!http.empty()) ext = http;
                }

                // TCP SYN Fingerprinting (Trigger once on the first open port found)
                bool expected = false;
                if (tcp_fp_done.compare_exchange_strong(expected, true)) {
                    tcp_fp = tcp_syn_fingerprint(ip, c.port, 1000);
                }
            }
            results[i]={c.port,c.name,c.cat,b,ok,{c.w_win,c.w_lin,c.w_bsd,c.w_net},ext};
        }));
    }
    for (auto& f:futs) f.get();
    std::sort(results.begin(),results.end(),[](auto& a,auto& b){return a.port<b.port;});

    int score[4]={0,0,0,0};
    std::map<std::string,int> cat_open;
    int open_c=0;

    print_section("DEEP TCP/SMB FINGERPRINTING");
    if (!tcp_fp.empty()) std::cout << BLOOD_RED << "  [TCP SYN/ACK]  " << WHITE << tcp_fp << "\n";
    else std::cout << BLOOD_RED << "  [TCP SYN/ACK]  " << WHITE << "Not detected (Raw Sockets disabled or firewalled)\n";

    std::string smb_verdict;
    std::string waf_verdict;

    std::cout<<"\n"<<BLOOD_RED<<BOLD<<"  PORT ANALYSIS:\n"<<RESET;
    for (auto& r:results) {
        std::cout<<BLOOD_RED<<"  ["<<WHITE<<std::left<<std::setw(5)<<r.port<<" "<<std::setw(12)<<r.name<<" "<<std::setw(8)<<r.cat<<BLOOD_RED<<"] ";
        if (r.open) {
            std::cout<<WHITE<<"OPEN  "<<RESET;
            if(!r.bnr.empty()) std::cout<<WHITE<<sanitize(r.bnr.substr(0,40))<<"  ";
            if(!r.extra.empty()) {
                std::cout<<BLOOD_RED<<" {"<<WHITE<<r.extra<<BLOOD_RED<<"}";
                if (r.port == 445) smb_verdict = r.extra;
                if (r.extra.find("WAF=") != std::string::npos || r.extra.find("Cloudflare") != std::string::npos) waf_verdict = r.extra;
            }
            std::cout<<RESET;
            for(int j=0;j<4;j++) score[j]+=r.w[j];
            cat_open[r.cat]++;
            open_c++;
        } else {
            std::cout<<BLOOD_RED<<"closed"<<RESET;
        }
        std::cout<<"\n";
    }
    std::cout<<BLOOD_RED<<"  open: "<<WHITE<<open_c<<BLOOD_RED<<"/"<<WHITE<<checks.size()<<"\n"<<RESET;

    print_section("ICMP TTL ANALYSIS");
    auto pout=safe_exec({"ping","-c3","-W1",ip},5);
    std::vector<int> ttls;
    size_t sp=0;
    while(true){
        auto tp=pout.find("ttl=",sp); if(tp==std::string::npos) tp=pout.find("TTL=",sp);
        if(tp==std::string::npos) break;
        try{ttls.push_back(std::stoi(pout.substr(tp+4)));}catch(...){}
        sp=tp+4;
    }
    int ttl=ttls.empty()?0:ttls[0];
    bool stable=ttls.size()>1;
    for(size_t i=1;i<ttls.size();i++) if(ttls[i]!=ttls[0]){stable=false;break;}

    int init_ttl=0, hops=0;
    if(ttl>0){
        if     (ttl<=32)  init_ttl=32;
        else if(ttl<=64)  init_ttl=64;
        else if(ttl<=128) init_ttl=128;
        else              init_ttl=255;
        hops=init_ttl-ttl;
    }

    std::cout<<BLOOD_RED<<"  [ttl]          "<<WHITE<<(ttl?std::to_string(ttl):"n/a")<<"\n"<<RESET;
    std::cout<<BLOOD_RED<<"  [initial_ttl]  "<<WHITE<<(init_ttl?std::to_string(init_ttl):"n/a")<<"\n"<<RESET;
    std::cout<<BLOOD_RED<<"  [hops]         "<<WHITE<<(hops?std::to_string(hops):"n/a")<<"\n"<<RESET;
    std::cout<<BLOOD_RED<<"  [stable]       "<<WHITE<<(stable?"yes":"NO -- load balancer/multipath")<<"\n"<<RESET;

    print_section("VERDICT");
    static const char* os_names[4]={"Windows","Linux/Unix","BSD/macOS","Network Device"};
    int best=0;
    for(int i=1;i<4;i++) if(score[i]>score[best]) best=i;

    if     (init_ttl==128) score[0]+=15; // High confidence Windows
    else if(init_ttl==64)  score[1]+=15; // High confidence Linux/BSD
    else if(init_ttl==255) score[3]+=15; // High confidence Cisco/Network

    std::string verdict;

    // Exact overrides based on deep signatures
    if (!smb_verdict.empty()) {
        verdict = smb_verdict;
    } else if (tcp_fp.find("Windows") != std::string::npos) {
        verdict = "Windows (Confirmed via TCP SYN)";
    } else if (tcp_fp.find("Linux") != std::string::npos) {
        verdict = tcp_fp;
    } else if (tcp_fp.find("macOS") != std::string::npos) {
        verdict = "macOS / FreeBSD";
    } else if (tcp_fp.find("Network Device") != std::string::npos) {
        verdict = tcp_fp;
    } else {
        verdict = os_names[best];
        if (!waf_verdict.empty()) verdict += " (Behind Proxy/WAF)";
    }

    std::cout<<BLOOD_RED<<"  [os]       "<<WHITE<<BOLD<<verdict<<RESET<<"\n";
    std::cout<<BLOOD_RED<<"  [scores]   "<<WHITE;
    for(int i=0;i<4;i++) std::cout<<os_names[i]<<":"<<score[i]<<" ";
    std::cout<<"\n"<<RESET;

    g_result.os_guess=verdict;
    LOG_INFO("os_detect","target="+ip+" verdict="+verdict);
}
