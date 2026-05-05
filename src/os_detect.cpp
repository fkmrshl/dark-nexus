#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

void os_detect(const std::string& ip) {
    print_header("OS DETECTION // " + ip);

    struct Check {
        int port; const char* name; const char* cat;
        int w_win, w_lin, w_bsd, w_net;
    };
    static const std::vector<Check> checks = {
        {22,  "SSH",        "remote",   1, 10,  8,  5},
        {23,  "Telnet",     "remote",   2,  1,  1, 10},
        {25,  "SMTP",       "mail",     3,  7,  5,  1},
        {53,  "DNS",        "infra",    5,  7,  5,  8},
        {80,  "HTTP",       "web",      5,  7,  5,  3},
        {111, "RPCBind",    "unix",     0,  9,  8,  0},
        {135, "MSRPC",      "windows", 10,  0,  0,  0},
        {139, "NetBIOS-NS", "windows", 10,  1,  0,  0},
        {161, "SNMP",       "monitor",  5,  4,  3, 10},
        {179, "BGP",        "routing",  0,  1,  1, 10},
        {389, "LDAP",       "dir",      8,  4,  2,  0},
        {443, "HTTPS",      "web",      5,  7,  5,  3},
        {445, "SMB",        "windows", 10,  2,  1,  0},
        {548, "AFP",        "apple",    0,  0, 10,  0},
        {1433,"MSSQL",      "db",      10,  0,  0,  0},
        {2049,"NFS",        "unix",     0,  9,  7,  0},
        {3306,"MySQL",      "db",       3,  9,  5,  0},
        {3389,"RDP",        "windows", 10,  0,  0,  0},
        {5432,"PostgreSQL", "db",       2,  9,  7,  0},
        {5900,"VNC",        "remote",   3,  6,  5,  0},
        {5985,"WinRM",      "windows", 10,  0,  0,  0},
        {6379,"Redis",      "db",       1,  9,  5,  0},
        {9200,"Elastic",    "search",   2,  9,  4,  0},
    };

    struct Result { int port; std::string name, cat, bnr; bool open; int w[4]; };
    std::vector<Result> results(checks.size());
    ThreadPool pool(checks.size());
    std::vector<std::future<void>> futs; futs.reserve(checks.size());

    for (int i=0;i<(int)checks.size();i++) {
        futs.push_back(pool.submit([&,i]{
            const auto& c=checks[i];
            bool ok=tcp_probe(ip,c.port,800);
            std::string b; if(ok) b=banner(ip,c.port);
            results[i]={c.port,c.name,c.cat,b,ok,{c.w_win,c.w_lin,c.w_bsd,c.w_net}};
        }));
    }
    for (auto& f:futs) f.get();
    std::sort(results.begin(),results.end(),[](auto& a,auto& b){return a.port<b.port;});

    int score[4]={0,0,0,0};
    std::map<std::string,int> cat_open;
    int open_c=0;

    std::cout<<"\n"<<BLOOD_RED<<BOLD<<"  PORT FINGERPRINT:\n"<<RESET;
    for (auto& r:results) {
        std::cout<<BLOOD_RED<<"  ["<<WHITE<<std::left<<std::setw(5)<<r.port<<" "<<std::setw(12)<<r.name<<" "<<std::setw(8)<<r.cat<<BLOOD_RED<<"] ";
        if (r.open) {
            std::cout<<WHITE<<"OPEN  "<<RESET;
            if(!r.bnr.empty()) std::cout<<WHITE<<sanitize(r.bnr.substr(0,60));
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

    print_section("TTL ANALYSIS");
    auto pout=safe_exec({"ping","-c5","-W1",ip},8);
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

    print_section("BANNER ANALYSIS");
    struct BHint{const char* kw,*os,*detail;};
    static const std::vector<BHint> hints={
        {"Microsoft","Windows","Microsoft service"},{"IIS","Windows","IIS web server"},
        {"Win32","Windows","Win32 platform"},{"Windows","Windows","Windows banner"},
        {"Ubuntu","Linux/Ubuntu","Ubuntu distro"},{"Debian","Linux/Debian","Debian distro"},
        {"CentOS","Linux/CentOS","CentOS distro"},{"Red Hat","Linux/RHEL","RHEL distro"},
        {"FreeBSD","BSD/FreeBSD","FreeBSD system"},{"OpenBSD","BSD/OpenBSD","OpenBSD system"},
        {"Darwin","macOS","macOS/Darwin"},{"nginx","Linux","nginx web server"},
        {"Apache","Linux","Apache web server"},{"OpenSSH","Linux/Unix","OpenSSH"}
    };
    std::set<std::string> os_hints_found;
    for (auto& r:results) {
        if(!r.open||r.bnr.empty()) continue;
        std::string bl=r.bnr;
        std::transform(bl.begin(),bl.end(),bl.begin(),::tolower);
        for (auto& h:hints) {
            std::string kl=h.kw;
            std::transform(kl.begin(),kl.end(),kl.begin(),::tolower);
            if(bl.find(kl)!=std::string::npos){
                os_hints_found.insert(h.os);
                std::cout<<BLOOD_RED<<"  [port "<<WHITE<<r.port<<BLOOD_RED<<"] "<<WHITE<<h.detail<<RESET<<"\n";
            }
        }
    }

    print_section("VERDICT");
    static const char* os_names[4]={"Windows","Linux/Unix","BSD/macOS","Network Device"};
    int best=0;
    for(int i=1;i<4;i++) if(score[i]>score[best]) best=i;

    if     (ttl>=120&&ttl<=128) score[0]+=5;
    else if(ttl>=60 &&ttl<=64)  score[1]+=5;
    else if(ttl>=250)            score[3]+=5;

    std::string verdict=os_names[best];
    if(!os_hints_found.empty()) verdict=*os_hints_found.begin();

    std::cout<<BLOOD_RED<<"  [os]       "<<WHITE<<BOLD<<verdict<<RESET<<"\n";
    std::cout<<BLOOD_RED<<"  [scores]   "<<WHITE;
    for(int i=0;i<4;i++) std::cout<<os_names[i]<<":"<<score[i]<<" ";
    std::cout<<"\n"<<RESET;

    g_result.os_guess=verdict;
    LOG_INFO("os_detect","target="+ip+" verdict="+verdict);
}
