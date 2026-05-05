#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

static RateLimiter port_rl(10000.0);
static const std::vector<int> TOP1000 = {
    1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,
    70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,
    135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,
    280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,
    464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,
    563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,
    705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,
    888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,
    1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,
    1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,
    1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,
    1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,
    1072,1073,1074,1075,1076,1077,1078,1079,1080,1110,1234,1433,1434,1521,
    1720,1723,1755,1900,2000,2001,2049,2121,2181,2375,2376,3000,3128,3306,
    3389,3690,4444,4445,4899,5000,5432,5900,5901,6000,6001,6379,6443,7001,
    7443,8000,8008,8080,8081,8443,8888,9000,9090,9200,9300,10000,11211,
    27017,50070
};

struct AdaptiveConfig {
    int connect_ms;
    int banner_ms;
    int retry_count;
    int pool_size;
    int median_rtt;
};

struct VulnHint {
    std::string cve;
    std::string desc;
    std::string severity;
};

static int service_priority(int port) {
    if (port==80||port==443||port==22||port==445||port==3389||port==8080) return 100;
    if (port==21||port==25||port==53||port==110||port==143||port==3306||port==5432) return 50;
    return 10;
}

static std::string extract_version(const std::string& banner_raw, int port) {
    if (banner_raw.empty()) return "";
    std::regex re(R"(([A-Za-z0-9_\-]+[/\-][\d\.]+))");
    std::smatch m;
    if (std::regex_search(banner_raw, m, re)) return m[1].str();
    if (port==22 && banner_raw.find("SSH-")==0) return banner_raw;
    return "";
}

static std::vector<VulnHint> check_vulns(int port, const std::string& version_str,
                                          const std::string& bnr)
{
    std::vector<VulnHint> vulns;
    std::string bl=bnr, vl=version_str;
    std::transform(bl.begin(),bl.end(),bl.begin(),::tolower);
    std::transform(vl.begin(),vl.end(),vl.begin(),::tolower);

    if (port==22 && vl.find("openssh")!=std::string::npos) {
        std::regex re_ver("openssh[_\\s]([0-9]+)\\.([0-9]+)");
        std::smatch m;
        if (std::regex_search(vl,m,re_ver)) {
            int maj=std::stoi(m[1].str()), mn=std::stoi(m[2].str());
            if (maj<9||(maj==9&&mn<8))
                vulns.push_back({"CVE-2024-6387","regreSSHion - signal handler race","CRIT"});
            if (maj<9||(maj==9&&mn<3))
                vulns.push_back({"CVE-2023-38408","agent forwarding RCE","HIGH"});
            if (maj<8||(maj==8&&mn<5))
                vulns.push_back({"CVE-2021-41617","privilege escalation","MED"});
        }
    }

    if (port==21) {
        if (bl.find("anonymous")!=std::string::npos||bl.find("anon")!=std::string::npos)
            vulns.push_back({"N/A","anonymous FTP possibly allowed","MED"});
        if (vl.find("vsftpd 2.3.4")!=std::string::npos)
            vulns.push_back({"CVE-2011-2523","vsFTPd 2.3.4 backdoor","CRIT"});
    }

    if (port==445||port==139)
        vulns.push_back({"CHECK","SMB exposed - EternalBlue/SMBGhost/PrintNightmare","HIGH"});
    if (port==23)
        vulns.push_back({"N/A","telnet cleartext - credentials sniffable","HIGH"});
    if (port==6379) {
        if (bl.find("noauth")==std::string::npos&&bl.find("denied")==std::string::npos&&!bl.empty())
            vulns.push_back({"N/A","redis possibly unauthenticated - RCE risk","CRIT"});
    }
    if (port==27017) vulns.push_back({"CHECK","MongoDB exposed - check auth","HIGH"});
    if (port==2375)  vulns.push_back({"N/A","Docker API unencrypted - full host compromise","CRIT"});
    if (port==9200)  vulns.push_back({"CHECK","Elasticsearch exposed - check auth & data","HIGH"});
    if (port==3389)  vulns.push_back({"CHECK","RDP exposed - check BlueKeep CVE-2019-0708","HIGH"});
    if (port==6443)  vulns.push_back({"CHECK","K8s API exposed - check RBAC","HIGH"});
    if (port==11211) vulns.push_back({"CHECK","Memcached exposed - DDoS amplification","HIGH"});

    if ((port==80||port==443||port==8080||port==8443)&&!version_str.empty())
        vulns.push_back({"INFO","server version disclosed: "+version_str,"INFO"});

    return vulns;
}

static AdaptiveConfig calibrate_target(const std::string& ip) {
    AdaptiveConfig cfg;
    std::vector<int> rtts;
    int cal_ports[]={80,443,22,8080,53};

    for (int p : cal_ports) {
        auto t0=std::chrono::high_resolution_clock::now();
        int fd=socket(AF_INET,SOCK_STREAM,0);
        if (fd<0) continue;
        sockaddr_in sa{};
        sa.sin_family=AF_INET; sa.sin_port=htons(p);
        inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
        fcntl(fd,F_SETFL,O_NONBLOCK);
        connect(fd,(sockaddr*)&sa,sizeof(sa));
        fd_set fds; FD_ZERO(&fds); FD_SET(fd,&fds);
        timeval tv{0,800000};
        int r=select(fd+1,nullptr,&fds,nullptr,&tv);
        auto t1=std::chrono::high_resolution_clock::now();
        close(fd);
        if (r>0) {
            int ms=std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count();
            rtts.push_back(ms);
        }
    }

    if (rtts.empty()) {
        cfg.connect_ms=1500; cfg.banner_ms=3000;
        cfg.retry_count=2;   cfg.pool_size=50;
        cfg.median_rtt=-1;
        return cfg;
    }

    std::sort(rtts.begin(),rtts.end());
    cfg.median_rtt=rtts[rtts.size()/2];
    cfg.connect_ms=std::max(200,std::min(3000,cfg.median_rtt*3));
    cfg.banner_ms =std::max(500,std::min(5000,cfg.median_rtt*5));
    cfg.retry_count=(cfg.median_rtt<50)?1:2;

    if      (cfg.median_rtt<20)  cfg.pool_size=300;
    else if (cfg.median_rtt<100) cfg.pool_size=150;
    else                         cfg.pool_size=60;

    return cfg;
}

static std::pair<int,bool> probe_with_retry(const std::string& ip, int port,
                                            int timeout_ms, int retries)
{
    for (int attempt=0; attempt<=retries; attempt++) {
        int fd=socket(AF_INET,SOCK_STREAM,0);
        if (fd<0) return {-1,false};

        sockaddr_in sa{};
        sa.sin_family=AF_INET; sa.sin_port=htons(port);
        inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
        fcntl(fd,F_SETFL,O_NONBLOCK);

        auto t0=std::chrono::high_resolution_clock::now();
        int cr=connect(fd,(sockaddr*)&sa,sizeof(sa));

        if (cr==0) {
            int ms=std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now()-t0).count();
                close(fd);
                return {std::max(1,ms),false};
        }

        if (errno!=EINPROGRESS) { close(fd); return {-1,false}; }

        fd_set wfds,efds;
        FD_ZERO(&wfds); FD_SET(fd,&wfds);
        FD_ZERO(&efds); FD_SET(fd,&efds);
        timeval tv{timeout_ms/1000,(timeout_ms%1000)*1000};
        int sel=select(fd+1,nullptr,&wfds,&efds,&tv);

        if (sel>0&&FD_ISSET(fd,&wfds)) {
            int sockerr=0; socklen_t errlen=sizeof(sockerr);
            getsockopt(fd,SOL_SOCKET,SO_ERROR,&sockerr,&errlen);
            int ms=std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now()-t0).count();
                close(fd);
                if (sockerr==0) return {std::max(1,ms),false};
                return {-1,false};
        }

        close(fd);
        if (sel==0) {
            if (attempt==retries) return {-1,true};
            usleep(50000);
            continue;
        }
        return {-1,false};
    }
    return {-1,true};
}

static int sev_rank(const std::string& s) {
    if (s=="CRIT") return 0;
    if (s=="HIGH") return 1;
    if (s=="MED")  return 2;
    return 3;
}

std::string guess_os_from_ports(const std::vector<int>& open) {
    auto has=[&](int p){return std::find(open.begin(),open.end(),p)!=open.end();};
    if(has(3389)||has(5985)||has(5986)||has(445)||has(135)) return "Windows";
    if(has(22)&&!has(3389)){
        if(has(631))  return "Linux (CUPS)";
        if(has(2049)) return "Linux (NFS)";
        return "Linux/Unix";
    }
    if(has(548)||has(5353)) return "macOS/Darwin";
    if(has(23))             return "Network Device";
    if(has(161))            return "SNMP Device";
    return "unknown";
}

void port_scan(const std::string& ip, int start, int end_port) {
    print_header("PORT SCAN // " + ip);

    std::vector<int> ports;
    if (start==0&&end_port==0) {
        ports=TOP1000;
        std::cout<<BLOOD_RED<<"  mode: "<<WHITE<<"top-1000 ports\n"<<RESET;
    } else {
        for (int p=start;p<=end_port;p++) ports.push_back(p);
        std::cout<<BLOOD_RED<<"  range: "<<WHITE<<start<<"-"<<end_port
        <<BLOOD_RED<<" ("<<WHITE<<ports.size()<<BLOOD_RED<<" ports)\n"<<RESET;
    }

    print_section("PHASE 0 // CALIBRATION");
    std::cout<<BLOOD_RED<<"  measuring target latency...\n"<<RESET;

    auto cfg=calibrate_target(ip);
    std::cout<<BLOOD_RED<<"  rtt: "<<WHITE
    <<(cfg.median_rtt>=0?std::to_string(cfg.median_rtt)+"ms":"n/a")
    <<BLOOD_RED<<"  timeout: "<<WHITE<<cfg.connect_ms<<"ms"
    <<BLOOD_RED<<"  retries: "<<WHITE<<cfg.retry_count
    <<BLOOD_RED<<"  threads: "<<WHITE<<cfg.pool_size<<"\n"<<RESET;

    std::string hostname=ptr_lookup(ip);
    if (!hostname.empty()&&hostname!=ip)
        std::cout<<BLOOD_RED<<"  ptr: "<<WHITE<<hostname<<"\n"<<RESET;

    print_section("PHASE 1 // DISCOVERY");
    std::cout<<BLOOD_RED<<"  sweeping "<<WHITE<<ports.size()<<BLOOD_RED<<" ports...\n"<<RESET;

    struct QuickHit { int port; int latency_ms; };
    std::vector<QuickHit> open_hits;
    std::vector<int> filtered_ports;
    std::mutex mx;
    std::atomic<int> done_c{0}, open_c{0}, filt_c{0};
    int total=ports.size();

    std::vector<int> sorted_ports=ports;
    std::sort(sorted_ports.begin(),sorted_ports.end(),[](int a,int b){
        return service_priority(a)>service_priority(b);
    });

    auto scan_start=std::chrono::steady_clock::now();
    {
        int psz=std::min(cfg.pool_size,(int)sorted_ports.size());
        ThreadPool pool(psz);
        std::vector<std::future<void>> futs;
        futs.reserve(total);

        for (int i=0;i<total;i++) {
            futs.push_back(pool.submit([&,i]{
                int p=sorted_ports[i];
                port_rl.acquire();
                auto [lat, filtered] = probe_with_retry(ip, p, cfg.connect_ms, cfg.retry_count);
                done_c++;

                if (lat>0) {
                    std::lock_guard<std::mutex> lk(mx);
                    open_hits.push_back({p,lat}); open_c++;
                } else if (filtered) {
                    std::lock_guard<std::mutex> lk(mx);
                    filtered_ports.push_back(p); filt_c++;
                }

                if (done_c%50==0||done_c==total) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(done_c,total,
                                  std::to_string(open_c.load())+" open "+
                                  std::to_string(filt_c.load())+" filt");
                }
            }));
        }
        for (auto& f:futs) f.get();
    }

    auto scan_end=std::chrono::steady_clock::now();
    double scan_secs=std::chrono::duration<double>(scan_end-scan_start).count();

    draw_progress(total,total,
                  std::to_string(open_c.load())+" open "+std::to_string(filt_c.load())+" filt");
    std::cout<<"\n";
    std::cout<<BLOOD_RED<<"  discovery: "<<WHITE<<std::fixed<<std::setprecision(2)
    <<scan_secs<<"s "<<BLOOD_RED<<"("<<WHITE<<(int)(total/std::max(scan_secs,0.01))<<BLOOD_RED<<" ports/sec)\n"<<RESET;

    std::sort(open_hits.begin(),open_hits.end(),
              [](const QuickHit& a,const QuickHit& b){return a.port<b.port;});

    if (open_hits.empty()) {
        std::cout<<"\n"<<BLOOD_RED<<"  no open ports found\n"<<RESET;
        if (!filtered_ports.empty()) {
            std::sort(filtered_ports.begin(),filtered_ports.end());
            std::cout<<BLOOD_RED<<"  "<<WHITE<<filtered_ports.size()<<BLOOD_RED<<" filtered (fw silently drops)\n"<<RESET;
            std::cout<<BLOOD_RED<<"  sample: "<<WHITE;
            for (int i=0;i<std::min(10,(int)filtered_ports.size());i++)
                std::cout<<filtered_ports[i]<<" ";
            if ((int)filtered_ports.size()>10) std::cout<<"...";
            std::cout<<"\n"<<RESET;
        }
        LOG_INFO("port_scan","done target="+ip+" open=0 filtered="+
        std::to_string(filtered_ports.size()));
        return;
    }

    print_section("PHASE 2 // DEEP ANALYSIS");
    std::cout<<BLOOD_RED<<"  analyzing "<<WHITE<<open_hits.size()<<BLOOD_RED<<" open ports...\n"<<RESET;

    struct PortResult {
        int port, latency_ms;
        std::string service, banner_raw, version, risk;
        std::vector<VulnHint> vulns;
    };

    std::vector<PortResult> results(open_hits.size());
    std::atomic<int> deep_done{0};
    int deep_total=open_hits.size();

    {
        int dpool=std::min(30,deep_total);
        ThreadPool deep_pool(dpool);
        std::vector<std::future<void>> dfuts;
        dfuts.reserve(deep_total);

        for (int i=0;i<deep_total;i++) {
            dfuts.push_back(deep_pool.submit([&,i]{
                int p=open_hits[i].port;
                PortResult pr;
                pr.port=p;
                pr.latency_ms=open_hits[i].latency_ms;
                pr.service=svc(p);
                pr.risk=risk_label(p);
                pr.banner_raw=smart_banner(ip,p,cfg.banner_ms);
                pr.version=extract_version(pr.banner_raw,p);
                pr.vulns=check_vulns(p,pr.version,pr.banner_raw);
                results[i]=pr;
                deep_done++;

                if (deep_done%3==0||deep_done==deep_total) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(deep_done,deep_total,"banners...");
                }
            }));
        }
        for (auto& f:dfuts) f.get();
    }

    draw_progress(deep_total,deep_total,"done");
    std::cout<<"\n";

    print_section("PHASE 3 // RESULTS");
    std::cout<<"\n"<<BLOOD_RED<<BOLD
    <<"  PORT      SERVICE         VERSION                  LATENCY   RISK      BANNER\n"
    <<"  "<<std::string(100,'-')<<"\n"<<RESET;

    int vuln_crit=0,vuln_high=0,vuln_med=0,vuln_info=0;
    std::vector<VulnHint> all_vulns;
    std::vector<int> open_port_list;

    for (auto& pr:results) {
        open_port_list.push_back(pr.port);

        std::cout<<BLOOD_RED<<"  "<<WHITE<<std::left<<std::setw(10)<<pr.port
        <<std::setw(16)<<pr.service
        <<std::setw(25)<<(pr.version.empty()?"-":pr.version)
        <<std::setw(10)<<(std::to_string(pr.latency_ms)+"ms")
        <<std::setw(10)<<pr.risk;

        std::string dbnr=pr.banner_raw;
        if (dbnr.size()>45) dbnr=dbnr.substr(0,45)+"...";
        std::cout << sanitize(dbnr) << RESET << "\n";

        for (auto& v:pr.vulns) {
            all_vulns.push_back(v);
            if      (v.severity=="CRIT") vuln_crit++;
            else if (v.severity=="HIGH") vuln_high++;
            else if (v.severity=="MED")  vuln_med++;
            else                         vuln_info++;
        }

        g_result.open_ports.push_back({pr.port,pr.service});
    }

    if (!filtered_ports.empty()) {
        std::sort(filtered_ports.begin(),filtered_ports.end());
        std::cout<<"\n"<<BLOOD_RED<<"  "<<WHITE<<filtered_ports.size()<<BLOOD_RED<<" filtered: "<<WHITE;
        for (int i=0;i<std::min(15,(int)filtered_ports.size());i++)
            std::cout<<filtered_ports[i]<<" ";
        if ((int)filtered_ports.size()>15) std::cout<<"...";
        std::cout<<"\n"<<RESET;
    }

    if (!all_vulns.empty()) {
        print_section("VULNERABILITY HINTS");
        std::cout<<"\n";

        std::sort(all_vulns.begin(),all_vulns.end(),[](const VulnHint& a,const VulnHint& b){
            return sev_rank(a.severity)<sev_rank(b.severity);
        });

        for (auto& v:all_vulns) {
            std::cout<<BLOOD_RED<<"  "<<BOLD<<"["<<WHITE<<std::setw(4)<<v.severity<<BLOOD_RED<<"] "
            <<WHITE<<std::setw(16)<<v.cve<<"  "<<v.desc<<RESET<<"\n";
        }

        std::cout<<"\n"<<BLOOD_RED<<"  vuln summary: "
        <<WHITE<<vuln_crit <<BLOOD_RED<<" crit  "
        <<WHITE<<vuln_high <<BLOOD_RED<<" high  "
        <<WHITE<<vuln_med  <<BLOOD_RED<<" med  "
        <<WHITE<<vuln_info <<BLOOD_RED<<" info"
        <<RESET<<"\n";

        if      (vuln_crit>0)
            std::cout<<BLOOD_RED<<BOLD<<"\n  [!] "<<WHITE<<"CRITICAL issues found - immediate attention needed\n"<<RESET;
        else if (vuln_high>0)
            std::cout<<BLOOD_RED<<"\n  [!] "<<WHITE<<"high severity issues - review recommended\n"<<RESET;
    }

    std::string os_hint=guess_os_from_ports(open_port_list);
    if (os_hint!="unknown") {
        std::cout<<"\n"<<BLOOD_RED<<"  os hint (ports): "<<WHITE<<os_hint<<RESET<<"\n";
        g_result.os_guess=os_hint;
    }

    print_section("SCAN STATS");
    auto total_time=std::chrono::duration<double>(
        std::chrono::steady_clock::now()-scan_start).count();

        std::cout<<BLOOD_RED <<"  [target]       "<<WHITE<<ip<<"\n"<<RESET;
        std::cout<<BLOOD_RED <<"  [ports tested] "<<WHITE<<total<<"\n"<<RESET;
        std::cout<<BLOOD_RED <<"  [open]         "<<WHITE<<open_hits.size()<<"\n"<<RESET;
        std::cout<<BLOOD_RED <<"  [filtered]     "<<WHITE<<filtered_ports.size()<<"\n"<<RESET;
        std::cout<<BLOOD_RED <<"  [closed]       "<<WHITE
        <<(total-(int)open_hits.size()-(int)filtered_ports.size())<<"\n"<<RESET;
        std::cout<<BLOOD_RED <<"  [total time]   "<<WHITE<<std::fixed<<std::setprecision(2)
        <<total_time<<"s\n"<<RESET;
        std::cout<<BLOOD_RED <<"  [avg speed]    "<<WHITE
        <<(int)(total/std::max(total_time,0.01))<<" ports/sec\n"<<RESET;

        LOG_INFO("port_scan","done target="+ip+
        " open="+std::to_string(open_hits.size())+
        " filtered="+std::to_string(filtered_ports.size())+
        " time="+std::to_string((int)total_time)+"s");
}

void net_scan(const std::string& subnet) {
    print_header("NETWORK SCAN // " + subnet + ".0/24");

    static const std::vector<int> PROBE_PORTS={21,22,23,25,80,443,445,3389,8080,5985};

    std::cout<<BLOOD_RED<<"  phase 1: host discovery...\n"<<RESET;

    struct HostInfo {
        std::string ip, hostname, os;
        std::vector<std::pair<int,std::string>> ports;
        bool alive=false;
    };
    std::vector<HostInfo> hosts(254);
    std::atomic<int> cur(0), alive_c(0);

    ThreadPool pool(100);
    std::vector<std::future<void>> futs;
    futs.reserve(254);

    for (int i=1;i<=254;i++) {
        futs.push_back(pool.submit([&,i]{
            std::string ip=subnet+"."+std::to_string(i);
            HostInfo& h=hosts[i-1]; h.ip=ip;

            auto pout=safe_exec({"ping","-c1","-W1","-q",ip},2);
            bool alive=!pout.empty()&&pout.find("1 received")!=std::string::npos;
            if(!alive) for(int p:PROBE_PORTS){if(tcp_probe(ip,p,300)){alive=true;break;}}
            if(!alive) return;

            h.alive=true; alive_c++;
            char hbuf[NI_MAXHOST]={};
            sockaddr_in sa{}; sa.sin_family=AF_INET;
            inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
            getnameinfo((sockaddr*)&sa,sizeof(sa),hbuf,sizeof(hbuf),nullptr,0,0);
            h.hostname=strlen(hbuf)?sanitize(hbuf):"";

            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout<<BLOOD_RED<<"  [+] "<<WHITE<<std::left<<std::setw(16)<<ip;
            if(!h.hostname.empty()) std::cout<<BLOOD_RED<<" ("<<WHITE<<h.hostname<<BLOOD_RED<<")";
            std::cout<<RESET<<"\n";
        }));
    }
    for (auto& f:futs) f.get();

    std::cout<<BLOOD_RED<<"\n  found "<<WHITE<<alive_c<<BLOOD_RED<<" hosts -- phase 2: port scan...\n\n"<<RESET;

    std::vector<HostInfo*> alive_hosts;
    for (auto& h:hosts) if(h.alive) alive_hosts.push_back(&h);

    std::atomic<int> task(0);
    int ntasks=alive_hosts.size()*PROBE_PORTS.size();
    std::vector<std::future<void>> futs2; futs2.reserve(ntasks);

    for (int i=0;i<(int)alive_hosts.size();i++) {
        for (int p:PROBE_PORTS) {
            futs2.push_back(pool.submit([&,i,p]{
                if(!tcp_probe(alive_hosts[i]->ip,p,400)) return;
                std::string b=banner(alive_hosts[i]->ip,p,1000);
                std::lock_guard<std::mutex> lk(g_print_mtx);
                alive_hosts[i]->ports.emplace_back(p,b);
            }));
        }
    }
    for (auto& f:futs2) f.get();

    std::cout<<BLOOD_RED<<"  results:\n\n"<<RESET;
    int total_open=0;
    for (auto* h:alive_hosts) {
        std::sort(h->ports.begin(),h->ports.end());
        std::vector<int> op; for(auto& [p,_]:h->ports) op.push_back(p);
        h->os=guess_os_from_ports(op);

        std::cout<<BLOOD_RED<<"  ┌─ "<<WHITE<<std::left<<std::setw(16)<<h->ip;
        if(!h->hostname.empty()) std::cout<<BLOOD_RED<<" ["<<WHITE<<h->hostname<<BLOOD_RED<<"]";
        std::cout<<BLOOD_RED<<"  os: "<<WHITE<<h->os<<RESET<<"\n";

        if(h->ports.empty()) std::cout<<BLOOD_RED<<"  │  "<<WHITE<<"no open ports\n"<<RESET;
        for (auto& [p,b]:h->ports) {
            std::cout<<BLOOD_RED<<"  │  "<<WHITE<<std::setw(6)<<p<<" "<<std::setw(18)<<svc(p);
            if(!b.empty()) std::cout << "  " << sanitize(b);
            std::cout<<RESET<<"\n";
            total_open++;
        }
        std::cout<<BLOOD_RED<<"  └"<<std::string(36,'-')<<RESET<<"\n";
    }

    std::cout<<"\n"<<BLOOD_RED<<"  hosts alive: "<<WHITE<<alive_c<<BLOOD_RED<<"  open ports: "<<WHITE<<total_open<<"\n"<<RESET;
    LOG_INFO("net_scan","done subnet="+subnet+" alive="+std::to_string(alive_c));
}
