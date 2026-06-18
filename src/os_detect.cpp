#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"
#include "../include/os_fingerprint.hpp"
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

                if (c.port == 445) {
                    std::string smb = smb_os_probe(ip, 1000);
                    if (!smb.empty()) ext = "Native OS: " + smb;
                } else if (c.port == 80 || c.port == 443) {
                    std::string http = analyze_http_headers(ip, c.port, 1000);
                    if (!http.empty()) ext = http;
                }

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

    std::map<std::string,int> cat_open;
    int open_c=0;
    OsFingerprintInput fp_input;
    fp_input.tcp_syn_signature = tcp_fp;

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
            cat_open[r.cat]++;
            open_c++;
            fp_input.open_ports.push_back(r.port);
            OsPortSignal signal;
            signal.port = r.port;
            signal.name = r.name;
            signal.category = r.cat;
            signal.banner = r.bnr;
            signal.extra = r.extra;
            signal.open = true;
            signal.weights = {r.w[0], r.w[1], r.w[2], r.w[3]};
            fp_input.port_signals.push_back(signal);
        } else {
            std::cout<<BLOOD_RED<<"closed"<<RESET;
        }
        std::cout<<"\n";
    }
    std::cout<<BLOOD_RED<<"  open: "<<WHITE<<open_c<<BLOOD_RED<<"/"<<WHITE<<checks.size()<<"\n"<<RESET;

    print_section("ICMP TTL ANALYSIS");
    fp_input.ttl = collect_os_ttl_signal(ip, 3, 1);
    fp_input.smb_verdict = smb_verdict;
    fp_input.waf_verdict = waf_verdict;

    std::cout<<BLOOD_RED<<"  [ttl]          "<<WHITE<<(fp_input.ttl.ttl?std::to_string(fp_input.ttl.ttl):"n/a")<<"\n"<<RESET;
    std::cout<<BLOOD_RED<<"  [initial_ttl]  "<<WHITE<<(fp_input.ttl.initial_ttl?std::to_string(fp_input.ttl.initial_ttl):"n/a")<<"\n"<<RESET;
    std::cout<<BLOOD_RED<<"  [hops]         "<<WHITE<<(fp_input.ttl.hops?std::to_string(fp_input.ttl.hops):"n/a")<<"\n"<<RESET;
    std::cout<<BLOOD_RED<<"  [stable]       "<<WHITE<<(fp_input.ttl.stable?"yes":"NO -- load balancer/multipath")<<"\n"<<RESET;

    print_section("VERDICT");
    OsFingerprintResult verdict = fingerprint_os(fp_input);

    std::cout<<BLOOD_RED<<"  [os]       "<<WHITE<<BOLD<<verdict.verdict<<RESET<<"\n";
    std::cout<<BLOOD_RED<<"  [scores]   "<<WHITE<<os_score_line(verdict)<<"\n"<<RESET;

    {
        std::lock_guard<std::mutex> lk(g_result_mtx);
        g_result.os_guess=verdict.verdict;
    }
    LOG_INFO("os_detect","target="+ip+" verdict="+verdict.verdict);
}
