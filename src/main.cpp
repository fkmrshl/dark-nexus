#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

static void print_banner() {
    if (write(STDOUT_FILENO, "\033[2J\033[H", 7)) {}
    std::cout<<"\n"<<BLOOD_RED<<BOLD;
    std::cout<<"\n"<<BLOOD_RED<<BOLD;
    std::cout<<"  ██████╗  █████╗ ██████╗ ██╗  ██╗    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗\n";
    std::cout<<"  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝\n";
    std::cout<<"  ██║  ██║███████║██████╔╝█████╔╝     ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗\n";
    std::cout<<"  ██║  ██║██╔══██║██╔══██╗██╔═██╗     ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║\n";
    std::cout<<"  ██████╔╝██║  ██║██║  ██║██║  ██╗    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║\n";
    std::cout<<"  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝\n";
    std::cout<<RESET;
    std::cout<<WHITE<<BOLD<<"  NETWORK INTELLIGENCE TOOL\n"<<RESET;
    std::cout<<BLOOD_RED<<"  "<<std::string(80,'=')<<"\n"<<RESET;
    std::cout<<BLOOD_RED<<BOLD<<"  by marshal"<<RESET<<"    "<<BLOOD_RED<<"t.me/fuckmarshal\n"<<RESET<<"\n";
}


static void print_menu() {
    auto sep=[](){std::cout<<BLOOD_RED<<"  +------+--------------------+----------------------------------+\n"<<RESET;};
    std::cout<<"\n"; sep();
    std::cout<<BLOOD_RED<<"  | "<<BLOOD_RED<<BOLD<<std::left<<std::setw(4)<<"NUM"<<BLOOD_RED<<" | "<<std::setw(18)<<"MODULE"<<BLOOD_RED<<" | "<<std::setw(32)<<"EXAMPLE"<<BLOOD_RED<<"   |\n"<<RESET;
    sep();
    auto row=[&](const std::string& n,const std::string& m,const std::string& e){
        std::cout<<BLOOD_RED<<"  | "<<BLOOD_RED<<BOLD<<std::left<<std::setw(4)<<n<<BLOOD_RED<<" | "<<BLOOD_RED<<std::setw(18)<<m<<BLOOD_RED<<" | "<<WHITE<<std::setw(34)<<e<<BLOOD_RED<<" |\n"<<RESET;
    };
    row(" [1]","PORT SCAN",      "192.168.1.1   0=top1000 (add U for UDP)");
    row(" [2]","NETWORK SCAN",   "192.168.1.1");
    row(" [3]","OS DETECTION",   "192.168.1.1");
    row(" [4]","IP FULL INTEL",  "8.8.8.8");
    row(" [5]","DNS LOOKUP",     "google.com");
    row(" [6]","WHOIS LOOKUP",   "google.com / 8.8.8.8");
    row(" [7]","SITE --> IP",    "https://google.com");
    row(" [8]","OSINT",          "user / user@mail.com / +7900...");
    row(" [9]","TRACEROUTE",     "8.8.8.8");
    row("[10]","FULL IP RECON",  "8.8.8.8");
    row("[11]","SUBDOMAIN SCAN", "google.com");
    row("[12]","EXPORT JSON",    "save last scan");
    row(" [0]","EXIT",           "");
    sep();
    std::cout<<BLOOD_RED<<"  bugs / feedback -> t.me/fuckmarshal\n"<<RESET;
    std::cout<<"\n"<<BLOOD_RED<<BOLD<<"  DARK NEXUS~# "<<RESET;
}

static void print_help() {
    print_banner();
    std::cout << WHITE << BOLD << "  USAGE:\n"<<RESET;
    std::cout << BLOOD_RED << "    ./dark_nexus [options] <target>\n\n"<<RESET;
    std::cout << WHITE << BOLD << "  OPTIONS:\n"<<RESET;
    std::cout << BLOOD_RED << "    --portscan <ip> [ports] " << WHITE << "Run port scan (e.g. 0 for top1000, 0U for UDP, or 80-443)\n"<<RESET;
    std::cout << BLOOD_RED << "    --netscan <subnet>      " << WHITE << "Run network scan (e.g. 192.168.1.1)\n"<<RESET;
    std::cout << BLOOD_RED << "    --os-detect <ip>        " << WHITE << "Run OS detection\n"<<RESET;
    std::cout << BLOOD_RED << "    --ip-intel <ip>         " << WHITE << "Run full IP intelligence\n"<<RESET;
    std::cout << BLOOD_RED << "    --dns <domain>          " << WHITE << "Run DNS lookup\n"<<RESET;
    std::cout << BLOOD_RED << "    --whois <target>        " << WHITE << "Run WHOIS lookup\n"<<RESET;
    std::cout << BLOOD_RED << "    --site <url>            " << WHITE << "Convert site URL to IP and run intel\n"<<RESET;
    std::cout << BLOOD_RED << "    --osint <target>        " << WHITE << "Run OSINT on username/email/phone\n"<<RESET;
    std::cout << BLOOD_RED << "    --traceroute <ip>       " << WHITE << "Run traceroute\n"<<RESET;
    std::cout << BLOOD_RED << "    --recon <ip>            " << WHITE << "Run full IP recon\n"<<RESET;
    std::cout << BLOOD_RED << "    --subdomain <domain>    " << WHITE << "Run subdomain scan\n"<<RESET;
    std::cout << BLOOD_RED << "    --mode <F|D>            " << WHITE << "Subdomain scan mode (Fast or Deep)\n"<<RESET;
    std::cout << BLOOD_RED << "    --json <file>           " << WHITE << "Export result to JSON file\n"<<RESET;
    std::cout << BLOOD_RED << "    -h, --help              " << WHITE << "Show this help menu\n\n"<<RESET;
    std::cout << WHITE << BOLD << "  EXAMPLES:\n"<<RESET;
    std::cout << BLOOD_RED << "    ./dark_nexus --subdomain google.com --mode F --json result.json\n"<<RESET;
    std::cout << BLOOD_RED << "    ./dark_nexus --portscan 192.168.1.1 0U\n"<<RESET;
    std::cout << BLOOD_RED << "    ./dark_nexus --osint user@mail.com\n\n"<<RESET;
}

int main(int argc, char** argv) {
    Logger::get().init("dark_nexus.log", LogLevel::INFO);
    if (!drop_privileges()) {
        std::cerr << "  [!] failed to drop privileges\n";
        return 1;
    }
    LOG_INFO("main","dark nexus started");

    if (argc > 1) {
        std::vector<std::string> args;
        for (int i = 1; i < argc; i++) args.push_back(argv[i]);

        std::string mode, target, extra, json_out;
        char sub_mode = 'F';

        for (size_t i = 0; i < args.size(); i++) {
            if (args[i] == "-h" || args[i] == "--help") { print_help(); return 0; }
            else if (args[i] == "--json" && i + 1 < args.size()) { json_out = args[++i]; }
            else if (args[i] == "--mode" && i + 1 < args.size()) {
                sub_mode = toupper(args[++i][0]);
                if (sub_mode != 'F' && sub_mode != 'D') sub_mode = 'F';
            }
            else if (args[i].substr(0, 2) == "--") {
                mode = args[i].substr(2);
                if (i + 1 < args.size() && args[i+1].substr(0,2) != "--") {
                    target = args[++i];
                }
                if (mode == "portscan" && i + 1 < args.size() && args[i+1].substr(0,2) != "--") {
                    extra = args[++i];
                }
            }
        }

        if (mode.empty() || target.empty()) {
            std::cerr << BLOOD_RED << "  [!] missing module or target\n" << RESET;
            print_help();
            return 1;
        }

        print_banner();

        if (mode == "osint") {
            osint_scan(target);
        } else if (mode == "site") {
            site_lookup(target);
        } else if (mode == "subdomain") {
            if(!valid_target(target)) { std::cout<<BLOOD_RED<<"  invalid domain\n"<<RESET; return 1; }
            std::string wl = auto_find_wordlist();
            if (sub_mode == 'F') subdomain_scan(target, "", 200, false, true, true);
            else subdomain_scan(target, wl, 200, true, true, true);
        } else {
            if(!valid_target(target)){std::cout<<WHITE<<"  invalid input\n"<<RESET;return 1;}
            std::string ip_res=resolve(target);
            if(ip_res.empty()) ip_res=target;
            else if(ip_res!=target) std::cout<<BLOOD_RED<<"  resolved: "<<target<<" -> "<<ip_res<<"\n"<<RESET;

            if (mode == "portscan") {
                bool udp = false;
                if (!extra.empty() && (extra.back() == 'U' || extra.back() == 'u')) {
                    udp = true; extra.pop_back();
                }
                int s = 0, e = 0;
                if (!extra.empty()) {
                    auto dash = extra.find('-');
                    if (dash != std::string::npos) {
                        try { s = std::stoi(extra.substr(0, dash)); e = std::stoi(extra.substr(dash+1)); } catch (...) {}
                    } else {
                        try { s = std::stoi(extra); e = s; } catch (...) {}
                        if (s == 0) e = 0;
                    }
                }
                port_scan(ip_res, s, e, udp);
            }
            else if (mode == "netscan") net_scan(ip_res.substr(0,ip_res.rfind('.')));
            else if (mode == "os-detect") os_detect(ip_res);
            else if (mode == "ip-intel") ip_intel(ip_res);
            else if (mode == "dns") dns_lookup(ip_res);
            else if (mode == "whois") whois_lookup(ip_res);
            else if (mode == "traceroute") traceroute(ip_res);
            else if (mode == "recon") full_recon(ip_res);
            else { std::cout<<BLOOD_RED<<"  unknown module: "<<mode<<"\n"<<RESET; return 1; }
        }

        if (!json_out.empty()) {
            g_result.target = target;
            g_result.timestamp = now_str();
            export_json(json_out);
        }
        return 0;
    }

    print_banner();

    while(true){
        print_menu();
        std::string cs; std::cin>>cs;
        int choice=-1; try{choice=std::stoi(cs);}catch(...){}
        if(choice==0) break;

        if(choice==12){
            std::string fn="dark_nexus_"+g_result.target+".json";
            std::replace(fn.begin(),fn.end(),':','_');
            export_json(fn);
            print_sep(); std::cout<<"  press enter..."; std::cin.ignore(); std::cin.get();
            print_banner(); continue;
        }

        if(choice==8){
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::string u;
            std::cout<<WHITE<<"\n  osint target "<<RESET<<WHITE<<"(username / email / +phone): "<<RESET;
            std::getline(std::cin, u);
            while(!u.empty()&&(u.front()==' '||u.front()=='\t')) u.erase(u.begin());
            while(!u.empty()&&(u.back()==' '||u.back()=='\t'))   u.pop_back();
            if(u.empty()){std::cout<<BLOOD_RED<<"  empty input\n"<<RESET;}
            else osint_scan(u);
        } else if(choice==7){
            std::string s; std::cout<<BLOOD_RED<<"\n  site: "<<RESET; std::cin>>s;
            site_lookup(s);
        } else if(choice==11){
            std::string d;
            std::cout<<WHITE<<"\n  domain: "<<RESET; std::cin>>d;
            if(!valid_target(d)){
                std::cout<<BLOOD_RED<<"  invalid domain\n"<<RESET;
            } else {
                std::string wl = auto_find_wordlist();

                std::cout<<"\n"<<BLOOD_RED<<"  +----------------------------------------------------------+----------+\n"<<RESET;
                std::cout<<BLOOD_RED<<"  | "<<WHITE<<BOLD<<std::left<<std::setw(56)<<"SUBDOMAIN SCAN"<<BLOOD_RED<<" | "<<std::setw(8)<<"INFO"<<BLOOD_RED<<" |\n"<<RESET;
                std::cout<<BLOOD_RED<<"  +----------------------------------------------------------+----------+\n"<<RESET;

                if (wl.empty()) {
                    std::cout<<BLOOD_RED<<"  | "<<WHITE<<std::left<<std::setw(56)<<"wordlist: not found, using builtin ~300 words"<<BLOOD_RED<<" |          |\n"<<RESET;
                } else {
                    std::string wl_short = wl.size() > 54 ? "..."+wl.substr(wl.size()-51) : wl;
                    std::cout<<BLOOD_RED<<"  | "<<WHITE<<std::left<<std::setw(56)<<("[*] wordlist: "+wl_short)<<BLOOD_RED<<" |          |\n"<<RESET;
                }
                std::cout<<BLOOD_RED<<"  +----------------------------------------------------------+----------+\n"<<RESET;

                std::cout<<"\n"<<BLOOD_RED<<"  +-----+----------------------------------------------------+----------+\n"<<RESET;
                std::cout<<BLOOD_RED<<"  | "<<WHITE<<BOLD<<std::left<<std::setw(3)<<"MOD"<<RESET<<BLOOD_RED<<" | "<<WHITE<<BOLD<<std::left<<std::setw(50)<<"DESCRIPTION"<<BLOOD_RED<<" | "<<std::setw(8)<<"ETA"<<BLOOD_RED<<" |\n"<<RESET;
                std::cout<<BLOOD_RED<<"  +-----+----------------------------------------------------+----------+\n"<<RESET;
                std::cout<<BLOOD_RED<<"  | "<<BLOOD_RED<<BOLD<<" F"<<RESET<<BLOOD_RED<<"  | "<<WHITE<<std::left<<std::setw(50)<<"FAST  — builtin 300 words + passive + enrich"<<BLOOD_RED<<" | "<<WHITE<<"~3 min  "<<BLOOD_RED<<" |\n"<<RESET;
                std::cout<<BLOOD_RED<<"  | "<<BLOOD_RED<<BOLD<<" D"<<RESET<<BLOOD_RED<<"  | "<<WHITE<<std::left<<std::setw(50)<<"DEEP  — full wordlist + all sources + takeover scan"<<BLOOD_RED<<" | "<<WHITE<<"~1-2hr  "<<BLOOD_RED<<" |\n"<<RESET;
                std::cout<<BLOOD_RED<<"  +-----+----------------------------------------------------+----------+\n"<<RESET;

                std::cout<<BLOOD_RED<<"  select mode [F/D]: "<<RESET;
                std::string mode_in; std::cin>>mode_in;
                char mode = mode_in.empty() ? 'F' : (char)toupper(mode_in[0]);
                if (mode != 'F' && mode != 'D') { mode = 'F'; std::cout<<WHITE<<"  [!] defaulting to FAST\n"<<RESET; }

                if (mode == 'F') {
                    std::cout<<WHITE<<"  [*] FAST: passive + builtin 300 words + HTTP enrich + takeover\n"<<RESET;
                    subdomain_scan(d, "", 200, false, true, true);
                } else {
                    std::cout<<WHITE<<"  [*] DEEP: full wordlist + all sources + enrich + takeover validation\n"<<RESET;
                    subdomain_scan(d, wl, 200, true, true, true);
                }
            }
        } else {
            std::string target; std::cout<<WHITE<<"\n  target: "<<RESET; std::cin>>target;
            if(!valid_target(target)){std::cout<<WHITE<<"  invalid input\n"<<RESET;continue;}
            std::string ip_res=resolve(target);
            if(ip_res.empty()) ip_res=target;
            else if(ip_res!=target) std::cout<<BLOOD_RED<<"  resolved: "<<target<<" -> "<<ip_res<<"\n"<<RESET;

            switch(choice){
                case 1: {
                    std::string s_in;
                    std::cout<<BLOOD_RED<<"  start port (0=top1000) [add U for UDP, e.g. 0U]: "<<RESET; std::cin>>s_in;
                    bool udp = false;
                    if (!s_in.empty() && (s_in.back() == 'U' || s_in.back() == 'u')) {
                        udp = true; s_in.pop_back();
                    }
                    int s = 0;
                    try { s = std::stoi(s_in); } catch (...) {}
                    if (s == 0) { port_scan(ip_res, 0, 0, udp); }
                    else {
                        int e=0;
                        std::cout<<BLOOD_RED<<"  end port: "<<RESET; std::cin>>e;
                        if (!valid_port(s) || !valid_port(e) || s>e) { std::cout<<BLOOD_RED<<"  invalid range\n"<<RESET; break; }

                        port_scan(ip_res, s, e, udp);
                    }
                    break;
                }
                case 2:  net_scan(ip_res.substr(0,ip_res.rfind('.'))); break;
                case 3:  os_detect(ip_res);    break;
                case 4:  ip_intel(ip_res);     break;
                case 5:  dns_lookup(ip_res);   break;
                case 6:  whois_lookup(ip_res); break;
                case 9:  traceroute(ip_res);   break;
                case 10: full_recon(ip_res);   break;
                default: std::cout<<BLOOD_RED<<"  invalid option\n"<<RESET;
            }
        }

        print_sep();
        std::cout<<"  press enter to continue..."; std::cin.ignore(); std::cin.get();
        print_banner();
    }

    LOG_INFO("main","session ended");
    std::cout<<"\n"<<BLOOD_RED<<BOLD<<"  goodbye, marshal.\n\n"<<RESET;
    return 0;
}
