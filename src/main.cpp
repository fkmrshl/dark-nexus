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
    row(" [1]","PORT SCAN",      "192.168.1.1   0=top1000");
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

int main() {
    Logger::get().init("dark_nexus.log", LogLevel::INFO);
    if (!drop_privileges()) {
        std::cerr << "  [!] failed to drop privileges\n";
        return 1;
    }
    LOG_INFO("main","dark nexus started");

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
            if(u.empty()){std::cout<<RED<<"  empty input\n"<<RESET;}
            else osint_scan(u);
        } else if(choice==7){
            std::string s; std::cout<<BLOOD_RED<<"\n  site: "<<RESET; std::cin>>s;
            site_lookup(s);
        } else if(choice==11){
            std::string d;
            std::cout<<WHITE<<"\n  domain: "<<RESET; std::cin>>d;
            if(!valid_target(d)){
                std::cout<<RED<<"  invalid domain\n"<<RESET;
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
            std::string ip=resolve(target);
            if(ip.empty()) ip=target;
            else if(ip!=target) std::cout<<BLOOD_RED<<"  resolved: "<<target<<" -> "<<ip<<"\n"<<RESET;

            switch(choice){
                case 1:{
                    int s=0,e=0;
                    std::cout<<BLOOD_RED<<"  start port (0=top1000): "<<RESET; std::cin>>s;
                    if(s==0){port_scan(ip,0,0);}
                    else{
                        std::cout<<BLOOD_RED<<"  end port: "<<RESET; std::cin>>e;
                        if(!valid_port(s)||!valid_port(e)||s>e){std::cout<<RED<<"  invalid range\n"<<RESET;break;}
                        port_scan(ip,s,e);
                    }
                    break;
                }
                case 2:  net_scan(ip.substr(0,ip.rfind('.'))); break;
                case 3:  os_detect(ip);    break;
                case 4:  ip_intel(ip);     break;
                case 5:  dns_lookup(ip);   break;
                case 6:  whois_lookup(ip); break;
                case 9:  traceroute(ip);   break;
                case 10: full_recon(ip);   break;
                default: std::cout<<RED<<"  invalid option\n"<<RESET;
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
