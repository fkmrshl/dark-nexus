#include "../include/dark_nexus.hpp"

static void print_banner() {
    write(STDOUT_FILENO,"\033[2J\033[H",7);
    std::cout<<"\n"<<WHITE<<BOLD;
    std::cout<<"  ██████╗  █████╗ ██████╗ ██╗  ██╗    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗\n";
    std::cout<<"  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝\n";
    std::cout<<"  ██║  ██║███████║██████╔╝█████╔╝     ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗\n";
    std::cout<<"  ██║  ██║██╔══██║██╔══██╗██╔═██╗     ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║\n";
    std::cout<<"  ██████╔╝██║  ██║██║  ██║██║  ██╗    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║\n";
    std::cout<<GRAY<<"  ╫█╫══╝  ╚█╫  ╚╝╚█╫  ╚╝╚╝  ╚█╫    ╚╝  ╚═══╝╚══════╝╚╝  ╚═╝ ╚═════╝ ╚══════╝\n";
    std::cout<<DIM<<"    |        |     ||            |\n    .        .     ..            .\n"<<RESET;
    std::cout<<WHITE<<BOLD<<"  NETWORK INTELLIGENCE TOOL\n"<<RESET;
    std::cout<<CYAN<<"  "<<std::string(80,'=')<<"\n"<<RESET;
    std::cout<<MAGENTA<<BOLD<<"  by marshal"<<RESET<<"    "<<GRAY<<"t.me/fuckmarshal\n"<<RESET<<"\n";
}

static void print_menu() {
    auto sep=[](){std::cout<<CYAN<<"  +------+--------------------+----------------------------------+\n"<<RESET;};
    std::cout<<"\n"; sep();
    std::cout<<CYAN<<"  | "<<WHITE<<BOLD<<std::left<<std::setw(4)<<"NUM"<<CYAN<<" | "<<std::setw(18)<<"MODULE"<<CYAN<<" | "<<std::setw(32)<<"EXAMPLE"<<CYAN<<"   |\n"<<RESET;
    sep();
    auto row=[&](const std::string& n,const std::string& m,const std::string& e){
        std::cout<<CYAN<<"  | "<<YELLOW<<BOLD<<std::left<<std::setw(4)<<n<<CYAN<<" | "<<GREEN<<std::setw(18)<<m<<CYAN<<" | "<<WHITE<<std::setw(34)<<e<<CYAN<<" |\n"<<RESET;
    };
    row(" [1]","PORT SCAN",      "192.168.1.1   0=top1000");
    row(" [2]","NETWORK SCAN",   "192.168.1.1");
    row(" [3]","OS DETECTION",   "192.168.1.1");
    row(" [4]","IP FULL INTEL",  "8.8.8.8");
    row(" [5]","DNS LOOKUP",     "google.com");
    row(" [6]","WHOIS LOOKUP",   "google.com / 8.8.8.8");
    row(" [7]","SITE --> IP",    "https://google.com");
    row(" [8]","OSINT USERNAME", "marshal");
    row(" [9]","TRACEROUTE",     "8.8.8.8");
    row("[10]","FULL IP RECON",  "8.8.8.8");
    row("[11]","SUBDOMAIN SCAN", "google.com");
    row("[12]","EXPORT JSON",    "save last scan");
    row(" [0]","EXIT",           "");
    sep();
    std::cout<<GRAY<<"  bugs / feedback -> t.me/fuckmarshal\n"<<RESET;
    std::cout<<"\n"<<GREEN<<BOLD<<"  DARK NEXUS~# "<<RESET;
}

int main() {
    Logger::get().init("dark_nexus.log", LogLevel::INFO);
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
            std::string u; std::cout<<GREEN<<"\n  username: "<<RESET; std::cin>>u;
            if(!valid_username(u)){std::cout<<RED<<"  invalid username\n"<<RESET;}
            else osint_scan(u);
        } else if(choice==7){
            std::string s; std::cout<<GREEN<<"\n  site: "<<RESET; std::cin>>s;
            site_lookup(s);
        } else if(choice==11){
            std::string d; std::cout<<GREEN<<"\n  domain: "<<RESET; std::cin>>d;
            if(!valid_target(d)){std::cout<<RED<<"  invalid domain\n"<<RESET;}
            else subdomain_scan(d);
        } else {
            std::string target; std::cout<<GREEN<<"\n  target: "<<RESET; std::cin>>target;
            if(!valid_target(target)){std::cout<<RED<<"  invalid input\n"<<RESET;continue;}
            std::string ip=resolve(target);
            if(ip.empty()) ip=target;
            else if(ip!=target) std::cout<<YELLOW<<"  resolved: "<<target<<" -> "<<ip<<"\n"<<RESET;

            switch(choice){
                case 1:{
                    int s=0,e=0;
                    std::cout<<GREEN<<"  start port (0=top1000): "<<RESET; std::cin>>s;
                    if(s==0){port_scan(ip,0,0);}
                    else{
                        std::cout<<GREEN<<"  end port: "<<RESET; std::cin>>e;
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
    std::cout<<"\n"<<MAGENTA<<BOLD<<"  goodbye, marshal.\n\n"<<RESET;
    return 0;
}
