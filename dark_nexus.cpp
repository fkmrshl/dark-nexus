// dark_nexus 
// network intelligence tool
// github.com/fkmrshl/dark-nexus
 
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <future>
#include <queue>
#include <condition_variable>
#include <functional>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <regex>
#include <chrono>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
 
// ─── colors ──────────────────────────────────────────────────────
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[97m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"
#define GRAY    "\033[90m"
 
std::mutex g_print_mtx;
 
// ================================================================
//  THREAD POOL
//  proper task queue with futures, replaces raw thread vectors
// ================================================================
class ThreadPool {
public:
    explicit ThreadPool(size_t n = std::thread::hardware_concurrency())
        : stop_(false)
    {
        if (n == 0) n = 4;
        for (size_t i = 0; i < n; ++i) {
            workers_.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lk(mtx_);
                        cv_.wait(lk, [this]{ return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    active_++;
                    task();
                    active_--;
                    done_cv_.notify_all();
                }
            });
        }
    }
 
    template<class F, class... Args>
    auto submit(F&& f, Args&&... args)
        -> std::future<typename std::invoke_result<F,Args...>::type>
    {
        using R = typename std::invoke_result<F,Args...>::type;
        auto task = std::make_shared<std::packaged_task<R()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...));
        auto fut = task->get_future();
        { std::lock_guard<std::mutex> lk(mtx_); tasks_.emplace([task]{ (*task)(); }); }
        cv_.notify_one();
        return fut;
    }
 
    void wait() {
        std::unique_lock<std::mutex> lk(mtx_);
        done_cv_.wait(lk, [this]{ return tasks_.empty() && active_ == 0; });
    }
 
    ~ThreadPool() {
        { std::unique_lock<std::mutex> lk(mtx_); stop_ = true; }
        cv_.notify_all();
        for (auto& w : workers_) w.join();
    }
 
private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex mtx_;
    std::condition_variable cv_, done_cv_;
    std::atomic<bool> stop_;
    std::atomic<int>  active_{0};
};
 
// ================================================================
//  LOGGER
//  json-line format, per-session log file
// ================================================================
enum class LogLevel { DEBUG, INFO, WARN, ERROR };
 
class Logger {
public:
    static Logger& get() { static Logger l; return l; }
 
    void init(const std::string& path, LogLevel min = LogLevel::INFO) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (file_.is_open()) file_.close();
        file_.open(path, std::ios::app);
        min_ = min;
    }
 
    void log(LogLevel lv, const std::string& mod, const std::string& msg) {
        if (lv < min_) return;
        std::lock_guard<std::mutex> lk(mtx_);
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", localtime(&t));
        if (file_.is_open())
            file_ << "{\"t\":\"" << ts << "\",\"lv\":\"" << lvstr(lv)
                  << "\",\"mod\":\"" << mod << "\",\"msg\":\""
                  << esc(msg) << "\"}\n";
    }
 
private:
    Logger() = default;
    std::ofstream file_;
    std::mutex mtx_;
    LogLevel min_ = LogLevel::INFO;
 
    static const char* lvstr(LogLevel l) {
        switch(l){ case LogLevel::DEBUG: return "DBG";
                   case LogLevel::INFO:  return "INF";
                   case LogLevel::WARN:  return "WRN";
                   case LogLevel::ERROR: return "ERR"; }
        return "?";
    }
    static std::string esc(const std::string& s) {
        std::string o; for(char c:s){ if(c=='"') o+="\\\""; else if(c=='\\') o+="\\\\"; else if(c==10) o+="\\n"; else o+=c; } return o;
    }
};
 
#define LOG_INFO(mod,msg)  Logger::get().log(LogLevel::INFO,  mod, msg)
#define LOG_WARN(mod,msg)  Logger::get().log(LogLevel::WARN,  mod, msg)
#define LOG_ERR(mod,msg)   Logger::get().log(LogLevel::ERROR, mod, msg)
 
// ================================================================
//  PROCESS -- safe exec via fork+execvp, no shell
// ================================================================
struct ProcResult {
    std::string out, err;
    int code = -1;
    bool timed_out = false;
};
 
static ProcResult proc_run(const std::vector<std::string>& args,
                            int timeout_sec = 10,
                            const std::string& stdin_data = "",
                            size_t max_out = 4*1024*1024)
{
    ProcResult res;
    if (args.empty()) return res;
 
    std::vector<char*> argv;
    for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
 
    int pout[2], perr[2], pin[2];
    if (pipe(pout)<0 || pipe(perr)<0) return res;
    bool has_stdin = !stdin_data.empty();
    if (has_stdin && pipe(pin)<0) { close(pout[0]);close(pout[1]);close(perr[0]);close(perr[1]); return res; }
 
    pid_t pid = fork();
    if (pid == 0) {
        close(pout[0]); close(perr[0]);
        dup2(pout[1], STDOUT_FILENO); dup2(perr[1], STDERR_FILENO);
        close(pout[1]); close(perr[1]);
        if (has_stdin) { close(pin[1]); dup2(pin[0],STDIN_FILENO); close(pin[0]); }
        setpgid(0,0);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    if (pid < 0) return res;
 
    close(pout[1]); close(perr[1]);
    if (has_stdin) {
        close(pin[0]);
        write(pin[1], stdin_data.c_str(), stdin_data.size());
        close(pin[1]);
    }
 
    fcntl(pout[0], F_SETFL, O_NONBLOCK);
    fcntl(perr[0], F_SETFL, O_NONBLOCK);
 
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    int ofd = pout[0], efd = perr[0];
 
    while (ofd >= 0 || efd >= 0) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) { kill(-pid, SIGKILL); res.timed_out = true; break; }
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(deadline-now);
        timeval tv{us.count()/1000000, us.count()%1000000};
        fd_set rfds; FD_ZERO(&rfds);
        int maxfd = -1;
        if (ofd>=0){FD_SET(ofd,&rfds); maxfd=std::max(maxfd,ofd);}
        if (efd>=0){FD_SET(efd,&rfds); maxfd=std::max(maxfd,efd);}
        if (select(maxfd+1,&rfds,nullptr,nullptr,&tv) <= 0) continue;
        char buf[8192];
        if (ofd>=0 && FD_ISSET(ofd,&rfds)) {
            ssize_t n = read(ofd,buf,sizeof(buf));
            if (n<=0){close(ofd);ofd=-1;} else if(res.out.size()<max_out) res.out.append(buf,n);
        }
        if (efd>=0 && FD_ISSET(efd,&rfds)) {
            ssize_t n = read(efd,buf,sizeof(buf));
            if (n<=0){close(efd);efd=-1;} else if(res.err.size()<max_out) res.err.append(buf,n);
        }
    }
    if (ofd>=0) close(ofd);
    if (efd>=0) close(efd);
    int status; waitpid(pid,&status,0);
    res.code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return res;
}
 
// convenience wrappers
static std::string safe_exec(const std::vector<std::string>& args, int t=8) {
    auto r = proc_run(args, t);
    return r.out;
}
 
static std::string safe_curl(const std::string& url, int t=8) {
    if (url.find('\'')!=std::string::npos) return "";
    return safe_exec({"curl","-s","--max-time",std::to_string(t),
                      "-L","-A","Mozilla/5.0","--",url}, t+2);
}
 
// ================================================================
//  INPUT VALIDATION & SANITIZATION
// ================================================================
static bool valid_target(const std::string& s) {
    if (s.empty() || s.size()>253) return false;
    static const std::regex ok(R"(^[a-zA-Z0-9.\-_:/@]+$)");
    return std::regex_match(s, ok);
}
 
static bool valid_username(const std::string& s) {
    if (s.empty() || s.size()>64) return false;
    static const std::regex ok(R"(^[a-zA-Z0-9.\-_]+$)");
    return std::regex_match(s, ok);
}
 
static bool valid_port(int p) { return p>=1 && p<=65535; }
 
// strip ansi/escape sequences -- prevents terminal injection via banners
static std::string sanitize(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (size_t i=0;i<s.size();i++) {
        unsigned char c=s[i];
        if (c==0x1b) { while(i<s.size()&&s[i]!='m'&&s[i]!='J'&&s[i]!='H'&&s[i]!='K'&&s[i]!='A'&&s[i]!='B'&&s[i]!='C'&&s[i]!='D') i++; continue; }
        if ((c>=32&&c<=126)||c==10||c==9) o+=c;
    }
    return o;
}
 
// ================================================================
//  NETWORK HELPERS
// ================================================================
static std::string resolve(const std::string& host) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host.c_str(),nullptr,&hints,&res)!=0) return "";
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&((sockaddr_in*)res->ai_addr)->sin_addr,buf,sizeof(buf));
    freeaddrinfo(res);
    return buf;
}
 
static bool tcp_probe(const std::string& ip, int port, int ms=500) {
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) return false;
    timeval tv{ms/1000,(ms%1000)*1000};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
    inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
    fcntl(fd,F_SETFL,O_NONBLOCK);
    connect(fd,(sockaddr*)&sa,sizeof(sa));
    fd_set fds; FD_ZERO(&fds); FD_SET(fd,&fds);
    int r=select(fd+1,nullptr,&fds,nullptr,&tv);
    close(fd); return r>0;
}
 
static std::pair<bool,int> tcp_probe_ms(const std::string& ip, int port, int ms=1000) {
    auto t0=std::chrono::high_resolution_clock::now();
    bool ok=tcp_probe(ip,port,ms);
    int el=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()-t0).count();
    return {ok,el};
}
 
static std::string ptr_lookup(const std::string& ip) {
    sockaddr_in sa{}; sa.sin_family=AF_INET;
    inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
    char h[NI_MAXHOST]={};
    if (getnameinfo((sockaddr*)&sa,sizeof(sa),h,sizeof(h),nullptr,0,0)==0) return h;
    return "";
}
 
// ================================================================
//  ICMP CHECKSUM
// ================================================================
static uint16_t icmp_cksum(const void* data, int len) {
    const uint16_t* buf=(const uint16_t*)data;
    uint32_t sum=0;
    while(len>1){sum+=*buf++;len-=2;}
    if(len==1) sum+=*(const uint8_t*)buf;
    sum=(sum>>16)+(sum&0xffff); sum+=(sum>>16);
    return (uint16_t)~sum;
}
 
// ================================================================
//  SERVICE DB
// ================================================================
static std::string svc(int port) {
    static std::map<int,std::string> db={
        {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
        {80,"HTTP"},{110,"POP3"},{111,"RPC"},{135,"MSRPC"},{139,"NetBIOS"},
        {143,"IMAP"},{179,"BGP"},{389,"LDAP"},{443,"HTTPS"},{445,"SMB"},
        {465,"SMTPS"},{512,"rexec"},{513,"rlogin"},{514,"rsh"},
        {548,"AFP"},{587,"Submission"},{636,"LDAPS"},{993,"IMAPS"},
        {995,"POP3S"},{1080,"SOCKS"},{1433,"MSSQL"},{1521,"Oracle"},
        {2049,"NFS"},{2375,"Docker"},{2376,"Docker-TLS"},
        {3000,"Grafana"},{3306,"MySQL"},{3389,"RDP"},{4444,"Metasploit"},
        {5432,"Postgres"},{5900,"VNC"},{5985,"WinRM"},{5986,"WinRM-S"},
        {6379,"Redis"},{6443,"K8s"},{7001,"WebLogic"},{8080,"HTTP-Alt"},
        {8443,"HTTPS-Alt"},{8888,"Jupyter"},{9000,"SonarQube"},
        {9090,"Prometheus"},{9200,"Elastic"},{9300,"ES-Cluster"},
        {10000,"Webmin"},{11211,"Memcached"},{27017,"MongoDB"},
        {50070,"Hadoop"}
    };
    auto it=db.find(port);
    return it!=db.end()?it->second:"unknown";
}
 
static std::string risk_label(int port) {
    static std::vector<int> hi={21,23,512,513,514,3389,5900,445,2375,111,4444,7001,50070};
    static std::vector<int> md={22,3306,5432,27017,6379,1433,9200,1521,8888,10000};
    if (std::find(hi.begin(),hi.end(),port)!=hi.end()) return std::string(RED)+"HIGH"+RESET;
    if (std::find(md.begin(),md.end(),port)!=md.end()) return std::string(YELLOW)+"MED"+RESET;
    return std::string(GREEN)+"LOW"+RESET;
}
 
// banner grab with sanitized output
static std::string banner(const std::string& ip, int port, int ms=1500) {
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) return "";
    timeval tv{ms/1000,(ms%1000)*1000};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
    inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
    // non-blocking connect
    fcntl(fd,F_SETFL,O_NONBLOCK);
    connect(fd,(sockaddr*)&sa,sizeof(sa));
    fd_set wfds; FD_ZERO(&wfds); FD_SET(fd,&wfds);
    timeval ctv{0,ms*1000};
    if (select(fd+1,nullptr,&wfds,nullptr,&ctv)<=0){close(fd);return "";}
    if (port==80||port==8080||port==8888){
        std::string req="HEAD / HTTP/1.0\r\nHost: "+ip+"\r\n\r\n";
        send(fd,req.c_str(),req.size(),0);
    }
    std::vector<char> buf(512,0);
    fd_set rfds; FD_ZERO(&rfds); FD_SET(fd,&rfds);
    timeval rtv{0,ms*1000};
    std::string result;
    if (select(fd+1,&rfds,nullptr,nullptr,&rtv)>0){
        ssize_t n=recv(fd,buf.data(),buf.size()-1,0);
        if (n>0){
            result=std::string(buf.data(),n);
            result.erase(std::remove(result.begin(),result.end(),'\r'),result.end());
            auto nl=result.find('\n'); if(nl!=std::string::npos) result=result.substr(0,nl);
            if(result.size()>70) result=result.substr(0,70)+"...";
        }
    }
    close(fd);
    return sanitize(result);
}
 
// ================================================================
//  JSON EXPORT
// ================================================================
struct ScanResult {
    std::string target, timestamp;
    std::vector<std::pair<int,std::string>> open_ports;
    std::vector<std::string> subdomains, osint_hits;
    std::string geo_country, geo_city, geo_isp, geo_as, os_guess;
    bool proxy=false, hosting=false;
};
ScanResult g_result;
 
static std::string now_str() {
    time_t t=time(nullptr); char buf[32];
    strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",localtime(&t));
    return buf;
}
 
static void export_json(const std::string& fname) {
    std::ofstream f(fname);
    if (!f){std::cout<<RED<<"  failed to write "<<fname<<"\n"<<RESET;return;}
    f<<"{\n  \"target\":\""<<g_result.target<<"\",\n";
    f<<"  \"timestamp\":\""<<g_result.timestamp<<"\",\n";
    f<<"  \"geo\":{\"country\":\""<<g_result.geo_country<<"\",\"city\":\""<<g_result.geo_city
     <<"\",\"isp\":\""<<g_result.geo_isp<<"\",\"as\":\""<<g_result.geo_as
     <<"\",\"proxy\":"<<(g_result.proxy?"true":"false")
     <<",\"hosting\":"<<(g_result.hosting?"true":"false")<<"},\n";
    f<<"  \"os\":\""<<g_result.os_guess<<"\",\n";
    f<<"  \"open_ports\":[\n";
    for (size_t i=0;i<g_result.open_ports.size();i++){
        f<<"    {\"port\":"<<g_result.open_ports[i].first<<",\"service\":\""<<g_result.open_ports[i].second<<"\"}";
        if(i+1<g_result.open_ports.size()) f<<",";
        f<<"\n";
    }
    f<<"  ],\n  \"subdomains\":[";
    for(size_t i=0;i<g_result.subdomains.size();i++){f<<"\""<<g_result.subdomains[i]<<"\"";if(i+1<g_result.subdomains.size())f<<",";}
    f<<"],\n  \"osint\":[";
    for(size_t i=0;i<g_result.osint_hits.size();i++){f<<"\""<<g_result.osint_hits[i]<<"\"";if(i+1<g_result.osint_hits.size())f<<",";}
    f<<"]\n}\n";
    std::cout<<GREEN<<"  saved: "<<fname<<"\n"<<RESET;
    LOG_INFO("export", "json saved: "+fname);
}
 
// ================================================================
//  JSON VALUE EXTRACTOR
// ================================================================
static std::string json_val(const std::string& json, const std::string& key) {
    auto pos=json.find("\""+key+"\"");
    if(pos==std::string::npos) return "";
    pos=json.find(':',pos); if(pos==std::string::npos) return "";
    while(++pos<json.size()&&(json[pos]==' '||json[pos]=='\t'));
    if(pos>=json.size()) return "";
    if(json[pos]=='"'){pos++;auto end=json.find('"',pos);return end==std::string::npos?"":json.substr(pos,end-pos);}
    auto end=json.find_first_of(",}\n",pos);
    std::string v=json.substr(pos,(end==std::string::npos?json.size():end)-pos);
    while(!v.empty()&&(v.back()==' '||v.back()=='\r'||v.back()=='\n')) v.pop_back();
    return v;
}
 
// ================================================================
//  UI HELPERS
// ================================================================
static int term_width() {
    struct winsize w;
    if (ioctl(STDOUT_FILENO,TIOCGWINSZ,&w)==0&&w.ws_col>0) return w.ws_col;
    return 80;
}
 
static void draw_progress(int done, int total, const std::string& label="") {
    if (total<=0) return;
    int w=std::min(term_width()-20,50);
    int filled=(int)((double)done/total*w);
    std::string bar(filled,'=');
    if(filled<w) bar+='>';
    bar+=std::string(std::max(0,w-filled-1),' ');
    int pct=(int)((double)done/total*100);
    std::cout<<"\r"<<CYAN<<"  ["<<GREEN<<bar<<CYAN<<"] "<<WHITE<<std::setw(3)<<pct<<"% "<<GRAY<<label<<RESET<<std::flush;
}
 
static void print_sep() {
    std::cout<<CYAN<<"  "<<std::string(58,'=')<<RESET<<"\n";
}
 
static void print_header(const std::string& title) {
    std::cout<<"\n"<<CYAN<<BOLD<<"  +"<<std::string(58,'-')<<"+\n"
             <<"  |  "<<WHITE<<std::left<<std::setw(56)<<title<<CYAN<<"|\n"
             <<"  +"<<std::string(58,'-')<<"+\n"<<RESET;
}
 
static void print_section(const std::string& title) {
    int pad=std::max(0,46-(int)title.size());
    std::cout<<"\n"<<CYAN<<BOLD<<"  -- "<<WHITE<<title<<CYAN<<" "<<std::string(pad,'-')<<RESET<<"\n";
}
 
static void print_row(const std::string& label, const std::string& val) {
    if(val.empty()||val=="null") return;
    std::cout<<CYAN<<"  ["<<WHITE<<std::left<<std::setw(16)<<label<<CYAN<<"] "<<RESET<<sanitize(val)<<"\n";
}
 
// top-1000 default ports
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
 
// ================================================================
//  1. PORT SCAN
// ================================================================

// forward declaration for os guess
static std::string guess_os_from_ports(const std::vector<int>& open);

// prioritize common ports
static int service_priority(int port) {
    if (port == 80 || port == 443 || port == 22 || port == 445 || port == 3389 || port == 8080) return 100;
    if (port == 21 || port == 25 || port == 53 || port == 110 || port == 143 || port == 3306 || port == 5432) return 50;
    return 10;
}

// extract version from raw banner
static std::string extract_version(const std::string& banner_raw, int port) {
    if (banner_raw.empty()) return "";
    std::regex re(R"(([A-Za-z0-9_\-]+[/\-][\d\.]+))");
    std::smatch m;
    if (std::regex_search(banner_raw, m, re)) {
        return m[1].str();
    }
    if (port == 22 && banner_raw.find("SSH-") == 0) return banner_raw;
    return "";
}

// quick vuln hints based on port + version + banner
// not a real vuln scanner, just flags the obvious stuff
struct VulnHint {
    std::string cve;
    std::string desc;
    std::string severity; // CRIT, HIGH, MED, INFO
};

static std::vector<VulnHint> check_vulns(int port, const std::string& version_str,
                                          const std::string& bnr)
{
    std::vector<VulnHint> vulns;
    std::string bl = bnr;
    std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
    std::string vl = version_str;
    std::transform(vl.begin(), vl.end(), vl.begin(), ::tolower);

    // SSH
    if (port == 22 && vl.find("openssh") != std::string::npos) {
        std::regex re_ver("openssh[_\\s]([0-9]+)\\.([0-9]+)");
        std::smatch m;
        if (std::regex_search(vl, m, re_ver)) {
            int maj = std::stoi(m[1].str());
            int mn  = std::stoi(m[2].str());
            if (maj < 9 || (maj == 9 && mn < 8))
                vulns.push_back({"CVE-2024-6387", "regreSSHion - signal handler race", "CRIT"});
            if (maj < 9 || (maj == 9 && mn < 3))
                vulns.push_back({"CVE-2023-38408", "agent forwarding RCE", "HIGH"});
            if (maj < 8 || (maj == 8 && mn < 5))
                vulns.push_back({"CVE-2021-41617", "privilege escalation", "MED"});
        }
    }

    // FTP
    if (port == 21) {
        if (bl.find("anonymous") != std::string::npos || bl.find("anon") != std::string::npos)
            vulns.push_back({"N/A", "anonymous FTP possibly allowed", "MED"});
        if (vl.find("vsftpd 2.3.4") != std::string::npos)
            vulns.push_back({"CVE-2011-2523", "vsFTPd 2.3.4 backdoor", "CRIT"});
    }

    // flag critical exposed services
    if (port == 445 || port == 139)
        vulns.push_back({"CHECK", "SMB exposed - EternalBlue/SMBGhost/PrintNightmare", "HIGH"});
    if (port == 23)
        vulns.push_back({"N/A", "telnet cleartext - credentials sniffable", "HIGH"});
    if (port == 6379) {
        if (bl.find("noauth") == std::string::npos && bl.find("denied") == std::string::npos && !bl.empty())
            vulns.push_back({"N/A", "redis possibly unauthenticated - RCE risk", "CRIT"});
    }
    if (port == 27017)
        vulns.push_back({"CHECK", "MongoDB exposed - check auth", "HIGH"});
    if (port == 2375)
        vulns.push_back({"N/A", "Docker API unencrypted - full host compromise", "CRIT"});
    if (port == 9200)
        vulns.push_back({"CHECK", "Elasticsearch exposed - check auth & data", "HIGH"});
    if (port == 3389)
        vulns.push_back({"CHECK", "RDP exposed - check BlueKeep CVE-2019-0708", "HIGH"});
    if (port == 6443)
        vulns.push_back({"CHECK", "K8s API exposed - check RBAC", "HIGH"});
    if (port == 11211)
        vulns.push_back({"CHECK", "Memcached exposed - DDoS amplification", "HIGH"});

    // check version disclosure on web ports
    if ((port == 80 || port == 443 || port == 8080 || port == 8443) && !version_str.empty())
        vulns.push_back({"INFO", "server version disclosed: " + version_str, "INFO"});

    return vulns;
}

// protocol-aware banner grab, sends proper probes per service
static std::string smart_banner(const std::string& ip, int port, int ms = 2000) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";

    timeval tv{ms / 1000, (ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, (sockaddr*)&sa, sizeof(sa));

    fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
    timeval ctv{ms / 1000, (ms % 1000) * 1000};
    if (select(fd + 1, nullptr, &wfds, nullptr, &ctv) <= 0) { close(fd); return ""; }

    // verify connect didnt error out
    int sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen);
    if (sockerr != 0) { close(fd); return ""; }

    // back to blocking
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);

    // pick a probe based on what the port expects
    std::string probe;
    switch (port) {
        case 80: case 8080: case 8888: case 8000: case 3000: case 9090:
            probe = "GET / HTTP/1.1\r\nHost: " + ip +
                    "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            break;
        case 443: case 8443: case 9443:
            probe = "GET / HTTP/1.0\r\n\r\n"; // TLS wont work raw but sometimes leaks stuff
            break;
        case 25: case 587:
            probe = "EHLO probe.local\r\n";
            break;
        case 6379:
            probe = "INFO\r\n";
            break;
        case 11211:
            probe = "version\r\n";
            break;
        default:
            break; // ssh/ftp/pop3 etc send banner on connect
    }

    if (!probe.empty())
        send(fd, probe.c_str(), probe.size(), MSG_NOSIGNAL);

    // read response in chunks, bail early if we got something
    std::string result;
    char buf[2048];
    int waited = 0;
    while (result.size() < 4096 && waited < ms) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        timeval rtv{0, 300000};
        if (select(fd + 1, &rfds, nullptr, nullptr, &rtv) > 0) {
            ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            result.append(buf, n);
        } else {
            waited += 300;
            if (!result.empty()) break; // got data, dont hang around
        }
    }
    close(fd);

    result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());

    // HTTP: strip body, only want headers
    if (port == 80 || port == 8080 || port == 8888 || port == 8000 ||
        port == 443 || port == 8443 || port == 3000 || port == 9090) {
        auto hdr_end = result.find("\n\n");
        if (hdr_end != std::string::npos) result = result.substr(0, hdr_end);
    }

    // first line only for display
    auto nl = result.find('\n');
    std::string first_line = (nl != std::string::npos) ? result.substr(0, nl) : result;
    if (first_line.size() > 80) first_line = first_line.substr(0, 80) + "...";

    return sanitize(first_line);
}

// measure RTT to target and tune scan params accordingly
struct AdaptiveConfig {
    int connect_ms;
    int banner_ms;
    int retry_count;
    int pool_size;
    int median_rtt;
};

static AdaptiveConfig calibrate_target(const std::string& ip) {
    AdaptiveConfig cfg;
    std::vector<int> rtts;
    int cal_ports[] = {80, 443, 22, 8080, 53};

    for (int p : cal_ports) {
        auto t0 = std::chrono::high_resolution_clock::now();
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(p);
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        fcntl(fd, F_SETFL, O_NONBLOCK);
        connect(fd, (sockaddr*)&sa, sizeof(sa));
        fd_set fds; FD_ZERO(&fds); FD_SET(fd, &fds);
        timeval tv{0, 800000};
        int r = select(fd + 1, nullptr, &fds, nullptr, &tv);
        auto t1 = std::chrono::high_resolution_clock::now();
        close(fd);
        if (r > 0) {
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
            rtts.push_back(ms);
        }
    }

    if (rtts.empty()) {
        // cant reach anything, go conservative
        cfg.connect_ms = 1500;
        cfg.banner_ms = 3000;
        cfg.retry_count = 2;
        cfg.pool_size = 50;
        cfg.median_rtt = -1;
        return cfg;
    }

    std::sort(rtts.begin(), rtts.end());
    cfg.median_rtt = rtts[rtts.size() / 2];

    // 3x median, clamped
    cfg.connect_ms = std::max(200, std::min(3000, cfg.median_rtt * 3));
    cfg.banner_ms  = std::max(500, std::min(5000, cfg.median_rtt * 5));
    cfg.retry_count = (cfg.median_rtt < 50) ? 1 : 2;

    // fast = more threads
    if (cfg.median_rtt < 20)       cfg.pool_size = 300;
    else if (cfg.median_rtt < 100) cfg.pool_size = 150;
    else                           cfg.pool_size = 60;

    return cfg;
}

// connect with retry, distinguishes open / closed / filtered
// returns {latency_ms, is_filtered}  -- latency < 0 means not open
static std::pair<int, bool> probe_with_retry(const std::string& ip, int port,
                                              int timeout_ms, int retries)
{
    for (int attempt = 0; attempt <= retries; attempt++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return {-1, false};

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        fcntl(fd, F_SETFL, O_NONBLOCK);

        auto t0 = std::chrono::high_resolution_clock::now();
        int cr = connect(fd, (sockaddr*)&sa, sizeof(sa));

        // instant connect (localhost etc)
        if (cr == 0) {
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - t0).count();
            close(fd);
            return {std::max(1, ms), false};
        }

        if (errno != EINPROGRESS) {
            close(fd);
            return {-1, false}; // RST -> closed
        }

        fd_set wfds, efds;
        FD_ZERO(&wfds); FD_SET(fd, &wfds);
        FD_ZERO(&efds); FD_SET(fd, &efds);
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        int sel = select(fd + 1, nullptr, &wfds, &efds, &tv);

        if (sel > 0 && FD_ISSET(fd, &wfds)) {
            int sockerr = 0;
            socklen_t errlen = sizeof(sockerr);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen);
            int ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - t0).count();
            close(fd);
            if (sockerr == 0) return {std::max(1, ms), false}; // open
            return {-1, false}; // refused
        }

        close(fd);

        // sel == 0 -> timeout, likely filtered
        if (sel == 0) {
            if (attempt == retries) return {-1, true}; // all attempts timed out
            usleep(50000);
            continue;
        }

        // sel < 0 -> select error, bail
        return {-1, false};
    }
    return {-1, true};
}

// severity ordering for vuln sort
static int sev_rank(const std::string& s) {
    if (s == "CRIT") return 0;
    if (s == "HIGH") return 1;
    if (s == "MED")  return 2;
    return 3;
}

// ================================================================
//  port_scan -- main scan entry
// ================================================================
static void port_scan(const std::string& ip, int start, int end_port) {
    print_header("PORT SCAN // " + ip);

    std::vector<int> ports;
    if (start == 0 && end_port == 0) {
        ports = TOP1000;
        std::cout << YELLOW << "  mode: top-1000 ports\n" << RESET;
    } else {
        for (int p = start; p <= end_port; p++) ports.push_back(p);
        std::cout << YELLOW << "  range: " << start << "-" << end_port
                  << " (" << ports.size() << " ports)\n" << RESET;
    }

    // -- calibration --
    print_section("PHASE 0 // CALIBRATION");
    std::cout << YELLOW << "  measuring target latency...\n" << RESET;

    auto cfg = calibrate_target(ip);
    std::cout << GREEN << "  rtt: "
              << (cfg.median_rtt >= 0 ? std::to_string(cfg.median_rtt) + "ms" : "n/a")
              << "  timeout: " << cfg.connect_ms << "ms"
              << "  retries: " << cfg.retry_count
              << "  threads: " << cfg.pool_size << "\n" << RESET;

    std::string hostname = ptr_lookup(ip);
    if (!hostname.empty() && hostname != ip)
        std::cout << CYAN << "  ptr: " << hostname << "\n" << RESET;

    // -- discovery sweep --
    print_section("PHASE 1 // DISCOVERY");
    std::cout << YELLOW << "  sweeping " << ports.size() << " ports...\n" << RESET;

    struct QuickHit { int port; int latency_ms; };
    std::vector<QuickHit> open_hits;
    std::vector<int> filtered_ports;
    std::mutex mx;
    std::atomic<int> done_c{0}, open_c{0}, filt_c{0};
    int total = ports.size();

    // important ports first
    std::vector<int> sorted_ports = ports;
    std::sort(sorted_ports.begin(), sorted_ports.end(), [](int a, int b) {
        return service_priority(a) > service_priority(b);
    });

    auto scan_start = std::chrono::steady_clock::now();
    {
        int psz = std::min(cfg.pool_size, (int)sorted_ports.size());
        ThreadPool pool(psz);
        std::vector<std::future<void>> futs;
        futs.reserve(total);

        for (int i = 0; i < total; i++) {
            futs.push_back(pool.submit([&, i] {
                int p = sorted_ports[i];
                auto [lat, filtered] = probe_with_retry(ip, p, cfg.connect_ms, cfg.retry_count);
                done_c++;

                if (lat > 0) {
                    std::lock_guard<std::mutex> lk(mx);
                    open_hits.push_back({p, lat});
                    open_c++;
                } else if (filtered) {
                    std::lock_guard<std::mutex> lk(mx);
                    filtered_ports.push_back(p);
                    filt_c++;
                }

                if (done_c % 50 == 0 || done_c == total) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(done_c, total,
                        std::to_string(open_c.load()) + " open " +
                        std::to_string(filt_c.load()) + " filt");
                }
            }));
        }
        for (auto& f : futs) f.get();
    }

    auto scan_end = std::chrono::steady_clock::now();
    double scan_secs = std::chrono::duration<double>(scan_end - scan_start).count();

    draw_progress(total, total,
        std::to_string(open_c.load()) + " open " + std::to_string(filt_c.load()) + " filt");
    std::cout << "\n";
    std::cout << GRAY << "  discovery: " << std::fixed << std::setprecision(2)
              << scan_secs << "s (" << (int)(total / std::max(scan_secs, 0.01)) << " ports/sec)\n" << RESET;

    std::sort(open_hits.begin(), open_hits.end(),
              [](const QuickHit& a, const QuickHit& b) { return a.port < b.port; });

    if (open_hits.empty()) {
        std::cout << "\n" << YELLOW << "  no open ports found\n" << RESET;
        if (!filtered_ports.empty()) {
            std::sort(filtered_ports.begin(), filtered_ports.end());
            std::cout << GRAY << "  " << filtered_ports.size()
                      << " filtered (fw silently drops)\n" << RESET;
            std::cout << GRAY << "  sample: ";
            for (int i = 0; i < std::min(10, (int)filtered_ports.size()); i++)
                std::cout << filtered_ports[i] << " ";
            if ((int)filtered_ports.size() > 10) std::cout << "...";
            std::cout << "\n" << RESET;
        }
        LOG_INFO("port_scan", "done target=" + ip + " open=0 filtered=" +
                 std::to_string(filtered_ports.size()));
        return;
    }

    // -- deep analysis: banners, versions, vulns --
    print_section("PHASE 2 // DEEP ANALYSIS");
    std::cout << YELLOW << "  analyzing " << open_hits.size() << " open ports...\n" << RESET;

    struct PortResult {
        int port;
        int latency_ms;
        std::string service;
        std::string banner_raw;
        std::string version;
        std::string risk;
        std::vector<VulnHint> vulns;
    };

    std::vector<PortResult> results(open_hits.size());
    std::atomic<int> deep_done{0};
    int deep_total = open_hits.size();

    // fewer threads here, banner grabs are slower and we dont want to flood
    {
        int dpool = std::min(30, deep_total);
        ThreadPool deep_pool(dpool);
        std::vector<std::future<void>> dfuts;
        dfuts.reserve(deep_total);

        for (int i = 0; i < deep_total; i++) {
            dfuts.push_back(deep_pool.submit([&, i] {
                int p = open_hits[i].port;
                PortResult pr;
                pr.port = p;
                pr.latency_ms = open_hits[i].latency_ms;
                pr.service = svc(p);
                pr.risk = risk_label(p);
                pr.banner_raw = smart_banner(ip, p, cfg.banner_ms);
                pr.version = extract_version(pr.banner_raw, p);
                pr.vulns = check_vulns(p, pr.version, pr.banner_raw);
                results[i] = pr;
                deep_done++;

                if (deep_done % 3 == 0 || deep_done == deep_total) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(deep_done, deep_total, "banners...");
                }
            }));
        }
        for (auto& f : dfuts) f.get();
    }

    draw_progress(deep_total, deep_total, "done");
    std::cout << "\n";

    // -- results table --
    print_section("PHASE 3 // RESULTS");

    std::cout << "\n" << BOLD << WHITE
              << "  PORT      SERVICE         VERSION                  LATENCY   RISK      BANNER\n"
              << "  " << std::string(100, '-') << "\n" << RESET;

    int vuln_crit = 0, vuln_high = 0, vuln_med = 0, vuln_info = 0;
    std::vector<VulnHint> all_vulns;
    std::vector<int> open_port_list;

    for (auto& pr : results) {
        open_port_list.push_back(pr.port);

        std::cout << GREEN << "  " << std::left << std::setw(10) << pr.port
                  << WHITE << std::setw(16) << pr.service
                  << CYAN  << std::setw(25) << (pr.version.empty() ? "-" : pr.version)
                  << YELLOW << std::setw(10) << (std::to_string(pr.latency_ms) + "ms")
                  << std::setw(10) << pr.risk;

        std::string dbnr = pr.banner_raw;
        if (dbnr.size() > 45) dbnr = dbnr.substr(0, 45) + "...";
        std::cout << GRAY << dbnr << RESET << "\n";

        for (auto& v : pr.vulns) {
            all_vulns.push_back(v);
            if      (v.severity == "CRIT") vuln_crit++;
            else if (v.severity == "HIGH") vuln_high++;
            else if (v.severity == "MED")  vuln_med++;
            else                           vuln_info++;
        }

        g_result.open_ports.push_back({pr.port, pr.service});
    }

    // filtered summary
    if (!filtered_ports.empty()) {
        std::sort(filtered_ports.begin(), filtered_ports.end());
        std::cout << "\n" << GRAY << "  " << filtered_ports.size() << " filtered: ";
        for (int i = 0; i < std::min(15, (int)filtered_ports.size()); i++)
            std::cout << filtered_ports[i] << " ";
        if ((int)filtered_ports.size() > 15) std::cout << "...";
        std::cout << "\n" << RESET;
    }

    // -- vuln report --
    if (!all_vulns.empty()) {
        print_section("VULNERABILITY HINTS");
        std::cout << "\n";

        // sort by severity: crit first
        std::sort(all_vulns.begin(), all_vulns.end(), [](const VulnHint& a, const VulnHint& b) {
            return sev_rank(a.severity) < sev_rank(b.severity);
        });

        for (auto& v : all_vulns) {
            const char* color = WHITE;
            if      (v.severity == "CRIT") color = RED;
            else if (v.severity == "HIGH") color = YELLOW;
            else if (v.severity == "MED")  color = CYAN;
            else                           color = GRAY;

            std::cout << "  " << color << BOLD << "[" << std::setw(4) << v.severity << "] "
                      << RESET << color << std::setw(16) << v.cve << "  " << v.desc
                      << RESET << "\n";
        }

        // vuln score bar
        std::cout << "\n" << CYAN << "  vuln summary: "
                  << RED   << vuln_crit << " crit  "
                  << YELLOW << vuln_high << " high  "
                  << CYAN   << vuln_med  << " med  "
                  << GRAY   << vuln_info << " info"
                  << RESET << "\n";

        if (vuln_crit > 0)
            std::cout << RED << BOLD << "\n  [!] CRITICAL issues found - immediate attention needed\n" << RESET;
        else if (vuln_high > 0)
            std::cout << YELLOW << "\n  [!] high severity issues - review recommended\n" << RESET;
    }

    // -- OS guess from open ports --
    std::string os_hint = guess_os_from_ports(open_port_list);
    if (os_hint != "unknown") {
        std::cout << "\n" << CYAN << "  os hint (ports): " << WHITE << os_hint << RESET << "\n";
        g_result.os_guess = os_hint;
    }

    // -- final stats --
    print_section("SCAN STATS");
    auto total_time = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - scan_start).count();

    std::cout << CYAN  << "  [target]       " << WHITE << ip << "\n" << RESET;
    std::cout << CYAN  << "  [ports tested] " << WHITE << total << "\n" << RESET;
    std::cout << GREEN << "  [open]         " << WHITE << open_hits.size() << "\n" << RESET;
    std::cout << GRAY  << "  [filtered]     " << WHITE << filtered_ports.size() << "\n" << RESET;
    std::cout << CYAN  << "  [closed]       " << WHITE
              << (total - (int)open_hits.size() - (int)filtered_ports.size()) << "\n" << RESET;
    std::cout << CYAN  << "  [total time]   " << WHITE << std::fixed << std::setprecision(2)
              << total_time << "s\n" << RESET;
    std::cout << CYAN  << "  [avg speed]    " << WHITE
              << (int)(total / std::max(total_time, 0.01)) << " ports/sec\n" << RESET;

    LOG_INFO("port_scan", "done target=" + ip +
             " open=" + std::to_string(open_hits.size()) +
             " filtered=" + std::to_string(filtered_ports.size()) +
             " time=" + std::to_string((int)total_time) + "s");
}

// ================================================================
//  2. NETWORK SCAN -- two-phase: discovery then port scan
// ================================================================
 
static std::string guess_os_from_ports(const std::vector<int>& open) {
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
 
static void net_scan(const std::string& subnet) {
    print_header("NETWORK SCAN // " + subnet + ".0/24");
 
    static const std::vector<int> PROBE_PORTS={21,22,23,25,80,443,445,3389,8080,5985};
 
    std::cout<<YELLOW<<"  phase 1: host discovery...\n"<<RESET;
 
    struct HostInfo { std::string ip, hostname, os; std::vector<std::pair<int,std::string>> ports; bool alive=false; };
    std::vector<HostInfo> hosts(254);
    std::atomic<int> cur(0), alive_c(0);
 
    ThreadPool pool(100);
    std::vector<std::future<void>> futs;
    futs.reserve(254);
 
    for(int i=1;i<=254;i++){
        futs.push_back(pool.submit([&,i]{
            std::string ip=subnet+"."+std::to_string(i);
            HostInfo& h=hosts[i-1]; h.ip=ip;
 
            // icmp ping
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
            std::cout<<GREEN<<"  [+] "<<std::left<<std::setw(16)<<ip;
            if(!h.hostname.empty()) std::cout<<CYAN<<" ("<<h.hostname<<")";
            std::cout<<RESET<<"\n";
        }));
    }
    for(auto& f:futs) f.get();
 
    std::cout<<CYAN<<"\n  found "<<alive_c<<" hosts -- phase 2: port scan...\n\n"<<RESET;
 
    // phase 2: port scan alive hosts
    std::vector<HostInfo*> alive_hosts;
    for(auto& h:hosts) if(h.alive) alive_hosts.push_back(&h);
 
    std::atomic<int> task(0);
    int ntasks=alive_hosts.size()*PROBE_PORTS.size();
    std::vector<std::future<void>> futs2; futs2.reserve(ntasks);
 
    for(int i=0;i<(int)alive_hosts.size();i++){
        for(int p:PROBE_PORTS){
            futs2.push_back(pool.submit([&,i,p]{
                if(!tcp_probe(alive_hosts[i]->ip,p,400)) return;
                std::string b=banner(alive_hosts[i]->ip,p,1000);
                std::lock_guard<std::mutex> lk(g_print_mtx);
                alive_hosts[i]->ports.emplace_back(p,b);
            }));
        }
    }
    for(auto& f:futs2) f.get();
 
    // output
    std::cout<<YELLOW<<"  results:\n\n"<<RESET;
    int total_open=0;
    for(auto* h:alive_hosts){
        std::sort(h->ports.begin(),h->ports.end());
        std::vector<int> op; for(auto& [p,_]:h->ports) op.push_back(p);
        h->os=guess_os_from_ports(op);
 
        std::cout<<GREEN<<"  ┌─ "<<std::left<<std::setw(16)<<h->ip;
        if(!h->hostname.empty()) std::cout<<CYAN<<" ["<<h->hostname<<"]";
        std::cout<<YELLOW<<"  os: "<<h->os<<RESET<<"\n";
 
        if(h->ports.empty()) std::cout<<GRAY<<"  │  no open ports\n"<<RESET;
        for(auto& [p,b]:h->ports){
            std::cout<<CYAN<<"  │  "<<std::setw(6)<<p<<GREEN<<" "<<std::setw(18)<<svc(p);
            if(!b.empty()) std::cout<<GRAY<<"  "<<b;
            std::cout<<RESET<<"\n";
            total_open++;
        }
        std::cout<<GREEN<<"  └"<<std::string(36,'-')<<RESET<<"\n";
    }
 
    std::cout<<"\n"<<YELLOW<<"  hosts alive: "<<alive_c<<"  open ports: "<<total_open<<"\n"<<RESET;
    LOG_INFO("net_scan","done subnet="+subnet+" alive="+std::to_string(alive_c));
}
 
// ================================================================
//  3. OS DETECTION -- weighted port fingerprint + TTL analysis
// ================================================================
static void os_detect(const std::string& ip) {
    print_header("ADVANCED OS DETECTION // " + ip);
 
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
 
    // scan all ports in parallel
    struct Result { int port; std::string name, cat, bnr; bool open; int w[4]; };
    std::vector<Result> results(checks.size());
    std::mutex mx;
    ThreadPool pool(checks.size());
    std::vector<std::future<void>> futs; futs.reserve(checks.size());
 
    for(int i=0;i<(int)checks.size();i++){
        futs.push_back(pool.submit([&,i]{
            const auto& c=checks[i];
            bool ok=tcp_probe(ip,c.port,800);
            std::string b; if(ok) b=banner(ip,c.port);
            results[i]={c.port,c.name,c.cat,b,ok,{c.w_win,c.w_lin,c.w_bsd,c.w_net}};
        }));
    }
    for(auto& f:futs) f.get();
    std::sort(results.begin(),results.end(),[](auto& a,auto& b){return a.port<b.port;});
 
    // weighted score
    int score[4]={0,0,0,0};
    std::map<std::string,int> cat_open;
    int open_c=0;
 
    std::cout<<"\n"<<BOLD<<WHITE<<"  PORT FINGERPRINT:\n"<<RESET;
    for(auto& r:results){
        std::cout<<CYAN<<"  ["<<std::left<<std::setw(5)<<r.port<<" "<<std::setw(12)<<r.name<<" "<<std::setw(8)<<r.cat<<"] ";
        if(r.open){
            std::cout<<GREEN<<"OPEN  "<<RESET;
            if(!r.bnr.empty()) std::cout<<GRAY<<r.bnr.substr(0,60);
            std::cout<<RESET;
            for(int j=0;j<4;j++) score[j]+=r.w[j];
            cat_open[r.cat]++;
            open_c++;
        } else {
            std::cout<<RED<<"closed"<<RESET;
        }
        std::cout<<"\n";
    }
    std::cout<<CYAN<<"  open: "<<RESET<<open_c<<"/"<<checks.size()<<"\n";
 
    // TTL analysis (5 pings for stability)
    print_section("TTL ANALYSIS");
    auto pout=safe_exec({"ping","-c5","-W1",ip},8);
    std::vector<int> ttls;
    size_t sp=0;
    while(true){
        auto tp=pout.find("ttl=",sp); if(tp==std::string::npos) tp=pout.find("TTL=",sp); if(tp==std::string::npos) break;
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
 
    std::cout<<CYAN<<"  [ttl]          "<<RESET<<(ttl?std::to_string(ttl):"n/a")<<"\n";
    std::cout<<CYAN<<"  [initial_ttl]  "<<RESET<<(init_ttl?std::to_string(init_ttl):"n/a")<<"\n";
    std::cout<<CYAN<<"  [hops]         "<<RESET<<(hops?std::to_string(hops):"n/a")<<"\n";
    std::cout<<CYAN<<"  [stable]       "<<RESET<<(stable?"yes":YELLOW " NO -- load balancer/multipath" RESET)<<"\n";
   
 // banner deep analysis
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
    for(auto& r:results){
        if(!r.open||r.bnr.empty()) continue;
        std::string bl=r.bnr;
        std::transform(bl.begin(),bl.end(),bl.begin(),::tolower);
        for(auto& h:hints){
            std::string kl=h.kw;
            std::transform(kl.begin(),kl.end(),kl.begin(),::tolower);
            if(bl.find(kl)!=std::string::npos){
                os_hints_found.insert(h.os);
                std::cout<<CYAN<<"  [port "<<r.port<<"] "<<GREEN<<h.detail<<RESET<<"\n";
            }
        }
    }
 
    // final verdict
    print_section("VERDICT");
    static const char* os_names[4]={"Windows","Linux/Unix","BSD/macOS","Network Device"};
    int best=0;
    for(int i=1;i<4;i++) if(score[i]>score[best]) best=i;
 
    // ttl-based boost
    if(ttl>=120&&ttl<=128) score[0]+=5;
    else if(ttl>=60&&ttl<=64) score[1]+=5;
    else if(ttl>=250) score[3]+=5;
 
    std::string verdict=os_names[best];
    if(!os_hints_found.empty()) verdict=*os_hints_found.begin();
 
    std::cout<<CYAN<<"  [os]       "<<YELLOW<<BOLD<<verdict<<RESET<<"\n";
    std::cout<<CYAN<<"  [scores]   "<<RESET;
    for(int i=0;i<4;i++) std::cout<<os_names[i]<<":"<<score[i]<<" ";
    std::cout<<"\n";
 
    g_result.os_guess=verdict;
    LOG_INFO("os_detect","target="+ip+" verdict="+verdict);
}
 
// ================================================================
//  4. IP FULL INTELLIGENCE
// ================================================================
static void ip_intel(const std::string& ip) {
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
            auto proxy=g("proxy"),hosting=g("hosting"),mobile=g("mobile");
            std::cout<<CYAN<<"  [proxy/vpn]    "<<(proxy=="true"?RED "YES  detected":GREEN "no")<<RESET<<"\n";
            std::cout<<CYAN<<"  [hosting/dc]   "<<(hosting=="true"?YELLOW "yes - datacenter":GREEN "no - residential")<<RESET<<"\n";
            std::cout<<CYAN<<"  [mobile]       "<<RESET<<(mobile=="true"?"yes":"no")<<"\n";
            g_result.geo_country=g("country"); g_result.geo_city=g("city");
            g_result.geo_isp=g("isp"); g_result.geo_as=g("as");
            g_result.proxy=proxy=="true"; g_result.hosting=hosting=="true";
            auto lat=g("lat"),lon=g("lon");
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
                if(col!=std::string::npos) std::cout<<CYAN<<"  ["<<std::left<<std::setw(8)<<line.substr(0,col)<<"] "<<RESET<<sanitize(line.substr(col+1))<<"\n";
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
            std::string ll=line; std::transform(ll.begin(),ll.end(),ll.begin(),::tolower);
            for(auto& w:want){
                std::string wl=w; std::transform(wl.begin(),wl.end(),wl.begin(),::tolower);
                if(ll.find(wl)!=std::string::npos){
                    auto col=line.find(':');
                    if(col!=std::string::npos) std::cout<<CYAN<<"  ["<<std::left<<std::setw(16)<<line.substr(0,col)<<"] "<<YELLOW<<sanitize(line.substr(col+1))<<RESET<<"\n";
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
        if(!tcp_probe(ip,p,600)) continue; any=true;
        std::string b=banner(ip,p), s=svc(p);
        std::cout<<GREEN<<"  "<<std::left<<std::setw(12)<<p<<WHITE<<std::setw(16)<<s<<std::setw(10)<<risk_label(p)<<GRAY<<(b.size()>40?b.substr(0,40):b)<<RESET<<"\n";
        g_result.open_ports.push_back({p,s});
    }
    if(!any) std::cout<<GRAY<<"  top ports closed\n"<<RESET;
 
    if(tcp_probe(ip,443,500)){
        print_section("SSL CERTIFICATE");
        auto cert=safe_exec({"sh","-c","echo Q | openssl s_client -connect "+ip+":443 -servername "+ip+" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null"},10);
        if(cert.empty()) std::cout<<GRAY<<"  could not fetch cert\n"<<RESET;
        else{ std::istringstream ss(cert); std::string l; while(std::getline(ss,l)) std::cout<<CYAN<<"  "<<sanitize(l)<<RESET<<"\n"; }
    }
    LOG_INFO("ip_intel","done target="+ip);
}
 
// ================================================================
//  5. DNS LOOKUP -- parallel async queries + SPF + DNSSEC
// ================================================================
 
static std::vector<std::string> split_lines(const std::string& s){
    std::vector<std::string> v; std::istringstream ss(s); std::string l;
    while(std::getline(ss,l)) if(!l.empty()) v.push_back(l);
    return v;
}
 
static std::string dig_short(const std::string& domain, const std::string& type, int t=6){
    return safe_exec({"dig","+short","+time=4","+tries=2",domain,type},t);
}
static std::string dig_full(const std::string& domain, const std::string& type, int t=6){
    return safe_exec({"dig","+noall","+answer","+time=4","+tries=2",domain,type},t);
}
 
static void dns_lookup(const std::string& domain){
    print_header("DNS LOOKUP // " + domain);
 
    // A + AAAA + PTR in parallel
    std::cout<<YELLOW<<"\n  -- A / AAAA / PTR --\n"<<RESET;
    auto fut_a    = std::async(std::launch::async, dig_short, domain, "A",    6);
    auto fut_aaaa = std::async(std::launch::async, dig_short, domain, "AAAA", 6);
    auto a_ips    = split_lines(fut_a.get());
    auto aaaa_ips = split_lines(fut_aaaa.get());
 
    for(auto& ip:a_ips){
        std::string ptr=ptr_lookup(ip);
        std::cout<<GREEN<<"  [A]    "<<std::left<<std::setw(18)<<sanitize(ip);
        if(!ptr.empty()) std::cout<<CYAN<<"  PTR -> "<<sanitize(ptr);
        std::cout<<RESET<<"\n";
    }
    for(auto& ip:aaaa_ips) std::cout<<GREEN<<"  [AAAA] "<<sanitize(ip)<<RESET<<"\n";
    if(a_ips.empty()&&aaaa_ips.empty()) std::cout<<GRAY<<"  no A/AAAA records\n"<<RESET;
 
    // all record types in parallel
    std::vector<std::string> types={"MX","NS","TXT","CNAME","SOA","CAA","SRV"};
    auto fetch=[&](const std::string& t)->std::pair<std::string,std::string>{
        return {t, dig_full(domain, t)};
    };
    std::vector<std::future<std::pair<std::string,std::string>>> futs;
    futs.reserve(types.size());
    for(auto& t:types) futs.push_back(std::async(std::launch::async,fetch,t));
 
    std::cout<<YELLOW<<"\n  -- Records --\n"<<RESET;
    for(auto& f:futs){
        auto [t,out]=f.get();
        std::cout<<"\n"<<YELLOW<<"  ["<<t<<"]:\n"<<RESET;
        if(out.empty()) std::cout<<GRAY<<"  none\n"<<RESET;
        else std::cout<<CYAN<<sanitize(out)<<RESET;
    }
 
    // SPF analysis
    std::cout<<YELLOW<<"\n  -- SPF --\n"<<RESET;
    auto txt=dig_short(domain,"TXT",6);
    bool spf_found=false;
    for(auto& line:split_lines(txt)){
        if(line.find("v=spf1")!=std::string::npos){
            std::cout<<GREEN<<"  [SPF] "<<sanitize(line)<<RESET<<"\n";
            spf_found=true;
            // expand include: chains
            std::regex re_inc(R"(include:(\S+)|redirect=(\S+))");
            std::smatch m; std::string s=line;
            while(std::regex_search(s,m,re_inc)){
                std::string inc=m[1].matched?m[1].str():m[2].str();
                std::cout<<CYAN<<"    -> "<<sanitize(inc)<<RESET<<"\n";
                auto sub=dig_short(inc,"TXT",5);
                if(!sub.empty()) std::cout<<GRAY<<"    "<<sanitize(sub)<<RESET<<"\n";
                s=m.suffix();
            }
        }
    }
    if(!spf_found) std::cout<<RED<<"  [!] no SPF -- email spoofing may be possible\n"<<RESET;
 
    // DMARC
    std::cout<<YELLOW<<"\n  -- DMARC --\n"<<RESET;
    auto dmarc=dig_full("_dmarc."+domain,"TXT",5);
    if(dmarc.empty()) std::cout<<YELLOW<<"  [-] no DMARC\n"<<RESET;
    else std::cout<<GREEN<<sanitize(dmarc)<<RESET;
 
    // DNSSEC
    std::cout<<YELLOW<<"\n  -- DNSSEC --\n"<<RESET;
    auto ds=dig_short(domain,"DS",5);
    auto dnskey=dig_short(domain,"DNSKEY",5);
    if(!ds.empty()||!dnskey.empty()) std::cout<<GREEN<<"  [+] DNSSEC enabled\n"<<RESET;
    else std::cout<<YELLOW<<"  [-] DNSSEC not detected\n"<<RESET;
 
    // Zone transfer -- try all NS
    std::cout<<YELLOW<<"\n  -- Zone Transfer (AXFR) --\n"<<RESET;
    auto ns_raw=dig_short(domain,"NS",6);
    for(auto ns:split_lines(ns_raw)){
        while(!ns.empty()&&(ns.back()=='.'||ns.back()=='\n')) ns.pop_back();
        if(ns.empty()) continue;
        std::cout<<CYAN<<"  trying "<<sanitize(ns)<<RESET<<"\n";
        auto zt=safe_exec({"dig","axfr","@"+ns,domain},10);
        if(zt.empty()||zt.find("Transfer failed")!=std::string::npos||zt.find("REFUSED")!=std::string::npos)
            std::cout<<GREEN<<"    refused (secure)\n"<<RESET;
        else std::cout<<RED<<"  [!!!] ZONE TRANSFER SUCCEEDED on "<<sanitize(ns)<<"!\n"<<sanitize(zt)<<RESET;
    }
 
    LOG_INFO("dns_lookup","done domain="+domain);
}
 
// ================================================================
//  6. WHOIS
// ================================================================
static void whois_lookup(const std::string& target){
    print_header("WHOIS // " + target);
    std::vector<std::string> keys={"Domain","Registrar","Created","Updated","Expir","Name Server","CIDR","NetRange","OrgName","Country","RegDate","NetName","inetnum","netname","descr","origin","Email","Phone","Address"};
    auto raw=safe_exec({"whois",target},10);
    if(raw.empty()){std::cout<<RED<<"  install: sudo apt install whois\n"<<RESET;return;}
    std::istringstream ss(raw); std::string line;
    while(std::getline(ss,line)){
        if(line.empty()||line[0]=='%'||line[0]=='#') continue;
        for(auto& k:keys){
            std::string ll=line,kl=k;
            std::transform(ll.begin(),ll.end(),ll.begin(),::tolower);
            std::transform(kl.begin(),kl.end(),kl.begin(),::tolower);
            if(ll.find(kl)==std::string::npos) continue;
            auto c=line.find(':');
            if(c!=std::string::npos) std::cout<<CYAN<<"  ["<<std::left<<std::setw(16)<<line.substr(0,c)<<"] "<<YELLOW<<sanitize(line.substr(c+1))<<RESET<<"\n";
            break;
        }
    }
}
 
// ================================================================
//  7. SITE -> IP
// ================================================================
static void site_lookup(const std::string& raw){
    print_header("SITE -> IP // " + raw);
    std::string s=raw;
    for(auto& p:{"https://","http://","www."})
        if(s.size()>=strlen(p)&&s.substr(0,strlen(p))==p) s=s.substr(strlen(p));
    for(char sep:{'/',  '?','#',':'}) {auto p=s.find(sep);if(p!=std::string::npos) s=s.substr(0,p);}
    while(!s.empty()&&(s.back()==' '||s.back()==10||s.back()==13)) s.pop_back();
    if(!valid_target(s)){std::cout<<RED<<"  invalid input\n"<<RESET;return;}
    std::cout<<YELLOW<<"  resolving "<<s<<"...\n"<<RESET;
    std::string ip=resolve(s);
    if(ip.empty()){std::cout<<RED<<"  could not resolve\n"<<RESET;return;}
    std::cout<<GREEN<<"  "<<s<<" -> "<<ip<<"\n"<<RESET;
    ip_intel(ip);
}
 
// ================================================================
//  8. OSINT -- 50 platforms + web mentions
// ================================================================
static void osint_scan(const std::string& username){
    print_header("OSINT // " + username);
    struct Site{std::string name,url,dead,cat;};
    static const std::vector<Site> sites={
        {"Instagram",   "https://www.instagram.com/{}/",         "page isn't available",  "social"},
        {"TikTok",      "https://www.tiktok.com/@{}/",           "couldn't find",         "social"},
        {"Twitter/X",   "https://twitter.com/{}/",               "doesn't exist",         "social"},
        {"Reddit",      "https://www.reddit.com/user/{}/",       "page not found",        "social"},
        {"VK",          "https://vk.com/{}/",                    "not found",             "social"},
        {"Pinterest",   "https://www.pinterest.com/{}/",         "not found",             "social"},
        {"Tumblr",      "https://{}.tumblr.com/",                "not found",             "social"},
        {"Flickr",      "https://www.flickr.com/people/{}/",     "not found",             "social"},
        {"GitHub",      "https://github.com/{}/",                "not found",             "dev"},
        {"GitLab",      "https://gitlab.com/{}/",                "not found",             "dev"},
        {"Replit",      "https://replit.com/@{}/",               "not found",             "dev"},
        {"HackerOne",   "https://hackerone.com/{}/",             "not found",             "dev"},
        {"Pastebin",    "https://pastebin.com/u/{}/",            "not found",             "dev"},
        {"Bugcrowd",    "https://bugcrowd.com/{}/",              "not found",             "dev"},
        {"HackerNews",  "https://news.ycombinator.com/user?id={}","no such user",         "dev"},
        {"Steam",       "https://steamcommunity.com/id/{}/",     "error",                 "gaming"},
        {"Twitch",      "https://www.twitch.tv/{}/",             "not found",             "gaming"},
        {"Minecraft",   "https://namemc.com/profile/{}/",        "not found",             "gaming"},
        {"Roblox",      "https://www.roblox.com/user.aspx?username={}","not found",       "gaming"},
        {"Chess.com",   "https://www.chess.com/member/{}/",      "not found",             "gaming"},
        {"Telegram",    "https://t.me/{}/",                      "if you have telegram",  "msg"},
        {"Keybase",     "https://keybase.io/{}/",                "not found",             "msg"},
        {"Medium",      "https://medium.com/@{}/",               "not found",             "blog"},
        {"Dev.to",      "https://dev.to/{}/",                    "not found",             "blog"},
        {"Hashnode",    "https://hashnode.com/@{}/",             "not found",             "blog"},
        {"Substack",    "https://{}.substack.com/",              "not found",             "blog"},
        {"Spotify",     "https://open.spotify.com/user/{}/",     "not found",             "music"},
        {"SoundCloud",  "https://soundcloud.com/{}/",            "not found",             "music"},
        {"Bandcamp",    "https://{}.bandcamp.com/",              "not found",             "music"},
        {"Last.fm",     "https://www.last.fm/user/{}/",          "not found",             "music"},
        {"LinkedIn",    "https://www.linkedin.com/in/{}/",       "not found",             "other"},
        {"Gravatar",    "https://en.gravatar.com/{}/",           "not found",             "other"},
        {"Letterboxd",  "https://letterboxd.com/{}/",            "not found",             "other"},
        {"Goodreads",   "https://www.goodreads.com/user/show/{}/","not found",            "other"},
        {"Strava",      "https://www.strava.com/athletes/{}/",   "not found",             "other"},
        {"Dribbble",    "https://dribbble.com/{}/",              "not found",             "other"},
        {"Behance",     "https://www.behance.net/{}/",           "not found",             "other"},
        {"ProductHunt", "https://www.producthunt.com/@{}/",      "not found",             "other"},
        {"Trakt",       "https://trakt.tv/users/{}/",            "not found",             "other"},
        {"Wattpad",     "https://www.wattpad.com/user/{}/",      "not found",             "other"},
    };
 
    std::cout<<YELLOW<<"  checking "<<sites.size()<<" platforms...\n\n"<<RESET;
    std::vector<std::pair<std::string,std::string>> found;
    std::mutex fm;
    std::atomic<int> done_c(0);
    int total=sites.size();
 
    ThreadPool pool(sites.size());
    std::vector<std::future<void>> futs; futs.reserve(total);
 
    for(auto& s:sites){
        futs.push_back(pool.submit([&,s]{
            std::string url=s.url;
            auto pos=url.find("{}"); if(pos!=std::string::npos) url.replace(pos,2,username);
            std::string body=safe_curl(url,6);
            std::string bl=body; std::transform(bl.begin(),bl.end(),bl.begin(),::tolower);
            bool hit=!body.empty()&&bl.find(s.dead)==std::string::npos;
            done_c++;
            std::lock_guard<std::mutex> lk(g_print_mtx);
            if(hit){
                std::cout<<"\r"<<GREEN<<"  [+] "<<std::left<<std::setw(14)<<s.name<<GRAY<<"["<<s.cat<<"]  "<<CYAN<<url<<"\n"<<RESET;
                std::lock_guard<std::mutex> fl(fm); found.push_back({s.name,url});
                g_result.osint_hits.push_back(url);
            } else {
                std::cout<<"\r"<<RED<<"  [-] "<<std::left<<std::setw(14)<<s.name<<GRAY<<"["<<s.cat<<"]"<<RESET<<"\n";
            }
            draw_progress(done_c,total,std::to_string(found.size())+" found");
        }));
    }
    for(auto& f:futs) f.get();
 
    std::cout<<"\n"<<CYAN<<"\n  found "<<found.size()<<"/"<<sites.size()<<" accounts\n"<<RESET;
 
    // web mentions
    print_section("WEB MENTIONS");
    std::cout<<YELLOW<<"  searching...\n"<<RESET;
    auto ddg=safe_curl("https://html.duckduckgo.com/html/?q=%22"+username+"%22",10);
    if(!ddg.empty()){
        std::string marker="href=\""; size_t p=0; int cnt=0;
        while((p=ddg.find(marker,p))!=std::string::npos&&cnt<8){
            p+=marker.size(); auto end=ddg.find('"',p); if(end==std::string::npos) break;
            std::string url=ddg.substr(p,end-p);
            if(url.find("http")==0&&url.find("duckduckgo")==std::string::npos){
                std::cout<<CYAN<<"  "<<sanitize(url)<<"\n"<<RESET; cnt++;
            }
            p=end;
        }
        if(cnt==0) std::cout<<GRAY<<"  no public mentions\n"<<RESET;
    }
    LOG_INFO("osint","done username="+username+" found="+std::to_string(found.size()));
}
 
// ================================================================
//  9. TRACEROUTE 
// ================================================================
// All tuneable parameters live here — change these instead of
// hunting through the code if you need to adjust behavior.
struct TraceConfig {
    std::string target;
    int max_hops        = 40;
    int queries_per_hop = 5;   // more probes = better loss/jitter stats, but slower
    int timeout_ms      = 2000;
    int parallel_hops   = 8;   // how many TTL levels we probe simultaneously
    int src_port        = 33434;
    int dst_port        = 33434; // standard traceroute UDP base port
    bool resolve_dns    = true;
    bool detect_mtu     = true;
    bool show_jitter    = true;
    bool show_loss      = true;
    bool as_lookup      = true;
    enum Protocol { ICMP, UDP, TCP_SYN } protocol = ICMP;
};
 
// Holds the raw result of a single packet sent to one hop.
// rtt_ms < 0 means the probe timed out — no response came back.
struct ProbeResult {
    int ttl              = 0;
    int probe_id         = 0;
    std::string addr;
    std::string hostname;
    double rtt_ms        = -1.0;   // <0 = timeout
    bool reached_target  = false;
    int icmp_type        = -1;
    int icmp_code        = -1;
    int reply_ttl        = 0;
    int mtu_suggestion   = 0;      // populated when we get ICMP frag-needed
};
 
// Aggregated statistics for a single hop after all probes are done.
// compute() does the math — call it once after filling rtts[].
struct HopStats {
    int ttl = 0;
    std::string addr;
    std::string hostname;
    std::string asn_info;
    std::vector<double> rtts;  // only successful probe RTTs go in here
    int sent    = 0;
    int received = 0;
    double min_rtt = 0, max_rtt = 0, avg_rtt = 0, stddev = 0, jitter = 0;
    double loss_pct = 0;
    int mtu = 0;
    bool is_target = false;
 
    void compute() {
        if (rtts.empty()) { loss_pct = 100.0; return; }
        std::sort(rtts.begin(), rtts.end());
        min_rtt = rtts.front();
        max_rtt = rtts.back();
        avg_rtt = std::accumulate(rtts.begin(), rtts.end(), 0.0) / rtts.size();
        double var = 0;
        for (auto r : rtts) var += (r - avg_rtt) * (r - avg_rtt);
        stddev = std::sqrt(var / rtts.size());
        // jitter = mean absolute deviation between consecutive samples,
        // same formula VoIP equipment typically uses
        if (rtts.size() > 1) {
            double j = 0;
            for (size_t i = 1; i < rtts.size(); i++)
                j += std::abs(rtts[i] - rtts[i-1]);
            jitter = j / (rtts.size() - 1);
        }
        loss_pct = 100.0 * (1.0 - (double)received / sent);
    }
};
 
// Core engine — owns no state between runs, fully reentrant.
// Each TracerouteEngine instance is tied to one config + one thread pool.
class TracerouteEngine {
public:
    explicit TracerouteEngine(const TraceConfig& cfg, ThreadPool& pool)
        : cfg_(cfg), pool_(pool) {}
 
    // Standard one's complement checksum used in ICMP headers.
    // Works on any buffer; handles odd-length payloads correctly.
    static uint16_t icmp_checksum(const void* data, int len) {
        auto p = reinterpret_cast<const uint16_t*>(data);
        uint32_t sum = 0;
        for (; len > 1; len -= 2) sum += *p++;
        if (len == 1) sum += *reinterpret_cast<const uint8_t*>(p);
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }
 
    // Resolve the configured target hostname to an IPv4 address.
    // Returns false if DNS fails or the result is not AF_INET.
    bool resolve_target(std::string& out_ip) {
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_RAW;
        if (getaddrinfo(cfg_.target.c_str(), nullptr, &hints, &res) != 0 || !res)
            return false;
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf));
        out_ip = buf;
        freeaddrinfo(res);
        return true;
    }
 
    // PTR record lookup — best effort, returns empty string on failure.
    // We don't cache results; callers should avoid calling this in a tight loop.
    static std::string reverse_dns(const std::string& ip) {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        char host[NI_MAXHOST];
        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                        host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0)
            return host;
        return "";
    }
 
    // Query Team Cymru's DNS-based ASN service to get the AS number
    // and description for an IP. Spawns dig via fork so we don't pull
    // in a DNS library dependency. Returns empty string if dig isn't
    // installed or the query times out.
    static std::string as_lookup(const std::string& ip) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return "";
        uint8_t* o = reinterpret_cast<uint8_t*>(&addr.s_addr);
        std::ostringstream query;
        // Cymru format: reverse the octets, append .origin.asn.cymru.com
        query << (int)o[3] << "." << (int)o[2] << "."
              << (int)o[1] << "." << (int)o[0] << ".origin.asn.cymru.com";
        std::string q = query.str();
        int fds[2];
        if (pipe(fds) < 0) return "";
        pid_t pid = fork();
        if (pid == 0) {
            dup2(fds[1], STDOUT_FILENO);
            close(fds[0]); close(fds[1]);
            execlp("dig", "dig", "+short", "+time=1", "+tries=1", q.c_str(), "TXT", nullptr);
            _exit(127);
        }
        close(fds[1]);
        char buf[256] = {};
        read(fds[0], buf, sizeof(buf) - 1);
        close(fds[0]);
        int st; waitpid(pid, &st, 0);
        std::string result(buf);
        // dig wraps TXT records in quotes — strip them
        result.erase(std::remove(result.begin(), result.end(), '"'), result.end());
        while (!result.empty() && (result.back() == '\n' || result.back() == ' '))
            result.pop_back();
        // Response format: "ASN | prefix | CC | registry | description"
        // We only care about the first and last fields
        auto pipe_pos = result.find('|');
        if (pipe_pos != std::string::npos) {
            std::string asn = result.substr(0, pipe_pos);
            while (!asn.empty() && asn.back() == ' ') asn.pop_back();
            auto desc_pos = result.rfind('|');
            std::string desc = (desc_pos != std::string::npos && desc_pos != pipe_pos)
                ? result.substr(desc_pos + 1) : "";
            while (!desc.empty() && desc.front() == ' ') desc.erase(desc.begin());
            if (!asn.empty()) return "AS" + asn + (desc.empty() ? "" : " " + desc.substr(0, 30));
        }
        return "";
    }
 
    // ICMP Echo probe — the classic traceroute method. Works against
    // virtually every host but is frequently rate-limited by routers.
    // We send one echo request and wait for either TTL-exceeded or
    // echo-reply. Up to 3 receive attempts to filter out unrelated traffic.
    ProbeResult probe_icmp(int ttl, int probe_id, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl;
        pr.probe_id = probe_id;
 
        int sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_send < 0) return pr;
        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }
 
        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
 
        struct timeval tv;
        tv.tv_sec  = cfg_.timeout_ms / 1000;
        tv.tv_usec = (cfg_.timeout_ms % 1000) * 1000;
        setsockopt(sock_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
 
        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);
 
        // Build the echo request — sequence encodes TTL+probe so we
        // can match replies even when probes are running in parallel
        struct { struct icmphdr hdr; char data[56]; } packet{};
        packet.hdr.type             = ICMP_ECHO;
        packet.hdr.code             = 0;
        packet.hdr.un.echo.id       = htons(getpid() & 0xFFFF);
        packet.hdr.un.echo.sequence = htons((uint16_t)(ttl * 100 + probe_id));
        memset(packet.data, 0x42, sizeof(packet.data));
        packet.hdr.checksum = 0;
        packet.hdr.checksum = icmp_checksum(&packet, sizeof(packet));
 
        auto t_start = std::chrono::high_resolution_clock::now();
        ssize_t sent = sendto(sock_send, &packet, sizeof(packet), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent <= 0) { close(sock_send); close(sock_recv); return pr; }
 
        char buf[512];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);
 
        // Retry loop handles the case where we receive an unrelated ICMP
        // packet from a different probe running concurrently
        for (int attempts = 0; attempts < 3; attempts++) {
            ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&from, &fromlen);
            if (n <= 0) break;
 
            auto t_end = std::chrono::high_resolution_clock::now();
            double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();
 
            struct iphdr* ip_hdr = (struct iphdr*)buf;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n < ip_hdr_len + (int)sizeof(struct icmphdr)) continue;
 
            struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));
 
            // Intermediate hop replied with TTL exceeded
            if (icmp_reply->type == ICMP_TIME_EXCEEDED && icmp_reply->code == ICMP_EXC_TTL) {
                pr.addr      = addr_str;
                pr.rtt_ms    = rtt;
                pr.icmp_type = icmp_reply->type;
                pr.icmp_code = icmp_reply->code;
                pr.reply_ttl = ip_hdr->ttl;
                break;
            }
            // Got an echo reply — we reached the destination
            if (icmp_reply->type == ICMP_ECHOREPLY) {
                uint16_t recv_id = ntohs(icmp_reply->un.echo.id);
                if (recv_id == (uint16_t)(getpid() & 0xFFFF)) {
                    pr.addr           = addr_str;
                    pr.rtt_ms         = rtt;
                    pr.reached_target = true;
                    pr.icmp_type      = icmp_reply->type;
                    pr.reply_ttl      = ip_hdr->ttl;
                    break;
                }
            }
            // Destination unreachable with frag-needed = path MTU discovery hit
            if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED) {
                pr.addr           = addr_str;
                pr.rtt_ms         = rtt;
                pr.icmp_type      = icmp_reply->type;
                pr.icmp_code      = icmp_reply->code;
                pr.mtu_suggestion = ntohs(icmp_reply->un.frag.mtu);
                break;
            }
        }
 
        close(sock_send); close(sock_recv);
        if (cfg_.resolve_dns && !pr.addr.empty())
            pr.hostname = reverse_dns(pr.addr);
        return pr;
    }
 
    // UDP probe — traditional Unix traceroute approach. We send to a
    // high-numbered port that's almost certainly not listening, so the
    // destination returns ICMP port-unreachable when we finally arrive.
    // Port increments per probe to avoid being dropped by stateful firewalls.
    ProbeResult probe_udp(int ttl, int probe_id, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl;
        pr.probe_id = probe_id;
 
        int sock_send = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_send < 0) return pr;
        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }
 
        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
 
        struct timeval tv;
        tv.tv_sec  = cfg_.timeout_ms / 1000;
        tv.tv_usec = (cfg_.timeout_ms % 1000) * 1000;
        setsockopt(sock_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
 
        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(cfg_.dst_port + ttl + probe_id);
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);
 
        char payload[32];
        memset(payload, 0x42, sizeof(payload));
 
        auto t_start = std::chrono::high_resolution_clock::now();
        sendto(sock_send, payload, sizeof(payload), 0,
               (struct sockaddr*)&dest, sizeof(dest));
 
        char buf[512];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                             (struct sockaddr*)&from, &fromlen);
        if (n > 0) {
            auto t_end = std::chrono::high_resolution_clock::now();
            double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();
 
            struct iphdr* ip_hdr = (struct iphdr*)buf;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n >= ip_hdr_len + (int)sizeof(struct icmphdr)) {
                struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));
 
                pr.addr      = addr_str;
                pr.rtt_ms    = rtt;
                pr.icmp_type = icmp_reply->type;
                pr.icmp_code = icmp_reply->code;
                pr.reply_ttl = ip_hdr->ttl;
 
                // ICMP port unreachable = destination reached
                if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_PORT_UNREACH)
                    pr.reached_target = true;
                // MTU hint
                if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_FRAG_NEEDED)
                    pr.mtu_suggestion = ntohs(icmp_reply->un.frag.mtu);
            }
        }
 
        close(sock_send); close(sock_recv);
        if (cfg_.resolve_dns && !pr.addr.empty())
            pr.hostname = reverse_dns(pr.addr);
        return pr;
    }
 
    // TCP SYN probe on port 80 — useful when ICMP and UDP are blocked
    // by firewalls but HTTP traffic is allowed through. We initiate a
    // connection and wait for either a TTL-exceeded ICMP from a router
    // or a SYN-ACK from the destination itself.
    ProbeResult probe_tcp_syn(int ttl, int probe_id, const std::string& target_ip) {
        ProbeResult pr;
        pr.ttl = ttl;
        pr.probe_id = probe_id;
 
        int sock_send = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_send < 0) return pr;
        int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv < 0) { close(sock_send); return pr; }
 
        setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
 
        struct timeval tv;
        tv.tv_sec  = cfg_.timeout_ms / 1000;
        tv.tv_usec = (cfg_.timeout_ms % 1000) * 1000;
        setsockopt(sock_recv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
 
        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(80);
        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);
 
        // Non-blocking connect so we don't block the thread pool worker
        fcntl(sock_send, F_SETFL, O_NONBLOCK);
        auto t_start = std::chrono::high_resolution_clock::now();
        connect(sock_send, (struct sockaddr*)&dest, sizeof(dest));
 
        // Primary path: router returns ICMP TTL exceeded on the raw socket
        char buf[512];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0,
                             (struct sockaddr*)&from, &fromlen);
        if (n > 0) {
            auto t_end = std::chrono::high_resolution_clock::now();
            double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();
 
            struct iphdr* ip_hdr = (struct iphdr*)buf;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (n >= ip_hdr_len + (int)sizeof(struct icmphdr)) {
                struct icmphdr* icmp_reply = (struct icmphdr*)(buf + ip_hdr_len);
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));
 
                pr.addr      = addr_str;
                pr.rtt_ms    = rtt;
                pr.icmp_type = icmp_reply->type;
                pr.icmp_code = icmp_reply->code;
                pr.reply_ttl = ip_hdr->ttl;
 
                if (pr.addr == target_ip)
                    pr.reached_target = true;
            }
        } else {
            // Fallback: destination sent SYN-ACK, the socket became writable
            fd_set wfds; FD_ZERO(&wfds); FD_SET(sock_send, &wfds);
            struct timeval stv{0, 10000};
            if (select(sock_send + 1, nullptr, &wfds, nullptr, &stv) > 0) {
                auto t_end = std::chrono::high_resolution_clock::now();
                double rtt = std::chrono::duration<double, std::milli>(t_end - t_start).count();
                pr.addr           = target_ip;
                pr.rtt_ms         = rtt;
                pr.reached_target = true;
            }
        }
 
        close(sock_send); close(sock_recv);
        if (cfg_.resolve_dns && !pr.addr.empty())
            pr.hostname = reverse_dns(pr.addr);
        return pr;
    }
 
    // Main trace loop. Probes TTL values in sliding windows so we're
    // hitting multiple hops at once rather than waiting hop-by-hop.
    // Window size = cfg_.parallel_hops. Stops as soon as any probe
    // in the window reports reached_target = true.
    std::vector<HopStats> run(const std::string& target_ip) {
        std::vector<HopStats> hops;
        bool reached = false;
 
        for (int base = 1; base <= cfg_.max_hops && !reached; base += cfg_.parallel_hops) {
            int end = std::min(base + cfg_.parallel_hops - 1, cfg_.max_hops);
            int count = end - base + 1;
 
            // 2D matrix: results[hop_index][probe_index]
            std::vector<std::vector<ProbeResult>> results(count,
                std::vector<ProbeResult>(cfg_.queries_per_hop));
 
            std::vector<std::future<void>> futs;
            futs.reserve(count * cfg_.queries_per_hop);
 
            // Submit all probes in this window at once
            for (int h = 0; h < count; h++) {
                for (int p = 0; p < cfg_.queries_per_hop; p++) {
                    int ttl = base + h;
                    int pid = p;
                    int hi  = h;
                    futs.push_back(pool_.submit([this, ttl, pid, hi, p,
                                                 &results, &target_ip] {
                        ProbeResult pr;
                        switch (cfg_.protocol) {
                            case TraceConfig::ICMP:    pr = probe_icmp(ttl, pid, target_ip); break;
                            case TraceConfig::UDP:     pr = probe_udp(ttl, pid, target_ip);  break;
                            case TraceConfig::TCP_SYN: pr = probe_tcp_syn(ttl, pid, target_ip); break;
                        }
                        results[hi][p] = pr;
                    }));
                }
            }
            // Wait for every probe in this window to finish before moving on
            for (auto& f : futs) f.get();
 
            // Collapse the raw probes into per-hop statistics
            for (int h = 0; h < count; h++) {
                HopStats hs;
                hs.ttl  = base + h;
                hs.sent = cfg_.queries_per_hop;
 
                for (auto& pr : results[h]) {
                    if (pr.rtt_ms >= 0) {
                        hs.rtts.push_back(pr.rtt_ms);
                        hs.received++;
                        if (hs.addr.empty()) {
                            hs.addr     = pr.addr;
                            hs.hostname = pr.hostname;
                        }
                        if (pr.reached_target) {
                            hs.is_target = true;
                            reached = true;
                        }
                        if (pr.mtu_suggestion > 0 && cfg_.detect_mtu)
                            hs.mtu = pr.mtu_suggestion;
                    }
                }
                hs.compute();
 
                // AS lookup happens after aggregation so we only query once per hop
                if (!hs.addr.empty() && cfg_.as_lookup)
                    hs.asn_info = as_lookup(hs.addr);
 
                hops.push_back(hs);
                if (hs.is_target) break;
            }
        }
        return hops;
    }
 
private:
    const TraceConfig& cfg_;
    ThreadPool& pool_;
};
 
// Visual latency indicator — 9-segment bar colored green→yellow→red.
// Gives a quick at-a-glance feel for how bad a hop is without reading numbers.
static std::string rtt_bar(double rtt_ms) {
    if (rtt_ms < 0) return std::string(GRAY) + "         " + RESET;
    int buckets[] = {5, 15, 30, 60, 100, 200, 500, 1000, 2000};
    int idx = 0;
    for (int b : buckets) { if (rtt_ms < b) break; idx++; }
    const char* colors[] = {GREEN, GREEN, CYAN, CYAN, YELLOW, YELLOW, RED, RED, RED, RED};
    std::string bar = colors[idx];
    bar += std::string(std::min(idx + 1, 9), '|');
    bar += std::string(std::max(0, 9 - idx - 1), ' ');
    bar += RESET;
    return bar;
}
 
// Short human-readable name for each protocol mode — used in headers and
// the comparison table so the user knows what they're looking at.
static const char* proto_label(TraceConfig::Protocol p) {
    switch (p) {
        case TraceConfig::ICMP:    return "ICMP Echo";
        case TraceConfig::UDP:     return "UDP";
        case TraceConfig::TCP_SYN: return "TCP SYN :80";
    }
    return "?";
}
 
// Entry point called from main(). Handles user input, drives the engine,
// and renders everything to the terminal. Mode 0 runs all three protocols
// back-to-back and prints a comparison table at the end.
static void traceroute(const std::string& target) {
    print_header("ADVANCED TRACEROUTE // " + target);
 
    TraceConfig cfg;
    cfg.target = target;
 
    // Let the user pick a protocol — or 0 to run all three
    std::cout << YELLOW << "\n  protocol: [0] ALL  [1] ICMP  [2] UDP  [3] TCP-SYN  (default=1): " << RESET;
    std::string pc;
    std::getline(std::cin >> std::ws, pc);
    bool all_modes = (pc == "0");
    if      (pc == "2") cfg.protocol = TraceConfig::UDP;
    else if (pc == "3") cfg.protocol = TraceConfig::TCP_SYN;
    else                cfg.protocol = TraceConfig::ICMP;
 
    std::cout << YELLOW << "  probes/hop (default=5): " << RESET;
    std::string qc;
    std::getline(std::cin >> std::ws, qc);
    if (!qc.empty()) {
        try { cfg.queries_per_hop = std::max(1, std::min(10, std::stoi(qc))); } catch (...) {}
    }
 
    // Resolve hostname to IP — fall back to treating input as a raw IP
    std::string target_ip;
    {
        target_ip = resolve(target);
        if (target_ip.empty()) {
            if (inet_addr(target.c_str()) != INADDR_NONE)
                target_ip = target;
            else {
                std::cout << RED << "  could not resolve " << target << "\n" << RESET;
                return;
            }
        }
    }
 
    // Encapsulates one full protocol pass: prints the hop table header,
    // runs the engine, and returns the raw hop data for later analysis.
    auto run_pass = [&](TraceConfig::Protocol proto) -> std::vector<HopStats> {
        TraceConfig pcfg = cfg;
        pcfg.protocol = proto;
 
        std::cout << "\n" << CYAN << "  target:   " << WHITE << target_ip << "\n"
                  << CYAN << "  protocol: " << BOLD << WHITE << proto_label(proto) << "\n" << RESET
                  << CYAN << "  probes:   " << WHITE << pcfg.queries_per_hop << "/hop\n"
                  << CYAN << "  max hops: " << WHITE << pcfg.max_hops << "\n"
                  << CYAN << "  parallel: " << WHITE << pcfg.parallel_hops << " hops at once\n"
                  << RESET << "\n";
 
        std::cout << BOLD << WHITE
                  << "  HOP  ADDRESS           HOSTNAME                  "
                     "AVG      MIN      MAX      JITTER   LOSS  AS INFO\n"
                  << "  " << std::string(110, '-') << "\n" << RESET;
 
        ThreadPool pool(pcfg.parallel_hops * pcfg.queries_per_hop);
        TracerouteEngine engine(pcfg, pool);
        return engine.run(target_ip);
    };
 
    // Collect results from one or all three protocol passes
    std::vector<std::pair<TraceConfig::Protocol, std::vector<HopStats>>> all_results;
 
    if (all_modes) {
        for (auto proto : {TraceConfig::ICMP, TraceConfig::UDP, TraceConfig::TCP_SYN}) {
            print_section(std::string("PASS // ") + proto_label(proto));
            all_results.push_back({proto, run_pass(proto)});
        }
    } else {
        all_results.push_back({cfg.protocol, run_pass(cfg.protocol)});
    }
 
    // Use the first protocol pass as the primary output for the hop table
    auto hops = all_results[0].second;
 
    // Render each hop row — timeouts get a star line, live hops get full stats
    for (auto& hs : hops) {
        std::cout << CYAN << "  " << std::setw(3) << hs.ttl << "  ";
 
        if (hs.received == 0) {
            // Every probe for this TTL timed out — router is silently dropping
            std::cout << YELLOW << std::left << std::setw(18) << "*"
                      << std::setw(27) << "request timeout"
                      << GRAY  << std::string(36, ' ')
                      << RED   << "100%"
                      << RESET << "\n";
            continue;
        }
 
        std::string display_ip = hs.addr;
        std::string display_host = hs.hostname.empty() ? "" : hs.hostname;
        if (display_host.size() > 26) display_host = display_host.substr(0, 23) + "...";
 
        std::cout << (hs.is_target ? GREEN : WHITE)
                  << std::left << std::setw(18) << display_ip
                  << CYAN      << std::setw(27) << sanitize(display_host);
 
        // Format a millisecond value for the table — negative means no data
        auto fmt_ms = [](double ms) -> std::string {
            if (ms < 0) return "*       ";
            std::ostringstream ss;
            ss << std::fixed << std::setprecision(1) << ms << "ms";
            return ss.str();
        };
 
        std::cout << YELLOW << std::setw(9) << fmt_ms(hs.avg_rtt)
                  << GREEN  << std::setw(9) << fmt_ms(hs.min_rtt)
                  << RED    << std::setw(9) << fmt_ms(hs.max_rtt);
 
        if (cfg.show_jitter)
            std::cout << CYAN << std::setw(9) << fmt_ms(hs.jitter);
 
        if (cfg.show_loss) {
            std::string loss_str = std::to_string((int)hs.loss_pct) + "%";
            std::cout << (hs.loss_pct > 0 ? RED : GREEN) << std::setw(6) << loss_str;
        }
 
        // Only show MTU if we actually got a frag-needed ICMP back
        if (hs.mtu > 0)
            std::cout << MAGENTA << "  MTU:" << hs.mtu;
 
        if (!hs.asn_info.empty())
            std::cout << GRAY << "  " << hs.asn_info.substr(0, 28);
 
        std::cout << "  " << rtt_bar(hs.avg_rtt);
        std::cout << RESET << "\n";
 
        if (hs.is_target)
            std::cout << "\n" << GREEN << BOLD << "  [+] destination reached in " << hs.ttl << " hops\n" << RESET;
    }
 
    // Per-run summary with an overall quality verdict
    print_section("TRACE SUMMARY");
 
    if (!hops.empty()) {
        double total_latency = 0;
        int    total_loss    = 0;
        int    total_hops    = hops.size();
        int    timeout_hops  = 0;
        double max_jitter    = 0;
        std::string worst_hop;
 
        for (auto& hs : hops) {
            if (hs.received == 0) { timeout_hops++; continue; }
            total_latency += hs.avg_rtt;
            if (hs.loss_pct > 0) total_loss++;
            if (hs.jitter > max_jitter) {
                max_jitter = hs.jitter;
                worst_hop = hs.addr;
            }
        }
 
        auto& last = hops.back();
        std::cout << CYAN  << "  [hops]          " << WHITE << total_hops << "\n" << RESET;
        std::cout << CYAN  << "  [total RTT]     " << WHITE << std::fixed << std::setprecision(1)
                  << total_latency << "ms\n" << RESET;
        std::cout << CYAN  << "  [timeout hops]  " << (timeout_hops > 0 ? YELLOW : GREEN)
                  << timeout_hops << "\n" << RESET;
        std::cout << CYAN  << "  [hops w/ loss]  " << (total_loss > 0 ? RED : GREEN)
                  << total_loss << "\n" << RESET;
        if (max_jitter > 0)
            std::cout << CYAN << "  [worst jitter]  " << WHITE
                      << std::fixed << std::setprecision(1) << max_jitter << "ms  "
                      << GRAY << "@ " << worst_hop << "\n" << RESET;
        std::cout << CYAN  << "  [reached]       " << (last.is_target ? GREEN "yes" : RED "no (TTL exhausted)")
                  << "\n" << RESET;
 
        // Simple threshold-based verdict — good enough for a quick read
        std::cout << "\n";
        double avg_rtt = (total_hops > 0) ? total_latency / total_hops : 0;
        if      (avg_rtt < 20 && total_loss == 0 && timeout_hops == 0)
            std::cout << GREEN  << BOLD << "  [quality] EXCELLENT -- low latency, no loss\n" << RESET;
        else if (avg_rtt < 80 && total_loss <= 1)
            std::cout << GREEN  << "  [quality] GOOD -- acceptable path\n" << RESET;
        else if (avg_rtt < 200 || total_loss <= 2)
            std::cout << YELLOW << "  [quality] FAIR -- some congestion or loss detected\n" << RESET;
        else
            std::cout << RED    << "  [quality] POOR -- high latency or significant loss\n" << RESET;
    }
 
    // Cross-protocol comparison table — only shown in mode 0
    if (all_modes && all_results.size() > 1) {
        print_section("PROTOCOL COMPARISON");
        std::cout << "\n" << BOLD << WHITE
                  << "  " << std::left << std::setw(12) << "PROTOCOL"
                  << std::setw(8)  << "HOPS"
                  << std::setw(12) << "TOTAL RTT"
                  << std::setw(10) << "AVG/HOP"
                  << std::setw(10) << "TIMEOUTS"
                  << std::setw(8)  << "REACHED"
                  << "QUALITY\n"
                  << "  " << std::string(80, '-') << "\n" << RESET;
 
        for (auto& [proto, ph] : all_results) {
            double total_rtt = 0; int timeouts = 0; bool reached = false;
            int valid = 0;
            for (auto& h : ph) {
                if (h.received == 0) { timeouts++; continue; }
                total_rtt += h.avg_rtt; valid++;
                if (h.is_target) reached = true;
            }
            double avg_per_hop = valid > 0 ? total_rtt / valid : 0;
            std::string quality;
            const char* qcolor;
            if      (avg_per_hop < 20 && timeouts == 0) { quality = "EXCELLENT"; qcolor = GREEN; }
            else if (avg_per_hop < 80 && timeouts <= 1) { quality = "GOOD";      qcolor = GREEN; }
            else if (avg_per_hop < 200 || timeouts <= 2){ quality = "FAIR";      qcolor = YELLOW;}
            else                                         { quality = "POOR";      qcolor = RED;   }
 
            std::cout << "  " << CYAN << std::left << std::setw(12) << proto_label(proto)
                      << WHITE << std::setw(8)  << ph.size()
                      << YELLOW<< std::setw(12) << (std::to_string((int)total_rtt) + "ms")
                      << CYAN  << std::setw(10) << (std::to_string((int)avg_per_hop) + "ms")
                      << (timeouts > 0 ? RED : GRAY) << std::setw(10) << timeouts
                      << (reached ? GREEN : RED) << std::setw(8) << (reached ? "yes" : "no")
                      << qcolor << quality << RESET << "\n";
        }
    }
 
    LOG_INFO("traceroute", "done target=" + target + " hops=" + std::to_string(hops.size()));
}
 
// ================================================================
//  10. FULL RECON
// ================================================================
static void full_recon(const std::string& ip){
    std::cout<<"\n"<<MAGENTA<<BOLD
             <<"  +"<<std::string(56,'=')<<"+\n"
             <<"  |  FULL RECON // "<<std::left<<std::setw(40)<<ip<<"|\n"
             <<"  +"<<std::string(56,'=')<<"+\n"<<RESET;
    ip_intel(ip);
    dns_lookup(ip);
    os_detect(ip);
    port_scan(ip,0,0);
}
 
// ================================================================
//  11. SUBDOMAIN SCAN
// ================================================================
static void subdomain_scan(const std::string& domain) {
    print_header("SUBDOMAIN SCAN // " + domain);

    const int MAX_THREADS = 200;
    const std::vector<uint16_t> SCAN_PORTS = {80,443,8080,8443,8000,8888,3000,5000,9090,9443,8081,8082,4443,2083,2087,10000};

    struct SubResult {
        std::string sub;
        std::vector<std::string> ips;
        std::string cname;
        std::string http_code;
        std::string server;
        std::string title;
        std::vector<uint16_t> open_ports;
        std::string source;
        bool wildcard = false;
    };

    std::mutex mtx;
    std::vector<SubResult> results;
    std::set<std::string> found_set;
    std::atomic<int> checked{0}, found_count{0};
    std::atomic<bool> has_wildcard{false};
    std::set<std::string> wildcard_ips;

    // ===================== WORDLIST =====================
    static const std::vector<std::string> wordlist = {
        "www","mail","ftp","admin","api","dev","test","staging","blog","shop",
        "cdn","static","vpn","remote","portal","app","m","mobile","secure",
        "login","dashboard","panel","cpanel","webmail","smtp","pop","imap",
        "store","web","cloud","media","video","img","images","assets","forum",
        "news","support","help","docs","wiki","status","git","gitlab","jenkins",
        "jira","beta","alpha","demo","sandbox","uat","qa","stage","preprod",
        "prod","production","server","server1","server2","host","node","edge",
        "lb","proxy","cache","gateway","relay","backup","old","new","ns1","ns2",
        "ns3","ns4","dns","dns1","dns2","mx","mx1","mx2","mail2","mail3",
        "www1","www2","www3","web1","web2","ftp2","pop3","smtp2","exchange",
        "owa","outlook","office","sso","auth","oauth","ldap","intranet",
        "extranet","internal","external","corp","corporate","manage","console",
        "cms","wp","wordpress","joomla","drupal","magento","crm","erp","hr",
        "billing","pay","payment","checkout","autodiscover","autoconfig","whm",
        "plesk","directadmin","doc","kb","knowledge","learning","lms","edu",
        "upload","download","file","files","share","transfer","data","archive",
        "mirror","repo","repository","pkg","packages","npm","pip","gem","maven",
        "docker","registry","k8s","kube","kubernetes","swarm","mesos","ecs",
        "lambda","functions","serverless","run","compute","batch","job","jobs",
        "worker","workers","task","tasks","queue","mq","amqp","rabbit","kafka",
        "db","db1","db2","db3","db4","db5","database","sql","mysql","postgres",
        "pgsql","postgresql","mongo","mongodb","redis","memcached","memcache",
        "elastic","elasticsearch","es","solr","lucene","cassandra",
        "mariadb","oracle","mssql","sqlserver","neo4j","graph",
        "couchdb","couchbase","dynamodb","influxdb","influx",
        "clickhouse","timescale","rds","aurora",
        "grafana","kibana","prometheus","nagios","zabbix","datadog","splunk",
        "sentry","newrelic","pagerduty","opsgenie","uptime","monitor",
        "ci","cd","build","deploy","release","argocd","terraform","ansible",
        "puppet","chef","vault","consul","nomad","traefik","envoy","istio",
        "waf","firewall","ids","ips","scan","pentest","bounty","security",
        "cert","certs","pki","ca","ocsp","crl","acme","letsencrypt",
        "rabbitmq","nats","pulsar","eventbus","events","stream","streams",
        "websocket","ws","wss","socket","hook","hooks","webhook","webhooks",
        "mx3","mx4","mail4","mail5","mailgw","spam","antispam","dkim","dmarc",
        "postfix","sendmail","zimbra","roundcube","horde",
        "s3","minio","storage","blob","bucket","assets1","assets2","static1",
        "static2","cdn1","cdn2","origin","edge1","edge2","media1","media2",
        "api1","api2","api3","gw","gw1","gw2","router","switch","fw","fw1",
        "core","core1","core2","mgmt","management","noc","oob","ipmi","ilo",
        "bmc","kvm","pdu","ups","ntp","time","log","logs","syslog","audit",
        "analytics","metrics","stats","telemetry","trace","tracing","jaeger","zipkin",
        "us","eu","ap","us-east","us-west","eu-west","eu-central","ap-south",
        "dev1","dev2","test1","test2","stg","stg1","stg2","prd","prd1","prd2",
        "canary","green","blue","primary","secondary","failover","dr",
        "accounts","account","signup","register","reset","password","token",
        "callback","redirect","connect","link","go","click","track","pixel",
        "preview","draft","temp","tmp","debug","info","health","healthz",
        "readyz","livez","ping","echo","version","v1","v2","v3","graphql",
        "rest","soap","rpc","grpc","proto","ws","sse","poll"
    };

    // ============ wildcard detection ============
    print_section("WILDCARD CHECK");
    std::string wc_test = "randomnxdomain7742test." + domain;
    std::string wc_ip = resolve(wc_test);
    if (!wc_ip.empty()) {
        has_wildcard = true;
        wildcard_ips.insert(wc_ip);
        std::string wc_test2 = "anotherfake9981nx." + domain;
        std::string wc_ip2 = resolve(wc_test2);
        if (!wc_ip2.empty()) wildcard_ips.insert(wc_ip2);
        std::cout << YELLOW << "  [!] wildcard DNS detected -> " << wc_ip;
        if (!wc_ip2.empty() && wc_ip2 != wc_ip) std::cout << ", " << wc_ip2;
        std::cout << "\n  [!] filtering wildcard results\n" << RESET;
    } else {
        std::cout << GREEN << "  [+] no wildcard DNS\n" << RESET;
    }

    // ============ passive sources (crt.sh) ============
    print_section("PASSIVE ENUM (crt.sh)");
    std::cout << YELLOW << "  querying certificate transparency logs...\n" << RESET;

    std::set<std::string> passive_subs;
    auto crt_body = safe_curl("https://crt.sh/?q=%25." + domain + "&output=json", 15);
    if (!crt_body.empty()) {
        std::regex re_name("\"(?:common_name|name_value)\"\\s*:\\s*\"([^\"]+)\"");
        std::sregex_iterator it(crt_body.begin(), crt_body.end(), re_name), end;
        for (; it != end; ++it) {
            std::string val = (*it)[1].str();
            std::istringstream vss(val);
            std::string part;
            while (std::getline(vss, part, '\n')) {
                if (part.size() > 2 && part[0] == '*' && part[1] == '.')
                    part = part.substr(2);
                std::transform(part.begin(), part.end(), part.begin(), ::tolower);
                if (part.size() > domain.size() &&
                    part.substr(part.size() - domain.size()) == domain &&
                    (part[part.size() - domain.size() - 1] == '.' ||
                     part.size() == domain.size())) {
                    passive_subs.insert(part);
                }
                if (part == domain) passive_subs.insert(part);
            }
        }
        std::cout << GREEN << "  [+] crt.sh returned " << passive_subs.size() << " unique names\n" << RESET;
    } else {
        std::cout << GRAY << "  [-] crt.sh unavailable or empty\n" << RESET;
    }

    // ============ merge wordlist + passive ============
    std::vector<std::string> all_subs;
    std::set<std::string> dedup;

    for (auto& w : wordlist) {
        std::string full = w + "." + domain;
        if (dedup.insert(full).second) all_subs.push_back(full);
    }
    for (auto& s : passive_subs) {
        if (s != domain && dedup.insert(s).second) all_subs.push_back(s);
    }

    int total = all_subs.size();
    print_section("BRUTE FORCE + RESOLVE");
    std::cout << YELLOW << "  checking " << total << " subdomains (" << wordlist.size()
              << " wordlist + " << passive_subs.size() << " passive)...\n\n" << RESET;

    // ============ parallel resolution ============
    ThreadPool pool(std::min(MAX_THREADS, total));
    std::vector<std::future<void>> futs;
    futs.reserve(total);

    for (int i = 0; i < total; i++) {
        futs.push_back(pool.submit([&, i] {
            const std::string& sub = all_subs[i];

            addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            int rc = getaddrinfo(sub.c_str(), nullptr, &hints, &res);
            checked++;

            if (rc != 0 || !res) {
                if (checked % 200 == 0) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(checked, total, std::to_string(found_count.load()) + " found");
                }
                return;
            }

            std::vector<std::string> ips;
            for (addrinfo* p = res; p; p = p->ai_next) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, buf, sizeof(buf));
                std::string ipstr = buf;
                if (std::find(ips.begin(), ips.end(), ipstr) == ips.end())
                    ips.push_back(ipstr);
            }
            freeaddrinfo(res);

            if (has_wildcard && ips.size() == 1 && wildcard_ips.count(ips[0])) {
                if (checked % 200 == 0) {
                    std::lock_guard<std::mutex> lk(g_print_mtx);
                    draw_progress(checked, total, std::to_string(found_count.load()) + " found");
                }
                return;
            }

            std::string cname;
            auto cname_out = safe_exec({"dig", "+short", "+time=2", "+tries=1", sub, "CNAME"}, 4);
            if (!cname_out.empty()) {
                auto lines = split_lines(cname_out);
                if (!lines.empty()) {
                    cname = lines[0];
                    while (!cname.empty() && cname.back() == '.') cname.pop_back();
                }
            }

            std::vector<uint16_t> open_ports;
            for (auto port : SCAN_PORTS) {
                if (tcp_probe(ips[0], port, 300)) open_ports.push_back(port);
            }

            std::string http_code, server_hdr, page_title;

            auto http_check = [&](const std::string& url) {
                auto resp = safe_exec({"curl", "-s", "--max-time", "4", "-o", "/dev/null",
                                       "-w", "%{http_code}|%{redirect_url}",
                                       "-A", "Mozilla/5.0",
                                       "-H", "Host: " + sub,
                                       "-k", "-L", "--", url}, 6);
                if (!resp.empty()) {
                    auto pipe_pos = resp.find('|');
                    if (pipe_pos != std::string::npos) http_code = resp.substr(0, pipe_pos);
                    else http_code = resp;
                    http_code.erase(std::remove_if(http_code.begin(), http_code.end(), ::isspace), http_code.end());
                }
            };

            auto grab_info = [&](const std::string& url) {
                auto body = safe_exec({"curl", "-s", "--max-time", "4",
                                       "-A", "Mozilla/5.0",
                                       "-H", "Host: " + sub,
                                       "-k", "-D", "-", "--", url}, 6);
                if (!body.empty()) {
                    std::regex re_srv("^[Ss]erver:\\s*(.+)", std::regex::multiline);
                    std::smatch m;
                    if (std::regex_search(body, m, re_srv)) {
                        server_hdr = m[1].str();
                        while (!server_hdr.empty() && (server_hdr.back() == '\r' || server_hdr.back() == '\n'))
                            server_hdr.pop_back();
                        if (server_hdr.size() > 40) server_hdr = server_hdr.substr(0, 40);
                    }
                    std::regex re_title("<title[^>]*>([^<]+)</title>", std::regex::icase);
                    if (std::regex_search(body, m, re_title)) {
                        page_title = m[1].str();
                        while (!page_title.empty() && (page_title.front() == ' ' || page_title.front() == '\n'))
                            page_title.erase(page_title.begin());
                        while (!page_title.empty() && (page_title.back() == ' ' || page_title.back() == '\n'))
                            page_title.pop_back();
                        if (page_title.size() > 50) page_title = page_title.substr(0, 50) + "...";
                    }
                }
            };

            bool has_443 = std::find(open_ports.begin(), open_ports.end(), 443) != open_ports.end();
            bool has_80 = std::find(open_ports.begin(), open_ports.end(), 80) != open_ports.end();

            if (has_443) {
                http_check("https://" + sub);
                grab_info("https://" + sub);
            } else if (has_80) {
                http_check("http://" + sub);
                grab_info("http://" + sub);
            }

            std::string source;
            bool from_passive = passive_subs.count(sub) > 0;
            std::string prefix = sub.substr(0, sub.size() - domain.size() - 1);
            bool from_wordlist = std::find(wordlist.begin(), wordlist.end(), prefix) != wordlist.end();
            if (from_passive && from_wordlist) source = "both";
            else if (from_passive) source = "crt.sh";
            else source = "brute";

            SubResult sr;
            sr.sub = sub;
            sr.ips = ips;
            sr.cname = cname;
            sr.http_code = http_code;
            sr.server = server_hdr;
            sr.title = page_title;
            sr.open_ports = open_ports;
            sr.source = source;

            found_count++;
            {
                std::lock_guard<std::mutex> lk(mtx);
                results.push_back(sr);
                found_set.insert(sub);
                g_result.subdomains.push_back(sub);
            }

            {
                std::lock_guard<std::mutex> lk(g_print_mtx);
                std::cout << "\r" << GREEN << "  [+] " << std::left << std::setw(40) << sub;
                for (auto& ip : ips) std::cout << CYAN << ip << " ";
                if (!cname.empty()) std::cout << YELLOW << "CNAME:" << cname << " ";
                if (!http_code.empty() && http_code != "000")
                    std::cout << MAGENTA << "HTTP:" << http_code << " ";
                if (!server_hdr.empty()) std::cout << GRAY << "[" << server_hdr << "] ";
                if (!open_ports.empty()) {
                    std::cout << CYAN << "ports:";
                    for (auto p : open_ports) std::cout << p << ",";
                }
                std::cout << DIM << " (" << source << ")" << RESET << "\n";
            }

            if (checked % 100 == 0) {
                std::lock_guard<std::mutex> lk(g_print_mtx);
                draw_progress(checked, total, std::to_string(found_count.load()) + " found");
            }
        }));
    }

    for (auto& f : futs) f.get();
    draw_progress(total, total, std::to_string(found_count.load()) + " found");
    std::cout << "\n";

    // ============ sort and summary ============
    std::sort(results.begin(), results.end(), [](const SubResult& a, const SubResult& b) {
        return a.sub < b.sub;
    });

    print_section("SUMMARY");
    std::cout << "\n" << BOLD << WHITE
              << "  " << std::left << std::setw(40) << "SUBDOMAIN"
              << std::setw(18) << "IP"
              << std::setw(8) << "HTTP"
              << std::setw(20) << "SERVER"
              << std::setw(8) << "PORTS"
              << "TITLE\n"
              << "  " << std::string(110, '-') << "\n" << RESET;

    int cnt_https = 0, cnt_http = 0, cnt_cname = 0;
    std::map<std::string, int> server_stats;

    for (auto& r : results) {
        std::cout << GREEN << "  " << std::left << std::setw(40) << r.sub;
        std::cout << CYAN << std::setw(18) << (r.ips.empty() ? "-" : r.ips[0]);

        if (r.http_code.empty() || r.http_code == "000") {
            std::cout << GRAY << std::setw(8) << "-";
        } else {
            int code = 0;
            try { code = std::stoi(r.http_code); } catch (...) {}
            if (code >= 200 && code < 300) std::cout << GREEN;
            else if (code >= 300 && code < 400) std::cout << YELLOW;
            else if (code >= 400) std::cout << RED;
            else std::cout << WHITE;
            std::cout << std::setw(8) << r.http_code;
        }

        std::cout << GRAY << std::setw(20) << (r.server.empty() ? "-" : r.server);

        if (r.open_ports.empty()) {
            std::cout << std::setw(8) << "-";
        } else {
            std::string ps;
            for (auto p : r.open_ports) {
                if (!ps.empty()) ps += ",";
                ps += std::to_string(p);
            }
            if (ps.size() > 7) ps = ps.substr(0, 7) + "..";
            std::cout << CYAN << std::setw(8) << ps;
        }

        std::cout << WHITE << sanitize(r.title) << RESET << "\n";

        if (!r.cname.empty()) {
            std::cout << YELLOW << "    -> CNAME: " << r.cname << RESET << "\n";
            cnt_cname++;
        }
        if (r.ips.size() > 1) {
            std::cout << GRAY << "    -> also: ";
            for (size_t j = 1; j < r.ips.size(); j++) std::cout << r.ips[j] << " ";
            std::cout << RESET << "\n";
        }

        bool h443 = std::find(r.open_ports.begin(), r.open_ports.end(), 443) != r.open_ports.end();
        bool h80 = std::find(r.open_ports.begin(), r.open_ports.end(), 80) != r.open_ports.end();
        if (h443) cnt_https++;
        if (h80 && !h443) cnt_http++;
        if (!r.server.empty()) server_stats[r.server]++;
    }

    // ============ statistics ============
    print_section("STATISTICS");
    std::cout << CYAN << "  [total found]     " << WHITE << results.size() << "\n" << RESET;
    std::cout << CYAN << "  [checked]         " << WHITE << total << "\n" << RESET;
    std::cout << CYAN << "  [HTTPS (443)]     " << GREEN << cnt_https << "\n" << RESET;
    std::cout << CYAN << "  [HTTP only (80)]  " << YELLOW << cnt_http << "\n" << RESET;
    std::cout << CYAN << "  [with CNAME]      " << WHITE << cnt_cname << "\n" << RESET;
    std::cout << CYAN << "  [wildcard]        " << (has_wildcard.load() ? RED "YES" : GREEN "no") << "\n" << RESET;

    if (!server_stats.empty()) {
        std::cout << CYAN << "\n  [server distribution]\n" << RESET;
        std::vector<std::pair<std::string, int>> sorted_srv(server_stats.begin(), server_stats.end());
        std::sort(sorted_srv.begin(), sorted_srv.end(),
                  [](const std::pair<std::string,int>& a, const std::pair<std::string,int>& b) {
                      return a.second > b.second;
                  });
        for (auto& kv : sorted_srv) {
            std::cout << GRAY << "    " << std::left << std::setw(30) << kv.first
                      << CYAN << kv.second << "\n" << RESET;
        }
    }

    // ============ takeover hints ============
    print_section("TAKEOVER CANDIDATES");
    static const std::vector<std::pair<std::string, std::string>> takeover_sigs = {
        {"github.io",        "GitHub Pages"},
        {"herokuapp.com",    "Heroku"},
        {"azurewebsites.net","Azure"},
        {"cloudfront.net",   "CloudFront"},
        {"s3.amazonaws.com", "AWS S3"},
        {"shopify.com",      "Shopify"},
        {"ghost.io",         "Ghost"},
        {"wordpress.com",    "WordPress"},
        {"pantheon.io",      "Pantheon"},
        {"zendesk.com",      "Zendesk"},
        {"readme.io",        "ReadMe"},
        {"surge.sh",         "Surge"},
        {"bitbucket.io",     "Bitbucket"},
        {"netlify.app",      "Netlify"},
        {"vercel.app",       "Vercel"},
        {"fly.dev",          "Fly.io"},
        {"render.com",       "Render"},
        {"pages.dev",        "Cloudflare Pages"},
    };
    bool any_takeover = false;
    for (auto& r : results) {
        if (r.cname.empty()) continue;
        std::string cl = r.cname;
        std::transform(cl.begin(), cl.end(), cl.begin(), ::tolower);
        for (auto& sig : takeover_sigs) {
            if (cl.find(sig.first) != std::string::npos) {
                std::string tip = resolve(r.cname);
                if (tip.empty()) {
                    std::cout << RED << "  [!!!] " << r.sub << " -> CNAME " << r.cname
                              << " (" << sig.second << ") -- DANGLING! possible takeover\n" << RESET;
                } else {
                    std::cout << YELLOW << "  [?]   " << r.sub << " -> CNAME " << r.cname
                              << " (" << sig.second << ") -- resolves, verify manually\n" << RESET;
                }
                any_takeover = true;
                break;
            }
        }
    }
    if (!any_takeover) std::cout << GREEN << "  no obvious takeover candidates\n" << RESET;

    LOG_INFO("subdomain_scan", "done domain=" + domain + " found=" + std::to_string(results.size()));
}

// ================================================================
//  BANNER + MENU
// ================================================================
static void print_banner(){
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
 
static void print_menu(){
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
 
// ================================================================
//  MAIN
// ================================================================
int main(){
    // init logger
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
