#include "../include/dark_nexus.hpp"

bool valid_target(const std::string& s) {
    if (s.empty() || s.size()>253) return false;
    static const std::regex ok(R"(^[a-zA-Z0-9.\-_:/@]+$)");
    return std::regex_match(s, ok);
}

bool valid_username(const std::string& s) {
    if (s.empty() || s.size()>64) return false;
    static const std::regex ok(R"(^[a-zA-Z0-9.\-_]+$)");
    return std::regex_match(s, ok);
}

bool valid_port(int p) { return p>=1 && p<=65535; }

std::string sanitize(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (size_t i=0; i<s.size(); i++) {
        unsigned char c=s[i];
        if (c==0x1b) {
            while(i<s.size()&&s[i]!='m'&&s[i]!='J'&&s[i]!='H'&&s[i]!='K'
                  &&s[i]!='A'&&s[i]!='B'&&s[i]!='C'&&s[i]!='D') i++;
            continue;
        }
        if ((c>=32&&c<=126)||c==10||c==9) o+=c;
    }
    return o;
}

std::string resolve(const std::string& host) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host.c_str(),nullptr,&hints,&res)!=0) return "";
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&((sockaddr_in*)res->ai_addr)->sin_addr,buf,sizeof(buf));
    freeaddrinfo(res);
    return buf;
}

bool tcp_probe(const std::string& ip, int port, int ms) {
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

std::pair<bool,int> tcp_probe_ms(const std::string& ip, int port, int ms) {
    auto t0=std::chrono::high_resolution_clock::now();
    bool ok=tcp_probe(ip,port,ms);
    int el=std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now()-t0).count();
    return {ok,el};
}

std::string ptr_lookup(const std::string& ip) {
    sockaddr_in sa{}; sa.sin_family=AF_INET;
    inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
    char h[NI_MAXHOST]={};
    if (getnameinfo((sockaddr*)&sa,sizeof(sa),h,sizeof(h),nullptr,0,0)==0) return h;
    return "";
}

[[maybe_unused]] static uint16_t icmp_cksum(const void* data, int len) {
    const uint16_t* buf=(const uint16_t*)data;
    uint32_t sum=0;
    while(len>1){sum+=*buf++;len-=2;}
    if(len==1) sum+=*(const uint8_t*)buf;
    sum=(sum>>16)+(sum&0xffff); sum+=(sum>>16);
    return (uint16_t)~sum;
}

std::string svc(int port) {
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

std::string risk_label(int port) {
    static std::vector<int> hi={21,23,512,513,514,3389,5900,445,2375,111,4444,7001,50070};
    static std::vector<int> md={22,3306,5432,27017,6379,1433,9200,1521,8888,10000};
    if (std::find(hi.begin(),hi.end(),port)!=hi.end()) return std::string(RED)+"HIGH"+RESET;
    if (std::find(md.begin(),md.end(),port)!=md.end()) return std::string(YELLOW)+"MED"+RESET;
    return std::string(GREEN)+"LOW"+RESET;
}

std::string banner(const std::string& ip, int port, int ms) {
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) return "";
    timeval tv{ms/1000,(ms%1000)*1000};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
    inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
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

std::string smart_banner(const std::string& ip, int port, int ms) {
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

    int sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen);
    if (sockerr != 0) { close(fd); return ""; }

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);

    std::string probe;
    switch (port) {
        case 80: case 8080: case 8888: case 8000: case 3000: case 9090:
            probe = "GET / HTTP/1.1\r\nHost: " + ip +
                    "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            break;
        case 443: case 8443: case 9443:
            probe = "GET / HTTP/1.0\r\n\r\n";
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
            break;
    }

    if (!probe.empty())
        send(fd, probe.c_str(), probe.size(), MSG_NOSIGNAL);

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
            if (!result.empty()) break;
        }
    }
    close(fd);

    result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());

    if (port == 80 || port == 8080 || port == 8888 || port == 8000 ||
        port == 443 || port == 8443 || port == 3000 || port == 9090) {
        auto hdr_end = result.find("\n\n");
        if (hdr_end != std::string::npos) result = result.substr(0, hdr_end);
    }

    auto nl = result.find('\n');
    std::string first_line = (nl != std::string::npos) ? result.substr(0, nl) : result;
    if (first_line.size() > 80) first_line = first_line.substr(0, 80) + "...";

    return sanitize(first_line);
}
