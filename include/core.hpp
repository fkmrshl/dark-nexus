#ifndef CORE_HPP
#define CORE_HPP

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
 
#endif
