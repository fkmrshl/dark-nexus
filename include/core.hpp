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

extern std::mutex g_print_mtx;

struct ProcResult {
    std::string out, err;
    int code = -1;
    bool timed_out = false;
};

struct ScanResult {
    std::string target, timestamp;
    std::vector<std::pair<int,std::string>> open_ports;
    std::vector<std::string> subdomains, osint_hits;
    std::string geo_country, geo_city, geo_isp, geo_as, os_guess;
    bool proxy=false, hosting=false;
};

extern ScanResult g_result;

ProcResult proc_run(const std::vector<std::string>& args, 
                    int timeout_sec = 10, 
                    const std::string& stdin_data = "", 
                    size_t max_out = 4*1024*1024);

std::string now_str();
void export_json(const std::string& fname);

#endif
