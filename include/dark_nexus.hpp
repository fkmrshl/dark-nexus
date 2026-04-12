#pragma once

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
#include <ares.h>
#include <sys/select.h>
#include <fstream>
#include <random>
#include <unordered_set>
#include <unordered_map>

#include "colors.hpp"
#include "logger.hpp"
#include "thread_pool.hpp"
#include "traceroute.hpp"

struct ScanResult {
    std::string target, timestamp;
    std::vector<std::pair<int,std::string>> open_ports;
    std::vector<std::string> subdomains, osint_hits;
    std::string geo_country, geo_city, geo_isp, geo_as, os_guess;
    bool proxy = false, hosting = false;
};

extern ScanResult   g_result;
extern std::mutex   g_print_mtx;

std::string safe_exec(const std::vector<std::string>& args, int t = 8);
std::string safe_curl(const std::string& url, int t = 8);

bool        valid_target(const std::string& s);
bool        valid_username(const std::string& s);
bool        valid_port(int p);
std::string sanitize(const std::string& s);
std::string resolve(const std::string& host);
bool        tcp_probe(const std::string& ip, int port, int ms = 500);
std::pair<bool,int> tcp_probe_ms(const std::string& ip, int port, int ms = 1000);
std::string ptr_lookup(const std::string& ip);
std::string svc(int port);
std::string risk_label(int port);
std::string banner(const std::string& ip, int port, int ms = 1500);
std::string smart_banner(const std::string& ip, int port, int ms = 2000);

std::string now_str();
void        export_json(const std::string& fname);
std::string json_val(const std::string& json, const std::string& key);
int         term_width();
void        draw_progress(int done, int total, const std::string& label = "");
void        print_sep();
void        print_header(const std::string& title);
void        print_section(const std::string& title);
void        print_row(const std::string& label, const std::string& val);
std::vector<std::string> split_lines(const std::string& s);
std::string dig_short(const std::string& domain, const std::string& type, int t = 6);
std::string dig_full(const std::string& domain, const std::string& type, int t = 6);

void        port_scan(const std::string& ip, int start, int end_port);
void        net_scan(const std::string& subnet);
std::string guess_os_from_ports(const std::vector<int>& open);

void os_detect(const std::string& ip);

void ip_intel(const std::string& ip);

void dns_lookup(const std::string& domain);
void whois_lookup(const std::string& target);
void site_lookup(const std::string& raw);

void osint_scan(const std::string& username);

void traceroute(const std::string& target);
void full_recon(const std::string& ip);

void subdomain_scan(const std::string& domain, 
                    const std::string& wordlist_path = "", 
                    int max_threads = 200,
                    bool run_permutations = true, 
                    bool deep_passive = true);
