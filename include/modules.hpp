#ifndef MODULES_HPP
#define MODULES_HPP

#include "core.hpp"

void port_scan(const std::string& ip, int start, int end);
void net_scan(const std::string& subnet);
void os_detect(const std::string& ip);
void ip_intel(const std::string& ip);
void dns_lookup(const std::string& ip);
void whois_lookup(const std::string& target);
void osint_scan(const std::string& username);
void traceroute(const std::string& target);
void subdomain_scan(const std::string& domain);
void full_recon(const std::string& target);

std::string safe_exec(const std::vector<std::string>& args, int t = 8);
std::string safe_curl(const std::string& url, int t = 8);
std::string resolve(const std::string& host);
std::string sanitize(const std::string& s);
void draw_progress(int done, int total, const std::string& label);
void print_header(const std::string& title);
void print_row(const std::string& label, const std::string& val);

#endif
