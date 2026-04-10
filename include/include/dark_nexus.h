#pragma once

#include <string>
#include <vector>

extern std::mutex g_print_mtx;

struct ScanResult {
    std::string target, timestamp;
    std::vector<std::pair<int,std::string>> open_ports;
    std::vector<std::string> subdomains, osint_hits;
    std::string geo_country, geo_city, geo_isp, geo_as, os_guess;
    bool proxy = false, hosting = false;
};

extern ScanResult g_result;

std::string now_str();
void export_json(const std::string& fname);
