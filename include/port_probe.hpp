#pragma once

#include <string>
#include <utility>
#include "dark_nexus.hpp"

struct AdaptiveConfig {
    int connect_ms;
    int banner_ms;
    int retry_count;
    int pool_size;
    int median_rtt;
};

bool port_scan_is_v6(const std::string& ip);
FdGuard port_tcp_socket(const std::string& ip);
bool port_tcp_connect_to(const std::string& ip, int port, int timeout_ms, int fd);
AdaptiveConfig calibrate_port_target(const std::string& ip);
std::pair<int,bool> port_probe_connect(const std::string& ip, int port, int timeout_ms, int retries);
std::pair<int,bool> port_probe_syn(const std::string& ip, int port, int timeout_ms, int retries);
std::pair<int,bool> port_probe_udp_smart(const std::string& ip, int port, int timeout_ms);
