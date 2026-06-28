#pragma once

#include "port_scan_engine.hpp"

bool port_vuln_is_significant(const std::string& severity);
std::vector<VulnHint> check_port_vulns(int port,
                                       const std::string& version,
                                       const std::string& banner,
                                       const TLSInfo* tls,
                                       const HttpInfo* http);
std::vector<VulnHint> dedupe_port_vulns(std::vector<VulnHint> vulns);
