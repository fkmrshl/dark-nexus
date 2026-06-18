#pragma once

#include <string>
#include "port_scan_engine.hpp"

bool port_is_tls_http_port(int port);
bool port_is_http_candidate(int port);
bool port_is_tls_candidate(int port);
int port_service_priority(int port);
std::string port_extract_version(const std::string& banner_raw, int port);
bool port_banner_usable(const std::string& s);
std::string port_resolve_sni_host(const std::string& scan_ip);

std::string port_probe_redis_ping(const std::string& ip, int port, int timeout_ms);
std::string port_probe_mongo_ping(const std::string& ip, int port, int timeout_ms);
std::string port_probe_ssh_banner(const std::string& ip, int port, int timeout_ms);
std::string port_probe_ftp_banner(const std::string& ip, int port, int timeout_ms);
std::string port_probe_smtp_banner(const std::string& ip, int port, int timeout_ms);
std::string port_probe_mysql_banner(const std::string& ip, int port, int timeout_ms);
std::string port_probe_postgres_banner(const std::string& ip, int port, int timeout_ms);

TLSInfo port_inspect_tls(const std::string& ip, int port, int timeout_ms, const std::string& sni_host);
TlsHttpResult port_probe_tls_http(const std::string& ip, int port, int timeout_ms,
                                  const std::string& sni_host, int max_redirects);
HttpInfo port_probe_http(const std::string& ip, int port, int timeout_ms, bool aggressive,
                         const std::string& host_header);

void print_port_http_enrichment(const HttpInfo& http);
void print_port_powered_by_line(const HttpInfo& http);
void print_port_stack_disclosures(const ScanResults& r);
void print_port_tls_enrichment(const TLSInfo& tls);
