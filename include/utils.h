#pragma once
#ifndef DARK_NEXUS_UTILS_H
#define DARK_NEXUS_UTILS_H

#include <string>
#include <vector>

bool valid_target(const std::string& s);
bool valid_username(const std::string& s);
bool valid_port(int p);
std::string sanitize(const std::string& s);
std::string resolve(const std::string& host);
std::string ptr_lookup(const std::string& ip);
std::string safe_exec(const std::vector<std::string>& args, int timeout = 8);
std::string safe_curl(const std::string& url, int timeout = 8);
std::string now_str();

#endif
