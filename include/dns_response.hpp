#pragma once

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <vector>

namespace dns_response {
struct Result {
    std::vector<std::string> addresses;
    int status = -1;
    std::string error;
    bool valid = false;
};

inline std::string name_key(std::string value) {
    if (!value.empty() && value.back() == '.') value.pop_back();
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

inline bool valid_name(const std::string& input) {
    const auto name = name_key(input);
    if (name.empty() || name.size() > 253) return false;
    std::size_t start = 0;
    while (start < name.size()) {
        const auto dot = name.find('.', start);
        const auto end = dot == std::string::npos ? name.size() : dot;
        if (end == start || end - start > 63 || name[start] == '-' || name[end - 1] == '-') return false;
        for (auto i = start; i < end; ++i) {
            const auto c = static_cast<unsigned char>(name[i]);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
        }
        if (dot == std::string::npos) return true;
        start = dot + 1;
    }
    return false;
}

inline Result parse_doh_response(const std::string& body, const std::string& hostname, int qtype = 1) {
    Result result;
    auto fail = [&](const std::string& error) { result.addresses.clear(); result.error = error; return result; };
    if ((qtype != 1 && qtype != 28) || !valid_name(hostname)) return fail("invalid DNS question");
    if (body.size() > 1024 * 1024) return fail("DNS JSON response exceeds size limit");
    try {
        bool too_deep = false;
        const auto data = nlohmann::json::parse(body, [&](int depth, nlohmann::json::parse_event_t, nlohmann::json&) {
            if (depth > 32) { too_deep = true; return false; }
            return true;
        });
        if (too_deep) return fail("DNS JSON nesting exceeded limit");
        if (!data.is_object() || !data.contains("Status") || !data["Status"].is_number_integer()) return fail("missing DNS status");
        if (data["Status"] < 0 || data["Status"] > 65535) return fail("invalid DNS status range");
        result.status = data["Status"].get<int>();
        if (data.contains("TC") && (!data["TC"].is_boolean() || data["TC"].get<bool>())) return fail("truncated or malformed DNS response");
        if (result.status != 0 && result.status != 3) return fail("DNS server returned status " + std::to_string(result.status));
        if (data.contains("Question")) {
            if (!data["Question"].is_array() || data["Question"].size() != 1) return fail("invalid DNS question section");
            const auto& question = data["Question"][0];
            if (!question.is_object() || !question.contains("name") || !question["name"].is_string() ||
                !question.contains("type") || !question["type"].is_number_integer() ||
                name_key(question["name"].get<std::string>()) != name_key(hostname) || question["type"] != qtype)
                return fail("DNS response question mismatch");
        }
        if (!data.contains("Answer")) { result.valid = true; return result; }
        if (!data["Answer"].is_array() || data["Answer"].size() > 4096) return fail("invalid DNS answer section");
        struct Record { std::string name, value; int type; };
        std::vector<Record> records;
        std::map<std::string, std::string> aliases;
        for (const auto& entry : data["Answer"]) {
            if (!entry.is_object() || !entry.contains("type") || !entry["type"].is_number_integer()) return fail("invalid DNS record type");
            if (entry["type"] < 0 || entry["type"] > 65535) return fail("invalid DNS record type range");
            const auto type = entry["type"].get<int>();
            if (type != qtype && type != 5) continue;
            if (!entry.contains("name") || !entry["name"].is_string() || !entry.contains("data") || !entry["data"].is_string())
                return fail("invalid DNS record fields");
            const auto name = name_key(entry["name"].get<std::string>());
            const auto value = entry["data"].get<std::string>();
            if (!valid_name(name)) return fail("invalid DNS record owner");
            if (type == 5) {
                if (!valid_name(value)) return fail("invalid CNAME target");
                const auto target = name_key(value);
                if (aliases.count(name) && aliases[name] != target) return fail("conflicting CNAME targets");
                aliases[name] = target;
            }
            records.push_back({name, value, type});
        }
        std::set<std::string> reachable;
        auto name = name_key(hostname);
        for (std::size_t hops = 0;; ++hops) {
            if (!reachable.insert(name).second) return fail("CNAME cycle");
            const auto alias = aliases.find(name);
            if (alias == aliases.end()) break;
            if (hops >= 16) return fail("CNAME chain exceeds limit");
            name = alias->second;
        }
        for (const auto& record : records) {
            if (!reachable.count(record.name)) return fail("unrelated DNS answer owner");
            if (record.type == 5) continue;
            if (result.status == 3 || aliases.count(record.name)) return fail("contradictory DNS answer");
            unsigned char address[sizeof(in6_addr)] = {};
            const auto family = qtype == 1 ? AF_INET : AF_INET6;
            if (record.value.find('\0') != std::string::npos || inet_pton(family, record.value.c_str(), address) != 1)
                return fail("invalid DNS address");
            char formatted[INET6_ADDRSTRLEN] = {};
            if (!inet_ntop(family, address, formatted, sizeof(formatted))) return fail("cannot format DNS address");
            result.addresses.emplace_back(formatted);
        }
        std::sort(result.addresses.begin(), result.addresses.end());
        result.addresses.erase(std::unique(result.addresses.begin(), result.addresses.end()), result.addresses.end());
        result.valid = true;
        return result;
    } catch (const nlohmann::json::exception&) { return fail("malformed DNS JSON response"); }
}
} // namespace dns_response
