#pragma once

#include <string>
#include <vector>

namespace dns_query {

struct Record {
    std::string owner, ttl, type, value;
    std::string text() const;
};

struct Reply {
    std::string status;
    std::vector<Record> records;
    bool malformed = false;
    bool truncated = false;
};

bool valid_name(const std::string& name, bool service_labels = false);
Reply parse_reply(const std::string& output);
// Retain only records for the question or its bounded, non-cyclic CNAME chain.
bool correlate_reply(Reply& reply, const std::string& question_name, const std::string& type);
std::string reverse_name(const std::string& address);
bool complete_transfer(const Reply& reply, const std::string& zone);
std::string txt_value(const std::string& value);
std::vector<std::string> spf_references(const std::string& value);

} // namespace dns_query
