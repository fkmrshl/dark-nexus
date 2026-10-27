#include "dns_query.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdint>
#include <map>
#include <set>
#include <sstream>

namespace dns_query {
namespace {
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string name_key(std::string value) {
    if (!value.empty() && value.back() == '.') value.pop_back();
    return lower(value);
}

bool number(const std::string& value, std::uint64_t maximum = UINT32_MAX) {
    if (value.empty() || value.size() > 10) return false;
    std::uint64_t parsed = 0;
    for (unsigned char c : value) {
        if (c < '0' || c > '9') return false;
        parsed = parsed * 10 + c - '0';
        if (parsed > maximum) return false;
    }
    return true;
}

bool owner_name(const std::string& value) {
    if (value == ".") return true;
    if (value.rfind("*.", 0) == 0) return valid_name(value.substr(2), true);
    return valid_name(value, true);
}

// RFC 1035 presentation escapes denote one octet, including escaped label dots.
bool escaped_octet(const std::string& value, std::size_t& position, unsigned char& octet) {
    if (++position >= value.size()) return false;
    if (value[position] >= '0' && value[position] <= '9') {
        if (position + 2 >= value.size()) return false;
        unsigned int decoded = 0;
        for (std::size_t i = position; i <= position + 2; ++i) {
            if (value[i] < '0' || value[i] > '9') return false;
            decoded = decoded * 10 + value[i] - '0';
        }
        if (decoded > 255) return false;
        position += 2;
        octet = static_cast<unsigned char>(decoded);
    } else octet = static_cast<unsigned char>(value[position]);
    return true;
}

bool mailbox_name(const std::string& value) {
    if (value == ".") return true;
    if (value.empty()) return false;
    std::size_t label = 0, wire_length = 1;
    for (std::size_t i = 0; i < value.size(); ++i) {
        auto octet = static_cast<unsigned char>(value[i]);
        if (octet == '.') {
            if (!label) return false;
            wire_length += label + 1;
            label = 0;
            if (i + 1 == value.size()) return wire_length <= 255;
            continue;
        }
        if (octet == '\\') {
            if (!escaped_octet(value, i, octet)) return false;
        } else if (octet <= 32 || octet == 127 || octet == '"' || octet == ';' || octet == '(' || octet == ')') {
            return false;
        }
        if (++label > 63) return false;
    }
    return label && wire_length + label + 1 <= 255;
}

bool character_strings(const std::string& value, bool quoted_required, bool multiple, std::string* decoded = nullptr) {
    std::size_t position = 0, count = 0;
    while (position < value.size()) {
        while (position < value.size() && std::isspace(static_cast<unsigned char>(value[position]))) ++position;
        if (position == value.size()) break;
        if (count && !multiple) return false;
        const bool quoted = value[position] == '"';
        if (quoted_required && !quoted) return false;
        if (quoted) ++position;
        bool closed = !quoted;
        for (; position < value.size(); ++position) {
            auto octet = static_cast<unsigned char>(value[position]);
            if (quoted && octet == '"') { ++position; closed = true; break; }
            if (!quoted && std::isspace(octet)) break;
            if (!quoted && (octet == '"' || octet == ';' || octet == '(' || octet == ')')) return false;
            if (octet == '\\' && !escaped_octet(value, position, octet)) return false;
            if (decoded) *decoded += static_cast<char>(octet);
        }
        if (!closed) return false;
        ++count;
    }
    return count > 0;
}

bool algorithm(const std::string& value) {
    if (number(value, UINT8_MAX)) return true;
    // Mnemonics are legal presentation forms; interpreting algorithms is not
    // part of this syntactic check, including algorithms added in the future.
    if (value.empty() || !std::isalpha(static_cast<unsigned char>(value.front()))) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    });
}

std::string encoded_data(const std::vector<std::string>& parts) {
    std::string value;
    for (std::size_t i = 3; i < parts.size(); ++i) value += parts[i];
    if (value.size() > 1 && value.front() == '(' && value.back() == ')')
        value = value.substr(1, value.size() - 2);
    return value;
}

bool base64_data(const std::string& value) {
    if (value.empty()) return false;
    const auto padding = value.find('=');
    const auto length = padding == std::string::npos ? value.size() : padding;
    if (!length || length % 4 == 1) return false;
    if (padding != std::string::npos &&
        (value.size() % 4 || value.size() - padding > 2 ||
         !std::all_of(value.begin() + padding, value.end(), [](char c) { return c == '='; }))) return false;
    return std::all_of(value.begin(), value.begin() + length, [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
    });
}

bool record_value(const Record& record) {
    std::vector<std::string> parts;
    std::string item;
    for (std::size_t i = 0; i < record.value.size(); ++i) {
        const auto c = static_cast<unsigned char>(record.value[i]);
        if (c == '\\') {
            item += static_cast<char>(c);
            if (i + 1 < record.value.size()) item += record.value[++i];
        } else if (std::isspace(c)) {
            if (!item.empty()) { parts.push_back(std::move(item)); item.clear(); }
        } else item += static_cast<char>(c);
    }
    if (!item.empty()) parts.push_back(std::move(item));
    if (parts.empty()) return false;
    if (record.type == "A" || record.type == "AAAA") {
        unsigned char address[sizeof(in6_addr)] = {};
        return parts.size() == 1 && inet_pton(record.type == "A" ? AF_INET : AF_INET6,
                                             parts[0].c_str(), address) == 1;
    }
    if (record.type == "NS" || record.type == "CNAME" || record.type == "PTR")
        return parts.size() == 1 && valid_name(parts[0]);
    if (record.type == "MX")
        return parts.size() == 2 && number(parts[0], UINT16_MAX) &&
               (parts[1] == "." || valid_name(parts[1]));
    if (record.type == "SRV")
        return parts.size() == 4 && number(parts[0], UINT16_MAX) && number(parts[1], UINT16_MAX) &&
               number(parts[2], UINT16_MAX) && (parts[3] == "." || valid_name(parts[3]));
    if (record.type == "SOA") {
        if (parts.size() != 7 || !valid_name(parts[0]) || !mailbox_name(parts[1])) return false;
        return std::all_of(parts.begin() + 2, parts.end(), [](const auto& value) { return number(value); });
    }
    if (record.type == "TXT") {
        return character_strings(record.value, true, true);
    }
    if (record.type == "CAA") {
        if (parts.size() < 3 || !number(parts[0], UINT8_MAX) || parts[1].empty() || parts[1].size() > 255 ||
            !std::all_of(parts[1].begin(), parts[1].end(), [](unsigned char c) {
                return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            })) return false;
        std::istringstream fields(record.value);
        std::string flag, tag, value;
        fields >> flag >> tag;
        std::getline(fields >> std::ws, value);
        return character_strings(value, false, false);
    }
    if (record.type == "DS") {
        if (parts.size() < 4 || !number(parts[0], UINT16_MAX) || !algorithm(parts[1]) || !number(parts[2], UINT8_MAX)) return false;
        const auto digest = encoded_data(parts);
        return !digest.empty() && digest.size() % 2 == 0 &&
            std::all_of(digest.begin(), digest.end(), [](unsigned char c) {
                return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
            });
    }
    if (record.type == "DNSKEY") {
        return parts.size() >= 4 && number(parts[0], UINT16_MAX) && number(parts[1], UINT8_MAX) &&
               algorithm(parts[2]) && base64_data(encoded_data(parts));
    }
    return true;
}
} // namespace

std::string Record::text() const { return owner + " " + ttl + " IN " + type + " " + value; }

bool valid_name(const std::string& name, bool service_labels) {
    const auto value = name_key(name);
    if (value.empty() || value.size() > 253) return false;
    std::size_t start = 0;
    while (start < value.size()) {
        const auto end = value.find('.', start);
        const auto count = (end == std::string::npos ? value.size() : end) - start;
        if (!count || count > 63 || value[start] == '-' || value[start + count - 1] == '-') return false;
        for (std::size_t i = start; i < start + count; ++i) {
            const unsigned char c = value[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
                  (service_labels && c == '_'))) return false;
        }
        if (end == std::string::npos) return true;
        start = end + 1;
    }
    return false;
}

Reply parse_reply(const std::string& output) {
    Reply reply;
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        line.erase(0, first);
        if (line.rfind(";; ->>HEADER<<-", 0) == 0) {
            if (line.find("opcode: QUERY,") == std::string::npos) reply.malformed = true;
            const auto marker = line.find("status: ");
            if (marker == std::string::npos) { reply.malformed = true; continue; }
            const auto end = line.find(',', marker + 8);
            const auto status = line.substr(marker + 8, end == std::string::npos ? end : end - marker - 8);
            if (status.empty() || !std::all_of(status.begin(), status.end(), [](unsigned char c) {
                    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
                }) || (!reply.status.empty() && reply.status != status)) reply.malformed = true;
            else reply.status = status;
            continue;
        }
        if (line.rfind(";; flags:", 0) == 0) {
            const auto end = line.find(';', 9);
            std::istringstream flags(line.substr(9, end == std::string::npos ? end : end - 9));
            std::string flag;
            bool response = false;
            while (flags >> flag) {
                if (flag == "tc") reply.truncated = true;
                if (flag == "qr") response = true;
            }
            if (!response) reply.malformed = true;
            continue;
        }
        if (line.front() == ';') continue;
        if (reply.records.size() >= 4096) { reply.malformed = true; break; }
        std::istringstream fields(line);
        Record record;
        std::string record_class;
        if (!(fields >> record.owner >> record.ttl >> record_class >> record.type) ||
            !owner_name(record.owner) || !number(record.ttl) || record_class != "IN" ||
            record.type.empty() || !std::all_of(record.type.begin(), record.type.end(), [](unsigned char c) {
                return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
            })) {
            reply.malformed = true;
            continue;
        }
        std::getline(fields >> std::ws, record.value);
        if (record.value.empty() || std::any_of(record.value.begin(), record.value.end(), [](unsigned char c) {
                return c < 32 || c == 127;
            }) || !record_value(record)) {
            reply.malformed = true;
            continue;
        }
        reply.records.push_back(std::move(record));
    }
    return reply;
}

bool correlate_reply(Reply& reply, const std::string& question_name, const std::string& type) {
    std::map<std::string, std::string> aliases;
    for (const auto& record : reply.records) {
        if (record.type != "CNAME") continue;
        const auto owner = name_key(record.owner), target = name_key(record.value);
        const auto previous = aliases.find(owner);
        if (previous != aliases.end() && previous->second != target) return false;
        aliases[owner] = target;
    }
    std::set<std::string> reachable;
    auto cursor = name_key(question_name);
    for (std::size_t hops = 0;; ++hops) {
        if (!reachable.insert(cursor).second) return false;
        const auto alias = aliases.find(cursor);
        if (alias == aliases.end()) break;
        if (hops >= 16) return false;
        cursor = alias->second;
    }
    for (const auto& record : reply.records) {
        if (record.type != type && record.type != "CNAME") continue;
        const auto owner = name_key(record.owner);
        if (!reachable.count(owner)) return false;
        if (record.type != "CNAME" && aliases.count(owner)) return false;
        if (reply.status == "NXDOMAIN" && record.type == type && record.type != "CNAME") return false;
    }
    reply.records.erase(std::remove_if(reply.records.begin(), reply.records.end(), [&](const auto& record) {
        return record.type != type && record.type != "CNAME";
    }), reply.records.end());
    return true;
}

std::string reverse_name(const std::string& address) {
    unsigned char bytes[sizeof(in6_addr)] = {};
    if (inet_pton(AF_INET, address.c_str(), bytes) == 1) {
        std::string result;
        for (int i = 3; i >= 0; --i) result += std::to_string(bytes[i]) + '.';
        return result + "in-addr.arpa";
    }
    if (inet_pton(AF_INET6, address.c_str(), bytes) == 1) {
        static constexpr char hex[] = "0123456789abcdef";
        std::string result;
        for (int i = 15; i >= 0; --i) {
            result += hex[bytes[i] & 15]; result += '.';
            result += hex[bytes[i] >> 4]; result += '.';
        }
        return result + "ip6.arpa";
    }
    return "";
}

bool complete_transfer(const Reply& reply, const std::string& zone) {
    if (reply.malformed || reply.truncated || (!reply.status.empty() && reply.status != "NOERROR") || reply.records.size() < 3)
        return false;
    const auto& first = reply.records.front();
    const auto& last = reply.records.back();
    if (first.type != "SOA" || last.type != "SOA" || name_key(first.owner) != name_key(zone) ||
        name_key(last.owner) != name_key(zone) || first.value != last.value) return false;
    if (std::count_if(reply.records.begin(), reply.records.end(), [](const auto& record) {
            return record.type == "SOA";
        }) != 2) return false;
    const auto key = name_key(zone);
    return std::all_of(reply.records.begin(), reply.records.end(), [&](const auto& record) {
        const auto owner = name_key(record.owner);
        return owner == key || (owner.size() > key.size() &&
            owner.compare(owner.size() - key.size(), key.size(), key) == 0 &&
            owner[owner.size() - key.size() - 1] == '.');
    });
}

std::string txt_value(const std::string& value) {
    std::string result;
    return character_strings(value, true, true, &result) ? result : "";
}

std::vector<std::string> spf_references(const std::string& value) {
    std::istringstream words(value);
    std::vector<std::string> result;
    std::string word;
    while (words >> word) {
        if (result.size() >= 64) break;
        if (!word.empty() && (word.front() == '+' || word.front() == '-' || word.front() == '~' || word.front() == '?'))
            word.erase(0, 1);
        const auto key = lower(word);
        if (key.rfind("include:", 0) == 0) result.push_back(word.substr(8));
        else if (key.rfind("redirect=", 0) == 0) result.push_back(word.substr(9));
    }
    return result;
}

} // namespace dns_query
