#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"
#include "dns_query.hpp"
#include "process.hpp"

#include <arpa/inet.h>
#include <map>
#include <set>

namespace {
constexpr int total_budget_ms = 60000;
constexpr std::size_t dns_output_limit = 256 * 1024;
constexpr std::size_t enrichment_limit = 8;

bool cancelled() { return g_cancel_token.cancelled.load(std::memory_order_relaxed); }

std::string clean(const std::string& value, std::size_t limit = 2048) {
    return InputGuard::sanitize_output(value, limit);
}

std::string trim(std::string value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    value.erase(0, start);
    value.erase(value.find_last_not_of(" \t\r\n") + 1);
    return value;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool ip_literal(const std::string& value) {
    unsigned char address[sizeof(in6_addr)] = {};
    return inet_pton(AF_INET, value.c_str(), address) == 1 ||
           inet_pton(AF_INET6, value.c_str(), address) == 1;
}

std::string whois_message(std::string line) {
    line = lower(trim(line));
    while (!line.empty() && (line.front() == '%' || line.front() == '#'))
        line = trim(line.substr(1));
    return line;
}

bool whois_negative(const std::string& message) {
    return message.rfind("no match for ", 0) == 0 || message == "not found" || message == "not found." ||
           message == "no entries found" ||
           (message.rfind("error:101:", 0) == 0 && message.find("no entries found") != std::string::npos);
}

bool whois_refusal(const std::string& message) {
    for (const auto* prefix : {"whois limit exceeded", "whois query limit exceeded", "query limit exceeded",
            "query rate limit exceeded", "query rate exceeded", "rate limit exceeded", "quota exceeded",
            "query quota exceeded", "too many requests", "error:", "access denied"}) {
        const std::string value(prefix);
        if (message == value || (message.rfind(value, 0) == 0 &&
            (value.back() == ':' || std::isspace(static_cast<unsigned char>(message[value.size()])) ||
             message[value.size()] == ':' || message[value.size()] == '.' || message[value.size()] == '-')))
            return true;
    }
    return false;
}

void diagnostic(const std::string& message, bool optional) {
    (optional ? g_result.warnings : g_result.errors).push_back(clean(message));
}

std::string process_error(const ProcessResult& result, int timeout_ms) {
    if (result.cancelled) return "cancelled";
    if (result.timed_out) return "timed out after " + std::to_string(timeout_ms) + " ms";
    if (result.truncated) return "helper output exceeded the capture limit; response is incomplete";
    if (result.code != 0) {
        std::string message = "helper exited with code " + std::to_string(result.code);
        const auto detail = trim(clean(result.err, 512));
        if (!detail.empty()) message += ": " + detail;
        return message;
    }
    return "";
}

struct Query {
    dns_query::Reply reply;
    bool success = false;
};

class DnsSession {
public:
    explicit DnsSession(int timeout_ms) : timeout_ms_(std::clamp(timeout_ms, 1, 60000)),
        deadline_(std::chrono::steady_clock::now() + std::chrono::milliseconds(total_budget_ms)) {}

    Query query(const std::string& name, const std::string& type, bool optional = false, bool reverse = false) {
        Query query;
        if (cancelled()) return query;
        const auto remaining = remaining_ms();
        if (remaining <= 0) {
            budget_warning(optional);
            return query;
        }
        const auto limit = std::min(timeout_ms_, remaining);
        auto args = arguments(limit);
        if (reverse) args.push_back("-x");
        args.push_back(name);
        args.push_back(type);
        const auto result = run_process(args, limit, &g_cancel_token.cancelled, dns_output_limit);
        if (result.cancelled || cancelled()) return query;
        const auto label = "DNS " + name + " " + type + ": ";
        const auto failure = process_error(result, limit);
        if (!failure.empty()) {
            diagnostic(label + failure, optional);
            return query;
        }
        query.reply = dns_query::parse_reply(result.out);
        if (query.reply.truncated) {
            diagnostic(label + "DNS response has the TC (truncated) flag; complete answer was not obtained", optional);
            return query;
        }
        if (query.reply.malformed || query.reply.status.empty()) {
            diagnostic(label + "malformed response or missing DNS status header", optional);
            return query;
        }
        if (query.reply.status != "NOERROR" && query.reply.status != "NXDOMAIN") {
            diagnostic(label + "server returned " + query.reply.status, optional);
            return query;
        }
        const auto question = reverse ? dns_query::reverse_name(name) : name;
        if (question.empty() || !dns_query::correlate_reply(query.reply, question, type)) {
            diagnostic(label + "response records do not match the question or a valid CNAME chain", optional);
            return query;
        }
        query.success = true;
        for (const auto& record : query.reply.records) save(record);
        return query;
    }

    void transfer(const std::string& zone, const std::string& server) {
        if (cancelled()) return;
        const auto remaining = remaining_ms();
        if (remaining <= 0) { budget_warning(true); return; }
        const auto limit = std::min(timeout_ms_, remaining);
        auto args = arguments(limit);
        args.insert(args.end(), {"axfr", "@" + server, zone});
        const auto result = run_process(args, limit, &g_cancel_token.cancelled, dns_output_limit);
        if (result.cancelled || cancelled()) return;
        const auto label = "AXFR " + zone + " at " + server + ": ";
        const auto reply = dns_query::parse_reply(result.out);
        const auto failure = process_error(result, limit);
        if (failure.empty() && dns_query::complete_transfer(reply, zone)) {
            std::cout << "  transfer completed at " << clean(server) << " (" << reply.records.size() << " records)\n";
            for (const auto& record : reply.records) save(record);
        } else if (!result.timed_out && !result.truncated && result.code == 0 && !reply.malformed && reply.status == "REFUSED") {
            g_result.warnings.push_back(label + "server refused the transfer; this does not establish overall zone security");
            std::cout << "  " << clean(server) << ": transfer refused\n";
        } else {
            diagnostic(label + (failure.empty() ? "transfer not confirmed; missing or invalid complete SOA framing" : failure), true);
            std::cout << "  " << clean(server) << ": transfer outcome unknown\n";
        }
    }

    bool exhausted() const { return remaining_ms() <= 0; }

private:
    int timeout_ms_;
    std::chrono::steady_clock::time_point deadline_;
    std::set<std::string> saved_;
    bool reported_budget_ = false;

    int remaining_ms() const {
        return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline_ - std::chrono::steady_clock::now()).count());
    }

    void budget_warning(bool optional) {
        if (reported_budget_) return;
        reported_budget_ = true;
        diagnostic("DNS total time budget of 60000 ms exhausted; remaining checks were skipped", optional);
    }

    static std::vector<std::string> arguments(int timeout_ms) {
        return {"dig", "-r", "+noall", "+answer", "+comments", "+nomultiline",
            "+time=" + std::to_string(std::max(1, (timeout_ms + 999) / 1000)), "+tries=1"};
    }

    void save(const dns_query::Record& record) {
        const auto text = record.text();
        if (saved_.insert(text).second) g_result.dns_records.push_back(text);
    }
};

void display(const std::string& type, const Query& query) {
    std::cout << "\n  [" << type << "]\n";
    if (!query.success) { std::cout << "  unavailable (see diagnostics)\n"; return; }
    if (query.reply.status == "NXDOMAIN") { std::cout << "  resolver returned NXDOMAIN\n"; return; }
    if (query.reply.records.empty()) { std::cout << "  no matching records (NOERROR)\n"; return; }
    for (const auto& record : query.reply.records) std::cout << "  " << clean(record.text(), dns_output_limit) << '\n';
}
} // namespace

void dns_lookup(const std::string& domain, int timeout_ms) {
    print_header("DNS LOOKUP // " + domain);
    DnsSession session(timeout_ms);
    if (ip_literal(domain)) {
        const auto query = session.query(domain, "PTR", false, true);
        if (!cancelled()) display("PTR", query);
        return;
    }
    if (!dns_query::valid_name(domain)) throw std::runtime_error("invalid DNS domain name: " + clean(domain));

    std::map<std::string, Query> queries;
    for (const auto& type : {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "DS", "DNSKEY"}) {
        if (cancelled()) return;
        auto query = session.query(domain, type);
        display(type, query);
        queries.emplace(type, std::move(query));
        if (session.exhausted()) {
            diagnostic("DNS total time budget exhausted; some planned queries were not completed", false);
            break;
        }
    }
    if (cancelled()) return;

    std::cout << "\n  -- DMARC --\n";
    const auto dmarc = session.query("_dmarc." + domain, "TXT");
    display("DMARC TXT", dmarc);
    if (dmarc.success) std::cout << "  TXT records are reported as observed; DMARC policy validation is not performed.\n";
    if (cancelled()) return;

    std::cout << "\n  -- SPF --\n";
    const auto txt = queries.find("TXT");
    bool found_spf = false;
    std::set<std::string> references;
    if (txt != queries.end() && txt->second.success) {
        for (const auto& record : txt->second.reply.records) {
            if (record.type != "TXT") continue;
            const auto value = dns_query::txt_value(record.value);
            const auto lowered = lower(value);
            if (lowered != "v=spf1" && lowered.rfind("v=spf1 ", 0) != 0) continue;
            found_spf = true;
            std::cout << "  SPF-like TXT observed; policy validation is not performed.\n";
            for (const auto& reference : dns_query::spf_references(value)) {
                if (cancelled()) return;
                if (!dns_query::valid_name(reference)) {
                    diagnostic("SPF reference skipped: invalid or unsupported DNS name " + reference, true);
                    continue;
                }
                const auto key = lower(reference);
                if (references.count(key)) continue;
                if (references.size() >= enrichment_limit) {
                    diagnostic("SPF reference limit of 8 reached; additional references were skipped", true);
                    break;
                }
                references.insert(key);
                display("SPF reference " + reference, session.query(reference, "TXT", true));
            }
        }
        if (!found_spf) std::cout << "  no SPF record observed in the successful TXT response\n";
    } else std::cout << "  SPF could not be checked (TXT query unavailable)\n";
    if (cancelled()) return;

    std::cout << "\n  -- DNSSEC records --\n";
    const auto ds = queries.find("DS"), dnskey = queries.find("DNSKEY");
    if (ds == queries.end() || dnskey == queries.end() || !ds->second.success || !dnskey->second.success)
        std::cout << "  DNSSEC record checks incomplete; validation is not performed\n";
    else {
        const auto matching = [](const Query& query, const std::string& type) {
            return std::any_of(query.reply.records.begin(), query.reply.records.end(), [&](const auto& record) { return record.type == type; });
        };
        std::cout << (matching(ds->second, "DS") || matching(dnskey->second, "DNSKEY") ?
            "  DS/DNSKEY records observed; cryptographic DNSSEC validation is not performed\n" :
            "  no DS/DNSKEY records observed; cryptographic DNSSEC validation is not performed\n");
    }

    std::cout << "\n  -- Reverse DNS --\n";
    std::set<std::string> addresses;
    for (const auto& type : {"A", "AAAA"}) {
        const auto query = queries.find(type);
        if (query == queries.end() || !query->second.success) continue;
        for (const auto& record : query->second.reply.records) {
            if (cancelled()) return;
            if (record.type != type || addresses.count(record.value)) continue;
            if (addresses.size() >= enrichment_limit) {
                diagnostic("PTR enrichment limit of 8 reached; additional addresses were skipped", true);
                break;
            }
            addresses.insert(record.value);
            display("PTR " + record.value, session.query(record.value, "PTR", true, true));
        }
    }
    if (cancelled()) return;

    std::cout << "\n  -- Zone transfer (AXFR) --\n";
    const auto nameservers = queries.find("NS");
    std::set<std::string> servers;
    if (nameservers != queries.end() && nameservers->second.success) {
        for (const auto& record : nameservers->second.reply.records) {
            if (cancelled()) return;
            if (record.type != "NS") continue;
            auto server = record.value;
            if (!server.empty() && server.back() == '.') server.pop_back();
            if (!dns_query::valid_name(server)) { diagnostic("AXFR skipped invalid nameserver " + server, true); continue; }
            const auto key = lower(server);
            if (servers.count(key)) continue;
            if (servers.size() >= enrichment_limit) {
                diagnostic("AXFR nameserver limit of 8 reached; additional nameservers were skipped", true);
                break;
            }
            servers.insert(key);
            session.transfer(domain, server);
        }
        if (servers.empty()) std::cout << "  no nameservers observed; AXFR not attempted\n";
    } else std::cout << "  AXFR not attempted because the NS query was unavailable\n";
    LOG_INFO("dns_lookup", "done domain=" + domain);
}

void whois_lookup(const std::string& target, int timeout_ms) {
    print_header("WHOIS // " + target);
    if (cancelled()) return;
    if (!ip_literal(target) && !dns_query::valid_name(target))
        throw std::runtime_error("invalid WHOIS domain or IP address: " + clean(target));
    const auto limit = std::clamp(timeout_ms, 1, 60000);
    const auto result = run_process({"whois", target}, limit, &g_cancel_token.cancelled, 1024 * 1024);
    const auto previous_records = g_result.whois_records.size();
    std::istringstream lines(result.out);
    std::string line;
    bool semantic_failure = false;
    while (std::getline(lines, line)) {
        line = trim(clean(line, 1024 * 1024));
        if (line.empty()) continue;
        const auto message = whois_message(line);
        const bool negative = whois_negative(message);
        if (!negative && whois_refusal(message)) {
            semantic_failure = true;
            diagnostic("WHOIS " + target + ": server refused the query: " + line, false);
            continue;
        }
        if (!negative && (line.front() == '%' || line.front() == '#')) continue;
        g_result.whois_records.push_back(line);
        const auto colon = line.find(':');
        if (colon == std::string::npos) std::cout << "  " << line << '\n';
        else std::cout << "  [" << line.substr(0, colon) << "] " << trim(line.substr(colon + 1)) << '\n';
    }
    if (result.cancelled || cancelled()) return;
    std::istringstream diagnostics(result.err);
    while (std::getline(diagnostics, line)) {
        line = trim(clean(line, 1024 * 1024));
        const auto message = whois_message(line);
        if (!whois_negative(message) && whois_refusal(message)) {
            semantic_failure = true;
            diagnostic("WHOIS " + target + ": server refused the query: " + line, false);
        }
    }
    const auto failure = process_error(result, limit);
    if (!failure.empty()) diagnostic("WHOIS " + target + ": " + failure, false);
    else if (!semantic_failure && g_result.whois_records.size() == previous_records)
        diagnostic("WHOIS returned no usable data; the response was empty or contained only comments", false);
}

void site_lookup(const std::string& raw) {
    print_header("SITE -> IP // " + raw);
    std::string s=raw;
    for(auto& p:{"https://","http://","www."}) {
        if(s.size()>=strlen(p)&&s.substr(0,strlen(p))==p) s=s.substr(strlen(p));
    }
        for(char sep:{'/',  '?','#',':'}) {auto p=s.find(sep);if(p!=std::string::npos) s=s.substr(0,p);}
        while(!s.empty()&&(s.back()==' '||s.back()==10||s.back()==13)) s.pop_back();
        if(!valid_target(s)){std::cout<<BLOOD_RED<<"  invalid input\n"<<RESET;return;}
        std::cout<<BLOOD_RED<<"  resolving "<<WHITE<<s<<BLOOD_RED<<"...\n"<<RESET;
        std::string ip=resolve(s);
        if(ip.empty()) throw std::runtime_error("could not resolve site hostname: " + s);
        if (!InputGuard::is_valid_ipv4(ip)) throw std::runtime_error("site intelligence currently requires IPv4");
        g_result.resolved_ip = ip;
        std::cout<<BLOOD_RED<<"  "<<WHITE<<s<<BLOOD_RED<<" -> "<<WHITE<<ip<<"\n"<<RESET;
        ip_intel(ip);
}
