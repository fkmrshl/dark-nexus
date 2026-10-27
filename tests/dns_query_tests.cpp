#include "dns_query.hpp"

#include <iostream>
#include <string>

namespace {
int checks = 0;
int failures = 0;

void check(bool success, const std::string& name) {
    ++checks;
    if (!success) { ++failures; std::cerr << "FAIL: " << name << '\n'; }
}

std::string header(const std::string& status = "NOERROR") {
    return ";; ->>HEADER<<- opcode: QUERY, status: " + status + ", id: 1234\n"
           ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n";
}

const std::string soa = "example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 10 3600 600 86400 300\n";

void response_status_and_records() {
    const auto answer = dns_query::parse_reply(header() +
        ";; ANSWER SECTION:\nexample.test. 60 IN CNAME edge.example.test.\n"
        "edge.example.test. 60 IN A 192.0.2.4\n");
    check(answer.status == "NOERROR" && !answer.malformed, "BIND status and records parsed");
    check(answer.records.size() == 2 && answer.records[0].type == "CNAME" && answer.records[1].type == "A",
          "CNAME is distinct from an address record");
    check(answer.records[1].text() == "edge.example.test. 60 IN A 192.0.2.4", "canonical record text");
    const auto empty = dns_query::parse_reply(header());
    check(empty.status == "NOERROR" && empty.records.empty() && !empty.malformed, "NOERROR without data is valid");
    const auto negative = dns_query::parse_reply(header("NXDOMAIN"));
    check(negative.status == "NXDOMAIN" && negative.records.empty() && !negative.malformed, "NXDOMAIN retained as negative DNS status");
    for (const auto& status : {"SERVFAIL", "REFUSED", "FORMERR"}) {
        const auto reply = dns_query::parse_reply(header(status));
        check(reply.status == status && reply.records.empty(), "DNS failure status retained");
    }
    check(dns_query::parse_reply("example.test. 60 IN A 192.0.2.4\n").status.empty(), "headerless answer has no inferred DNS status");
    check(dns_query::parse_reply(header() + header("REFUSED")).malformed, "conflicting status headers rejected");
    check(dns_query::parse_reply(";; ->>HEADER<<- opcode: QUERY, id: 9\n").malformed, "missing status field rejected");
    check(dns_query::parse_reply(";; ->>HEADER<<- opcode: STATUS, status: NOERROR, id: 9\n").malformed, "non-query DNS opcode rejected");
    check(dns_query::parse_reply(header() + ";; flags: rd ra; QUERY: 1\n").malformed, "non-response flag set rejected");
    check(dns_query::parse_reply(header() + "communications error: timed out\n").malformed, "plain diagnostic is not a record");
    const auto diagnostics = dns_query::parse_reply(header() + ";; connection timed out; no servers could be reached\n");
    check(diagnostics.records.empty(), "comment diagnostics never become records");
    const auto truncated = dns_query::parse_reply(header() + ";; flags: qr tc rd ra; QUERY: 1\nexample.test. 60 IN A 192.0.2.4\n");
    check(truncated.truncated, "TC response flag is retained");
    check(!dns_query::parse_reply(header() + "example.test. 60 IN TXT \"tc\"\n").truncated,
          "TXT content cannot set response flags");
    check(!dns_query::parse_reply(header() + "example.test. 60 IN AAAA 2001:db8::4\n").malformed, "IPv6 address parsed");
    for (const auto& invalid : {
            "example.test. 60 IN A alias.example.test.\n", "example.test. 60 IN A 999.0.2.4\n",
            "example.test. 60 IN AAAA :::\n", "example.test. -1 IN A 192.0.2.4\n",
            "example.test. 4294967296 IN A 192.0.2.4\n", "example.test. 60 CH A 192.0.2.4\n",
            "example.test. 60 IN NS @127.0.0.1\n", "example.test. 60 IN NS +trace\n",
            "example.test. 60 IN TXT \"unterminated\n"})
        check(dns_query::parse_reply(header() + invalid).malformed, "malformed RR rejected");
    const auto control = std::string("example.test. 60 IN TXT \"unsafe") + '\033' + "[31m\"\n";
    check(dns_query::parse_reply(header() + control).malformed, "raw control bytes rejected in DNS RDATA");
}

void transfer_framing() {
    const auto body = soa + "www.example.test. 60 IN A 192.0.2.4\n" + soa;
    check(dns_query::complete_transfer(dns_query::parse_reply(header() + body), "example.test"), "framed successful transfer accepted");
    check(dns_query::complete_transfer(dns_query::parse_reply(body), "EXAMPLE.TEST."), "headerless transfer accepted with complete SOA framing");
    check(!dns_query::complete_transfer(dns_query::parse_reply(header("REFUSED") + body), "example.test"), "REFUSED header prevents transfer success");
    check(!dns_query::complete_transfer(dns_query::parse_reply(header() + soa), "example.test"), "single SOA is not a transfer");
    check(!dns_query::complete_transfer(dns_query::parse_reply(header() + soa + soa), "example.test"), "SOA-only response does not confirm transfer");
    check(!dns_query::complete_transfer(dns_query::parse_reply(header() + soa + soa + soa), "example.test"), "three SOA records do not confirm transfer");
    check(!dns_query::complete_transfer(dns_query::parse_reply(header() + soa + soa + "www.example.test. 60 IN A 192.0.2.4\n" + soa), "example.test"), "middle SOA invalidates transfer framing");
    check(!dns_query::complete_transfer(dns_query::parse_reply(header() + soa + "www.example.test. 60 IN A 192.0.2.4\n"), "example.test"), "missing closing SOA rejected");
    const auto changed = "example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 11 3600 600 86400 300\n";
    check(!dns_query::complete_transfer(dns_query::parse_reply(soa + "www.example.test. 60 IN A 192.0.2.4\n" + changed), "example.test"), "mismatching SOA serial rejected");
    check(!dns_query::complete_transfer(dns_query::parse_reply(body), "other.test"), "wrong SOA owner rejected");
    check(!dns_query::complete_transfer(dns_query::parse_reply(soa + "outside.test. 60 IN A 192.0.2.4\n" + soa), "example.test"), "out-of-zone data rejected");
    check(!dns_query::complete_transfer(dns_query::parse_reply(header() + ";; flags: qr tc; QUERY: 1\n" + body), "example.test"), "TC prevents transfer success");
    check(!dns_query::complete_transfer(dns_query::parse_reply(";; Transfer failed.\n"), "example.test"), "transfer diagnostic is not success");
}

void question_correlation() {
    auto answer = dns_query::parse_reply(header() + "example.test. 60 IN CNAME edge.example.test.\nedge.example.test. 60 IN A 192.0.2.4\n");
    check(dns_query::correlate_reply(answer, "EXAMPLE.TEST", "A") && answer.records.size() == 2,
          "matching question and reachable alias address accepted");
    auto unrelated = dns_query::parse_reply(header() + "outside.test. 60 IN A 192.0.2.4\n");
    check(!dns_query::correlate_reply(unrelated, "example.test", "A"), "unrelated address answer rejected");
    auto unrelated_txt = dns_query::parse_reply(header() + "outside.test. 60 IN TXT \"v=spf1 include:other.test\"\n");
    check(!dns_query::correlate_reply(unrelated_txt, "example.test", "TXT"), "unrelated SPF data rejected");
    auto cycle = dns_query::parse_reply(header() + "example.test. 60 IN CNAME edge.example.test.\nedge.example.test. 60 IN CNAME example.test.\n");
    check(!dns_query::correlate_reply(cycle, "example.test", "A"), "CNAME cycle rejected");
    auto conflicting = dns_query::parse_reply(header() + "example.test. 60 IN CNAME one.example.test.\nexample.test. 60 IN CNAME two.example.test.\n");
    check(!dns_query::correlate_reply(conflicting, "example.test", "A"), "conflicting CNAME targets rejected");
    auto alias_and_address = dns_query::parse_reply(header() + "example.test. 60 IN CNAME edge.example.test.\nexample.test. 60 IN A 192.0.2.4\n");
    check(!dns_query::correlate_reply(alias_and_address, "example.test", "A"), "CNAME owner cannot also supply address data");
    auto impossible_negative = dns_query::parse_reply(header("NXDOMAIN") + "example.test. 60 IN A 192.0.2.4\n");
    check(!dns_query::correlate_reply(impossible_negative, "example.test", "A"), "NXDOMAIN with terminal answer rejected");
    auto alias_negative = dns_query::parse_reply(header("NXDOMAIN") + "example.test. 60 IN CNAME missing.example.test.\n");
    check(dns_query::correlate_reply(alias_negative, "example.test", "A"), "NXDOMAIN with CNAME-only chain accepted");
    auto long_chain = header();
    for (int i = 0; i < 18; ++i)
        long_chain += "alias" + std::to_string(i) + ".test. 60 IN CNAME alias" + std::to_string(i + 1) + ".test.\n";
    auto over_limit = dns_query::parse_reply(long_chain);
    check(!dns_query::correlate_reply(over_limit, "alias0.test", "A"), "CNAME chain depth bounded");
    check(dns_query::reverse_name("192.0.2.4") == "4.2.0.192.in-addr.arpa", "IPv4 PTR owner derived from bytes");
    check(dns_query::reverse_name("2001:db8::1") ==
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "IPv6 PTR nibble owner derived from bytes");
    auto ptr = dns_query::parse_reply(header() + "4.2.0.192.in-addr.arpa. 60 IN PTR host.example.test.\n");
    check(dns_query::correlate_reply(ptr, dns_query::reverse_name("192.0.2.4"), "PTR"), "PTR owner correlated to reverse question");
    auto foreign_ptr = dns_query::parse_reply(header() + "5.2.0.192.in-addr.arpa. 60 IN PTR host.example.test.\n");
    check(!dns_query::correlate_reply(foreign_ptr, dns_query::reverse_name("192.0.2.4"), "PTR"), "foreign PTR owner rejected");
}

void names_and_spf() {
    for (const auto& name : {"example.test", "EXAMPLE.test.", "ns-1.example.test", "localhost"})
        check(dns_query::valid_name(name), "ordinary DNS name accepted");
    for (const auto& name : {"", "@127.0.0.1", "+trace", "-option", "bad..test", "bad-.test", "name%{d}.test", "bad name.test", "_dmarc.example.test"})
        check(!dns_query::valid_name(name), "unsafe or unsupported reference name rejected");
    check(dns_query::valid_name("_dmarc.example.test", true), "service-owner labels supported explicitly");
    check(!dns_query::valid_name(std::string(64, 'a') + ".test"), "overlong label rejected");
    const auto txt = dns_query::txt_value("\"v=spf1 \" \"include:mail.example.test redirect=other.example.test ~all\"");
    check(txt == "v=spf1 include:mail.example.test redirect=other.example.test ~all", "TXT chunks concatenate before SPF parsing");
    const auto references = dns_query::spf_references(txt);
    check(references.size() == 2 && references[0] == "mail.example.test" && references[1] == "other.example.test", "SPF include and redirect extracted");
    const auto hostile = dns_query::spf_references("v=spf1 include:@127.0.0.1 include:+trace redirect=-option ~all");
    check(hostile.size() == 3, "unsafe references remain visible for explicit diagnostics");
    for (const auto& reference : hostile) check(!dns_query::valid_name(reference), "unsafe SPF reference cannot be queried");
    check(dns_query::txt_value("\"v=spf1\\032-all\"") == "v=spf1 -all", "DNS decimal escapes decoded");
    check(dns_query::txt_value("\"unterminated").empty(), "unterminated TXT is not a policy");
}

void presentation_rdata() {
    for (const auto& mailbox : {"host\\.master.example.test.", "host\\046master.example.test.",
            "host\\032master.example.test.", "host\\ master.example.test.", "."}) {
        const auto reply = dns_query::parse_reply(header() + "example.test. 60 IN SOA ns.example.test. " + mailbox + " 1 3600 600 86400 60\n");
        check(!reply.malformed && reply.records.size() == 1, "SOA escaped mailbox presentation accepted");
    }
    for (const auto& mailbox : {"host\\999master.example.test.", "host\\12master.example.test.",
            "host..master.example.test.", "host\\"}) {
        const auto reply = dns_query::parse_reply(header() + "example.test. 60 IN SOA ns.example.test. " + mailbox + " 1 3600 600 86400 60\n");
        check(reply.malformed, "invalid SOA mailbox escape rejected");
    }
    const auto oversized_label = std::string(64, 'x') + ".example.test.";
    check(dns_query::parse_reply(header() + "example.test. 60 IN SOA ns.example.test. " + oversized_label + " 1 3600 600 86400 60\n").malformed,
          "SOA mailbox decoded label length bounded");
    for (const auto& txt : {"\"v=spf1\\256-all\"", "\"v=spf1\\999-all\"", "\"v=spf1\\12-all\""}) {
        check(dns_query::parse_reply(header() + "example.test. 60 IN TXT " + txt + "\n").malformed,
              "invalid TXT decimal escape rejected as malformed");
        check(dns_query::txt_value(txt).empty(), "invalid TXT decimal escape is not interpreted as SPF");
    }
    const auto octet = dns_query::txt_value("\"\\255\"");
    check(octet.size() == 1 && static_cast<unsigned char>(octet[0]) == 255, "TXT decimal octet upper bound accepted");
    for (const auto& caa : {"0 issue \"ca.example.test\"", "128 issue ca.example.test", "255 Future123 \"\"",
            "0 iodef \"mailto:host@example.test; parameter=value\"", "0 issue ca\\032issuer", "0 issue \"escaped\\034quote\""})
        check(!dns_query::parse_reply(header() + "example.test. 60 IN CAA " + caa + "\n").malformed, "valid CAA presentation accepted");
    for (const auto& caa : {"256 issue \"ca.example.test\"", "-1 issue \"ca.example.test\"", "0 bad-tag \"ca.example.test\"",
            "0 issue \"unterminated", "0 issue two values", "0 issue \"bad\\999value\"", "0 issue"})
        check(dns_query::parse_reply(header() + "example.test. 60 IN CAA " + caa + "\n").malformed, "malformed CAA presentation rejected");
    for (const auto& ds : {"12345 13 2 aBcDeF", "65535 RSASHA256 255 AB CD EF", "0 FUTUREALGORITHM 0 ( ABCD 1234 )"})
        check(!dns_query::parse_reply(header() + "example.test. 60 IN DS " + ds + "\n").malformed, "valid DS numeric or mnemonic presentation accepted");
    for (const auto& ds : {"65536 13 2 ABCDEF", "1 256 2 ABCDEF", "1 13 256 ABCDEF", "1 13 2 ABC",
            "1 13 2 XYZ123", "1 13 2", "1 13 2 ( ABCD", "1 -1 2 ABCDEF"})
        check(dns_query::parse_reply(header() + "example.test. 60 IN DS " + ds + "\n").malformed, "malformed DS presentation rejected");
    for (const auto& dnskey : {"257 3 13 AQIDBA==", "65535 255 ECDSAP256SHA256 ( AQID BA== )",
            "0 0 FUTUREALGORITHM AQID", "256 3 RSASHA256 AQID BA=="})
        check(!dns_query::parse_reply(header() + "example.test. 60 IN DNSKEY " + dnskey + "\n").malformed, "valid DNSKEY numeric or mnemonic presentation accepted");
    for (const auto& dnskey : {"65536 3 13 AQID", "257 256 13 AQID", "257 3 256 AQID", "257 3 13 ***!",
            "257 3 13 A", "257 3 13 AQ=ID", "257 3 13 AQID===", "257 3 13"})
        check(dns_query::parse_reply(header() + "example.test. 60 IN DNSKEY " + dnskey + "\n").malformed, "malformed DNSKEY presentation rejected");
    check(!dns_query::valid_name("host\\.master.example.test."), "SOA mailbox support does not relax helper argument validation");
}
} // namespace

int main() {
    response_status_and_records();
    transfer_framing();
    question_correlation();
    names_and_spf();
    presentation_rdata();
    std::cout << checks << " DNS parser checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
