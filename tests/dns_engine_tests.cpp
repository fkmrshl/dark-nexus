// Exercise the real c-ares engine against a loopback UDP fixture. Including the
// implementation also permits malformed wire replies without external traffic.
#include "../src/dns_engine.cpp"

#include <fstream>
#include <iostream>
#include <sys/time.h>

ScanResult g_result;
CancellationToken g_cancel_token;
std::mutex g_print_mtx, g_result_mtx;
std::string safe_exec(const std::vector<std::string>&, int) {
    throw std::logic_error("DNS engine tests must never execute helpers");
}

namespace {
using Bytes = std::vector<unsigned char>;
int checks = 0;
void check(bool value, const char* label) {
    ++checks;
    if (!value) throw std::runtime_error(label);
}
void integer(Bytes& bytes, unsigned value) {
    bytes.push_back(static_cast<unsigned char>(value >> 8));
    bytes.push_back(static_cast<unsigned char>(value));
}
void name(Bytes& bytes, const std::string& host) {
    std::size_t begin = 0;
    while (begin < host.size()) {
        const auto dot = host.find('.', begin);
        const auto end = dot == std::string::npos ? host.size() : dot;
        bytes.push_back(static_cast<unsigned char>(end - begin));
        bytes.insert(bytes.end(), host.begin() + begin, host.begin() + end);
        if (dot == std::string::npos) break;
        begin = dot + 1;
    }
    bytes.push_back(0);
}
struct RR { std::string owner; int type; Bytes value; };
RR address(const std::string& host, int type) {
    RR rr{host, type, Bytes(type == ns_t_a ? 4 : 16)};
    inet_pton(type == ns_t_a ? AF_INET : AF_INET6,
              type == ns_t_a ? "192.0.2.10" : "2001:db8::10", rr.value.data());
    return rr;
}
RR alias(const std::string& host, const std::string& target) {
    RR rr{host, ns_t_cname, {}}; name(rr.value, target); return rr;
}
Bytes reply(const std::string& host, int type, int status, const std::vector<RR>& records,
            unsigned flags = 0x8180) {
    Bytes bytes;
    integer(bytes, 123); integer(bytes, flags | status);
    integer(bytes, 1); integer(bytes, records.size()); integer(bytes, 0); integer(bytes, 0);
    name(bytes, host); integer(bytes, type); integer(bytes, 1);
    for (const auto& rr : records) {
        name(bytes, rr.owner); integer(bytes, rr.type); integer(bytes, 1);
        integer(bytes, 0); integer(bytes, 60); integer(bytes, rr.value.size());
        bytes.insert(bytes.end(), rr.value.begin(), rr.value.end());
    }
    return bytes;
}

class LocalDns {
    int fd_ = -1;
    std::atomic<bool> stop_{false};
    std::thread worker_;
public:
    std::atomic<bool> refuse_negative{false};
    std::atomic<bool> silent{false};
    std::atomic<int> requests{0};
    std::string endpoint;
    LocalDns() {
        fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd_ < 0) throw std::runtime_error("socket fixture failed");
        sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            close(fd_); throw std::runtime_error("loopback bind fixture failed");
        }
        socklen_t length = sizeof(local);
        getsockname(fd_, reinterpret_cast<sockaddr*>(&local), &length);
        endpoint = "127.0.0.1:" + std::to_string(ntohs(local.sin_port));
        timeval timeout{0, 50000};
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        worker_ = std::thread([this] {
            while (!stop_) {
                unsigned char packet[4096]{};
                sockaddr_in peer{}; socklen_t length = sizeof(peer);
                const auto count = recvfrom(fd_, packet, sizeof(packet), 0, reinterpret_cast<sockaddr*>(&peer), &length);
                if (count < 17) continue;
                ++requests;
                if (silent) continue;
                std::string host;
                std::size_t offset = 12;
                while (offset < static_cast<std::size_t>(count) && packet[offset]) {
                    const auto size = packet[offset++];
                    if (size > 63 || offset + size >= static_cast<std::size_t>(count)) break;
                    if (!host.empty()) host += '.';
                    host.append(reinterpret_cast<char*>(packet + offset), size); offset += size;
                }
                if (++offset + 4 > static_cast<std::size_t>(count)) continue;
                const int type = packet[offset] * 256 + packet[offset + 1];
                if (host.rfind("timeout.", 0) == 0) continue;
                int status = 0;
                std::vector<RR> records;
                if (host.size() >= 8 && host.compare(host.size() - 8, 8, ".invalid") == 0)
                    status = refuse_negative ? 2 : 3;
                else if (host == "negative.test") status = 3;
                else if (host == "error.test" || (host == "partial.test" && type == ns_t_aaaa)) status = 2;
                else if (host == "nodata.test" || (host == "v6.test" && type == ns_t_a)) {}
                else if (host == "bad-cname.test") records.push_back(alias("foreign.test", "edge.test"));
                else if (host == "alias.test") {
                    records.push_back(alias(host, "edge.test"));
                    if (type == ns_t_a || type == ns_t_aaaa) records.push_back(address("edge.test", type));
                } else if (type == ns_t_a || type == ns_t_aaaa)
                    records.push_back(address(host == "foreign.test" ? "unrelated.test" : host, type));
                auto output = reply(host, type, status, records);
                output[0] = packet[0]; output[1] = packet[1];
                sendto(fd_, output.data(), output.size(), 0, reinterpret_cast<sockaddr*>(&peer), length);
            }
        });
    }
    ~LocalDns() { stop_ = true; if (worker_.joinable()) worker_.join(); if (fd_ >= 0) close(fd_); }
};

template<class Function> bool throws(Function fn) {
    try { fn(); } catch (const std::exception&) { return true; } return false;
}
} // namespace

int main() {
    char pattern[] = "/tmp/dark-nexus-dns-engine-XXXXXX";
    const char* temporary = mkdtemp(pattern);
    if (!temporary) return 1;
    const std::filesystem::path root(temporary);
    try {
        LocalDns server, unhealthy;
        unhealthy.refuse_negative = true;
        auto& engine = DnsEngine::get();
        const auto file = root / "resolvers.txt";
        auto write = [&](const std::string& data) { std::ofstream(file) << data; };
        write(server.endpoint + '\n');
        engine.load_resolvers(file.string());
        check(engine.resolver_count() == 1, "loopback resolver passed positive and negative health checks");
        auto data = engine.resolve_batch_checked({"dual.test", "v6.test", "negative.test", "nodata.test",
            "partial.test", "error.test", "alias.test", "foreign.test"}, 8, 1500);
        check(!data.at("dual.test").failed && data.at("dual.test").ipv4.size() == 1 && data.at("dual.test").ipv6.size() == 1,
              "A and AAAA returned together");
        check(!data.at("v6.test").failed && data.at("v6.test").ipv4.empty() && !data.at("v6.test").ipv6.empty(), "AAAA-only host is discovered");
        check(!data.at("negative.test").failed && data.at("negative.test").ipv4.empty(), "NXDOMAIN is a successful negative");
        check(!data.at("nodata.test").failed && data.at("nodata.test").ipv6.empty(), "NODATA is a successful negative");
        check(data.at("partial.test").failed && !data.at("partial.test").ipv4.empty() && data.at("partial.test").ipv6.empty(), "one-family failure preserves the other family");
        check(data.at("error.test").failed && !data.at("error.test").error.empty(), "SERVFAIL is an operational failure");
        check(!data.at("alias.test").failed && !data.at("alias.test").ipv4.empty(), "correlated CNAME chain accepted");
        check(data.at("foreign.test").failed && data.at("foreign.test").ipv4.empty(), "unrelated address owner rejected");
        check(engine.resolve_cname("alias.test") == "edge.test", "CNAME enrichment validates the question and owner");
        check(engine.resolve_cname("bad-cname.test").empty(), "unrelated CNAME enrichment rejected");
        std::vector<std::string> slow;
        for (int i = 0; i < 20; ++i) slow.push_back("timeout." + std::to_string(i) + ".test");
        const auto start = std::chrono::steady_clock::now();
        data = engine.resolve_batch_checked(slow, 1, 80);
        check(std::chrono::steady_clock::now() - start < std::chrono::seconds(1), "whole-batch deadline is bounded");
        check(data.size() == slow.size() && std::all_of(data.begin(), data.end(), [](const auto& entry) { return entry.second.failed; }), "submitted and unsubmitted queries both report failure");
        data = engine.resolve_batch_checked({"error.test", "timeout.mixed.test"}, 4, 80);
        check(data.at("error.test").error.find(ares_strerror(ARES_ESERVFAIL)) != std::string::npos,
              "completed SERVFAIL diagnosis survives another host reaching the batch deadline");
        std::thread cancel([] { usleep(50000); g_cancel_token.cancelled = true; });
        const auto cancelled_at = std::chrono::steady_clock::now();
        const auto addresses = engine.resolve_aaaa("timeout.cancel.test");
        cancel.join();
        check(addresses.empty() && std::chrono::steady_clock::now() - cancelled_at < std::chrono::milliseconds(500), "AAAA lookup cancels promptly");
        const auto count = server.requests.load();
        data = engine.resolve_batch_checked({"dual.test"}, 1, 1000);
        check(data.at("dual.test").failed && server.requests == count, "pre-cancelled lookup makes no requests");
        g_cancel_token.cancelled = false;
        for (const auto& content : {std::string(""), std::string("# empty\n"), std::string("999.1.1.1\n"), std::string("127.0.0.1:0\n")}) {
            write(content);
            check(throws([&] { engine.load_resolvers(file.string()); }), "empty or invalid resolver file fails explicitly");
        }
        const auto fifo = root / "resolvers.fifo"; mkfifo(fifo.c_str(), 0600);
        check(throws([&] { engine.load_resolvers(fifo.string()); }), "FIFO resolver input does not block");
        check(throws([&] { engine.load_resolvers(root.string()); }), "directory resolver input rejected");
        write(std::string(2 * 1024 * 1024 + 1, 'x'));
        check(throws([&] { engine.load_resolvers(file.string()); }), "oversized resolver file rejected");
        write(unhealthy.endpoint + '\n');
        check(throws([&] { engine.load_resolvers(file.string()); }), "SERVFAIL on negative health probe is not healthy");
        write(server.endpoint + '\n' + unhealthy.endpoint + '\n');
        engine.load_resolvers(file.string());
        check(engine.resolver_count() == 1, "failed health resolvers never reenter the selected pool");
        unhealthy.silent = true;
        write(unhealthy.endpoint + '\n');
        std::thread cancel_health([] { usleep(50000); g_cancel_token.cancelled = true; });
        const auto health_at = std::chrono::steady_clock::now();
        const bool health_cancelled = throws([&] { engine.load_resolvers(file.string()); });
        cancel_health.join();
        check(health_cancelled && std::chrono::steady_clock::now() - health_at < std::chrono::milliseconds(500),
              "resolver health checks cancel promptly");
        g_cancel_token.cancelled = false;

        auto bytes = reply("wire.test", ns_t_a, 0, {address("wire.test", ns_t_a)});
        check(!parse_checked_address_reply(ARES_SUCCESS, bytes.data(), bytes.size(), "wire.test", ns_t_a).failed, "valid wire record parsed");
        bytes = reply("wire.test", ns_t_a, 0, {address("wire.test", ns_t_a)}, 0x8380);
        check(parse_checked_address_reply(ARES_SUCCESS, bytes.data(), bytes.size(), "wire.test", ns_t_a).failed, "TC reply rejected");
        bytes = reply("different.test", ns_t_a, 0, {address("different.test", ns_t_a)});
        check(parse_checked_address_reply(ARES_SUCCESS, bytes.data(), bytes.size(), "wire.test", ns_t_a).failed, "question mismatch rejected");
        bytes = reply("wire.test", ns_t_a, 3, {address("wire.test", ns_t_a)});
        check(parse_checked_address_reply(ARES_ENOTFOUND, bytes.data(), bytes.size(), "wire.test", ns_t_a).failed, "NXDOMAIN with positive data rejected");
        bytes.resize(5);
        check(parse_checked_address_reply(ARES_SUCCESS, bytes.data(), bytes.size(), "wire.test", ns_t_a).failed, "malformed wire packet rejected");
        std::filesystem::remove_all(root);
        std::cout << checks << " DNS engine checks passed (loopback fixtures only)\n";
        return 0;
    } catch (const std::exception& error) {
        g_cancel_token.cancelled = false;
        std::filesystem::remove_all(root);
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
