#include "../include/dns_engine.hpp"
#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"
#include <ares.h>
#include <curl/curl.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <random>
#include <new>
#include <map>
#include <set>
#include <stdexcept>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>

#include "dns_response.hpp"

#if __has_include(<liburing.h>)
#include <liburing.h>
#define DNS_HAS_URING 1
#else
#define DNS_HAS_URING 0
#endif

static const std::vector<std::string> ALL_RESOLVERS = {
    "8.8.8.8","8.8.4.4",
    "1.1.1.1","1.0.0.1",
    "9.9.9.9","149.112.112.112",
    "208.67.222.222","208.67.220.220",
    "8.26.56.26","8.20.247.20",
    "4.2.2.1","4.2.2.2","4.2.2.3","4.2.2.4",
    "64.6.64.6","64.6.65.6",
};

static constexpr int N_SHARDS    = 64;
static constexpr int N_CHANNELS  = 16;   
static constexpr int RESOLVERS_PER_CHANNEL = 4;
static constexpr int MAX_TOTAL_CONCURRENCY = 32000;
static constexpr int MAX_PER_CHANNEL_CONCURRENCY = 1000;
static constexpr size_t CUSTOM_HEALTHCHECK_MAX_TESTED = 4096;
static constexpr size_t CUSTOM_HEALTHCHECK_TARGET_HEALTHY = 256;
static constexpr int CUSTOM_HEALTHCHECK_CONCURRENCY = 128;
static constexpr int RESOLVER_HEALTH_TIMEOUT_MS = 1000;

static std::vector<std::string> g_custom_resolvers;
static std::mutex                g_custom_resolvers_mtx;
static std::once_flag            g_default_resolvers_once;
static std::mutex                g_default_resolvers_mtx;
static std::vector<std::string>  g_default_resolvers_checked;
static bool g_default_resolvers_ready = false;

static const std::vector<std::string>& default_resolver_pool();

static int clamp_total_concurrency(int c) {
    return std::clamp(c, 1, MAX_TOTAL_CONCURRENCY);
}

static int total_to_per_channel_concurrency(int total_concurrency, int n_ch) {
    int per_channel = (total_concurrency + n_ch - 1) / n_ch;
    return std::clamp(per_channel, 1, MAX_PER_CHANNEL_CONCURRENCY);
}

static std::vector<std::string> resolver_pool_snapshot() {
    std::vector<std::string> custom;
    {
        std::lock_guard<std::mutex> lk(g_custom_resolvers_mtx);
        custom = g_custom_resolvers;
    }
    if (!custom.empty()) { return custom; }
    return default_resolver_pool();
}

namespace {
class AresChannelGuard {
public:
    ares_channel channel = nullptr;
    ~AresChannelGuard() { if (channel) ares_destroy(channel); }
};

std::string dns_name_key(std::string name) {
    if (!name.empty() && name.back() == '.') name.pop_back();
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return name;
}

struct CheckedFamily {
    std::vector<std::string> addresses;
    bool completed = false, failed = false;
    std::string error;
};

bool negative_status(int status) { return status == ARES_ENODATA || status == ARES_ENOTFOUND; }

CheckedFamily parse_checked_address_reply(int status, const unsigned char* packet,
                                         int length, const std::string& name, int type) {
    CheckedFamily result;
    result.completed = status != ARES_EDESTRUCTION && status != ARES_ECANCELLED;
    if (status != ARES_SUCCESS && !negative_status(status)) {
        result.failed = true;
        result.error = ares_strerror(status);
        return result;
    }
    if ((!packet || length <= 0) && negative_status(status)) return result;
    ares_dns_record_t* raw = nullptr;
    const int parsed = packet && length > 0 ?
        ares_dns_parse(packet, static_cast<std::size_t>(length), 0, &raw) : ARES_EBADRESP;
    std::unique_ptr<ares_dns_record_t, decltype(&ares_dns_record_destroy)> message(raw, ares_dns_record_destroy);
    auto fail = [&](const char* error) {
        result.addresses.clear(); result.failed = true; result.error = error;
        return result;
    };
    if (parsed != ARES_SUCCESS || !message) return fail("Malformed DNS response");
    const auto flags = ares_dns_record_get_flags(message.get());
    if (!(flags & ARES_FLAG_QR) || (flags & ARES_FLAG_TC) ||
        ares_dns_record_get_opcode(message.get()) != ARES_OPCODE_QUERY)
        return fail("Invalid or truncated DNS response header");
    const auto rcode = ares_dns_record_get_rcode(message.get());
    if (rcode != ARES_RCODE_NOERROR && rcode != ARES_RCODE_NXDOMAIN)
        return fail("DNS server returned an unsuccessful response");
    const char* question = nullptr;
    ares_dns_rec_type_t question_type{};
    ares_dns_class_t question_class{};
    if (ares_dns_record_query_cnt(message.get()) != 1 ||
        ares_dns_record_query_get(message.get(), 0, &question, &question_type, &question_class) != ARES_SUCCESS ||
        !question || dns_name_key(question) != dns_name_key(name) ||
        static_cast<int>(question_type) != type || question_class != ARES_CLASS_IN)
        return fail("DNS response question does not match the request");
    const auto count = ares_dns_record_rr_cnt(message.get(), ARES_SECTION_ANSWER);
    if (count > 4096) return fail("DNS answer record limit exceeded");
    std::map<std::string, std::string> aliases;
    for (std::size_t i = 0; i < count; ++i) {
        const auto* record = ares_dns_record_rr_get_const(message.get(), ARES_SECTION_ANSWER, i);
        if (!record || ares_dns_rr_get_type(record) != ARES_REC_TYPE_CNAME) continue;
        const auto* owner = ares_dns_rr_get_name(record);
        const auto* target = ares_dns_rr_get_str(record, ARES_RR_CNAME_CNAME);
        if (ares_dns_rr_get_class(record) != ARES_CLASS_IN || !owner || !target || !*target)
            return fail("Invalid DNS CNAME record");
        const auto key = dns_name_key(owner), value = dns_name_key(target);
        const auto previous = aliases.find(key);
        if (previous != aliases.end() && previous->second != value) return fail("Conflicting DNS CNAME records");
        aliases[key] = value;
    }
    std::set<std::string> reachable;
    auto cursor = dns_name_key(name);
    for (std::size_t hops = 0;; ++hops) {
        if (!reachable.insert(cursor).second) return fail("DNS CNAME loop");
        const auto alias = aliases.find(cursor);
        if (alias == aliases.end()) break;
        if (hops >= 16) return fail("DNS CNAME chain limit exceeded");
        cursor = alias->second;
    }
    for (std::size_t i = 0; i < count; ++i) {
        const auto* record = ares_dns_record_rr_get_const(message.get(), ARES_SECTION_ANSWER, i);
        if (!record) return fail("Invalid DNS answer record");
        const auto record_type = ares_dns_rr_get_type(record);
        if (static_cast<int>(record_type) != type && record_type != ARES_REC_TYPE_CNAME) continue;
        const char* owner = ares_dns_rr_get_name(record);
        if (!owner || !reachable.count(dns_name_key(owner)) || ares_dns_rr_get_class(record) != ARES_CLASS_IN)
            return fail("DNS answer owner does not match the request");
        if (record_type == ARES_REC_TYPE_CNAME) continue;
        if (rcode == ARES_RCODE_NXDOMAIN || aliases.count(dns_name_key(owner)))
            return fail("DNS answer contradicts its negative response or CNAME");
        char address[INET6_ADDRSTRLEN]{};
        const void* bytes = type == ns_t_a ? static_cast<const void*>(ares_dns_rr_get_addr(record, ARES_RR_A_ADDR)) :
                                           static_cast<const void*>(ares_dns_rr_get_addr6(record, ARES_RR_AAAA_ADDR));
        if (!bytes || !inet_ntop(type == ns_t_a ? AF_INET : AF_INET6, bytes, address, sizeof(address)))
            return fail("Invalid DNS address record");
        result.addresses.emplace_back(address);
    }
    std::sort(result.addresses.begin(), result.addresses.end());
    result.addresses.erase(std::unique(result.addresses.begin(), result.addresses.end()), result.addresses.end());
    return result;
}

struct CheckedContext {
    CheckedFamily* family;
    std::atomic<int>* pending;
    const std::string* name;
    int type;
};

void checked_address_callback(void* argument, int status, int, unsigned char* packet, int length) noexcept {
    std::unique_ptr<CheckedContext> context(static_cast<CheckedContext*>(argument));
    try {
        *context->family = parse_checked_address_reply(status, packet, length, *context->name, context->type);
    } catch (...) {
        // Do not unwind through c-ares' C callback frame.
        context->family->completed = true;
        context->family->failed = true;
    }
    context->pending->fetch_sub(1, std::memory_order_release);
}
} // namespace

struct CnameCtx {
    std::string*      out;
    std::atomic<int>* pending;
    const std::string* name;
};

static std::string parse_first_cname_reply(unsigned char* abuf, int alen, const std::string& name) {
    if (!abuf || alen <= 0) { return ""; }

    ares_dns_record_t* raw_record = nullptr;
    if (ares_dns_parse(abuf, (size_t)alen, 0, &raw_record) != ARES_SUCCESS || !raw_record) {
        if (raw_record) { ares_dns_record_destroy(raw_record); }
        return "";
    }
    std::unique_ptr<ares_dns_record_t, decltype(&ares_dns_record_destroy)>
        record(raw_record, ares_dns_record_destroy);
    const char* question = nullptr;
    ares_dns_rec_type_t question_type{};
    ares_dns_class_t question_class{};
    const auto flags = ares_dns_record_get_flags(record.get());
    if (!(flags & ARES_FLAG_QR) || flags & ARES_FLAG_TC ||
        ares_dns_record_get_opcode(record.get()) != ARES_OPCODE_QUERY ||
        ares_dns_record_get_rcode(record.get()) != ARES_RCODE_NOERROR ||
        ares_dns_record_query_cnt(record.get()) != 1 ||
        ares_dns_record_query_get(record.get(), 0, &question, &question_type, &question_class) != ARES_SUCCESS ||
        !question || dns_name_key(question) != dns_name_key(name) ||
        question_type != ARES_REC_TYPE_CNAME || question_class != ARES_CLASS_IN) return "";
    std::map<std::string, std::string> aliases;
    size_t answer_count = ares_dns_record_rr_cnt(record.get(), ARES_SECTION_ANSWER);
    if (answer_count > 4096) return "";
    for (size_t i = 0; i < answer_count; i++) {
        const ares_dns_rr_t* rr =
            ares_dns_record_rr_get_const(record.get(), ARES_SECTION_ANSWER, i);
        if (!rr) { continue; }
        if (ares_dns_rr_get_type(rr) != ARES_REC_TYPE_CNAME) { continue; }
        if (ares_dns_rr_get_class(rr) != ARES_CLASS_IN) return "";
        const char* owner = ares_dns_rr_get_name(rr);
        const char* cname = ares_dns_rr_get_str(rr, ARES_RR_CNAME_CNAME);
        if (!owner || !cname || !dns_response::valid_name(owner) || !dns_response::valid_name(cname)) return "";
        const auto key = dns_name_key(owner), target = dns_name_key(cname);
        if (aliases.count(key) && aliases[key] != target) return "";
        aliases[key] = target;
    }
    std::set<std::string> reachable;
    auto cursor = dns_name_key(name);
    for (std::size_t hops = 0;; ++hops) {
        if (!reachable.insert(cursor).second) return "";
        const auto alias = aliases.find(cursor);
        if (alias == aliases.end()) break;
        if (hops >= 16) return "";
        cursor = alias->second;
    }
    for (const auto& alias : aliases) if (!reachable.count(alias.first)) return "";
    const auto first = aliases.find(dns_name_key(name));
    return first == aliases.end() ? "" : first->second;
}

static void ares_cname_cb(void* arg, int status, int, unsigned char* abuf, int alen) noexcept {
    std::unique_ptr<CnameCtx> ctx(static_cast<CnameCtx*>(arg));
    try { if (status == ARES_SUCCESS && abuf && alen > 0) {
        std::string cname = parse_first_cname_reply(abuf, alen, *ctx->name);
        if (!cname.empty()) { *ctx->out = std::move(cname); }
    } } catch (...) {}
    ctx->pending->fetch_sub(1, std::memory_order_release);
}

static void poll_loop_step(ares_channel ch) {
    ares_socket_t socks[ARES_GETSOCK_MAXNUM]{};
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    int bitmask = ares_getsock(ch, socks, ARES_GETSOCK_MAXNUM);
#pragma GCC diagnostic pop

    if (bitmask == 0) {
        ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        return;
    }

    struct timeval tvbuf{};
    struct timeval* tvp = ares_timeout(ch, nullptr, &tvbuf);
    int tms = 5;
    if (tvp) {
        tms = tvp->tv_sec * 1000 + tvp->tv_usec / 1000;
        if (tms < 1)   { tms = 1; }
        if (tms > 10)  { tms = 10; }
    }

    int nfds = 0;
    struct pollfd pfds[ARES_GETSOCK_MAXNUM]{};
    for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
        bool rd = ARES_GETSOCK_READABLE(bitmask, i);
        bool wr = ARES_GETSOCK_WRITABLE(bitmask, i);
        if (!rd && !wr) { continue; }
        pfds[nfds].fd     = socks[i];
        pfds[nfds].events = (rd ? POLLIN : 0) | (wr ? POLLOUT : 0);
        nfds++;
    }

    if (nfds == 0) {
        ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        return;
    }
    int poll_res = poll(pfds, nfds, tms);
    if (poll_res == 0) {
        ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        return;
    }
    if (poll_res < 0) { return; }

    bool processed = false;
    for (int i = 0; i < nfds; i++) {
        short err = POLLERR | POLLHUP | POLLNVAL;
        ares_socket_t rfd = (pfds[i].revents & (POLLIN | err))  ? pfds[i].fd : ARES_SOCKET_BAD;
        ares_socket_t wfd = (pfds[i].revents & POLLOUT) ? pfds[i].fd : ARES_SOCKET_BAD;
        if (rfd != ARES_SOCKET_BAD || wfd != ARES_SOCKET_BAD) {
            ares_process_fd(ch, rfd, wfd);
            processed = true;
        }
    }
    if (!processed) {
        ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }
}

static void health_poll_loop_step(ares_channel ch,
                                  std::chrono::steady_clock::time_point deadline) {
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) { return; }

    ares_socket_t socks[ARES_GETSOCK_MAXNUM]{};
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    int bitmask = ares_getsock(ch, socks, ARES_GETSOCK_MAXNUM);
#pragma GCC diagnostic pop

    if (bitmask == 0) {
        ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        auto wake = now + std::chrono::microseconds(100);
        std::this_thread::sleep_until(wake < deadline ? wake : deadline);
        return;
    }

    struct timeval tvbuf{};
    struct timeval* tvp = ares_timeout(ch, nullptr, &tvbuf);
    int tms = 5;
    if (tvp) {
        long long suggested = (long long)tvp->tv_sec * 1000LL + tvp->tv_usec / 1000;
        if (suggested < 0) { suggested = 0; }
        if (suggested > 10) { suggested = 10; }
        tms = (int)suggested;
    }

    auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    if (remaining_ms <= 0) { return; }
    if ((long long)tms > remaining_ms) { tms = (int)remaining_ms; }
    if (tms < 0) { tms = 0; }

    int nfds = 0;
    struct pollfd pfds[ARES_GETSOCK_MAXNUM]{};
    for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
        bool rd = ARES_GETSOCK_READABLE(bitmask, i);
        bool wr = ARES_GETSOCK_WRITABLE(bitmask, i);
        if (!rd && !wr) { continue; }
        pfds[nfds].fd     = socks[i];
        pfds[nfds].events = (rd ? POLLIN : 0) | (wr ? POLLOUT : 0);
        nfds++;
    }

    if (nfds == 0) {
        ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        return;
    }
    int poll_res = poll(pfds, nfds, tms);
    if (poll_res == 0) {
        ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        return;
    }
    if (poll_res < 0) { return; }

    bool processed = false;
    for (int i = 0; i < nfds; i++) {
        short err = POLLERR | POLLHUP | POLLNVAL;
        ares_socket_t rfd = (pfds[i].revents & (POLLIN | err))  ? pfds[i].fd : ARES_SOCKET_BAD;
        ares_socket_t wfd = (pfds[i].revents & POLLOUT) ? pfds[i].fd : ARES_SOCKET_BAD;
        if (rfd != ARES_SOCKET_BAD || wfd != ARES_SOCKET_BAD) {
            ares_process_fd(ch, rfd, wfd);
            processed = true;
        }
    }
    if (!processed) {
        ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }
}

static CheckedFamily query_resolver_a(const std::string& resolver_ip,
                                                 const std::string& hostname,
                                                 int timeout_ms) {
    CheckedFamily result;
    result.failed = true;
    if (timeout_ms <= 0 || g_cancel_token.cancelled) return result;
    std::atomic<int> pending{0};
    AresChannelGuard guard;
    struct ares_options opts{};
    opts.timeout = timeout_ms;
    opts.tries   = 1;
    if (ares_init_options(&guard.channel, &opts, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES) != ARES_SUCCESS) {
        return result;
    }
    if (ares_set_servers_ports_csv(guard.channel, resolver_ip.c_str()) != ARES_SUCCESS) {
        return result;
    }
    auto* context = new CheckedContext{&result, &pending, &hostname, ns_t_a};
    pending = 1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ares_query(guard.channel, hostname.c_str(), ns_c_in, ns_t_a, checked_address_callback, context);
#pragma GCC diagnostic pop
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (pending.load(std::memory_order_acquire) && !g_cancel_token.cancelled &&
           std::chrono::steady_clock::now() < deadline) {
        health_poll_loop_step(guard.channel, deadline);
    }
    const bool completed = pending.load(std::memory_order_acquire) == 0;
    ares_destroy(guard.channel);
    guard.channel = nullptr;
    if (!completed || g_cancel_token.cancelled) {
        result.addresses.clear(); result.failed = true;
    }
    return result;
}

static bool is_resolver_healthy(const std::string& resolver_ip,
                                const std::string& positive_host,
                                const std::string& negative_host,
                                int timeout_ms,
                                long long* elapsed_ms_out) {
    auto start = std::chrono::steady_clock::now();
    auto positive = query_resolver_a(resolver_ip, positive_host, timeout_ms);
    bool healthy = false;
    if (!positive.failed && !positive.addresses.empty() && !g_cancel_token.cancelled) {
        auto negative = query_resolver_a(resolver_ip, negative_host, timeout_ms);
        healthy = !negative.failed && negative.addresses.empty();
    }
    if (elapsed_ms_out) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        *elapsed_ms_out = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    }
    return healthy;
}

struct HealthyResolver {
    std::string resolver;
    long long elapsed_ms;
    size_t input_index;
};

static std::string make_health_negative_host() {
    unsigned long long value =
        (unsigned long long)std::chrono::steady_clock::now().time_since_epoch().count();
    try {
        std::random_device rd;
        value ^= ((unsigned long long)rd() << 32);
        value ^= (unsigned long long)rd();
    } catch (...) {
    }
    return "dnx-health-" + std::to_string(value) + ".invalid";
}

static std::vector<std::string>
filter_healthy_resolvers(const std::vector<std::string>& input_resolvers,
                         size_t max_tested,
                         size_t target_healthy,
                         int concurrency,
                         int timeout_ms,
                         size_t* tested_count_out,
                         size_t* passed_count_out) {
    if (tested_count_out) { *tested_count_out = 0; }
    if (passed_count_out) { *passed_count_out = 0; }
    if (input_resolvers.empty() || max_tested == 0) { return {}; }

    size_t test_count = std::min(max_tested, input_resolvers.size());
    size_t worker_count = std::min(test_count, (size_t)std::max(1, concurrency));
    std::vector<unsigned char> passed(test_count, 0);
    std::vector<long long> elapsed_ms(test_count, 0);
    std::atomic<size_t> next{0};
    std::atomic<size_t> tested{0};
    std::atomic<bool> failed{false};
    std::string negative_host = make_health_negative_host();
    const auto health_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    auto worker = [&]() {
        try {
        while (!g_cancel_token.cancelled && !failed && std::chrono::steady_clock::now() < health_deadline) {
            size_t idx = next.fetch_add(1, std::memory_order_relaxed);
            if (idx >= test_count) { break; }
            tested.fetch_add(1, std::memory_order_relaxed);
            long long resolver_elapsed_ms = 0;
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                health_deadline - std::chrono::steady_clock::now()).count();
            const int probe_timeout = static_cast<int>(std::min<long long>(timeout_ms, std::max<long long>(1, remaining / 2)));
            if (is_resolver_healthy(input_resolvers[idx], "example.com",
                                    negative_host, probe_timeout, &resolver_elapsed_ms)) {
                passed[idx] = 1;
                elapsed_ms[idx] = resolver_elapsed_ms;
            }
        }
        } catch (...) { failed = true; }
    };

    std::vector<std::thread> threads;
    threads.reserve(worker_count);
    try {
        for (size_t i = 0; i < worker_count; i++) { threads.emplace_back(worker); }
    } catch (...) { failed = true; }
    for (auto& t : threads) { t.join(); }
    if (failed) throw std::runtime_error("DNS resolver health workers could not complete");

    if (tested_count_out) { *tested_count_out = tested.load(std::memory_order_relaxed); }

    std::vector<HealthyResolver> passing;
    passing.reserve(test_count);
    for (size_t i = 0; i < test_count; i++) {
        if (passed[i]) { passing.push_back({input_resolvers[i], elapsed_ms[i], i}); }
    }
    std::sort(passing.begin(), passing.end(),
              [](const HealthyResolver& a, const HealthyResolver& b) {
                  if (a.elapsed_ms != b.elapsed_ms) { return a.elapsed_ms < b.elapsed_ms; }
                  return a.input_index < b.input_index;
              });
    if (passed_count_out) { *passed_count_out = passing.size(); }

    size_t result_count = passing.size();
    if (target_healthy > 0) { result_count = std::min(target_healthy, result_count); }
    std::vector<std::string> healthy;
    healthy.reserve(result_count);
    for (size_t i = 0; i < result_count; i++) {
        healthy.push_back(std::move(passing[i].resolver));
    }
    return healthy;
}

static const std::vector<std::string>& default_resolver_pool() {
    std::call_once(g_default_resolvers_once, []() {
        size_t tested = 0;
        size_t passed = 0;
        auto healthy = filter_healthy_resolvers(ALL_RESOLVERS,
                                                ALL_RESOLVERS.size(),
                                                ALL_RESOLVERS.size(),
                                                (int)ALL_RESOLVERS.size(),
                                                RESOLVER_HEALTH_TIMEOUT_MS,
                                                &tested,
                                                &passed);
        {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << BLOOD_RED << "  [*] DNS resolver health: " << WHITE
                      << passed << "/" << tested
                      << BLOOD_RED << " default resolvers passed\n" << RESET;
        }
        if (g_cancel_token.cancelled) throw std::runtime_error("DNS resolver health check cancelled");
        // Cache a failed health pass too: concurrent lookups must not repeat
        // the same network probes once for every waiting worker.
        {
            std::lock_guard<std::mutex> lk(g_default_resolvers_mtx);
            g_default_resolvers_checked = std::move(healthy);
            g_default_resolvers_ready = true;
        }
    });
    return g_default_resolvers_checked;
}

#if DNS_HAS_URING
[[maybe_unused]] static void uring_loop_step(ares_channel ch, struct io_uring* ring) {
    ares_socket_t socks[ARES_GETSOCK_MAXNUM]{};
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    int bitmask = ares_getsock(ch, socks, ARES_GETSOCK_MAXNUM);
#pragma GCC diagnostic pop

    if (bitmask == 0) {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        return;
    }

    int nfds = 0;
    int poll_fds[ARES_GETSOCK_MAXNUM];
    unsigned poll_masks[ARES_GETSOCK_MAXNUM];
    for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
        bool rd = ARES_GETSOCK_READABLE(bitmask, i);
        bool wr = ARES_GETSOCK_WRITABLE(bitmask, i);
        if (!rd && !wr) { continue; }
        poll_fds[nfds]   = socks[i];
        poll_masks[nfds] = (rd ? POLLIN : 0) | (wr ? POLLOUT : 0);
        nfds++;
    }
    if (nfds == 0) { return; }

    for (int i = 0; i < nfds; i++) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
        if (!sqe) { break; }
        io_uring_prep_poll_add(sqe, poll_fds[i], poll_masks[i]);
        io_uring_sqe_set_data64(sqe, (uint64_t)i);
    }
    io_uring_submit(ring);

    struct timeval tvbuf{};
    struct timeval* tvp = ares_timeout(ch, nullptr, &tvbuf);
    int tms = 5;
    if (tvp) {
        tms = tvp->tv_sec * 1000 + tvp->tv_usec / 1000;
        if (tms < 1) { tms = 1; }
        if (tms > 10)  { tms = 10; }
    }

    struct io_uring_cqe* cqe = nullptr;
    struct __kernel_timespec ts{ tms / 1000, (long)(tms % 1000) * 1000000L };
    if (io_uring_wait_cqe_timeout(ring, &cqe, &ts) == 0 && cqe) {
        unsigned head = 0;
        io_uring_for_each_cqe(ring, head, cqe) {
            int i2 = (int)io_uring_cqe_get_data64(cqe);
            if (i2 >= 0 && i2 < nfds) {
                ares_socket_t rfd = (cqe->res & POLLIN)  ? poll_fds[i2] : ARES_SOCKET_BAD;
                ares_socket_t wfd = (cqe->res & POLLOUT) ? poll_fds[i2] : ARES_SOCKET_BAD;
                if (rfd != ARES_SOCKET_BAD || wfd != ARES_SOCKET_BAD) {
                    ares_process_fd(ch, rfd, wfd);
                }
            }
        }
        io_uring_cq_advance(ring, head);
    }
}
#endif

DnsEngine& DnsEngine::get() {
    static DnsEngine inst;
    return inst;
}

DnsEngine::DnsEngine() {
    ares_library_init(ARES_LIB_INIT_ALL);
    io_uring_ok_ = detect_io_uring();
    for (int i = 0; i < N_SHARDS; i++) {
        shards_[i] = std::make_unique<CacheShard>();
    }
}

DnsEngine::~DnsEngine() {
    ares_library_cleanup();
}

bool DnsEngine::detect_io_uring() {
#if DNS_HAS_URING
    struct utsname u{};
    uname(&u);
    int major = 0, minor = 0;
    sscanf(u.release, "%d.%d", &major, &minor);
    if (major > 5 || (major == 5 && minor >= 1)) {
        struct io_uring ring{};
        if (io_uring_queue_init(8, &ring, 0) == 0) {
            io_uring_queue_exit(&ring);
            return true;
        }
    }
#endif
    return false;
}

static size_t shard_idx(const std::string& key) {
    size_t h = std::hash<std::string>{}(key);
    return h & (N_SHARDS - 1);
}

std::vector<std::string> DnsEngine::cache_get(const std::string& host) {
    auto& shard = *shards_[shard_idx(host)];
    std::lock_guard<std::mutex> lk(shard.mtx);
    auto it = shard.map.find(host);
    if (it == shard.map.end()) { return {}; }
    if (std::chrono::steady_clock::now() > it->second.expires) {
        shard.map.erase(it);
        return {};
    }
    return it->second.ips;
}

void DnsEngine::cache_put(const std::string& host, const std::vector<std::string>& ips) {
    auto& shard = *shards_[shard_idx(host)];
    std::lock_guard<std::mutex> lk(shard.mtx);
    shard.map[host] = { ips, std::chrono::steady_clock::now() + std::chrono::seconds(CACHE_TTL_S) };
}

void DnsEngine::set_concurrency(int c) { concurrency_ = clamp_total_concurrency(c); }

int DnsEngine::channel_count() const { return N_CHANNELS; }

int DnsEngine::max_per_channel_concurrency() const { return MAX_PER_CHANNEL_CONCURRENCY; }

size_t DnsEngine::resolver_count() const {
    {
        std::lock_guard<std::mutex> lk(g_custom_resolvers_mtx);
        if (!g_custom_resolvers.empty()) { return g_custom_resolvers.size(); }
    }
    {
        std::lock_guard<std::mutex> lk(g_default_resolvers_mtx);
        if (g_default_resolvers_ready) { return g_default_resolvers_checked.size(); }
    }
    return ALL_RESOLVERS.size();
}

void DnsEngine::clear_cache() {
    for (int i = 0; i < N_SHARDS; i++) {
        std::lock_guard<std::mutex> lk(shards_[i]->mtx);
        shards_[i]->map.clear();
    }
}

static std::string make_shard_csv(const std::vector<std::string>& resolvers,
                                  size_t base_offset,
                                  int channel_idx,
                                  int resolvers_per_channel) {
    size_t rpc = std::min((size_t)resolvers_per_channel, resolvers.size());
    size_t start = (base_offset + (size_t)channel_idx * (size_t)resolvers_per_channel) % resolvers.size();
    std::string csv;
    for (size_t i = 0; i < rpc; i++) {
        if (i) csv += ",";
        csv += resolvers[(start + i) % resolvers.size()];
    }
    return csv;
}

void DnsEngine::load_resolvers(const std::string& path) {
    if (path.empty()) throw std::runtime_error("DNS resolver path is empty");
    struct FileGuard { int fd = -1; ~FileGuard() { if (fd >= 0) close(fd); } } file;
    file.fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (file.fd < 0) throw std::runtime_error("Cannot open DNS resolver file: " + path);
    constexpr std::size_t maximum_bytes = 2 * 1024 * 1024;
    struct stat metadata{};
    if (fstat(file.fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size < 0 ||
        static_cast<std::uintmax_t>(metadata.st_size) > maximum_bytes)
        throw std::runtime_error("DNS resolver file must be a readable regular file of at most 2 MiB: " + path);
    std::string content;
    char buffer[4096];
    while (!g_cancel_token.cancelled) {
        const auto count = read(file.fd, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("Cannot read DNS resolver file: " + path);
        }
        if (content.size() + static_cast<std::size_t>(count) > maximum_bytes)
            throw std::runtime_error("DNS resolver file exceeded its 2 MiB limit: " + path);
        content.append(buffer, static_cast<std::size_t>(count));
    }
    if (g_cancel_token.cancelled) throw std::runtime_error("DNS resolver loading cancelled");
    auto endpoint = [](const std::string& value) -> std::string {
        std::string address = value, port;
        if (value.empty() || value.find_first_of(" \t\r\n\0", 0, 5) != std::string::npos) return "";
        if (value.front() == '[') {
            const auto end = value.find(']');
            if (end == std::string::npos) return "";
            address = value.substr(1, end - 1);
            if (end + 1 < value.size()) {
                if (value[end + 1] != ':') return "";
                port = value.substr(end + 2);
                if (port.empty()) return "";
            }
        } else if (std::count(value.begin(), value.end(), ':') == 1) {
            const auto colon = value.find(':');
            address = value.substr(0, colon); port = value.substr(colon + 1);
            if (port.empty()) return "";
        }
        if (!port.empty()) {
            if (port.size() > 5 || !std::all_of(port.begin(), port.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) return "";
            const int number = std::stoi(port);
            if (number < 1 || number > 65535) return "";
            port = ':' + std::to_string(number);
        }
        unsigned char bytes[sizeof(in6_addr)]{};
        char formatted[INET6_ADDRSTRLEN]{};
        if (inet_pton(AF_INET, address.c_str(), bytes) == 1 && inet_ntop(AF_INET, bytes, formatted, sizeof(formatted)))
            return std::string(formatted) + port;
        if (inet_pton(AF_INET6, address.c_str(), bytes) == 1 && inet_ntop(AF_INET6, bytes, formatted, sizeof(formatted)))
            return '[' + std::string(formatted) + ']' + port;
        return "";
    };
    std::istringstream f(content);
    std::vector<std::string> loaded;
    std::unordered_set<std::string> seen;
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(f, line)) {
        if (++line_number > 100000) throw std::runtime_error("DNS resolver file exceeds 100000 lines");
        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
            line.pop_back();
        size_t start = 0;
        while (start < line.size() && std::isspace(static_cast<unsigned char>(line[start]))) start++;
        if (start > 0) line.erase(0, start);
        if (line.empty() || line[0]=='#') continue;
        const auto normalized = endpoint(line);
        if (normalized.empty()) throw std::runtime_error("Invalid DNS resolver on line " + std::to_string(line_number));
        if (seen.insert(normalized).second) loaded.push_back(normalized);
    }
    if (loaded.empty()) throw std::runtime_error("DNS resolver file contains no addresses: " + path);
    {
        size_t tested = 0;
        size_t passed = 0;
        auto healthy = filter_healthy_resolvers(loaded,
                                                CUSTOM_HEALTHCHECK_MAX_TESTED,
                                                CUSTOM_HEALTHCHECK_TARGET_HEALTHY,
                                                CUSTOM_HEALTHCHECK_CONCURRENCY,
                                                RESOLVER_HEALTH_TIMEOUT_MS,
                                                &tested,
                                                &passed);
        if (g_cancel_token.cancelled) throw std::runtime_error("DNS resolver health check cancelled");
        if (healthy.empty()) throw std::runtime_error("No custom DNS resolver passed positive and negative health checks");
        const auto final_count = healthy.size();
        {
            std::lock_guard<std::mutex> lk(g_custom_resolvers_mtx);
            g_custom_resolvers = std::move(healthy);
        }
        {
            std::lock_guard<std::mutex> lk(g_print_mtx);
                std::cout << BLOOD_RED << "  [*] DNS resolver health: " << WHITE
                          << passed << "/" << tested
                          << BLOOD_RED << " custom resolvers passed, using ";
                if (final_count < passed) {
                    std::cout << WHITE << "fastest " << final_count
                              << BLOOD_RED << " healthy subset\n" << RESET;
                } else {
                    std::cout << WHITE << "all " << final_count
                              << BLOOD_RED << " passing resolvers\n" << RESET;
                }
            std::cout << BLOOD_RED << "  [+] " << WHITE << final_count
                      << BLOOD_RED << " custom resolvers loaded\n" << RESET;
        }
    }
}

std::unordered_map<std::string, DnsLookupResult>
DnsEngine::resolve_batch_checked(const std::vector<std::string>& hosts, int concurrency,
                                 int timeout_ms) {
    std::unordered_map<std::string, DnsLookupResult> output;
    std::vector<std::string> names;
    names.reserve(hosts.size());
    for (const auto& host : hosts) {
        if (output.emplace(host, DnsLookupResult{}).second) names.push_back(host);
    }
    if (names.empty()) return output;
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(std::clamp(timeout_ms, 1, 30000));
    auto fail_all = [&](const std::string& error) {
        for (auto& entry : output) { entry.second.failed = true; entry.second.error = error; }
    };
    if (g_cancel_token.cancelled) { fail_all("DNS lookup cancelled"); return output; }
    std::vector<std::string> resolvers;
    try { resolvers = resolver_pool_snapshot(); }
    catch (const std::exception& error) { fail_all(error.what()); return output; }
    if (resolvers.empty()) { fail_all("No healthy DNS resolvers available"); return output; }

    struct HostState { CheckedFamily ipv4, ipv6; };
    std::vector<HostState> states(names.size());
    const int total_slots = clamp_total_concurrency(concurrency);
    const int channels = std::min<int>({N_CHANNELS, total_slots, static_cast<int>(std::min<std::size_t>(names.size(), N_CHANNELS))});
    const int slots = total_to_per_channel_concurrency(total_slots, channels);
    const auto rotation = resolver_rotation_.fetch_add(static_cast<std::size_t>(channels) * RESOLVERS_PER_CHANNEL);
    std::atomic<std::size_t> next{0};
    std::atomic<bool> worker_failure{false};
    auto worker = [&](int channel_index) noexcept {
        try {
            // The channel is destroyed before pending, and callbacks retain
            // references only to the stable names/states arrays above.
            std::atomic<int> pending{0};
            AresChannelGuard guard;
            ares_options options{};
            options.timeout = 500;
            options.tries = 1;
            const int initialized = ares_init_options(&guard.channel, &options, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES);
            if (initialized != ARES_SUCCESS ||
                ares_set_servers_ports_csv(guard.channel,
                    make_shard_csv(resolvers, rotation, channel_index, RESOLVERS_PER_CHANNEL).c_str()) != ARES_SUCCESS) {
                worker_failure = true;
                return;
            }
            while (!g_cancel_token.cancelled && !worker_failure && std::chrono::steady_clock::now() < deadline) {
                while (pending.load(std::memory_order_acquire) < slots && !g_cancel_token.cancelled &&
                       !worker_failure && std::chrono::steady_clock::now() < deadline) {
                    const auto index = next.fetch_add(1);
                    if (index >= names.size()) break;
                    const auto key = dns_name_key(names[index]);
                    if (!InputGuard::is_valid_host(key) || key.find(':') != std::string::npos) {
                        for (auto* family : {&states[index].ipv4, &states[index].ipv6}) {
                            family->completed = true; family->failed = true; family->error = "Invalid DNS hostname";
                        }
                        continue;
                    }
                    for (const int type : {ns_t_a, ns_t_aaaa}) {
                        auto* family = type == ns_t_a ? &states[index].ipv4 : &states[index].ipv6;
                        auto* context = new CheckedContext{family, &pending, &names[index], type};
                        pending.fetch_add(1, std::memory_order_release);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                        ares_query(guard.channel, names[index].c_str(), ns_c_in, type, checked_address_callback, context);
#pragma GCC diagnostic pop
                    }
                }
                if (pending.load(std::memory_order_acquire) == 0 && next.load() >= names.size()) break;
                poll_loop_step(guard.channel);
            }
        } catch (...) { worker_failure = true; }
    };
    std::vector<std::thread> threads;
    threads.reserve(channels);
    try {
        for (int i = 0; i < channels; ++i) threads.emplace_back(worker, i);
    } catch (...) { worker_failure = true; }
    for (auto& thread : threads) if (thread.joinable()) thread.join();
    for (std::size_t i = 0; i < names.size(); ++i) {
        auto& result = output.at(names[i]);
        result.ipv4 = std::move(states[i].ipv4.addresses);
        result.ipv6 = std::move(states[i].ipv6.addresses);
        const std::array<std::pair<const char*, CheckedFamily*>, 2> families{{
            {"A", &states[i].ipv4}, {"AAAA", &states[i].ipv6}}};
        for (const auto family : families) {
            if (family.second->completed && !family.second->failed) continue;
            result.failed = true;
            if (!result.error.empty()) result.error += "; ";
            result.error += std::string(family.first) + ": ";
            if (g_cancel_token.cancelled) result.error += "DNS lookup cancelled";
            else if (family.second->completed && !family.second->error.empty()) result.error += family.second->error;
            else if (worker_failure) result.error += "DNS worker or channel initialization failed";
            else if (!family.second->completed || std::chrono::steady_clock::now() >= deadline)
                result.error += "DNS deadline exceeded or query was not completed";
            else result.error += family.second->error.empty() ? "DNS response processing failed" : family.second->error;
        }
    }
    return output;
}

std::unordered_map<std::string, std::vector<std::string>>
DnsEngine::run_ares_batch(const std::vector<std::string>& hosts,
                           int concurrency,
                           int deadline_s)
{
    auto checked = resolve_batch_checked(hosts, concurrency, std::clamp(deadline_s, 1, 30) * 1000);
    std::unordered_map<std::string, std::vector<std::string>> output;
    for (auto& entry : checked) output.emplace(entry.first, std::move(entry.second.ipv4));
    return output;
}

static std::string doh_http_get(const std::string& url) {
    if (g_cancel_token.cancelled) return "";
    std::string body;
    CURL* c = curl_easy_init();
    if (!c) return "";
    struct curl_slist* hdrs = curl_slist_append(nullptr, "Accept: application/dns-json");
    hdrs = curl_slist_append(hdrs, "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
    auto cb = +[](char* p, size_t s, size_t n, void* u) -> size_t {
        auto* b = static_cast<std::string*>(u);
        const auto bytes = s * n;
        if (bytes > 256 * 1024 - std::min<std::size_t>(b->size(), 256 * 1024)) return 0;
        try { b->append(p, bytes); } catch (...) { return 0; }
        return bytes;
    };
    curl_easy_setopt(c, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,     &body);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,       4L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 2L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER,1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST,2L);
    curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, +[](void*, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> int {
        return g_cancel_token.cancelled ? 1 : 0;
    });
    curl_easy_setopt(c, CURLOPT_NOSIGNAL,      1L);
    const auto code = curl_easy_perform(c);
    long http_status = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    return code == CURLE_OK && http_status == 200 && !g_cancel_token.cancelled ? body : "";
}

static std::vector<std::string> doh_resolve_single(const std::string& host) {
    if (!InputGuard::is_valid_host(host)) return {};
    const std::vector<std::pair<std::string,std::string>> providers = {
        {"https://cloudflare-dns.com/dns-query?name="+host+"&type=A", "cloudflare"},
        {"https://dns.google/resolve?name="+host+"&type=A",           "google"},
    };
    for (auto& [url, name] : providers) {
        if (g_cancel_token.cancelled) return {};
        const auto response = doh_http_get(url);
        if (response.empty()) continue;
        auto parsed = dns_response::parse_doh_response(response, host, 1);
        if (parsed.valid && !parsed.addresses.empty()) return parsed.addresses;
    }
    return {};
}

static std::unordered_map<std::string, std::vector<std::string>>
doh_batch(const std::vector<std::string>& hosts, int max_slots)
{
    std::unordered_map<std::string, std::vector<std::string>> out;
    if (hosts.empty()) { return out; }

    std::atomic<int> next{0};
    int total = (int)hosts.size();
    std::mutex out_mtx;
    std::atomic<bool> failed{false};

    auto worker = [&]() {
        try {
        while (!failed) {
            if (g_cancel_token.cancelled) { break; }
            int idx = next.fetch_add(1, std::memory_order_relaxed);
            if (idx >= total) { break; }
            auto ips = doh_resolve_single(hosts[idx]);
            if (!ips.empty()) {
                std::lock_guard<std::mutex> lk(out_mtx);
                out[hosts[idx]] = std::move(ips);
            }
        }
        } catch (...) { failed = true; }
    };

    int nw = std::min(max_slots, std::min(total, 64));
    std::vector<std::thread> threads;
    threads.reserve(nw);
    try {
        for (int i = 0; i < nw; i++) { threads.emplace_back(worker); }
    } catch (...) { failed = true; }
    for (auto& t : threads) { t.join(); }

    return out;
}

std::vector<std::string> DnsEngine::resolve(const std::string& host) {
    auto cached = cache_get(host);
    if (!cached.empty()) { return cached; }

    auto res = run_ares_batch({host}, 4, 8);
    auto& ips = res[host];
    if (!ips.empty()) {
        cache_put(host, ips);
        return ips;
    }

    auto doh = doh_resolve_single(host);
    if (!doh.empty()) {
        cache_put(host, doh);
        return doh;
    }

    auto sys = safe_exec({"getent","hosts",host}, 3);
    if (!sys.empty()) {
        std::istringstream ss(sys); std::string ip, nm;
        ss >> ip;
        if (!ip.empty()) {
            cache_put(host, {ip});
            return {ip};
        }
    }

    return {};
}

std::vector<std::string> DnsEngine::resolve_aaaa(const std::string& host) {
    if (g_cancel_token.cancelled) return {};
    const auto key = host + ":AAAA";
    const auto cached = cache_get(key);
    if (!cached.empty()) return cached;
    auto result = resolve_batch_checked({host}, 2, 5000);
    auto addresses = std::move(result.at(host).ipv6);
    if (!addresses.empty()) cache_put(key, addresses);
    return addresses;
}

std::string DnsEngine::resolve_cname(const std::string& host) {
    if (g_cancel_token.cancelled || !dns_response::valid_name(host)) return "";
    const auto key = host + ":CNAME";
    const auto cached = cache_get(key);
    if (!cached.empty()) return cached.front();
    const auto resolvers = resolver_pool_snapshot();
    if (resolvers.empty()) return "";
    std::string cname;
    std::atomic<int> pending{0};
    AresChannelGuard guard;
    ares_options options{};
    options.timeout = 500; options.tries = 1;
    if (ares_init_options(&guard.channel, &options, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES) != ARES_SUCCESS) return "";
    const auto offset = resolver_rotation_.fetch_add(RESOLVERS_PER_CHANNEL);
    const auto servers = make_shard_csv(resolvers, offset, 0, RESOLVERS_PER_CHANNEL);
    if (ares_set_servers_ports_csv(guard.channel, servers.c_str()) != ARES_SUCCESS) return "";
    auto* context = new CnameCtx{&cname, &pending, &host};
    pending = 1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ares_query(guard.channel, host.c_str(), ns_c_in, ns_t_cname, ares_cname_cb, context);
#pragma GCC diagnostic pop
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (pending.load(std::memory_order_acquire) && !g_cancel_token.cancelled &&
           std::chrono::steady_clock::now() < deadline) poll_loop_step(guard.channel);
    const bool completed = pending.load(std::memory_order_acquire) == 0;
    ares_destroy(guard.channel); guard.channel = nullptr;
    if (!completed || g_cancel_token.cancelled || cname.empty()) return "";
    cache_put(key, {cname});
    return cname;
}

std::string DnsEngine::resolve_ptr(const std::string& ip) {
    std::string key = ip + ":PTR";
    auto cached = cache_get(key);
    if (!cached.empty()) { return cached[0]; }

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) { return ""; }
    char host[NI_MAXHOST]{};
    if (getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa),
                    host, sizeof(host), nullptr, 0, 0) == 0) {
        std::string result(host);
        cache_put(key, {result});
        return result;
    }
    return "";
}

std::unordered_map<std::string, std::vector<std::string>>
DnsEngine::resolve_batch(const std::vector<std::string>& hosts, int concurrency, const std::unordered_set<std::string>* doh_allow)
{
    std::vector<std::string> uncached;
    std::unordered_map<std::string, std::vector<std::string>> out;
    out.reserve(hosts.size() * 2);

    for (auto& h : hosts) {
        auto cached = cache_get(h);
        if (!cached.empty()) {
            out[h] = std::move(cached);
        } else {
            uncached.push_back(h);
            out[h];
        }
    }

    if (uncached.empty()) { return out; }

    int n = (int)uncached.size();
    int deadline_s = (n <= 100)    ? 8 :
                     (n <= 10000)  ? 30 :
                     std::min(120, std::max(45, n / 1000 + 30));

    int effective_concurrency = clamp_total_concurrency(concurrency > 0 ? concurrency : concurrency_);
    auto fresh = run_ares_batch(uncached, effective_concurrency, deadline_s);

    std::vector<std::string> doh_queue;
    for (auto& [h, ips] : fresh) {
        if (!ips.empty()) {
            cache_put(h, ips);
            out[h] = std::move(ips);
        } else {
            if (doh_allow && doh_allow->count(h) == 0) continue;
            doh_queue.push_back(h);
        }
    }

    if (!doh_queue.empty()) {
        constexpr int DOH_CAP = 500;
        if ((int)doh_queue.size() > DOH_CAP) {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << BLOOD_RED << "  [*] DoH cascade: " << doh_queue.size()
                      << " hosts unresolved via c-ares (capped at " << DOH_CAP << ")...\n" << RESET;
            doh_queue.resize(DOH_CAP);
        } else {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << BLOOD_RED << "  [*] DoH cascade: " << doh_queue.size()
                      << " hosts unresolved via c-ares, trying DoH...\n" << RESET;
        }

        auto doh_res = doh_batch(doh_queue, 64);
        int doh_ok = 0;
        for (auto& [h, ips] : doh_res) {
            if (!ips.empty()) {
                cache_put(h, ips);
                out[h] = std::move(ips);
                doh_ok++;
            }
        }

        if (doh_ok > 0) {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << BLOOD_RED << "  [+] DoH resolved: " << doh_ok << "/"
                      << doh_queue.size() << "\n" << RESET;
        }
    }

    return out;
}
