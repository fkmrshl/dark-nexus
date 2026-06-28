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

struct AresCtx {
    std::vector<std::string>* out;
    std::atomic<int>*         pending;
};

struct BulkAContext {
    std::vector<std::vector<std::string>>* per_host_results;
    size_t index;
    std::atomic<int>* pending;
};

struct CnameCtx {
    std::string*      out;
    std::atomic<int>* pending;
};

static std::string trim_trailing_dns_dots(std::string name) {
    while (!name.empty() && name.back() == '.') { name.pop_back(); }
    return name;
}

static std::string parse_first_cname_reply(unsigned char* abuf, int alen) {
    if (!abuf || alen <= 0) { return ""; }

    ares_dns_record_t* raw_record = nullptr;
    if (ares_dns_parse(abuf, (size_t)alen, 0, &raw_record) != ARES_SUCCESS || !raw_record) {
        if (raw_record) { ares_dns_record_destroy(raw_record); }
        return "";
    }
    std::unique_ptr<ares_dns_record_t, decltype(&ares_dns_record_destroy)>
        record(raw_record, ares_dns_record_destroy);

    size_t answer_count = ares_dns_record_rr_cnt(record.get(), ARES_SECTION_ANSWER);
    for (size_t i = 0; i < answer_count; i++) {
        const ares_dns_rr_t* rr =
            ares_dns_record_rr_get_const(record.get(), ARES_SECTION_ANSWER, i);
        if (!rr) { continue; }
        if (ares_dns_rr_get_type(rr) != ARES_REC_TYPE_CNAME) { continue; }
        if (ares_dns_rr_get_class(rr) != ARES_CLASS_IN) { continue; }
        const char* cname = ares_dns_rr_get_str(rr, ARES_RR_CNAME_CNAME);
        if (!cname || !*cname) { continue; }
        return trim_trailing_dns_dots(std::string(cname));
    }

    return "";
}

static void ares_aaaa_cb(void* arg, int status, int, struct ares_addrinfo* res) {
    std::unique_ptr<AresCtx> ctx(static_cast<AresCtx*>(arg));
    if (status == ARES_SUCCESS && res) {
        for (auto* n = res->nodes; n; n = n->ai_next) {
            if (n->ai_family == AF_INET6) {
                char buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6,
                    &reinterpret_cast<sockaddr_in6*>(n->ai_addr)->sin6_addr,
                    buf, sizeof(buf));
                ctx->out->emplace_back(buf);
            }
        }
        ares_freeaddrinfo(res);
    }
    ctx->pending->fetch_sub(1, std::memory_order_release);
}

static void bulk_a_cb(void* arg, int status, int, unsigned char* abuf, int alen) {
    std::unique_ptr<BulkAContext> ctx(static_cast<BulkAContext*>(arg));
    try {
        if (ctx && status == ARES_SUCCESS && abuf && alen > 0 &&
            ctx->per_host_results && ctx->index < ctx->per_host_results->size()) {
            struct hostent* raw_host = nullptr;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            int parse_status = ares_parse_a_reply(abuf, alen, &raw_host, nullptr, nullptr);
#pragma GCC diagnostic pop
            std::unique_ptr<struct hostent, decltype(&ares_free_hostent)>
                host(raw_host, ares_free_hostent);
            if (parse_status == ARES_SUCCESS && host &&
                host->h_addrtype == AF_INET && host->h_length == (int)sizeof(struct in_addr)) {
                auto& out = (*ctx->per_host_results)[ctx->index];
                for (char** addr = host->h_addr_list; addr && *addr; ++addr) {
                    char buf[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, *addr, buf, sizeof(buf))) {
                        out.emplace_back(buf);
                    }
                }
            }
        }
    } catch (...) {
    }
    if (ctx && ctx->pending) {
        ctx->pending->fetch_sub(1, std::memory_order_release);
    }
}

static void ares_cname_cb(void* arg, int status, int, unsigned char* abuf, int alen) {
    std::unique_ptr<CnameCtx> ctx(static_cast<CnameCtx*>(arg));
    if (status == ARES_SUCCESS && abuf && alen > 0) {
        std::string cname = parse_first_cname_reply(abuf, alen);
        if (!cname.empty()) { *ctx->out = std::move(cname); }
    }
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

struct ResolverHealthCtx {
    std::vector<std::string> ips;
    bool done = false;
};

static void resolver_health_cb(void* arg, int status, int, unsigned char* abuf, int alen) {
    auto* ctx = static_cast<ResolverHealthCtx*>(arg);
    if (status == ARES_SUCCESS && abuf && alen > 0) {
        struct hostent* host = nullptr;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        int parse_status = ares_parse_a_reply(abuf, alen, &host, nullptr, nullptr);
#pragma GCC diagnostic pop
        if (parse_status == ARES_SUCCESS && host &&
            host->h_addrtype == AF_INET && host->h_length == (int)sizeof(struct in_addr)) {
            for (char** addr = host->h_addr_list; addr && *addr; ++addr) {
                char buf[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, *addr, buf, sizeof(buf))) {
                    ctx->ips.emplace_back(buf);
                }
            }
        }
        if (host) { ares_free_hostent(host); }
    }
    ctx->done = true;
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

static std::vector<std::string> query_resolver_a(const std::string& resolver_ip,
                                                 const std::string& hostname,
                                                 int timeout_ms) {
    if (timeout_ms <= 0) { return {}; }

    struct ares_options opts{};
    opts.timeout = timeout_ms;
    opts.tries   = 1;
    ares_channel ch;
    if (ares_init_options(&ch, &opts, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES) != ARES_SUCCESS) {
        return {};
    }

    if (ares_set_servers_csv(ch, resolver_ip.c_str()) != ARES_SUCCESS) {
        ares_destroy(ch);
        return {};
    }

    ResolverHealthCtx ctx;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ares_query(ch, hostname.c_str(), ns_c_in, ns_t_a, resolver_health_cb, &ctx);
#pragma GCC diagnostic pop

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (!ctx.done && std::chrono::steady_clock::now() < deadline) {
        health_poll_loop_step(ch, deadline);
    }

    bool completed = ctx.done;
    ares_destroy(ch);
    if (!completed) { return {}; }
    return ctx.ips;
}

static bool is_resolver_healthy(const std::string& resolver_ip,
                                const std::string& positive_host,
                                const std::string& negative_host,
                                int timeout_ms,
                                long long* elapsed_ms_out) {
    auto start = std::chrono::steady_clock::now();
    auto positive = query_resolver_a(resolver_ip, positive_host, timeout_ms);
    bool healthy = false;
    if (!positive.empty()) {
        auto negative = query_resolver_a(resolver_ip, negative_host, timeout_ms);
        healthy = negative.empty();
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
    std::string negative_host = make_health_negative_host();

    auto worker = [&]() {
        while (true) {
            size_t idx = next.fetch_add(1, std::memory_order_relaxed);
            if (idx >= test_count) { break; }
            tested.fetch_add(1, std::memory_order_relaxed);
            long long resolver_elapsed_ms = 0;
            if (is_resolver_healthy(input_resolvers[idx], "example.com",
                                    negative_host, timeout_ms, &resolver_elapsed_ms)) {
                passed[idx] = 1;
                elapsed_ms[idx] = resolver_elapsed_ms;
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(worker_count);
    for (size_t i = 0; i < worker_count; i++) { threads.emplace_back(worker); }
    for (auto& t : threads) { t.join(); }

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
        std::vector<std::string> chosen;
        if (healthy.size() >= 4) {
            chosen = std::move(healthy);
        } else {
            chosen = ALL_RESOLVERS;
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << BLOOD_RED
                      << "  [!] DNS resolver health: fallback to unfiltered default resolver pool\n"
                      << RESET;
        }
        if (chosen.empty()) { chosen = ALL_RESOLVERS; }
        {
            std::lock_guard<std::mutex> lk(g_default_resolvers_mtx);
            g_default_resolvers_checked = std::move(chosen);
        }
    });
    return g_default_resolvers_checked.empty() ? ALL_RESOLVERS : g_default_resolvers_checked;
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
        if (!g_default_resolvers_checked.empty()) { return g_default_resolvers_checked.size(); }
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
    if (path.empty()) return;
    std::ifstream f(path);
    if (!f.is_open()) return;
    std::vector<std::string> loaded;
    loaded.reserve(100000);
    std::unordered_set<std::string> seen;
    seen.reserve(100000);
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
            line.pop_back();
        size_t start = 0;
        while (start < line.size() && std::isspace(static_cast<unsigned char>(line[start]))) start++;
        if (start > 0) line.erase(0, start);
        if (line.empty() || line[0]=='#') continue;
        if (InputGuard::is_valid_ipv4(line) && seen.insert(line).second) loaded.push_back(line);
    }
    if (!loaded.empty()) {
        size_t tested = 0;
        size_t passed = 0;
        auto healthy = filter_healthy_resolvers(loaded,
                                                CUSTOM_HEALTHCHECK_MAX_TESTED,
                                                CUSTOM_HEALTHCHECK_TARGET_HEALTHY,
                                                CUSTOM_HEALTHCHECK_CONCURRENCY,
                                                RESOLVER_HEALTH_TIMEOUT_MS,
                                                &tested,
                                                &passed);
        size_t required = std::min((size_t)4, loaded.size());
        bool use_healthy = healthy.size() >= required;
        size_t final_count = use_healthy ? healthy.size() : loaded.size();
        {
            std::lock_guard<std::mutex> lk(g_custom_resolvers_mtx);
            g_custom_resolvers = use_healthy ? std::move(healthy) : std::move(loaded);
        }
        {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            if (use_healthy) {
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
            } else {
                std::cout << BLOOD_RED
                          << "  [!] DNS resolver health: too few custom resolvers passed, using original loaded list\n"
                          << RESET;
            }
            std::cout << BLOOD_RED << "  [+] " << WHITE << final_count
                      << BLOOD_RED << " custom resolvers loaded\n" << RESET;
        }
    }
}

std::unordered_map<std::string, std::vector<std::string>>
DnsEngine::run_ares_batch(const std::vector<std::string>& hosts,
                           const std::vector<std::string>& resolvers,
                           int concurrency,
                           int deadline_s)
{
    int total = (int)hosts.size();

    std::unordered_map<std::string, std::vector<std::string>> results;
    results.reserve(total * 2);
    for (auto& h : hosts) { results[h]; }

    if (total == 0) { return results; }

    std::vector<std::vector<std::string>> per_host_results(hosts.size());

    int n_ch = (total <= 50)    ? 1 :
               (total <= 250)   ? std::min(N_CHANNELS, 4) :
               (total <= 2000)  ? std::min(N_CHANNELS, 8) :
                                  N_CHANNELS;
    int per_channel = total_to_per_channel_concurrency(clamp_total_concurrency(concurrency), n_ch);

    std::vector<std::string> fallback_resolvers;
    const std::vector<std::string>* resolver_pool = &resolvers;
    if (resolver_pool->empty()) {
        fallback_resolvers = resolver_pool_snapshot();
        resolver_pool = &fallback_resolvers;
    }
    size_t active_slots = (size_t)n_ch * (size_t)RESOLVERS_PER_CHANNEL;
    size_t base_offset = resolver_rotation_.fetch_add(active_slots, std::memory_order_relaxed);

    std::atomic<int> next_host{0};

    auto worker = [&](int tid) {
#if DNS_HAS_URING
        struct io_uring ring{};
        bool ring_ok = false;
#endif
        struct ares_options opts{};
        opts.timeout = 400;
        opts.tries   = 1;
        ares_channel ch;
        if (ares_init_options(&ch, &opts, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES) != ARES_SUCCESS) {
#if DNS_HAS_URING
            if (ring_ok) { io_uring_queue_exit(&ring); }
#endif
            return;
        }

        std::string csv = make_shard_csv(*resolver_pool, base_offset, tid, RESOLVERS_PER_CHANNEL);
        if (ares_set_servers_csv(ch, csv.c_str()) != ARES_SUCCESS) {
            ares_destroy(ch);
#if DNS_HAS_URING
            if (ring_ok) { io_uring_queue_exit(&ring); }
#endif
            return;
        }

        std::atomic<int> pending{0};
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(deadline_s);

        while (true) {
            if (g_cancel_token.cancelled) { break; }
            if (std::chrono::steady_clock::now() > deadline) { break; }

            while (pending.load(std::memory_order_acquire) < per_channel) {
                int idx = next_host.fetch_add(1, std::memory_order_relaxed);
                if (idx >= total) { goto drain; }

                const std::string& h = hosts[idx];
                auto* ctx = new (std::nothrow) BulkAContext{&per_host_results, (size_t)idx, &pending};
                if (!ctx) { continue; }
                pending.fetch_add(1, std::memory_order_acquire);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                ares_query(ch, h.c_str(), ns_c_in, ns_t_a, bulk_a_cb, ctx);
#pragma GCC diagnostic pop
            }

            drain:
            if (pending.load(std::memory_order_acquire) == 0 &&
                next_host.load(std::memory_order_relaxed) >= total) {
                break;
            }

            poll_loop_step(ch);
        }

        ares_destroy(ch);
#if DNS_HAS_URING
        if (ring_ok) { io_uring_queue_exit(&ring); }
#endif
    };

    std::vector<std::thread> threads;
    threads.reserve(n_ch);
    for (int i = 0; i < n_ch; i++) { threads.emplace_back(worker, i); }
    for (auto& t : threads) { t.join(); }

    for (size_t i = 0; i < per_host_results.size(); i++) {
        if (per_host_results[i].empty()) { continue; }
        auto& dst = results[hosts[i]];
        dst.insert(dst.end(), per_host_results[i].begin(), per_host_results[i].end());
    }

    for (auto& entry : results) {
        auto& ips = entry.second;
        if (ips.size() < 2) { continue; }
        std::unordered_set<std::string> seen;
        seen.reserve(ips.size());
        std::vector<std::string> unique_ips;
        unique_ips.reserve(ips.size());
        for (auto& ip : ips) {
            if (seen.insert(ip).second) { unique_ips.push_back(std::move(ip)); }
        }
        ips = std::move(unique_ips);
    }

    return results;
}

static std::string doh_http_get(const std::string& url) {
    std::string body;
    CURL* c = curl_easy_init();
    if (!c) return "";
    struct curl_slist* hdrs = curl_slist_append(nullptr, "Accept: application/dns-json");
    hdrs = curl_slist_append(hdrs, "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
    auto cb = +[](char* p, size_t s, size_t n, void* u) -> size_t {
        auto* b = static_cast<std::string*>(u);
        if (b->size() < 32768) b->append(p, std::min(s*n, 32768-b->size()));
        return s*n;
    };
    curl_easy_setopt(c, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,     &body);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,       4L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER,0L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL,      1L);
    curl_easy_perform(c);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    return body;
}

static std::vector<std::string> doh_resolve_single(const std::string& host) {
    if (!InputGuard::is_valid_host(host)) return {};
    const std::vector<std::pair<std::string,std::string>> providers = {
        {"https://cloudflare-dns.com/dns-query?name="+host+"&type=A", "cloudflare"},
        {"https://dns.google/resolve?name="+host+"&type=A",           "google"},
    };
    for (auto& [url, name] : providers) {
        auto resp = doh_http_get(url);
        if (resp.empty()) { continue; }
        std::vector<std::string> addrs;
        std::regex re("\"data\"\\s*:\\s*\"([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\"");
        std::sregex_iterator it(resp.begin(), resp.end(), re), end;
        for (; it != end; ++it) { addrs.push_back((*it)[1].str()); }
        if (!addrs.empty()) { return addrs; }
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

    auto worker = [&]() {
        while (true) {
            if (g_cancel_token.cancelled) { break; }
            int idx = next.fetch_add(1, std::memory_order_relaxed);
            if (idx >= total) { break; }
            auto ips = doh_resolve_single(hosts[idx]);
            if (!ips.empty()) {
                std::lock_guard<std::mutex> lk(out_mtx);
                out[hosts[idx]] = std::move(ips);
            }
        }
    };

    int nw = std::min(max_slots, std::min(total, 64));
    std::vector<std::thread> threads;
    threads.reserve(nw);
    for (int i = 0; i < nw; i++) { threads.emplace_back(worker); }
    for (auto& t : threads) { t.join(); }

    return out;
}

std::vector<std::string> DnsEngine::resolve(const std::string& host) {
    auto cached = cache_get(host);
    if (!cached.empty()) { return cached; }

    auto res = run_ares_batch({host}, resolver_pool_snapshot(), 4, 8);
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
    std::string key = host + ":AAAA";
    auto cached = cache_get(key);
    if (!cached.empty()) { return cached; }

    struct ares_options opts{};
    opts.timeout = 500;
    opts.tries   = 2;
    ares_channel ch;
    if (ares_init_options(&ch, &opts, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES) != ARES_SUCCESS) {
        return {};
    }
    auto resolvers = resolver_pool_snapshot();
    if (resolvers.empty()) {
        ares_destroy(ch);
        return {};
    }
    size_t base_offset = resolver_rotation_.fetch_add(static_cast<size_t>(RESOLVERS_PER_CHANNEL), std::memory_order_relaxed);
    std::string csv = make_shard_csv(resolvers, base_offset, 0, RESOLVERS_PER_CHANNEL);
    if (ares_set_servers_csv(ch, csv.c_str()) != ARES_SUCCESS) {
        ares_destroy(ch);
        return {};
    }

    std::vector<std::string> ips;
    std::atomic<int> pending{1};

    struct ares_addrinfo_hints hints{};
    hints.ai_family = AF_INET6;
    ares_getaddrinfo(ch, host.c_str(), nullptr, &hints,
                     ares_aaaa_cb, new AresCtx{&ips, &pending});

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (pending.load(std::memory_order_acquire) > 0 &&
           std::chrono::steady_clock::now() < deadline) {
        poll_loop_step(ch);
    }
    ares_destroy(ch);

    if (!ips.empty()) { cache_put(key, ips); }
    return ips;
}

std::string DnsEngine::resolve_cname(const std::string& host) {
    std::string key = host + ":CNAME";
    auto cached = cache_get(key);
    if (!cached.empty()) { return cached[0]; }

    struct ares_options opts{};
    opts.timeout = 500;
    opts.tries   = 2;
    ares_channel ch;
    if (ares_init_options(&ch, &opts, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES) != ARES_SUCCESS) {
        return "";
    }

    auto resolvers = resolver_pool_snapshot();
    if (resolvers.empty()) {
        ares_destroy(ch);
        return "";
    }

    size_t base_offset = resolver_rotation_.fetch_add(static_cast<size_t>(RESOLVERS_PER_CHANNEL), std::memory_order_relaxed);
    std::string csv = make_shard_csv(resolvers, base_offset, 0, RESOLVERS_PER_CHANNEL);
    if (ares_set_servers_csv(ch, csv.c_str()) != ARES_SUCCESS) {
        ares_destroy(ch);
        return "";
    }

    std::string cname;
    std::atomic<int> pending{1};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ares_query(ch, host.c_str(), ns_c_in, ns_t_cname,
               ares_cname_cb, new CnameCtx{&cname, &pending});
#pragma GCC diagnostic pop

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (pending.load(std::memory_order_acquire) > 0 &&
           !g_cancel_token.cancelled &&
           std::chrono::steady_clock::now() < deadline) {
        poll_loop_step(ch);
    }

    bool completed = pending.load(std::memory_order_acquire) == 0;
    bool cancelled = g_cancel_token.cancelled;
    ares_destroy(ch);

    if (!completed || cancelled || cname.empty()) { return ""; }
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
    auto fresh = run_ares_batch(uncached, resolver_pool_snapshot(),
                                effective_concurrency, deadline_s);

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
