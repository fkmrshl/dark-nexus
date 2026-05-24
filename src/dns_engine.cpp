#include "../include/dns_engine.hpp"
#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"
#include <ares.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <cstring>

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
static constexpr int N_CHANNELS  = 4;
static constexpr int RESOLVERS_PER_CHANNEL = 4;
static constexpr int CONCURRENCY_PER_CHANNEL = 500;

struct AresCtx {
    std::vector<std::string>* out;
    std::atomic<int>*         pending;
};

static void ares_addr_cb(void* arg, int status, int, struct ares_addrinfo* res) {
    std::unique_ptr<AresCtx> ctx(static_cast<AresCtx*>(arg));
    if (status == ARES_SUCCESS && res) {
        for (auto* n = res->nodes; n; n = n->ai_next) {
            if (n->ai_family == AF_INET) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET,
                    &reinterpret_cast<sockaddr_in*>(n->ai_addr)->sin_addr,
                    buf, sizeof(buf));
                ctx->out->emplace_back(buf);
            }
        }
        ares_freeaddrinfo(res);
    }
    ctx->pending->fetch_sub(1, std::memory_order_release);
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

static void poll_loop_step(ares_channel ch) {
    ares_socket_t socks[ARES_GETSOCK_MAXNUM]{};
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    int bitmask = ares_getsock(ch, socks, ARES_GETSOCK_MAXNUM);
#pragma GCC diagnostic pop

    if (bitmask == 0) {
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

    if (nfds == 0) { return; }
    poll(pfds, nfds, tms);

    for (int i = 0; i < nfds; i++) {
        ares_socket_t rfd = (pfds[i].revents & POLLIN)  ? pfds[i].fd : ARES_SOCKET_BAD;
        ares_socket_t wfd = (pfds[i].revents & POLLOUT) ? pfds[i].fd : ARES_SOCKET_BAD;
        if (rfd != ARES_SOCKET_BAD || wfd != ARES_SOCKET_BAD) {
            ares_process_fd(ch, rfd, wfd);
        }
    }
}

#if DNS_HAS_URING
static void uring_loop_step(ares_channel ch, struct io_uring* ring) {
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

void DnsEngine::set_concurrency(int c) { concurrency_ = c; }

void DnsEngine::clear_cache() {
    for (int i = 0; i < N_SHARDS; i++) {
        std::lock_guard<std::mutex> lk(shards_[i]->mtx);
        shards_[i]->map.clear();
    }
}

static std::string make_shard_csv(int channel_idx) {
    int start = (channel_idx * RESOLVERS_PER_CHANNEL) % (int)ALL_RESOLVERS.size();
    std::string csv;
    for (int i = 0; i < RESOLVERS_PER_CHANNEL; i++) {
        if (i) { csv += ","; }
        csv += ALL_RESOLVERS[(start + i) % ALL_RESOLVERS.size()];
    }
    return csv;
}

std::unordered_map<std::string, std::vector<std::string>>
DnsEngine::run_ares_batch(const std::vector<std::string>& hosts,
                           const std::vector<std::string>& /*resolvers*/,
                           int concurrency,
                           int deadline_s)
{
    int total = (int)hosts.size();

    std::unordered_map<std::string, std::vector<std::string>> results;
    results.reserve(total * 2);
    for (auto& h : hosts) { results[h]; }

    if (total == 0) { return results; }

    int n_ch = (total <= 50)   ? 1 :
               (total <= 2000) ? std::min(N_CHANNELS, 2) :
               N_CHANNELS;

    std::atomic<int> next_host{0};

    auto worker = [&](int tid) {
#if DNS_HAS_URING
        struct io_uring ring{};
        bool ring_ok = false;
        if (io_uring_ok_) {
            ring_ok = (io_uring_queue_init(4096, &ring, 0) == 0);
        }
#endif
        struct ares_options opts{};
        opts.timeout = 500;
        opts.tries   = 2;
        ares_channel ch;
        if (ares_init_options(&ch, &opts, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES) != ARES_SUCCESS) {
#if DNS_HAS_URING
            if (ring_ok) { io_uring_queue_exit(&ring); }
#endif
            return;
        }

        std::string csv = make_shard_csv(tid);
        ares_set_servers_csv(ch, csv.c_str());

        std::atomic<int> pending{0};
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(deadline_s);

        while (true) {
            if (g_cancel_token.cancelled) { break; }
            if (std::chrono::steady_clock::now() > deadline) { break; }

            while (pending.load(std::memory_order_acquire) < concurrency) {
                int idx = next_host.fetch_add(1, std::memory_order_relaxed);
                if (idx >= total) { goto drain; }

                const std::string& h = hosts[idx];
                auto* out_vec = &results[h];

                pending.fetch_add(1, std::memory_order_acquire);

                struct ares_addrinfo_hints hints{};
                hints.ai_family = AF_INET;
                ares_getaddrinfo(ch, h.c_str(), nullptr, &hints,
                                 ares_addr_cb,
                                 new AresCtx{out_vec, &pending});
            }

            drain:
            if (pending.load(std::memory_order_acquire) == 0 &&
                next_host.load(std::memory_order_relaxed) >= total) {
                break;
            }

#if DNS_HAS_URING
            if (ring_ok) { uring_loop_step(ch, &ring); }
            else          { poll_loop_step(ch); }
#else
            poll_loop_step(ch);
#endif
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

    return results;
}

static std::vector<std::string> doh_resolve_single(const std::string& host) {
    if (!InputGuard::is_valid_host(host)) return {};
    const std::vector<std::pair<std::string,std::string>> providers = {
        {"https://cloudflare-dns.com/dns-query?name="+host+"&type=A", "cloudflare"},
        {"https://dns.google/resolve?name="+host+"&type=A",           "google"},
    };
    for (auto& [url, name] : providers) {
        auto resp = safe_exec({"curl","-s","--max-time","4",
                               "-H","Accept: application/dns-json","--",url}, 6);
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

    auto res = run_ares_batch({host}, ALL_RESOLVERS, 4, 8);
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
    std::string csv = make_shard_csv(0);
    ares_set_servers_csv(ch, csv.c_str());

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
DnsEngine::resolve_batch(const std::vector<std::string>& hosts, int /*concurrency*/)
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
    int deadline_s = (n <= 100)    ? 10 :
                     (n <= 10000)  ? 30 :
                     (int)std::max(300, n / 5000 + 60);

    auto fresh = run_ares_batch(uncached, ALL_RESOLVERS,
                                CONCURRENCY_PER_CHANNEL, deadline_s);

    std::vector<std::string> doh_queue;
    for (auto& [h, ips] : fresh) {
        if (!ips.empty()) {
            cache_put(h, ips);
            out[h] = std::move(ips);
        } else {
            doh_queue.push_back(h);
        }
    }

    if (!doh_queue.empty()) {
        constexpr int DOH_CAP = 2000;
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
