#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <array>

struct DnsLookupResult {
    std::vector<std::string> ipv4, ipv6;
    bool failed = false;
    bool ipv4_failed = false, ipv6_failed = false;
    bool ipv4_retryable = false, ipv6_retryable = false;
    // Attempted describes this call; deadline flags for unselected families are preserved.
    bool ipv4_attempted = false, ipv6_attempted = false;
    bool ipv4_deadline_exceeded = false, ipv6_deadline_exceeded = false;
    std::string ipv4_error, ipv6_error;
    std::string error;
};

class DnsEngine {
public:
    static DnsEngine& get();

    DnsEngine(const DnsEngine&)            = delete;
    DnsEngine& operator=(const DnsEngine&) = delete;

    std::vector<std::string> resolve(const std::string& host);
    std::vector<std::string> resolve_aaaa(const std::string& host);
    std::string              resolve_cname(const std::string& host);
    std::string              resolve_ptr(const std::string& ip);

    std::unordered_map<std::string, std::vector<std::string>>
    resolve_batch(const std::vector<std::string>& hosts, int concurrency = 800, const std::unordered_set<std::string>* doh_allow = nullptr);

    // A and AAAA together, without DoH or a cache that could hide failures.
    // Negative DNS answers are successful empty results; operational failures
    // retain any addresses collected from the other family.
    std::unordered_map<std::string, DnsLookupResult>
    resolve_batch_checked(const std::vector<std::string>& hosts, int concurrency = 800,
                          int timeout_ms = 30000, int query_timeout_ms = 500,
                          const std::unordered_map<std::string, DnsLookupResult>* retry_previous = nullptr);

    void set_concurrency(int c);
    void clear_cache();
    void load_resolvers(const std::string& path);
    int channel_count() const;
    int max_per_channel_concurrency() const;
    size_t resolver_count() const;

private:
    DnsEngine();
    ~DnsEngine();

    struct CacheEntry {
        std::vector<std::string>               ips;
        std::chrono::steady_clock::time_point  expires;
    };

    static constexpr int N_SHARDS    = 64;
    static constexpr int CACHE_TTL_S = 300;

    struct CacheShard {
        std::unordered_map<std::string, CacheEntry> map;
        std::mutex                                   mtx;
    };

    std::array<std::unique_ptr<CacheShard>, N_SHARDS> shards_;
    int  concurrency_{800};
    bool io_uring_ok_{false};
    std::atomic<size_t> resolver_rotation_{0};

    std::vector<std::string> cache_get(const std::string& host);
    void                     cache_put(const std::string& host,
                                       const std::vector<std::string>& ips);

    std::unordered_map<std::string, std::vector<std::string>>
    run_ares_batch(const std::vector<std::string>& hosts,
                   int concurrency,
                   int deadline_s);

    std::unordered_map<std::string, DnsLookupResult>
    resolve_batch_checked_impl(const std::vector<std::string>& hosts, int concurrency,
                               int timeout_ms, int query_timeout_ms,
                               const std::unordered_map<std::string, DnsLookupResult>* retry_previous,
                               int resolvers_per_channel);

    bool detect_io_uring();
};
