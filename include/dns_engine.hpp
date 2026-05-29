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

class DnsEngine {
public:
    static DnsEngine& get();

    DnsEngine(const DnsEngine&)            = delete;
    DnsEngine& operator=(const DnsEngine&) = delete;

    std::vector<std::string> resolve(const std::string& host);
    std::vector<std::string> resolve_aaaa(const std::string& host);
    std::string              resolve_ptr(const std::string& ip);

    std::unordered_map<std::string, std::vector<std::string>>
    resolve_batch(const std::vector<std::string>& hosts, int concurrency = 800, const std::unordered_set<std::string>* doh_allow = nullptr);

    void set_concurrency(int c);
    void clear_cache();
    void load_resolvers(const std::string& path);

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

    std::vector<std::string> cache_get(const std::string& host);
    void                     cache_put(const std::string& host,
                                       const std::vector<std::string>& ips);

    std::unordered_map<std::string, std::vector<std::string>>
    run_ares_batch(const std::vector<std::string>& hosts,
                   const std::vector<std::string>& resolvers,
                   int concurrency,
                   int deadline_s);

    bool detect_io_uring();
};
