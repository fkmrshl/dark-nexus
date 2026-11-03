#pragma once

#include <algorithm>
#include <cstddef>

// Keep each checked call small enough to drain even when every query times out.
// The engine uses one resolver per channel; retries are owned by the pipeline.
inline std::size_t subdomain_dns_batch_limit(int concurrency, int query_timeout_ms) {
    const auto slots = static_cast<std::size_t>(std::clamp(concurrency, 16, 2000));
    const auto timeout = static_cast<std::size_t>(std::clamp(query_timeout_ms, 100, 5000));
    const auto waves = std::max<std::size_t>(1, 5000 / timeout);
    return std::clamp<std::size_t>(slots * waves / 2, 1, 10000);
}

inline int subdomain_dns_deadline(std::size_t count, int concurrency, int query_timeout_ms) {
    const auto slots = static_cast<std::size_t>(std::clamp(concurrency, 16, 2000));
    const auto timeout = static_cast<std::size_t>(std::clamp(query_timeout_ms, 100, 5000));
    // Callers split at batch_limit, so this multiplication is bounded. Allow
    // twice the worst-case wire time plus polling/scheduling slack.
    const auto waves = (std::min<std::size_t>(count, 10000) * 2 + slots - 1) / slots;
    return static_cast<int>(std::clamp<std::size_t>(2 * waves * timeout + 1000, 1000, 30000));
}
