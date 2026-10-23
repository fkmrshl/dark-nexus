// Exercise the production parser without opening sockets. Function sections
// let this test link only the parser/statistics used below, excluding CLI entry
// points and their networking dependencies from the included translation unit.
#include "../src/traceroute.cpp"

#include <array>
#include <cassert>
#include <memory>

namespace {
constexpr int outer_length = 20;
constexpr int quote_offset = outer_length + sizeof(struct icmphdr);

void packet_boundaries_and_correlation() {
    alignas(8) std::array<char, 128> packet{};
    auto* original = reinterpret_cast<struct iphdr*>(packet.data() + quote_offset);
    original->version = 4;
    original->ihl = 5;
    original->protocol = IPPROTO_UDP;
    assert(inet_pton(AF_INET, "127.0.0.1", &original->daddr) == 1);

    constexpr int minimum_length = quote_offset + 20 + 8;
    for (int length = 0; length < minimum_length; ++length) {
        // Use an allocation of precisely the claimed length so sanitizers also
        // detect accidental reads beyond a truncated packet's real buffer.
        std::unique_ptr<char[]> truncated(new char[std::max(length, 1)]);
        std::memcpy(truncated.get(), packet.data(), length);
        assert(!TracerouteEngine::quoted_transport(truncated.get(), length,
            outer_length, IPPROTO_UDP, "127.0.0.1"));
    }

    assert(TracerouteEngine::quoted_transport(packet.data(), minimum_length,
        outer_length, IPPROTO_UDP, "127.0.0.1") == packet.data() + quote_offset + 20);
    // Other traffic on the raw socket must not satisfy this probe.
    assert(!TracerouteEngine::quoted_transport(packet.data(), minimum_length,
        outer_length, IPPROTO_TCP, "127.0.0.1"));
    assert(!TracerouteEngine::quoted_transport(packet.data(), minimum_length,
        outer_length, IPPROTO_UDP, "127.0.0.2"));

    for (const int invalid_ihl : {0, 4, 15}) {
        original->ihl = invalid_ihl;
        assert(!TracerouteEngine::quoted_transport(packet.data(), minimum_length,
            outer_length, IPPROTO_UDP, "127.0.0.1"));
    }
    // Valid IPv4 options move the quoted transport header further into the packet.
    original->ihl = 15;
    assert(TracerouteEngine::quoted_transport(packet.data(), quote_offset + 60 + 8,
        outer_length, IPPROTO_UDP, "127.0.0.1") == packet.data() + quote_offset + 60);
    original->ihl = 5;
    original->version = 6;
    assert(!TracerouteEngine::quoted_transport(packet.data(), minimum_length,
        outer_length, IPPROTO_UDP, "127.0.0.1"));
}

void jitter_preserves_probe_order() {
    HopStats stats;
    stats.sent = 4;
    stats.received = 3;
    stats.rtts = {10, 30, 20};
    stats.compute();
    assert(stats.min_rtt == 10 && stats.max_rtt == 30 && stats.avg_rtt == 20);
    assert(stats.jitter == 15 && stats.loss_pct == 25);
    assert((stats.rtts == std::vector<double>{10, 30, 20}));

    HopStats missing;
    missing.sent = 3;
    missing.compute();
    assert(missing.loss_pct == 100);
}
} // namespace

int main() {
    packet_boundaries_and_correlation();
    jitter_preserves_probe_order();
}
