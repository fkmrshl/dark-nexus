# Subdomain Scanner Refactor Overview

This document describes the major subdomain scanner refactors that changed the scanner architecture, data flow, DNS execution model, and long-scan behavior. Small hotfixes and isolated cleanups are not listed here.

## Scope

The refactor focused on the subdomain module and its DNS backend. The public CLI stayed compatible with the existing workflow:

```bash
dark-nexus --subdomain example.com --mode F
dark-nexus --subdomain example.com --mode D
```

No extra flag is required for the new DNS pipeline or resolver handling.

## File layout

The old monolithic subdomain implementation was split into focused source files:

| File | Responsibility |
|---|---|
| `src/subdomain.cpp` | Scan orchestration, queues, phase barriers, wildcard checks, checkpointing, export flow |
| `src/subdomain_common.hpp` | Internal shared types and helper declarations |
| `src/subdomain_generate.cpp` | Wordlist normalization, candidate generation, permutation generation, extraction helpers |
| `src/subdomain_http.cpp` | HTTP probing, enrichment, web technology detection helpers |
| `src/subdomain_passive.cpp` | Passive source collection and passive enumeration helpers |
| `src/dns_engine.cpp` | Async DNS execution, resolver loading, resolver health, cache, DoH fallback coordination |
| `include/dns_engine.hpp` | Public DNS engine interface |

This split keeps the scanner behavior intact while reducing the size and coupling of `src/subdomain.cpp`.

## Streaming wordlist pipeline

Deep scans no longer load the full wordlist into memory before DNS work starts.

The scanner now:

1. Reads the wordlist incrementally.
2. Normalizes each candidate into a fully qualified domain name.
3. Deduplicates candidates per batch.
4. Resolves batches as soon as they are full.
5. Pushes resolved hosts into the HTTP enrichment queue.

This allows large wordlists to be scanned without building a multi-million-entry in-memory candidate set.

## DNS batch execution

The DNS backend was rebuilt around a bounded async batch model.

Key changes:

- `resolve_batch()` now respects the requested concurrency.
- Resolver rotation is applied across c-ares channels.
- Batch size is capped by the scanner, not by full wordlist size.
- DNS result collection uses per-index storage and merges results after worker threads finish.
- Shared result maps are not written directly from c-ares callbacks.
- Empty DNS results are not cached as successful answers.

This removed data races and made DNS execution predictable under high concurrency.

## Resolver pool handling

Custom and built-in resolvers now go through health filtering before use.

The resolver system now:

- Loads custom resolver files when present.
- Deduplicates resolver IPs.
- Tests resolvers with positive and negative DNS probes.
- Keeps a safe healthy subset.
- Ranks custom resolvers by measured response time.
- Falls back to the built-in resolver list when too few custom resolvers pass health checks.

Supported resolver file locations include:

```text
./resolvers.txt
./resolvers_trusted.txt
~/resolvers.txt
/usr/share/wordlists/resolvers.txt
/opt/resolvers.txt
```

Users can provide custom resolvers by placing `resolvers.txt` in one of those locations. No CLI flag is required.

## c-ares event loop fix

The DNS hot path now drives c-ares timeout processing correctly.

The previous event loop waited for socket readiness but did not consistently notify c-ares when no socket event arrived before timeout. That caused unresolved candidates to remain pending until the outer batch deadline.

The corrected poll backend now calls:

```cpp
ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
```

when there are no active sockets, no poll file descriptors, poll timeout, or ready events that do not produce a processed descriptor.

Bulk DNS also uses the corrected poll backend instead of the previous `io_uring` hot path. The `io_uring` code remains in the source tree, but bulk subdomain DNS no longer depends on it.

## Direct A-record queries

Bulk A-record resolution now uses direct c-ares queries:

```cpp
ares_query(ch, host.c_str(), ns_c_in, ns_t_a, bulk_a_cb, ctx);
```

The response is parsed with the c-ares A reply parser and stored in per-index result vectors.

This keeps the brute-force DNS path focused on A records and avoids general `getaddrinfo` behavior in the bulk wordlist path.

## HTTP pipeline phase barriers

The HTTP enrichment queue now tracks queued and active work.

The scanner waits for the HTTP pipeline at key phase boundaries:

1. After base wordlist and passive DNS resolution.
2. After permutation DNS resolution.

This prevents snapshots from being taken while HTTP workers are still enriching recently resolved hosts.

## Result attribution

Result attribution is now subdomain-based.

The scanner no longer reuses HTTP metadata from another host on the same IP. This avoids incorrect titles, server headers, WAF labels, and technology fingerprints when multiple hosts share an address.

## Wildcard detection

Wildcard filtering was changed from a simple IP union check to a fingerprint model.

The scanner now probes multiple random names and builds a wildcard fingerprint using:

- Positive probe count.
- IP union.
- IP frequency.
- Sorted response signatures.

A candidate is treated as wildcard only when its full signature matches a wildcard signature or all of its addresses are inside the wildcard address set. Partial overlap is not enough to discard the candidate.

## Permutation generation

Permutation candidates are streamed into DNS batches instead of being fully materialized first.

The scanner now emits permutation candidates through an iterator-style helper and flushes DNS batches as they fill. This avoids large memory spikes on domains with many base discoveries.

## JavaScript scraping phase

The JavaScript scraping phase now uses a lightweight host list instead of copying the full result structure.

Only hosts with useful HTTP responses are selected as JS scraping targets. New candidates found in scripts are resolved once and passed through the same DNS and HTTP pipeline.

## CNAME and AAAA enrichment

CNAME lookup no longer depends on external `dig` execution.

CNAME and AAAA enrichment use the internal DNS engine and c-ares resolver state. This removes shell execution overhead and avoids polluted CNAME values from command stderr or resolver timeout messages.

## Checkpoint export

Long-running subdomain scans now write an atomic checkpoint file:

```text
<domain>_subdomains_checkpoint.json
```

The checkpoint contains partial results and is written through a temporary file followed by rename. Checkpoints are generated at safe phase and batch boundaries, not from inside per-result hot paths.

## Current scan flow

The deep scan flow is now:

1. Load and health-check resolvers.
2. Check wildcard behavior for the target domain.
3. Collect passive candidates.
4. Stream the wordlist into DNS batches.
5. Queue resolved hosts for HTTP enrichment.
6. Wait for base HTTP enrichment to finish.
7. Stream permutation candidates into DNS batches.
8. Wait for permutation HTTP enrichment to finish.
9. Scrape selected HTTP targets for JavaScript candidates.
10. Resolve JS candidates.
11. Write checkpoint and final JSON/CSV output.
12. Run takeover candidate checks where applicable.

## Operational effect

The refactor changed the subdomain scanner from a memory-heavy, phase-leaky pipeline into a streamed DNS and HTTP pipeline with bounded queues, stable resolver handling, checkpointing, and corrected c-ares timeout processing.

The user-facing commands stayed the same.
