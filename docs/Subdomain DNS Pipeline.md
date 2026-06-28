
# Subdomain DNS Pipeline

This document describes the current DNS execution path used by the subdomain scanner.

## Modes

The scanner keeps the existing public modes:

```bash
dark-nexus --subdomain example.com --mode F
dark-nexus --subdomain example.com --mode D
```

Fast mode uses the built-in candidate set and passive enumeration limits. Deep mode streams the configured wordlist and runs the full DNS, HTTP, permutation, and JavaScript candidate pipeline.

## Resolver discovery

The DNS engine can use custom resolvers without a CLI flag.

Resolver files are searched in this order:

```text
./resolvers.txt
./resolvers_trusted.txt
~/resolvers.txt
/usr/share/wordlists/resolvers.txt
/opt/resolvers.txt
```

If no custom resolver file is found, the built-in resolver list is used.

## Custom resolver setup

A user can install a resolver list globally for their account:

```bash
curl -LfsS https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt -o ~/resolvers.txt
```

Or use a resolver list only for one working directory:

```bash
mkdir -p ~/dn-scan
cd ~/dn-scan
curl -LfsS https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt -o resolvers.txt
dark-nexus --subdomain example.com --mode D
```

No `--resolvers` option is required.

## Resolver health check

Before scanning, custom resolvers are validated.

The health check uses both:

- A positive DNS probe that should return an A record.
- A negative random `.invalid` probe that should not return an A record.

Passing resolvers are ranked by response time. For large custom lists, the scanner keeps the fastest healthy subset instead of using every resolver blindly.

If too few custom resolvers pass, the scanner falls back to the built-in resolver list.

## Batch model

The scanner resolves candidates in batches.

Current behavior:

- Wordlist candidates are streamed into fixed-size batches.
- Duplicates are removed inside the active batch.
- Resolved hosts are queued into the HTTP enrichment pipeline.
- Empty answers are not cached as successful DNS results.
- DNS callbacks write into per-index result vectors.
- Results are merged only after worker threads complete.

This keeps the hot path bounded and avoids shared-map writes from callbacks.

## c-ares execution

Bulk A-record lookup uses direct c-ares A queries:

```cpp
ares_query(ch, host.c_str(), ns_c_in, ns_t_a, bulk_a_cb, ctx);
```

The callback parses A replies and writes IPv4 addresses into the per-index result vector for that host.

AAAA and CNAME enrichment use separate internal DNS engine paths and are not handled by the bulk A callback.

## Timeout processing

The poll backend explicitly drives c-ares timeout handling by calling:

```cpp
ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
```

This happens when:

- c-ares reports no sockets.
- no poll descriptors are available.
- `poll()` times out.
- `poll()` reports readiness but no descriptor is processed.

Socket error states such as `POLLERR`, `POLLHUP`, and `POLLNVAL` are passed back to c-ares as readable readiness so c-ares can fail or close the socket state.

## io_uring status

The project still contains `io_uring` detection and helper code.

Bulk subdomain DNS currently uses the corrected poll backend. The older `io_uring` hot path is kept out of bulk DNS execution because the poll backend has the correct c-ares timeout behavior and simpler lifecycle handling.

## DoH fallback

DoH fallback is preserved.

The `doh_allow` parameter controls fallback behavior:

| Value | Meaning |
|---|---|
| `nullptr` | DoH fallback is allowed for unresolved hosts |
| pointer to empty set | DoH fallback is suppressed |
| pointer to passive allow-set | DoH fallback is allowed only for hosts in that set |

This allows passive candidates to use fallback behavior without making brute-force DNS rely on DoH.

## HTTP handoff

After DNS resolution, positive hosts are passed into the HTTP enrichment queue.

The DNS phase does not directly write final HTTP metadata. HTTP workers enrich results with status code, server header, title, WAF label, language, CMS, and stack signals where available.

The scanner waits for the queue to become idle before taking snapshots for later phases.

## Performance profile

After the DNS event loop fix, large wordlists resolve in a streamed batch model instead of stalling on unresolved candidates until the outer batch deadline.

Typical deep scan behavior now shows:

- 10,000-host DNS batches completing in seconds on a working resolver set.
- Stable checkpoint writes during long scans.
- Permutation batches using the same DNS and HTTP pipeline.

Actual speed depends on resolver quality, network path, VM networking, packet loss, and the number of positive hosts that require HTTP enrichment.

## Modes

The scanner keeps the existing public modes:

```bash
dark-nexus --subdomain example.com --mode F
dark-nexus --subdomain example.com --mode D
```

Fast mode uses the built-in candidate set and passive enumeration limits. Deep mode streams the configured wordlist and runs the full DNS, HTTP, permutation, and JavaScript candidate pipeline.

## Resolver discovery

The DNS engine can use custom resolvers without a CLI flag.

Resolver files are searched in this order:

```text
./resolvers.txt
./resolvers_trusted.txt
~/resolvers.txt
/usr/share/wordlists/resolvers.txt
/opt/resolvers.txt
```

If no custom resolver file is found, the built-in resolver list is used.

## Custom resolver setup

A user can install a resolver list globally for their account:

```bash
curl -LfsS https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt -o ~/resolvers.txt
```

Or use a resolver list only for one working directory:

```bash
mkdir -p ~/dn-scan
cd ~/dn-scan
curl -LfsS https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt -o resolvers.txt
dark-nexus --subdomain example.com --mode D
```

No `--resolvers` option is required.

## Resolver health check

Before scanning, custom resolvers are validated.

The health check uses both:

- A positive DNS probe that should return an A record.
- A negative random `.invalid` probe that should not return an A record.

Passing resolvers are ranked by response time. For large custom lists, the scanner keeps the fastest healthy subset instead of using every resolver blindly.

If too few custom resolvers pass, the scanner falls back to the built-in resolver list.

## Batch model

The scanner resolves candidates in batches.

Current behavior:

- Wordlist candidates are streamed into fixed-size batches.
- Duplicates are removed inside the active batch.
- Resolved hosts are queued into the HTTP enrichment pipeline.
- Empty answers are not cached as successful DNS results.
- DNS callbacks write into per-index result vectors.
- Results are merged only after worker threads complete.

This keeps the hot path bounded and avoids shared-map writes from callbacks.

## c-ares execution

Bulk A-record lookup uses direct c-ares A queries:

```cpp
ares_query(ch, host.c_str(), ns_c_in, ns_t_a, bulk_a_cb, ctx);
```

The callback parses A replies and writes IPv4 addresses into the per-index result vector for that host.

AAAA and CNAME enrichment use separate internal DNS engine paths and are not handled by the bulk A callback.

## Timeout processing

The poll backend explicitly drives c-ares timeout handling by calling:

```cpp
ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
```

This happens when:

- c-ares reports no sockets.
- no poll descriptors are available.
- `poll()` times out.
- `poll()` reports readiness but no descriptor is processed.

Socket error states such as `POLLERR`, `POLLHUP`, and `POLLNVAL` are passed back to c-ares as readable readiness so c-ares can fail or close the socket state.

## io_uring status

The project still contains `io_uring` detection and helper code.

Bulk subdomain DNS currently uses the corrected poll backend. The older `io_uring` hot path is kept out of bulk DNS execution because the poll backend has the correct c-ares timeout behavior and simpler lifecycle handling.

## DoH fallback

DoH fallback is preserved.

The `doh_allow` parameter controls fallback behavior:

| Value | Meaning |
|---|---|
| `nullptr` | DoH fallback is allowed for unresolved hosts |
| pointer to empty set | DoH fallback is suppressed |
| pointer to passive allow-set | DoH fallback is allowed only for hosts in that set |

This allows passive candidates to use fallback behavior without making brute-force DNS rely on DoH.

## HTTP handoff

After DNS resolution, positive hosts are passed into the HTTP enrichment queue.

The DNS phase does not directly write final HTTP metadata. HTTP workers enrich results with status code, server header, title, WAF label, language, CMS, and stack signals where available.

The scanner waits for the queue to become idle before taking snapshots for later phases.

## Performance profile

After the DNS event loop fix, large wordlists resolve in a streamed batch model instead of stalling on unresolved candidates until the outer batch deadline.

Typical deep scan behavior now shows:

- 10,000-host DNS batches completing in seconds on a working resolver set.
- Stable checkpoint writes during long scans.
- Permutation batches using the same DNS and HTTP pipeline.

Actual speed depends on resolver quality, network path, VM networking, packet loss, and the number of positive hosts that require HTTP enrichment.
