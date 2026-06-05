# Port scan engine — audit notes and what we shipped

This document records the port scanner audit (TASK 1–6 and follow-up work from the same pass), what was wrong, what we changed, and what we deliberately left alone.

**Main code:** `src/port_scan.cpp` (~2160 lines)

**Also touched:** `src/utils.cpp`, `src/main.cpp`, `include/dark_nexus.hpp`

**Left alone on purpose:** `include/port_scan_engine.hpp` — no struct or `PortScanEngine` API changes.

For the longer TLS/HTTP/banner design write-up, see `port_scan_improvement_plan.md`. This file is the audit + implementation log for everything that actually landed in the tree.

---

## The timing hang (BUG-01)

The worst bug was config assembly order in `port_scan()`.

Calibration ran first and set sensible values for a big scan (e.g. `pool_size` 150+, `connect_ms` tied to RTT). Then large-range caps applied. Then the timing `switch` ran **again** and wiped that work — T2 on a full 1–65535 scan fell back to `pool_size=30` and `connect_ms=1500`, which matched multi-hour runtimes on a LAN.

**Fix:** split timing into two passes.

Early pass (before `calibrate_target`): apply T0/T1/T2 base values; T3 is a no-op.

Calibration merge:

- **T3, T4, T5:** take `connect_ms`, `banner_ms`, `retry_count`, `pool_size` from calibration (same as before for T3).
- **T0–T2:** merge timeouts from calibration with `std::max` so stealth floors stay (T2 keeps its 1500ms connect intent), but **do not** let calibration raise `pool_size` or `retry_count` — those stay on the timing profile values.

Then FD limit clamp, large-range floors, UDP caps, and finally a **late** pass that only applies T4/T5 speed modifiers. Pool is capped at 600 so T5 on a fast LAN does not spawn 1000+ threads.

Large-range floors (after calibration merge, before T4/T5):

- More than 5000 ports: `retry_count` capped at 1, `pool_size` floor 150, `connect_ms` capped at 800 (with a 150ms minimum), rate limiter disabled.
- More than 1000 ports: `retry_count` capped at 1, `pool_size` floor 80.
- T0/T1 only, more than 100 ports: `pool_size` floor 20.

T4/T5 got RTT-aware connect floors so aggressive profiles do not outrun the target on WAN links: T4 uses `max(halved_timeout, min(1500, median_rtt * 5))` with a 100ms floor; T5 uses `max(50, min(800, median_rtt * 3))`. T4 also keeps at least one retry.

**Status:** done.

---

## Security hints (TASK 2–6)

### Port exposure layer (TASK 2)

Added `check_port_exposure_hints()` and call it first inside `check_vulns()`. It fires on any open port without needing a banner — RDP 3389, Postgres 5432, MSSQL 1433, Mongo 27017, Elasticsearch 9200/9300, etcd 2379, CouchDB 5984, Memcached 11211, VNC 5900/5901, Metasploit-ish 4444, X11 6000, Hadoop 50070, and similar. Fixes BUG-04 for ports like 9200 where banner-based checks never ran.

### Redis and Mongo probes (TASK 3)

When Phase 2 has no banner on 6379 or 27017:

- **Redis:** `PING\r\n` over TCP; keep raw RESP (`+PONG`, `-NOAUTH`, etc.).
- **Mongo:** 58-byte `isMaster` OP_QUERY; validate message length; return response if `ismaster` appears, else sentinel `mongodb-open`.

Existing `check_vulns` Redis/Mongo rules then have something to chew on.

### PHP EOL false positive (TASK 4, BUG-03)

`X-Powered-By: PHP/8.1+` was flagged as EOL because the check treated all PHP 8 as end-of-life. Now only PHP &lt; 7, 7.x &lt; 7.4, and **8.0** are flagged.

### Web CVEs on all HTTP ports (TASK 5, BUG-05)

`check_web_version_cves()` runs for any port in `HTTP_PORTS`, not just 80/443/8080/8443. Apache 2.4.49 on 8000 or 3000 gets CVE-2021-41773.

### Banner-based service checks (TASK 6)

Extra rules when a banner exists:

- **9200:** `cluster_name` or `you know, for search` → Elasticsearch without auth (CRIT). May duplicate the exposure hint — different keys, dedupe keeps both.
- **27017:** `mongodb-open` or `ismaster` → Mongo without auth challenge.
- **11211:** `version` or `stat` in response → Memcached stats without auth.

Dynamic text in hints goes through `InputGuard::sanitize_output()` where it embeds probe output.

**Status:** TASK 2–6 done in code.

---

## TLS and HTTP (from the improvement plan, same pass)

A lot of the improvement plan landed in the same edits:

- `tcp_connect_wait()` — wait for TCP before TLS.
- `cfg.sni_host` from `g_result.target` (domain), else PTR, else IP.
- `probe_tls_http()` — one connection for TLS + HTTP on shared ports (443, 8443, …).
- Cleartext `probe_http()` only on non-TLS HTTP ports.
- `inspect_tls()` fills cipher, expiry, SANs, proper self-signed check.
- `print_tls_enrichment()` / `print_http_enrichment()` under each port row.
- HTTP cleartext ports populate `banner_raw` / `version` from status + Server when Phase 2 uses `probe_http()`.

**Status:** done for the core path. STARTTLS on 993/995/465 is still optional future work.

---

## Banners and protocol probes (Phase 2)

**`banner_usable()`** rejects garbage: shorter than 5 chars, all whitespace, or mostly non-printable. Applied after `smart_banner` and after Redis/Mongo probes.

When `smart_banner` is empty on common service ports, dedicated probes run:

- 22 SSH (read initial line)
- 21 FTP, 25/587/465 SMTP (EHLO/read)
- 3306 MySQL (handshake bytes)
- 5432 Postgres (SSL request / startup)

**OpenSSH CVE matching** searches the full fingerprint haystack (`banner` + `version` + HTTP Server/Powered-By), not just the truncated version field — so `SSH-2.0-OpenSSH_8.9` in the banner still matches regreSSHion rules.

**Status:** done.

---

## IPv6 and address family

New `ScanAddrFamily` enum: `Auto`, `IPv4`, `IPv6`.

`resolve_for_scan()` in `utils.cpp`:

- Literal v4/v6 returned as-is when family allows.
- **Auto:** A record first via `DnsEngine::resolve()`, then AAAA via `resolve_aaaa()`, then fallback to first A answer.
- **IPv4 / IPv6:** forced family; empty if DNS has no matching record.

CLI: `--ipv4`, `--ipv6`. Interactive port scan menu asks `4` / `6` / empty for auto.

`port_scan()` takes optional `addr_family`, resolves to `scan_ip`, prints which mode is active.

**IPv6 scanning:** no SYN (raw IPv4 only). `cfg.syn_scan = false`; message `IPv6 target (TCP connect scan)`. All probes use `sockaddr_storage` helpers: `scan_fill_endpoint`, `scan_tcp_socket`, dual-stack `probe_connect`, `tcp_connect_to`, `calibrate_target`.

`utils.cpp`: `tcp_probe`, `banner`, `smart_banner` also work on v6 sockets.

**Status:** done. JSON export still stores whatever IP was scanned; no separate `addr_family` field yet.

---

## SYN scan reliability (IPv4)

- No `cap_net_raw` → connect scan (unchanged idea, still in `probe_syn`).
- IPv6 target → connect scan.
- Source port formula: `32768 + ((port * 31337 + attempt * 7919) % 30000)` to reduce collisions on parallel scans.
- On final SYN timeout: **connect recheck** with at least 400ms before marking filtered — cuts false filtered on `-T4`/`-T5` when SYN reply is lost.

**Status:** done. Still requires `setcap cap_net_raw=eip` on the binary (see `install.sh`) for SYN on IPv4 without sudo.

---

## Terminal output

Under each open port in Phase 3:

- TLS and HTTP enrichment blocks (when data exists).
- `Stack:` line for `X-Powered-By` on that port (not duplicated in the main HTTP line).
- Up to **3** vulnerability hints inline (`hint [SEVERITY] CVE desc`).
- VERSION column truncated at 24 chars in the table; banner at 45.

After scan stats, **STACK DISCLOSURES** section lists port → `X-Powered-By` for all HTTP ports that disclosed it.

Global **SECURITY HINTS** section unchanged in spirit — deduped, sorted by severity.

**Status:** done.

---

## Config assembly order (reference)

Target pipeline in `port_scan()` Phase 0:

1. Early timing switch (T0–T2 bases, T3 noop)
2. `calibrate_target()` + selective merge
3. `RLIMIT_NOFILE` clamp on `pool_size`
4. Large-range floors
5. UDP caps
6. Late timing switch (T4/T5 only)
7. `pool_size = min(pool_size, 600)`
8. Engine run

---

## Files to push for this work

Required (build breaks if any missing):

- `src/port_scan.cpp`
- `src/utils.cpp`
- `src/main.cpp`
- `include/dark_nexus.hpp`

Docs (optional but recommended):

- `docs/port_scan_audit_plan.md` (this file)
- `docs/port_scan_improvement_plan.md`

No changes needed to `install.sh` or `CMakeLists.txt` for this pass.

---

## Verification (manual)

Build:

```bash
cd build && cmake -B . -G Ninja && cmake --build . -j$(nproc)
```

Smoke checks that matter:

- **T2, ports 1–65535 on LAN** — finishes in minutes, not hours; pool should stay ≥150 on large range.
- **T0/T1, &gt;100 ports** — pool floor 20, no hang.
- **T3/T4/T5** on top-100, top-1000, single port — spot-check no regression vs old behavior on small scans.
- **Open 3389** — RDP exposure hint without banner.
- **Open 9200** — CRIT Elasticsearch exposure even with no banner.
- **Open 6379 without auth** — Redis hint after PING probe.
- **PHP 8.2 in X-Powered-By** — no EOL hint.
- **Apache 2.4.49 on port 8000** — CVE-2021-41773.
- **SSH banner with OpenSSH version** — CVE hints match full banner text.
- **`scanme.nmap.org` or similar** — `-T2` more reliable than `-T4` on SYN-heavy paths; connect recheck should recover some SYN false filtered.
- **IPv6 host with `--ipv6`** — connect scan message, ports still discovered.
- **`--ipv4` on dual-stack name** — A record only.

Install path still applies caps after build:

```bash
curl -sL https://raw.githubusercontent.com/fkmrshl/dark-nexus/main/install.sh | sudo bash
```

---

## Known limitations (deferred)

Not fixed in this pass; fine to tackle later:

- **BUG-06:** TLS HTTP redirect to another host still connects to the original scan IP.
- **BUG-07:** `PortScanEngine` uses `token_` but much of the code still checks `g_cancel_token`.
- UDP dual timeout, global `port_rl` interaction, `getnameinfo` blocking in `net_scan`, SYN-only calibration on mixed stacks.
- Redis RESP may fail `banner_usable()` for odd binary-ish replies — exposure hint on open 6379 still applies.
- Aggressive `-T4`/`-T5` + SYN against filtered targets can still show mostly filtered; use `-T2` for accuracy.
- STARTTLS probes for 993/995/465 not implemented.
- OpenSSH CVE-2023-51385 extension was discussed but not added.

---

## Implementation checklist

- [x] Reorder `port_scan()` config (early/late timing, pool ceiling 600)
- [x] `check_port_exposure_hints()` + call first in `check_vulns()`
- [x] `probe_redis_ping` / `probe_mongo_ping` in Phase 2
- [x] PHP EOL fix (8.0 only, not all of 8.x)
- [x] `HTTP_PORTS.count(port)` for web CVE checks
- [x] Elasticsearch / MongoDB / Memcached banner checks
- [x] TLS+HTTP unified probe, SNI from target, TCP wait before SSL
- [x] Protocol banner probes (SSH, FTP, SMTP, MySQL, Postgres)
- [x] `banner_usable()` filter
- [x] IPv6 + `--ipv4` / `--ipv6` + dual-stack sockets
- [x] SYN source port + connect recheck on timeout
- [x] T4/T5 RTT-based connect floors
- [x] Per-port hints, STACK DISCLOSURES, version/banner truncation
- [ ] Full manual validation on your targets (runtime)

---

*Document version 2.0 — 2026-06-06*
