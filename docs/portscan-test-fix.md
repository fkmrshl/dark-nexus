# Dark Nexus port scanner — improvement plan

This document covers targeted work on `PortScanEngine` without a full rewrite and without changing the public `port_scan()` API or CLI flags.

**Files in play:** `src/port_scan.cpp`, `include/port_scan_engine.hpp`, `src/utils.cpp`, `include/dark_nexus.hpp`, `include/output.hpp`

---

## Where things stand today

**What already works**

Adaptive RTT calibration (`calibrate_target`) drives timeouts, thread pool size, and retry counts. Scanning runs in two phases: discovery first, then deep analysis on open ports. We have `probe_connect`, a partial `probe_syn` path, and UDP smart probes. Structs for enrichment exist (`TLSInfo`, `HttpInfo`, `VulnHint`, `PortResult`). OpenSSL is wired in via `HAVE_OPENSSL` in CMake.

**Messy bits**

The code mixes static helpers with `PortScanEngine` methods. Connection logic is duplicated — probes, banners, TLS, and HTTP each open their own TCP sessions. Phase 2 collects TLS/HTTP data, but almost none of it shows up in the terminal output, which makes it look like enrichment is broken even when it isn't.

---

## What's actually broken or missing

### TLS (`inspect_tls`)

TCP `connect` isn't always finished before `SSL_connect` runs. On slow targets that races and you get empty handshakes.

SNI is set to the raw IP (`SSL_set_tlsext_host_name(ssl, ip)`), so vhosts and CDNs often return the wrong cert or refuse the handshake entirely.

`tls.expiry` never gets filled. Cipher isn't extracted either, so we can't show what was negotiated. `self_signed` compares CN to issuer CN, which produces false positives and misses real cases.

`print_results` doesn't print a TLS block at all. Users reasonably assume TLS inspection doesn't work — the OpenSSL code is there, but reliability and visibility are both weak.

### HTTP (`probe_http`)

Sending cleartext `GET` to 443/8443 without TLS is the big one. You get `status_code == 0`, empty headers, no title.

443 sits in both `HTTP_PORTS` and `TLS_PORTS`, so Phase 2 opens two connections and the HTTP branch on TLS ports is useless.

A single `recv(4096)` truncates headers. Redirects aren't followed, so no final URL or status. `Host:` is the IP, which breaks shared hosting. HSTS/CSP/X-Frame hints only fire when `status_code > 0`, so they never trigger on HTTPS with the current probe.

### Banners (`smart_banner` in `utils.cpp`)

443/8443 get a plaintext HTTP probe → garbage or empty `banner_raw`. `extract_version` and `check_vulns` never see `Server:` from the banner path on web ports.

### Output and export

Console output is basically one table: PORT / SERVICE / VERSION / BANNER. JSON `PortEntry` has partial TLS fields — no SANs, issuer, cipher, HTTP status, or title. CSV is even thinner.

### Hostname for SNI

`port_scan(ip_res, ...)` only receives the resolved IP. `g_result.target` (the domain the user typed) never reaches the engine. PTR lookup runs for display only, not for probes.

---

## Goals and constraints

**We want**

1. Real TLS inspection on TLS ports: version, cipher, CN, SANs, issuer, validity, expired/self-signed flags.
2. HTTP/HTTPS enrichment: status, Server, title, security headers, Location; follow redirects (cap at 3 hops).
3. Useful banners and service detection; pull version from HTTP/TLS when the raw banner is empty.
4. Richer `check_vulns` using TLS and HTTP context.
5. Small extras: env hints (AWS, Cloudflare), RAII in new code, keep calibration and scan speed.

**We are not doing**

- Changing the `port_scan()` signature or CLI.
- Rewriting the scanner from scratch — surgical functions and Phase 2 edits only.
- Dropping adaptive calibration or large-range behavior.

Prefer routing new logic through `PortScanEngine` where it fits without forcing a big refactor.

---

## Implementation plan

### Shared connection helpers (TLS + HTTP)

**File:** `src/port_scan.cpp`

Add `static bool tcp_connect_wait(int fd, int timeout_ms)`: non-blocking connect → `poll(POLLOUT)` → `getsockopt(SO_ERROR)`. Same pattern as `probe_connect`.

Extend `PortScanConfig` with `std::string sni_host` for SNI and HTTP `Host:`.

Before creating the engine in `port_scan()`:

- If `g_result.target` looks like a hostname, use it for `cfg.sni_host`.
- Else try `ptr_lookup(ip)`.
- Else fall back to the IP.

No public API change.

### TLS inspection (priority 1)

**Files:** `include/port_scan_engine.hpp`, `src/port_scan.cpp`

Add `cipher` to `TLSInfo` and actually populate `expiry`.

Refactor `inspect_tls`:

1. TCP connect + `tcp_connect_wait`.
2. `SSL_CTX`, then `SSL_set_tlsext_host_name(ssl, sni_host.c_str())`.
3. Non-blocking `SSL_connect` with poll — keep the existing loop, but only after TCP succeeds.
4. Pull version (`SSL_get_version`), cipher name, CN, DNS SANs, issuer CN, human-readable expiry, `expired` via `ASN1_TIME_diff`, `self_signed` via `X509_check_issued(cert, cert)` or full DN compare.
5. RAII throughout: `FdGuard`, guaranteed `SSL_free` / `X509_free` on every exit path.

TLS port set for now: `443, 8443, 465, 993, 995, 636, 5671, 6443, 4443, 7443, 2083, 2087, 2053, 2096`. Mail ports (993/995/465) may need STARTTLS later — phase 2 if time allows.

### HTTP/HTTPS enrichment (priority 2)

**File:** `src/port_scan.cpp`

Add `redirect_location` to `HttpInfo`.

**TLS + HTTP ports (443, 8443, …):** one session — TCP → TLS → `GET /` → parse → follow redirects.

**HTTP-only (80, 8080, …):** keep cleartext `probe_http`, fix the issues above.

Suggested helpers:

- `probe_http_plain(...)` — current logic, cleaned up.
- `probe_tls_http(...)` — combined TLS + HTTP in one connection.
- `http_read_response(...)` — read until `\r\n\r\n`.
- `follow_redirects(..., max_hops=3)`.

Parse status with something like `HTTP/\d\.\d\s+(\d{3})`. Headers: Server, X-Powered-By, HSTS, CSP, X-Frame-Options, Location. Title from `<title>...</title>` — chunked bodies are best-effort. Use `cfg.sni_host` for both `Host:` and SNI.

Phase 2 orchestration:

- If port is in TLS_PORTS and `tls_inspect`: when also HTTP, call `probe_tls_http()`; otherwise `inspect_tls()`.
- Else if HTTP_PORTS and `http_probe`: `probe_http_plain()`.
- Else: `smart_banner()`.

Kill the third redundant connection on 443. When `banner_raw` is empty, fill it and `version` from HTTP `Server`.

### Banners and service detection (priority 3)

**File:** `src/utils.cpp`

Stop sending cleartext `GET` on 443/8443 in `smart_banner` — no-op there with a note that Phase 2 handles TLS.

Keep switch-based probes for non-web ports (SSH, SMTP, Redis, etc.).

In `extract_version`, prefer HTTP `Server` and TLS version/cipher on HTTPS when the raw banner is useless.

### Vulnerability hints (priority 4)

**File:** `src/port_scan.cpp` — extend `check_vulns` internally:

```cpp
check_vulns(port, version_str, banner_raw, tls, http)
```

Examples of new rules:

- TLS 1.0 / 1.1 negotiated → weak TLS version hint.
- Cert expires within 30 days → expiring soon.
- Cipher looks like RC4, DES, EXPORT, or NULL → weak cipher.
- Aggressive mode: 401/403 on admin paths → exposed path.
- Missing HSTS on a real HTTPS probe → informational.
- Keep existing Apache/nginx CVE checks; extend Redis/Mongo/K8s/Docker from banner text.

When `banner_raw` is empty on a web port, use `http.server` for fingerprinting.

### Output, JSON, env hints (priority 5)

After each port row in `print_results`, print enrichment:

```
  443       https           nginx/1.24.0             14ms      MED       TLSv1.3
            TLS: TLSv1.3 / TLS_AES_256_GCM_SHA384
            Cert: CN=example.com | Issuer: R3 | exp: 2026-09-15 | SANs: a, b
            HTTP: 200 | Server: nginx/1.24.0 | Title: Welcome
            Sec: HSTS=yes CSP=no X-Frame=SAMEORIGIN
```

Extend `PortEntry` / JSON with defaults for backward compatibility: `tls_cipher`, `tls_issuer`, `tls_sans`, `tls_expiry`, `http_status`, `http_server`, `http_title`, `http_redirect`, `http_hsts`, `http_csp`, `http_x_frame`.

Optional `guess_env_from_headers(http)` for Cloudflare (`cf-ray`), AWS (`awselb`), nginx/apache — either fold into `guess_os_from_ports` or add an `[env]` line under SCAN STATS.

### RAII and small cleanups

Use `FdGuard` for new socket code instead of raw `socket`/`close`. Don't add redundant OpenSSL init (1.1+ handles that). Reuse `banner_ms` / `connect_ms` from calibration; TLS+HTTP should share one deadline per port.

---

## Phase 2 flow (target)

For each open port:

1. If it's a TLS port and we inspect TLS: combined `probe_tls_http` when HTTP probing is on, else `inspect_tls` alone.
2. Else if it's HTTP-only: `probe_http_plain`.
3. Else: `smart_banner`.
4. Run `check_vulns` with whatever we collected.
5. `print_results` prints the table row plus TLS/HTTP blocks.

---

## Example output (typical web host)

Scan `example.com` ports 1–10000; 80 and 443 open:

```
PHASE 0 // CALIBRATION
  rtt: 18ms  timeout: 200ms  retries: 1  threads: 300
  ptr: example.com

PHASE 1 // DISCOVERY
  sweeping 10000 ports...
  [+] 80    /tcp  open  http        (11ms)
  [+] 443   /tcp  open  https       (13ms)

PHASE 2 // DEEP ANALYSIS
  analyzing 2 open ports...

PHASE 3 // RESULTS

  PORT      SERVICE         VERSION                  LATENCY   RISK      BANNER
  ----------------------------------------------------------------------------------------------------
  80        http            nginx/1.24.0             11ms      MED       HTTP/1.1 301 Moved Permanently
            HTTP: 301 -> https://example.com/ | Server: nginx/1.24.0 | Title: -
            Sec: HSTS=no CSP=no X-Frame=no

  443       https           nginx/1.24.0             13ms      MED       TLSv1.3
            TLS: TLSv1.3 / TLS_AES_256_GCM_SHA384
            Cert: CN=example.com | Issuer: Let's Encrypt R3 | exp: 2026-09-15
                  SANs: example.com, www.example.com
            HTTP: 200 | Server: nginx/1.24.0 | Title: Welcome to Example
            Sec: HSTS=max-age=31536000 CSP=no X-Frame=SAMEORIGIN

VULNERABILITY HINTS
  [INFO] N/A            missing Content-Security-Policy
  [INFO] INFO           server version disclosed: nginx/1.24.0

SCAN STATS
  [os guess]      Linux/Unix
  [env]           Cloudflare: no | CDN: no
  [open ports]    2
  [scan time]     42.50s
  [speed]         235 ports/sec
```

---

## Work order

- [ ] **P0** `tcp_connect_wait` + `cfg.sni_host` from `g_result.target`
- [ ] **P0** Fix `inspect_tls` (cipher, expiry, self-signed, wait for TCP)
- [ ] **P0** `probe_tls_http` for 443/8443; stop cleartext HTTP on TLS ports
- [ ] **P1** Redirect follow (max 3), multi-recv for headers
- [ ] **P1** Enrichment blocks in `print_results`
- [ ] **P1** Fix `smart_banner` on 443
- [ ] **P2** Extend `check_vulns` (TLS version, cert expiry, HTTP server)
- [ ] **P2** Extend `PortEntry` / JSON export
- [ ] **P2** Env hints (Cloudflare/AWS)
- [ ] **P3** STARTTLS for 993/995/465 (optional)
- [ ] **Verify** Build + smoke test on a host with 80/443 open

---

## Testing

1. Build: `cmake -B build && cmake --build build`
2. Single port 443 — quick TLS+HTTP sanity check.
3. Domain vs IP: scan `example.com` (SNI = domain) vs bare IP (PTR or IP fallback).
4. Large range 1–10000 — no timing regression (pool, timeouts).
5. Ctrl+C mid-scan — partial results, no SSL hang.

---

## Risks

**Phase 2 slows down on web ports** — mitigate with one TLS+HTTP connection instead of three separate TCP sessions.

**SNI wrong when scanning by IP** — use `g_result.target` first, then PTR.

**OpenSSL and threads** — don't share `SSL*` across workers; one SSL object per task.

**T5 aggressive timeouts (50ms)** — keep a floor on `banner_ms` for TLS work (e.g. 500ms minimum).

---

## Out of scope

- CLI or `port_scan()` signature changes
- Replacing the port scanner with async I/O or libcurl
- Rewriting the SYN engine
- Active exploitation or automated CVE verification

---

*Document version 1.1 — 2026-06-06 (English)*
