```
         ██████╗   █████╗  ██████╗  ██╗  ██╗     ███╗   ██╗ ███████╗ ██╗  ██╗ ██╗   ██╗  ███████╗
         ██╔══██╗ ██╔══██╗ ██╔══██╗ ██║ ██╔╝    ████╗  ██║ ██╔════╝ ╚██╗██╔╝ ██║   ██║ ██╔════╝
         ██║  ██║ ███████║ ██████╔╝ █████╔╝      ██╔██╗ ██║ █████╗    ╚███╔╝  ██║   ██║ ███████╗
         ██║  ██║ ██╔══██║ ██╔══██╗ ██╔═██╗     ██║╚██╗██║ ██╔══╝    ██╔██╗  ██║   ██║ ╚═══██║
         ██████╔╝ ██║  ██║ ██║  ██║ ██║  ██╗    ██║ ╚████║ ███████╗ ██╔╝ ██╗  ╚██████╔╝ ███████║

```
 
<div align="center">

**Network intelligence tool · C++17 · Linux**

![Language](https://img.shields.io/badge/language-C%2B%2B17-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/use-educational-red?style=flat-square)
![Modules](https://img.shields.io/badge/modules-12-cyan?style=flat-square)

</div>

---

## Modules

| # | Module | What it does |
|---|--------|--------------|
| 1 | **Port Scan** | 3-phase adaptive scan: RTT calibration → port sweep with open/closed/filtered tagging → smart protocol-aware banner grab, version extraction, CVE hints |
| 2 | **Network Scan** | 2-phase /24 subnet sweep: ICMP + TCP host discovery across all 254 hosts, then parallel port scan of alive hosts with OS fingerprinting |
| 3 | **OS Detection** | Weighted port scoring across 23 services (Windows/Linux/BSD/Network) combined with TTL analysis and banner confirmation |
| 4 | **IP Full Intel** | Geolocation, ASN/BGP, reverse DNS, abuse contacts, 4-DNSBL blacklist check, quick port scan, SSL certificate inspection |
| 5 | **DNS Lookup** | Parallel queries for A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/SRV + SPF chain expansion, DMARC, DNSSEC detection, AXFR zone transfer attempt |
| 6 | **WHOIS Lookup** | Full WHOIS data for a domain or IP with structured field extraction |
| 7 | **Site → IP** | Strips protocol/path from any URL, resolves to IP, runs full intel on it |
| 8 | **OSINT Username** | Checks username across 40 platforms in 7 categories + DuckDuckGo web mention scrape |
| 9 | **Traceroute** | Custom ICMP/UDP/TCP_SYN engine: up to 40 hops, 5 probes/hop, 8 parallel TTL levels, RTT/jitter/loss stats, ASN via Team Cymru, MTU detection |
| 10 | **Full IP Recon** | Chains geo, DNS lookup, OS detection and port scan into one full run |
| 11 | **Subdomain Scan** | Parallel bruteforce of 50+ subdomains, HTTP/HTTPS port probe, server header grab, statistics, wildcard detection, takeover candidate detection |
| 12 | **Export JSON** | Saves the last scan result to a structured JSON file |

---

## Module Details

### [1] Port Scan

Three-phase adaptive engine that tunes itself to the target before scanning.

```
PHASE 0  calibration    connects to 5 common ports, measures RTT, auto-configures:
                        timeout = max(200ms, min(3s, rtt×3))
                        threads = 300 (local) / 150 (LAN) / 60 (remote)
                        retries = 1 (fast) / 2 (slow)

PHASE 1  discovery      sweeps all selected ports sorted by priority (80/443/22 first),
                        tags each as: open / closed / filtered (timeout = firewall)

PHASE 2  deep analysis  protocol-aware smart banner grab, regex version extraction,
                        CVE hint engine, risk labeling (HIGH / MED / LOW)
```

**Smart banner probes - sends the right request per service:**

| Port(s) | Probe sent |
|---------|-----------|
| 80, 8080, 8000, 3000, 9090 | `GET / HTTP/1.1` + Host header |
| 443, 8443 | `GET / HTTP/1.0` (raw, leaks headers) |
| 25, 587 | `EHLO probe.local` |
| 6379 | `INFO\r\n` |
| 11211 | `version\r\n` |
| 22, 21, 110, 143, etc. | reads passive banner on connect |

**CVE and vulnerability hints:**

| CVE / Check | Condition | Severity |
|-------------|-----------|----------|
| CVE-2024-6387 | OpenSSH < 9.8 - regreSSHion signal handler race | CRIT |
| CVE-2023-38408 | OpenSSH < 9.3 - SSH agent forwarding RCE | HIGH |
| CVE-2021-41617 | OpenSSH < 8.5 - privilege escalation | MED |
| CVE-2011-2523 | vsFTPd 2.3.4 backdoor | CRIT |
| N/A | Anonymous FTP detected | MED |
| N/A | Telnet open - cleartext credentials | HIGH |
| CHECK | SMB 445/139 - EternalBlue / SMBGhost / PrintNightmare | HIGH |
| N/A | Redis 6379 unauthenticated - RCE risk | CRIT |
| N/A | Docker 2375 unencrypted API - full host compromise | CRIT |
| CHECK | RDP 3389 - BlueKeep CVE-2019-0708 | HIGH |
| CHECK | MongoDB 27017 - check auth enabled | HIGH |
| CHECK | Elasticsearch 9200 - check auth + data exposure | HIGH |
| CHECK | Kubernetes API 6443 - check RBAC | HIGH |
| CHECK | Memcached 11211 - DDoS amplification | HIGH |
| INFO | Web server version disclosed in banner | INFO |

**Scan modes:**
- `0` - top-1000 most common ports (default, fast)
- `start-end` - custom range up to 1–65535

---

### [2] Network Scan

Discovers and maps all live hosts in a `/24` subnet in two parallel phases.

**Phase 1 - Host Discovery** (100 threads, all 254 hosts in parallel)
- ICMP ping via `ping -c1 -W1`
- Fallback TCP probe on 10 ports: 21, 22, 23, 25, 80, 443, 445, 3389, 8080, 5985
- Reverse DNS (PTR) lookup for each alive host

**Phase 2 — Port Scan** (same 10 ports on all alive hosts)
- TCP connect probe with 400ms timeout
- Banner grab for each open port
- OS guess from open port combination

Output is grouped per host with tree-style formatting:
```
┌─ 192.168.1.1       [router.lan]   os: Network Device
│  22     SSH        SSH-2.0-OpenSSH_8.9
│  80     HTTP       HTTP/1.1 200 OK
└────────────────────────────────────
```

---

### [3] OS Detection

Weighted multi-signal fingerprinting. Probes 23 ports simultaneously and builds a score for each OS family.

**Scoring matrix (excerpt):**

| Port | Service | Win | Lin | BSD | Net |
|------|---------|-----|-----|-----|-----|
| 135 | MSRPC | 10 | 0 | 0 | 0 |
| 3389 | RDP | 10 | 0 | 0 | 0 |
| 445 | SMB | 10 | 2 | 1 | 0 |
| 5985 | WinRM | 10 | 0 | 0 | 0 |
| 22 | SSH | 1 | 10 | 8 | 5 |
| 111 | RPCBind | 0 | 9 | 8 | 0 |
| 2049 | NFS | 0 | 9 | 7 | 0 |
| 548 | AFP | 0 | 0 | 10 | 0 |
| 23 | Telnet | 2 | 1 | 1 | 10 |
| 179 | BGP | 0 | 1 | 1 | 10 |

Combined with TTL from `ping` output - Linux: 64, Windows: 128, Cisco: 255. Port scores + TTL hint produce the final OS guess with confidence level.

---

### [4] IP Full Intel

Deep single-IP investigation combining 6 data sources:

- **Geolocation** - `ip-api.com`: country, city, region, ISP, ASN, proxy/VPN flag, hosting flag, Google Maps link
- **Reverse DNS** - PTR record via `host`
- **ASN / BGP** - `whois.radb.net`: route, origin AS, description
- **Abuse Contacts** - WHOIS parse for OrgAbuseEmail, OrgName, Phone, Address
- **Blacklist Check** - reverse-IP DNSBL query against:
  - `zen.spamhaus.org`
  - `bl.spamcop.net`
  - `dnsbl.sorbs.net`
  - `b.barracudacentral.org`
- **Quick Port Scan** - 20 high-value ports with service name, risk label, banner
- **SSL Certificate** - on port 443: subject, issuer, validity dates via `openssl s_client`

---

### [5] DNS Lookup

Full parallel DNS investigation with security analysis.

**Record queries (all concurrent via `std::async`):**
A, AAAA (+ PTR reverse for each IP), MX, NS, TXT, CNAME, SOA, CAA, SRV

**Security checks:**
- **SPF** - finds `v=spf1` in TXT, expands all `include:` and `redirect=` chains recursively, warns if missing (email spoofing risk)
- **DMARC** - queries `_dmarc.<domain>`, reports policy
- **DNSSEC** - checks for DS + DNSKEY records
- **Zone Transfer (AXFR)** - attempts against every nameserver returned by NS query; reports success as critical finding

---

### [6] WHOIS Lookup

Runs system `whois` for domain or IP and extracts structured fields:

`Domain` · `Registrar` · `Created` · `Updated` · `Expires` · `Name Server` · `CIDR` · `NetRange` · `OrgName` · `Country` · `NetName` · `inetnum` · `Email` · `Phone` · `Address`

---

### [7] Site → IP

Accepts any raw URL (`https://example.com/path?q=1`) - strips protocol, path, query string and port, resolves the hostname to an IP, then runs the full **IP Full Intel** module on the result.

---

### [8] OSINT Username

Checks a username across **40 platforms** using concurrent HTTP requests (one thread per platform). Uses response body analysis - not HTTP status codes - to avoid false positives.

**Platform categories:**

| Category | Platforms |
|----------|-----------|
| Social | Instagram, TikTok, Twitter/X, Reddit, VK, Pinterest, Tumblr, Flickr |
| Dev | GitHub, GitLab, Replit, HackerOne, Pastebin, Bugcrowd, HackerNews |
| Gaming | Steam, Twitch, Minecraft (NameMC), Roblox, Chess.com |
| Messaging | Telegram, Keybase |
| Blog | Medium, Dev.to, Hashnode, Substack |
| Music | Spotify, SoundCloud, Bandcamp, Last.fm |
| Other | LinkedIn, Gravatar, Letterboxd, Goodreads, Strava, Dribbble, Behance, ProductHunt, Trakt, Wattpad |

After platform checks - scrapes **DuckDuckGo** for web mentions and prints up to 8 external URLs.

---

### [9] Traceroute

Custom traceroute engine built from scratch in C++ using raw sockets. Significantly more detailed than system `traceroute`.

**Configuration:**

| Parameter | Default | Notes |
|-----------|---------|-------|
| Max hops | 40 | configurable |
| Probes per hop | 5 | more = better stats |
| Parallel hops | 8 | TTL levels probed simultaneously |
| Timeout | 2000 ms | per probe |
| Protocol | ICMP | also supports UDP, TCP SYN |

**Per-hop statistics computed from 5 probes:**
- RTT: min / avg / max / stddev
- **Jitter** - mean absolute deviation between consecutive probes (VoIP formula)
- **Packet loss %** - probes sent vs responses received
- **MTU** - detected from ICMP Fragmentation Needed (type 3 code 4) replies

**Additional enrichment per hop:**
- Reverse DNS (PTR) - best-effort, non-blocking
- **ASN lookup** - Team Cymru DNS service (`<reversed-ip>.origin.asn.cymru.com TXT`), returns AS number + description

---

### [10] Full IP Recon

Chains four modules into one complete run against a single IP:

`Geolocation + ASN` → `DNS Lookup` → `OS Detection` → `Port Scan (top-1000)`

All results are also stored in `g_result` and available for JSON export.

---

### [11] Subdomain Scan

Parallel bruteforce of **50+ common subdomains** using a thread pool.

**Per subdomain:**
1. DNS resolution (A record via `getaddrinfo`)
2. TCP probe on port 80 and 443
3. HTTP `HEAD /` request to grab `Server:` header
4. CNAME detection

**After scan completes:**

| Stat | Detail |
|------|--------|
| Total found | subdomains that resolved |
| HTTPS (443) | how many have TLS |
| HTTP only | serving plain HTTP only |
| With CNAME | aliased to another host |
| Wildcard | detected if >80% of random probes resolve |
| Server distribution | top web servers across found subdomains |

**Subdomain Takeover Detection** - checks CNAME targets against 18 cloud providers:

`GitHub Pages` · `Heroku` · `Azure` · `CloudFront` · `AWS S3` · `Shopify` · `Ghost` · `WordPress` · `Pantheon` · `Zendesk` · `ReadMe` · `Surge` · `Bitbucket` · `Netlify` · `Vercel` · `Fly.io` · `Render` · `Cloudflare Pages`

If a CNAME points to one of these but the target **does not resolve** → flagged as `DANGLING — possible takeover`.

---

### [12] Export JSON

Saves the accumulated results from the last scan to `dark_nexus_<target>.json`:

```json
{
  "target": "8.8.8.8",
  "timestamp": "2025-01-01 12:00:00",
  "geo": {
    "country": "US",
    "city": "Mountain View",
    "isp": "Google LLC",
    "as": "AS15169",
    "proxy": false,
    "hosting": true
  },
  "os": "Linux",
  "open_ports": [
    { "port": 443, "service": "HTTPS" },
    { "port": 53,  "service": "DNS"   }
  ],
  "subdomains": ["mail.example.com", "api.example.com"],
  "osint": ["github.com/target", "twitter.com/target"]
}
```

Session activity is also written in JSON-lines format to `dark_nexus_YYYYMMDD.log`:

```json
{"t":"2025-01-01T12:00:00","lv":"INF","mod":"port_scan","msg":"done target=8.8.8.8 open=3 filtered=12 time=4s"}
```

---

## Security Internals

| Property | Implementation |
|----------|---------------|
| No shell execution | `fork()` + `execvp()` - zero `system()` or `popen()` calls anywhere |
| Input validation | Regex whitelist on all user input - only `[a-zA-Z0-9.\-_:/@]` allowed |
| ANSI sanitization | All captured banners stripped of escape sequences before display (prevents terminal injection) |
| Memory safety | `std::vector` / `std::string` throughout - no fixed C-style buffers |
| Non-blocking I/O | Strict socket timeouts on every connect/recv, tarpit-resistant |
| Thread pool | `std::packaged_task` + `std::future` queue with graceful shutdown, no detached threads |
| Process timeout | `fork`+`execvp` children killed with `SIGKILL` if they exceed their deadline |
| Output cap | External process stdout capped at 4MB to prevent memory exhaustion |

---

## Requirements

- Linux (Kali recommended)
- `g++` with C++17 support
- `curl` `whois` `dig` `traceroute` `openssl` `ping`

```bash
sudo apt update
sudo apt install build-essential g++ libssl-dev curl whois dnsutils traceroute iputils-ping -y

---

## Installation

```bash
git clone https://github.com/fkmrshl/dark-nexus.git
cd dark-nexus
g++ -std=c++17 -O3 -march=native -flto=auto -pthread dark_nexus.cpp -o dark_nexus -lssl -lcrypto
sudo ./dark_nexus
```

> `sudo` is required for raw socket operations used by the Traceroute and OS Detection modules.

---

## Usage

```
  +------+--------------------+----------------------------------+
  | NUM  | MODULE             | EXAMPLE                          |
  +------+--------------------+----------------------------------+
  |  [1] | PORT SCAN          | 192.168.1.1   0=top1000          |
  |  [2] | NETWORK SCAN       | 192.168.1.0/24                   |
  |  [3] | OS DETECTION       | 192.168.1.1                      |
  |  [4] | IP FULL INTEL      | 8.8.8.8                          |
  |  [5] | DNS LOOKUP         | google.com                       |
  |  [6] | WHOIS LOOKUP       | google.com / 8.8.8.8             |
  |  [7] | SITE --> IP        | https://google.com               |
  |  [8] | OSINT USERNAME     | marshal                          |
  |  [9] | TRACEROUTE         | 8.8.8.8                          |
  | [10] | FULL IP RECON      | 8.8.8.8                          |
  | [11] | SUBDOMAIN SCAN     | google.com                       |
  | [12] | EXPORT JSON        | save last scan                   |
  |  [0] | EXIT               |                                  |
  +------+--------------------+----------------------------------+
```

---

## Legal

For **educational purposes** and **authorized penetration testing only**.  
Do not use against systems you do not own or have explicit written permission to test.  
The author is not responsible for any misuse or damage caused by this tool.

---

## Author

**marshal** - [t.me/fuckmarshal](https://t.me/fuckmarshal)  
bugs & feedback welcome
