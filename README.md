```
         ██████╗   █████╗  ██████╗  ██╗  ██╗     ███╗   ██╗ ███████╗ ██╗  ██╗ ██╗   ██╗  ██████╗
         ██╔══██╗ ██╔══██╗ ██╔══██╗ ██║ ██╔╝     ████╗  ██║ ██╔════╝ ╚██╗██╔╝ ██║   ██║ ██╔════╝
         ██║  ██║ ███████║ ██████╔╝ █████╔╝      ██╔██╗ ██║ █████╗    ╚███╔╝  ██║   ██║ ███████╗
         ██║  ██║ ██╔══██║ ██╔══██╗ ██╔═██╗      ██║╚██╗██║ ██╔══╝    ██╔██╗  ██║   ██║ ╚════██║
         ██████╔╝ ██║  ██║ ██║  ██║ ██║  ██╗     ██║  ╚███║ ███████╗ ██╔╝ ██╗ ╚██████╔╝ ███████║

```
 
<div align="center">

**Network intelligence tool · C++17 · Linux**

![Language](https://img.shields.io/badge/language-C%2B%2B17-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square)
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
| 8 | **OSINT Username** | OSINT Intelligence & Identity Graph: Multi-vector Identity Graph (User/Email/Phone) with detect input type, bayes score verification, cross_reference orchestration (Sherlock, Maigret, Holehe, PhoneInfoga), Breach Intelligence.|
| 9 | **Traceroute** | Custom ICMP/UDP/TCP_SYN engine: up to 40 hops, 5 probes/hop, 8 parallel TTL levels, RTT/jitter/loss stats, ASN via Team Cymru, MTU detection |
| 10 | **Full IP Recon** | Chains geo, DNS lookup, OS detection and port scan into one full run |
| 11 | **Subdomain Scan** | Custom `DnsEngine` on c-ares - multi-channel parallel resolver with `poll()` + automatic `io_uring` on kernel ≥ 5.1, DoH cascade fallback, TTL cache. Two modes: **FAST** (~3 min) and **DEEP** (~1-2hr). Passive recon from 11 sources. WAF fingerprinting - 16 providers (Cloudflare, Akamai, Imperva, F5, AWS WAF…). Tech stack detection language, framework, CMS, CDN per subdomain. Takeover validation - live fingerprint check against 35+ services |
| 12 | **Export JSON** | Saves the last scan result to a structured JSON file |

---

## Requirements and Installation

- Linux (Kali, Black Arch recommended)
- `g++` with C++17 support
- `curl` `whois` `dig` `traceroute` `openssl` `ping`

                                             
## For Debian / Kali Linux:
```bash
sudo apt update && sudo apt install -y \
    build-essential g++ libssl-dev libcurl4-openssl-dev \
    libc-ares-dev liburing-dev curl whois dnsutils traceroute iputils-ping
```


## For Arch Linux / BlackArch: 
```bash
sudo pacman -Syu --needed base-devel openssl curl c-ares \
    liburing whois bind traceroute iputils
```


## Build & Setup
```bash
git clone https://github.com/fkmrshl/dark-nexus.git

cd dark-nexus

make

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
  |  [8] | OSINT USERNAME     | user / user@mail.com / +7900...  |
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

Structure & code architecture by - Marshal

Designed with AI

Bugs & feedback welcome - [t.me/fuckmarshal](https://t.me/fuckmarshal) 
