  <div align="center">
    <img src="assets/dark_nexus.svg" width="100%" alt="Dark Nexus Terminal">
  </div>
 
<div align="center">



<div align="center">

  

  ![Language](https://img.shields.io/badge/language-C%2B%2B17-dc143c?style=flat-square)
  ![Platform](https://img.shields.io/badge/platform-Linux-dc143c?style=flat-square)
  ![Modules](https://img.shields.io/badge/modules-12-dc143c?style=flat-square)


</div>


---
## Dark Nexus Project:
 
**The ultimate multi-threaded reconnaissance and pentesting toolkit packed into a single binary.**

Dark Nexus replaces dozens of disjointed utilities. Written in C++17, it compiles into a single standalone executable that requires no complex environment setup or dependency management. Everything is controlled through an intuitive hybrid CLI, supporting both an interactive menu and direct arguments

Under the hood, it leverages aggressive multi-threading, custom network engines (Raw Sockets, c-ares + io_uring + Thread Pool), and 11 powerful modules: ranging from ultra-fast subdomain scanning with Takeover validation, to in-depth OSINT gathering and heuristic OS fingerprinting.

---
## Preview

<img width="662" height="530" alt="image" src="https://github.com/user-attachments/assets/3c17b229-4d00-4335-b3e0-f6f60a8de3d4" />





---


## Modules

| # | Module | What it does |
|---|--------|--------------|
| 1 | **Subdomain Scan** | Custom `DnsEngine` on c-ares - multi-channel parallel resolver with `poll()` + automatic `io_uring` on kernel ≥ 5.1, DoH cascade fallback, TTL cache. Two modes: **FAST** (~3 min) and **DEEP** (~1-2hr). Passive recon from 11 sources. WAF fingerprinting - 16 providers (Cloudflare, Akamai, Imperva, F5, AWS WAF…). Tech stack detection language, framework, CMS, CDN per subdomain. Takeover validation - live fingerprint check against 35+ services |
| 2 | **OSINT** | OSINT Intelligence & Identity Graph: Multi-vector Identity Graph (User/Email/Phone) with detect input type, bayes score verification, cross_reference orchestration (Sherlock, Maigret, Holehe, PhoneInfoga), Breach Intelligence. |
| 3 | **Port Scan** | 3-phase adaptive scan: RTT calibration → port sweep with open/closed/filtered tagging → smart protocol-aware banner grab, version extraction, CVE hints |
| 4 | **Traceroute** | Custom ICMP/UDP/TCP_SYN engine: up to 40 hops, 5 probes/hop, 8 parallel TTL levels, RTT/jitter/loss stats, ASN via Team Cymru, MTU detection |
| 5 | **OS Detection** | Weighted port scoring across 23 services (Windows/Linux/BSD/Network) combined with TTL analysis and banner confirmation |
| 6 | **Network Scan** | 2-phase /24 subnet sweep: ICMP + TCP host discovery across all 254 hosts, then parallel port scan of alive hosts with OS fingerprinting |
| 7 | **DNS Lookup** | Parallel queries for A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/SRV + SPF chain expansion, DMARC, DNSSEC detection, AXFR zone transfer attempt |
| 8 | **WHOIS Lookup** | Full WHOIS data for a domain or IP with structured field extraction |
| 9 | **IP Full Intel** | Geolocation, ASN/BGP, reverse DNS, abuse contacts, 4-DNSBL blacklist check, quick port scan, SSL certificate inspection |
| 10 | **Full IP Recon** | Chains geo, DNS lookup, OS detection and port scan into one full run |
| 11 | **Site → IP** | Strips protocol/path from any URL, resolves to IP, runs full intel on it |
| 12 | **Export JSON** | Saves the last scan result to a structured JSON file

---

## Requirements and Installation

Dark Nexus is heavily automated. You can install it on any Debian, Ubuntu, Kali, Arch, or BlackArch system with a single command. It will automatically detect your OS, install the correct dependencies, build the project with CMake, and configure Linux capabilities so you can run it without sudo.

### Quick Install
```
curl -sL https://raw.githubusercontent.com/fkmrshl/dark-nexus/main/install.sh | sudo bash
```

### Local Install (if already cloned)
```
sudo bash install.sh
```

## Usage
Dark Nexus supports both an interactive menu and command-line arguments. It is globally installed to `/usr/local/bin`, so you can run it from anywhere.

**Interactive Mode:**
```
dark-nexus
```

**Command Line Mode:**
```
dark-nexus [options] <target>
```

**Options:**
- `--portscan <ip> [ports]`  Run port scan (e.g. 0 for top1000, 0U for UDP, or 80-443)
- `--netscan <subnet>`       Run network scan (e.g. 192.168.1.1)
- `--os-detect <ip>`         Run OS detection
- `--ip-intel <ip>`          Run full IP intelligence
- `--dns <domain>`           Run DNS lookup
- `--whois <target>`         Run WHOIS lookup
- `--site <url>`             Convert site URL to IP and run intel
- `--osint <target>`         Run OSINT on username/email/phone
- `--traceroute <ip>`        Run traceroute
- `--recon <ip>`             Run full IP recon
- `--subdomain <domain>`     Run subdomain scan
- `--mode <F|D>`             Subdomain scan mode (Fast or Deep)
- `--json <file>`            Export result to JSON file
- `-h, --help`               Show help menu

---


## Legal

For **educational purposes** and **authorized penetration testing only**.  
Do not use against systems you do not own or have explicit written permission to test.  
The author is not responsible for any misuse or damage caused by this tool.

---

## Author
By - Marshal with Jules❤️

Bugs & feedback welcome - [t.me/fuckmarshal](https://t.me/fuckmarshal) 
