# DARK NEXUS
### Network Intelligence Tool
 
```
  ██████╗  █████╗ ██████╗ ██╗  ██╗    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██║  ██║███████║██████╔╝█████╔╝     ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║  ██║██╔══██║██╔══██╗██╔═██╗     ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██████╔╝██║  ██║██║  ██║██║  ██╗    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
```
 
A fast, multithreaded network reconnaissance tool written in C++.  
Built for Kali Linux and security researchers.
 
---
 
## Features
 
| Module | Description |
|--------|-------------|
| Port Scan | Multithreaded port scanner with banner grabbing and risk level |
| Network Scan | Discover alive hosts in a subnet via ICMP + TCP |
| OS Detection | Fingerprint OS using TTL analysis and open ports |
| IP Full Intel | Geolocation, ASN, reverse DNS, blacklist check, SSL cert |
| DNS Lookup | A, AAAA, MX, NS, TXT, CNAME, SOA + zone transfer attempt |
| WHOIS Lookup | Full WHOIS info for domain or IP |
| Site → IP | Resolve any URL to IP with full intelligence |
| OSINT Username | Search username across 19 platforms + web mentions |
| Traceroute | Trace route to target (max 20 hops) |
| Full IP Recon | Everything at once — geo, dns, os, ports |
| Subdomain Scan | Bruteforce 50+ common subdomains |
 
---
 
## Requirements
 
- Linux (Kali recommended)
- `g++` with C++17 support
- `curl`, `whois`, `dig`, `traceroute`, `openssl`
 
Install dependencies:
```bash
sudo apt install build-essential curl whois dnsutils traceroute openssl
```
 
---
 
## Installation
 
```bash
git clone https://github.com/fkmrshl/dark-nexus.git
cd dark-nexus
g++ -o dark_nexus dark_nexus.cpp -std=c++17 -lpthread
./dark_nexus
```
 
---
 
## Usage
 
```
  +------+--------------------+----------------------------------+
  | NUM  | MODULE             | EXAMPLE                          |
  +------+--------------------+----------------------------------+
  |  [1] | PORT SCAN          | 192.168.1.1   1-65535            |
  |  [2] | NETWORK SCAN       | 192.168.1.1                      |
  |  [3] | OS DETECTION       | 192.168.1.1                      |
  |  [4] | IP FULL INTEL      | 8.8.8.8                          |
  |  [5] | DNS LOOKUP         | google.com                       |
  |  [6] | WHOIS LOOKUP       | google.com / 8.8.8.8             |
  |  [7] | SITE --> IP        | https://google.com               |
  |  [8] | OSINT USERNAME     | marshal                          |
  |  [9] | TRACEROUTE         | 8.8.8.8                          |
  | [10] | FULL IP RECON      | 8.8.8.8                          |
  | [11] | SUBDOMAIN SCAN     | google.com                       |
  |  [0] | EXIT               |                                  |
  +------+--------------------+----------------------------------+
```
 
---
 
## Security & Performance (v1.0 Update)
 
This isn't just another wrapper. The core has been completely rewritten for maximum safety:
 
- **No Shell Execution** — Uses `fork()` + `execvp()` instead of `system()` to prevent command injection.
- **Memory Safety** — Zero use of fixed-size C-style buffers. Fully powered by `std::vector` and `std::string`.
- **ANSI Sanitization** — All incoming banners and server responses are sanitized to prevent Terminal Injection attacks.
- **Non-blocking I/O** — Socket operations include strict timeouts to prevent Tarpit-DoS.
- **Input Validation** — Strict whitelist regex on all user input. Shell special characters are blocked at the gate.
 
---
 
## Planned Features
 
- [ ] Windows support (MinGW build)
- [ ] Export results to file (txt / json)
- [ ] CVE lookup by service version from banner
- [ ] Nmap integration
- [ ] Tor / proxy support for anonymity
 
---
 
## Legal
 
This tool is intended for **educational purposes** and **authorized penetration testing only**.  
Do not use against systems you don't own or have explicit permission to test.  
The author is not responsible for any misuse.
 
---
 
## Author
 
**marshal** — t.me/fuckmarshal  
bugs & feedback welcome
