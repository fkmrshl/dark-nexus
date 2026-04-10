# DARK NEXUS
### Network Intelligence Tool

```text
  ██████╗  █████╗ ██████╗ ██╗  ██╗    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██║  ██║███████║██████╔╝█████╔╝     ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║  ██║██╔══██║██╔══██╗██╔═██╗     ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██████╔╝██║  ██║██║  ██║██║  ██╗    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║

Dark Nexus is a high-performance, multithreaded network reconnaissance tool written in C++. Designed specifically for Kali Linux, security researchers, and penetration testers.
🛠 Features
Module	Description
Port Scan	Multithreaded scanner with banner grabbing and risk assessment
Network Scan	Discover alive hosts in a subnet via ICMP + TCP
OS Detection	Fingerprint OS using TTL analysis and open port heuristics
IP Full Intel	Geolocation, ASN, DNS records, Blacklist check, and SSL certs
DNS/WHOIS	Comprehensive domain intelligence and ownership data
OSINT	Search usernames across 19+ platforms and web mentions
Traceroute	High-speed route tracing to target (max 20 hops)
Subdomain Scan	Subdomain brute-forcing using a high-performance wordlist
Export JSON	Save scan results locally for further analysis
🚀 Installation & Setup
Prerequisites

Ensure you have the required dependencies installed:
Bash

sudo apt update && sudo apt install build-essential curl whois dnsutils traceroute openssl -y

Build from Source
Bash

git clone [https://github.com/fkmrshl/dark-nexus.git](https://github.com/fkmrshl/dark-nexus.git)
cd dark-nexus
g++ -o dark_nexus dark_nexus.cpp -std=c++17 -lpthread -lssl -lcrypto
chmod +x dark_nexus
./dark_nexus

⚠️ Disclaimer

This tool is intended for educational purposes and authorized penetration testing only.
Running Dark Nexus against targets without prior explicit permission is illegal. The author is not responsible for any misuse, legal consequences, or damage caused by this software.
👤 Author

marshal — t.me/fuckmarshal

Bugs, feedback, and contributions are welcome.
