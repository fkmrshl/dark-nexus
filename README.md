# Dark Nexus

Network reconnaissance and infrastructure analysis from a single C++17 command-line tool for Linux.

Explicit flags, module-specific help, and JSON, CSV, or text reports. Run one module per invocation; running without arguments shows help.

[CLI reference](docs/cli.md) · [Module guide](#modules) · [License](LICENSE)

## Install

Install or update with one command (Linux, with `curl` and `sudo`):

```sh
curl -fsSLm120 https://raw.githubusercontent.com/fkmrshl/dark-nexus/main/install.sh | sudo bash
```

Then run `dark-nexus --help`. The installer downloads the source, installs missing dependencies, builds the application and DNS wordlist, and attempts to configure raw socket capabilities. It shows live output and prints a log path. Optional OSINT helpers are attempted after the main application is installed; helper failures do not block it.

On Arch/CachyOS, the installer uses existing package databases and installs only missing packages. It does not launch a full system upgrade. See [installation troubleshooting](docs/install.md) for mirror errors, package locks, time limits, or a minimal installation.

For a local build or installation from a checkout:

```sh
git clone https://github.com/fkmrshl/dark-nexus.git
cd dark-nexus
```

### Build locally

Use a C++17 compiler, CMake 3.15+, Git, pkg-config, and the OpenSSL, liburing, and libcap development packages. Internet access is needed to fetch dependencies during configuration.

<details>
<summary>Build dependencies on Debian/Ubuntu and Arch</summary>

Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake git pkg-config ca-certificates libssl-dev liburing-dev libcap-dev libcurl4-openssl-dev nlohmann-json3-dev
```

Arch:

```sh
sudo pacman -S --needed base-devel cmake git pkgconf ca-certificates openssl liburing libcap curl nlohmann-json
```

These commands install development dependencies. Runtime helpers for individual modules are listed in the [CLI reference](docs/cli.md#dependencies-and-results).

</details>

From the cloned repository:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build --parallel 2
./build/dark_nexus --help
```

CMake fetches c-ares and prefers installed curl and nlohmann/json packages, fetching them if needed. A local build runs as `./build/dark_nexus`; use that path in place of `dark-nexus` in the examples below. No system installation is needed to view help or use TCP connect scans. Source builds can use `--wordlist` or the built-in list.

### Install system-wide

```sh
sudo bash install.sh
dark-nexus --help
```

The installer installs `dark-nexus` to `/usr/local/bin` and provisions the DNS wordlist. It supports Debian/Ubuntu, Arch/CachyOS, Fedora/RHEL, and openSUSE families. A failed download or build leaves the existing executable in place. Some modules also use `dig`, `host`, `whois`, `ping`, `curl`, or the `openssl` executable at runtime. See the [dependency notes](docs/cli.md#dependencies-and-results).

### Check the build

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

The automated tests use local fixtures and fake network helpers; they do not scan external targets. The optional real-socket loopback test is documented in the [CLI reference](docs/cli.md#offline-checks).

## Usage

```sh
dark-nexus --help
dark-nexus --list-modules
dark-nexus --help portscan
dark-nexus --portscan 127.0.0.1 --ports 22,80,443 --connect
dark-nexus --portscan 127.0.0.1 --ports 8000-8010 --output scan.json
dark-nexus --portscan 127.0.0.1 --ports 8080 --output - --format json
```

Use `--quiet` to suppress the human-readable report, `--no-color` for plain output, and `--output` to save a result. With `--output -`, stdout contains only the selected report format. The [CLI reference](docs/cli.md) covers all flags, defaults, compatibility syntax, and exit codes.

## Modules

Expand a module for its purpose, behavior, and an example. Domain examples use reserved names; replace them with an authorized target for live work.

<details>
<summary><strong>Port scan</strong> — TCP/UDP ports and service inspection</summary>

Find reachable ports using TCP SYN probes with a connect fallback, explicit TCP connect mode, or UDP probes. Select ports, concurrency, timeouts, retries, address family, and optional TLS/HTTP inspection. Service banners, OS guesses, and CVE hints help prioritize manual investigation; version-based hints do not establish a vulnerability, and unanswered UDP probes remain ambiguous.

```sh
dark-nexus --portscan 127.0.0.1 --ports 22,80,8000-8010 --connect --timeout 500
```

[Port scan options](docs/cli.md#port-scan)

</details>

<details>
<summary><strong>Subdomains</strong> — domain discovery and web metadata</summary>

Combine certificate transparency results with wordlist DNS resolution and wildcard filtering. Deep mode adds more passive sources, permutations, CNAME/AAAA checks, web technology hints, JavaScript discovery, and takeover signature checks. Fast mode uses fewer sources and lighter HTTP enrichment. Neither mode is passive-only: both send DNS queries and, by default, HTTP requests. Takeover matches need manual verification.

```sh
dark-nexus --subdomain example.test --mode fast --wordlist ./hosts.txt --no-enrich
```

[Subdomain options](docs/cli.md#subdomains)

</details>

<details>
<summary><strong>DNS</strong> — records and domain configuration</summary>

Query A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, and SRV records, inspect SPF includes and DMARC, check for DS/DNSKEY records, and attempt AXFR against discovered name servers. This is a configuration review, including active zone transfer requests; DS/DNSKEY presence is not full DNSSEC validation. Requires `dig`.

```sh
dark-nexus --dns example.test
```

</details>

<details>
<summary><strong>WHOIS</strong> — registration and allocation records</summary>

Read WHOIS information for a domain or IP address and display selected registration, organization, network, and contact fields. Available fields depend on the registry response and its privacy policy. Requires `whois`.

```sh
dark-nexus --whois example.com
```

</details>

<details>
<summary><strong>Network scan</strong> — IPv4 /24 host discovery</summary>

Check hosts `.1` through `.254` in an IPv4 /24 using ICMP and common TCP ports, then inspect a fixed set of ports on responding hosts. Reports hostnames, banners, and an OS estimate. This is a fixed /24 workflow, not a general CIDR scanner; filtered hosts may be missed.

```sh
dark-nexus --netscan 127.0.0.1
```

</details>

<details>
<summary><strong>OS detection</strong> — operating system estimates</summary>

Combine selected open ports, banners, SMB and HTTP signals, ICMP TTL, and TCP fingerprints into an OS estimate. Raw socket access improves the available signals. Firewalls, proxies, and load balancers can make a result incomplete or misleading.

```sh
dark-nexus --os-detect 127.0.0.1
```

</details>

<details>
<summary><strong>Traceroute</strong> — network paths and hop timing</summary>

Trace IPv4 paths using ICMP, UDP, or TCP probes. Configure hop limits, probes, concurrency, destination port, and timeouts; optionally disable reverse DNS, ASN lookups, and MTU detection. All protocols require `CAP_NET_RAW` to receive intermediate-hop ICMP replies. Reports hop timing and probe loss; missing replies do not establish packet loss for application traffic.

```sh
dark-nexus --traceroute 127.0.0.1 --protocol tcp --destination-port 8080 --max-hops 5 --no-asn
```

[Traceroute options](docs/cli.md#traceroute)

</details>

<details>
<summary><strong>IP intelligence</strong> — address context and a quick service check</summary>

Gather geolocation, reverse DNS, ASN/BGP and abuse contact information, DNS blocklist responses, a fixed TCP port check, and certificate details where available. Uses public services and local helper programs; lookups may be unavailable or rate limited. Results describe an address and its infrastructure, not a person's location or identity. The current blocklist workflow is IPv4-oriented.

```sh
dark-nexus --ip-intel 127.0.0.1
```

</details>

<details>
<summary><strong>Site lookup</strong> — URL host resolution and IP context</summary>

Extract a hostname from an HTTP(S) URL, resolve it, and run the IP intelligence workflow. This performs active port checks as well as external lookups. It describes the resolved address, which may belong to a CDN or shared host, rather than auditing the web application.

```sh
dark-nexus --site https://example.test/
```

</details>

<details>
<summary><strong>OSINT</strong> — public account observations and identity hypotheses</summary>

Detect username, email, or phone input and collect public observations, related candidates, confidence scores, and an identity graph summary. Available Sherlock, Maigret, Holehe, theHarvester, and PhoneInfoga helpers provide additional observations; missing helpers are skipped. Generated candidates are hypotheses, and confidence labels are heuristic. The module does not provide authenticated breach-database access by default.

```sh
dark-nexus --osint user@example.test
```

[Identity graph notes](docs/osint-identity-graph.md)

</details>

<details>
<summary><strong>Recon</strong> — combined IP investigation</summary>

Run IP intelligence, DNS lookup, OS detection, and the default port scan sequentially for one resolved IP. The component defaults apply; port scan and traceroute tuning flags belong to their standalone modules. This workflow makes active probes and external lookups and does not replace a full asset inventory or security assessment.

```sh
dark-nexus --recon 127.0.0.1 --output recon.json
```

</details>

## Project

By Marshal · [Feedback](https://t.me/serphb) · [GNU AGPL v3](LICENSE)

Use only on systems you own or have permission to assess. Public-source queries are subject to each provider's terms and availability.
