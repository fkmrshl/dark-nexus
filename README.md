# Dark Nexus

Network reconnaissance and infrastructure analysis from a single C++17 command-line tool for Linux.

Explicit flags, module-specific help, and JSON, CSV, or text reports. Run one module per invocation; running without arguments shows help.

[CLI reference](docs/cli.md) · [Module guide](#modules) · [License](LICENSE)

## Install

Install or update with one command (Linux, with `curl` and `sudo`):

```sh
curl -fsSLm120 https://raw.githubusercontent.com/fkmrshl/dark-nexus/main/install.sh | sudo bash
```

Then run `dark-nexus --help`; no separate build command is needed. The installer downloads the source, installs missing dependencies, compiles and installs the application, installs the DNS wordlist, and attempts to configure raw socket capabilities. In a terminal it shows a compact progress panel with the current stage, elapsed time, recent activity and real compilation task counts. Full output is saved to the printed log path; redirected output stays plain.

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

CMake fetches c-ares and prefers installed curl and nlohmann/json packages, fetching them if needed. A local build runs as `./build/dark_nexus`; use that path in place of `dark-nexus` in the examples below. No system installation is needed to view help or use TCP connect scans. Subdomain fast mode has a built-in list; deep mode requires an external list, supplied by the installer or selected with `--wordlist`.

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
dark-nexus doctor
dark-nexus --help portscan
dark-nexus --portscan 127.0.0.1 --ports 22,80,443 --connect
dark-nexus --portscan 127.0.0.1 --ports 8000-8010 --output scan.json
dark-nexus --portscan 127.0.0.1 --ports 8080 --output - --format json
```

Use `--quiet` to suppress the human-readable report, `--no-color` for plain output, and `--output` to save a result. With `--output -`, stdout contains only the selected report format. The [CLI reference](docs/cli.md) covers all flags, defaults, compatibility syntax, and exit codes.

Run `dark-nexus doctor` to inspect local runtime helpers, the DNS wordlist and raw-socket permissions without starting a scan or installing anything. Missing optional features produce warnings; missing core helpers identify the affected workflows. For machine-readable diagnostics, use `dark-nexus doctor --json -`. See [local diagnostics](docs/cli.md#local-diagnostics) and [automated build checks](docs/validation.md).

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

Combine passive sources with A/AAAA resolution. Fast mode uses 322 built-in words. Deep mode streams an external DNS wordlist automatically and enables additional passive sources, bounded permutations, CNAME inspection, web metadata, technologies, JavaScript discovery and service hints. The installer supplies the large list; without a readable external list, deep stops with instructions instead of falling back to the small one. `--wordlist PATH` overrides either profile. Wildcard DNS and inconclusive checks keep generated names out of the discovery list; independently sourced names remain separate candidates for review. Both modes send DNS queries and, by default, HTTP requests. Service fingerprints require manual verification.

```sh
dark-nexus --subdomain example.test --mode deep
dark-nexus --subdomain example.test --mode deep --no-js --no-service-hints
dark-nexus --subdomain example.test --mode fast --cname --tech
dark-nexus --subdomain example.test --mode deep --passive-only --no-enrich
```

Individual stages have `--stage` / `--no-stage` switches. Terminal output shows the first address per family and an extra-address count; `--full-addresses` shows all addresses. Saved reports always retain the full observed address lists.

[Subdomain options](docs/cli.md#subdomains)

</details>

<details>
<summary><strong>DNS</strong> — records and domain configuration</summary>

Query A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, and SRV records, inspect SPF references and DMARC TXT, check for DS/DNSKEY records, and attempt AXFR against discovered name servers. IP targets perform reverse PTR lookup. Operational errors remain distinct from negative DNS answers, and a transfer is confirmed only from a complete response. This includes active zone transfer requests; policy inspection and DS/DNSKEY presence do not establish SPF/DMARC or cryptographic DNSSEC validity. Requires `dig`.

```sh
dark-nexus --dns example.test --timeout 3000
```

[DNS and WHOIS options](docs/cli.md#dns-and-whois)

</details>

<details>
<summary><strong>WHOIS</strong> — registration and allocation records</summary>

Read WHOIS information for a domain or IP address. Non-comment stdout lines, including repeated and unfamiliar fields, are retained in JSON/CSV/TXT reports. Known rate-limit and access-denial messages on stdout or stderr are reported as failures; meaningful negative results remain valid responses. Available fields and message formats depend on the registry. Requires `whois`.

```sh
dark-nexus --whois example.com --timeout 5000 --output whois.json
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
<summary><strong>Recon</strong> — combined IP investigation</summary>

Run IP intelligence, DNS lookup, OS detection, and the default port scan sequentially for one resolved IP. The component defaults apply; port scan and traceroute tuning flags belong to their standalone modules. This workflow makes active probes and external lookups and does not replace a full asset inventory or security assessment.

```sh
dark-nexus --recon 127.0.0.1 --output recon.json
```

</details>

## Project

By Me · [Feedback](https://t.me/serphb) · [GNU AGPL v3](LICENSE)

Use only on systems you own or have permission to assess. Public-source queries are subject to each provider's terms and availability.
