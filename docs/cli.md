# CLI reference

```text
dark-nexus --MODULE TARGET [module options] [global options]
```

Choose exactly one module. Arguments can be reordered; options that take values accept `--key value` or `--key=value`. Running without arguments shows help and exits. The CLI never prompts for input.

```sh
dark-nexus --help
dark-nexus --help portscan
dark-nexus --portscan --help
dark-nexus --list-modules
dark-nexus --version
```

Unknown options, missing values, repeated or conflicting flags, and options that do not apply to the selected module are usage errors. Validation happens before the scan starts. Options such as `--timeout` and `--threads` configure only the modules listed below; they are not global limits for every operation. `--` ends option parsing.

## Modules and targets

| Flag | Target | Purpose |
| --- | --- | --- |
| `--portscan` | Hostname or IP | TCP/UDP port discovery and service inspection |
| `--subdomain` | Domain | Subdomain enumeration and optional enrichment |
| `--dns` | Domain | DNS records and configuration checks |
| `--whois` | Domain or IP | WHOIS registration/allocation fields |
| `--netscan` | IPv4 address | Host discovery and fixed-port inspection of the containing /24 |
| `--os-detect` | Hostname or IPv4 | OS fingerprint estimate |
| `--traceroute` | Hostname or IPv4 | Network path probes |
| `--ip-intel` | Hostname or IPv4 | IP context and quick port checks |
| `--site` | HTTP(S) URL or hostname | Resolve a website host and run IP intelligence |
| `--osint` | Username, email, or phone | Public observations and identity hypotheses |
| `--recon` | Hostname or IPv4 | Sequential IP intelligence, DNS, OS, and port checks |

The IPv4 network scanner takes an address and scans hosts `.1` through `.254` in its containing /24. CIDR notation and three-octet prefixes are unsupported.

```sh
dark-nexus --netscan 127.0.0.1
```

## Global options

| Option | Behavior |
| --- | --- |
| `-h`, `--help [module]` | Show general help or help for a module |
| `-V`, `--version` | Show version |
| `--list-modules` | List available module flags |
| `-q`, `--quiet` | Suppress the human-readable module report |
| `--color auto\|always\|never` | Set color behavior; default `auto` |
| `--no-color` | Alias for `--color never` |
| `-o`, `--output PATH` | Export the result; `-` selects stdout |
| `--format json\|csv\|txt` | Select export format; requires `--output` |
| `--json PATH` | Export JSON; shorthand for `--output PATH --format json` |
| `--log-file PATH` | Enable diagnostic logging to this file |
| `--no-log` | Disable diagnostic logging |

Logging is disabled unless requested. `--no-log` and `--log-file` cannot be combined. `--quiet` does not suppress errors or an explicitly selected export.

Automatic color follows terminal detection, `NO_COLOR`, and `TERM=dumb`. Redirected output is plain by default; `--color always` explicitly enables styling.

## Port scan

```sh
dark-nexus --portscan 127.0.0.1 --ports 22,80,8000-8010 --connect
dark-nexus --portscan ::1 --ports 8080 --ipv6 --connect
dark-nexus --portscan 127.0.0.1 --top-ports 100 --exclude 21-25,80
```

| Option | Values / default |
| --- | --- |
| `-p`, `--ports SPEC` | Comma-separated ports and inclusive ranges, e.g. `22,80,8000-8010` |
| `--top-ports 100\|1000` | Built-in preset; default `1000` |
| `--udp` | Use UDP probes instead of TCP |
| `--connect` | Force TCP connect probes |
| `--timing 0..5`, `-T0` … `-T5` | Timing profile; default `3` |
| `--exclude SPEC` | Exclude comma-separated ports and inclusive ranges |
| `--ipv4`, `--ipv6` | Select address family; mutually exclusive |
| `--threads N` | Worker count, `1..512`; otherwise derived from timing profile |
| `--timeout MS` | Probe timeout, `1..60000`; otherwise derived from timing profile |
| `--banner-timeout MS` | Banner/inspection timeout, `1..60000`; otherwise derived from timing profile |
| `--retries N` | Probe retry count, `0..10`; otherwise derived from timing profile |
| `--no-tls` | Disable optional TLS inspection |
| `--no-http` | Disable optional HTTP inspection |

Port numbers must be in `1..65535`. Lists are deduplicated, ranges must be ascending, and exclusions are applied after selection. Selecting no ports is an error. `--ports` and `--top-ports` are alternative selectors. `--udp` and `--connect` are mutually exclusive. Explicit `--retries` applies to TCP scans and cannot be combined with `--udp`.

The preset names `100` and `1000` select the existing built-in lists; they do not guarantee exactly that many probes. Use `--ports 1-65535` for an explicit complete port range. In automatic TCP mode the engine attempts SYN probing when raw sockets are available, with a connect fallback. `--connect` explicitly selects connect probes. Higher timing profiles use more concurrency and shorter timeouts; exact effective values depend on the profile and engine calibration.

`--no-http` and `--no-tls` control the dedicated inspection stages. Basic service/banner detection may still exchange application data. OS fingerprints and CVE hints are heuristics, and UDP silence cannot reliably distinguish an open port from filtering.

For compatibility, the positional port argument remains available:

```sh
dark-nexus --portscan 127.0.0.1 22,80
dark-nexus --portscan 127.0.0.1 0
dark-nexus --portscan 127.0.0.1 0-1
dark-nexus --portscan 127.0.0.1 0U
```

`0` selects the `1000` preset, `0-1` selects `100`, and `0U` selects the UDP preset. Prefer named flags for new scripts; do not combine a positional selector with `--ports` or `--top-ports`.

## Subdomains

```sh
dark-nexus --subdomain example.test --mode fast --wordlist ./hosts.txt --no-enrich
dark-nexus --subdomain example.test --mode deep --threads 64 --no-permutations
```

| Option | Values / default |
| --- | --- |
| `--mode fast\|deep` | Enumeration profile; default `fast`; `F` and `D` are compatibility aliases |
| `--wordlist PATH` | Explicit candidate wordlist; supported in both profiles |
| `--threads N` | HTTP worker count, `1..512`; default `200` |
| `--no-permutations` | Disable candidate permutation generation |
| `--no-enrich` | Disable HTTP and web metadata enrichment |
| `--no-deep-passive` | Disable the additional passive-source set |

Fast mode uses crt.sh, the built-in wordlist unless overridden, and lighter enrichment. Deep mode enables extra passive sources, permutations, and richer enrichment, and searches for an installed wordlist. The `--no-*` flags override profile defaults regardless of argument order. `--threads` sets the HTTP pool, not DNS concurrency; the DNS pipeline manages its own concurrency.

Both profiles perform active DNS resolution. `--no-enrich` disables web enrichment; it does not disable DNS queries or requests to passive-source APIs. Deep mode can read optional `VT_API_KEY`, `ST_API_KEY`, `SHODAN_API_KEY`, and `CENSYS_API_ID`/`CENSYS_API_SECRET` environment variables. Missing credentials skip the corresponding sources. External services may be unavailable or rate limited.

The module also writes its own `<domain>_subdomains.json`, `<domain>_subdomains.csv`, and checkpoint files in the working directory, independently of `--output`. These module files use a different layout from the common CLI report.

## Traceroute

```sh
dark-nexus --traceroute 127.0.0.1 --protocol tcp --destination-port 8080 \
  --max-hops 5 --probes 2 --timeout 500 --no-rdns --no-asn
```

| Option | Values / default |
| --- | --- |
| `--protocol icmp\|udp\|tcp` | Probe protocol; default `icmp` |
| `--max-hops N` | `1..255`; default `40` |
| `--probes N` | Probes per hop, `1..10`; default `5` |
| `--parallel-hops N` | Concurrent hops, `1..32`; default `8` |
| `--destination-port N` | TCP destination port / UDP base destination port, `1..65535`; default `33434` |
| `--timeout MS` | Per-probe timeout, `1..60000`; default `2000` |
| `--no-rdns` | Skip all reverse DNS requests and omit the hostname column |
| `--no-asn` | Skip all ASN requests and omit the ASN column |
| `--no-mtu` | Disable MTU detection |

All traceroute protocols require root privileges or `CAP_NET_RAW` to receive intermediate-hop ICMP replies. TCP may use connect probes when raw TCP sending is unavailable, but still requires raw ICMP reception. The current traceroute engine is IPv4; port-scan address-family flags do not apply here.

TCP probes use the specified destination port. UDP probes vary the port by hop and probe number, starting from the configured base and wrapping within `1..65535`. ICMP probes do not use the destination port.

`--no-rdns` and `--no-asn` bypass the corresponding lookup work entirely; they do more than hide columns. Resolving a hostname supplied as the target is still necessary. Use a numeric IPv4 target with both flags to avoid hostname and ASN enrichment requests. Intermediate routers may suppress or rate limit responses, so probe loss is not a measurement of end-to-end application loss.

## Reports and scripts

```sh
dark-nexus --portscan 127.0.0.1 --ports 8080 --connect --output result.json
dark-nexus --portscan 127.0.0.1 --ports 8080 --connect --quiet --output result.txt
dark-nexus --portscan 127.0.0.1 --ports 8080 --connect --output - --format json
dark-nexus --portscan 127.0.0.1 --ports 8080 --connect --output result.data --format json
```

Without `--format`, file extensions select JSON or CSV; other filenames select text. With `--output -`, the default format is JSON and stdout contains only the report, without ANSI escapes or progress messages; module status output goes to stderr unless `--quiet` is set. Use `--format` to override the filename. Diagnostic errors are written to stderr. Check the process exit status before consuming an export.

CSV writes one table to the requested path or stdout, with columns `record_type,target,identifier,value,details`. Row types include `metadata`, `geo`, `os`, `port`, `subdomain`, `osint`, `trace`, and `dns`; `details` contains a JSON object with fields for that record. This replaces the previous separate `*_ports.csv`, `*_subdomains.csv`, and similar common-report files; the subdomain module's own files are independent.

Exports contain fields populated in the shared scan result. They are not transcripts of the terminal report. DNS, WHOIS, and network discovery currently display more information than they store in the common report; an empty result array does not necessarily mean a lookup returned nothing. Subdomain module files contain additional data.

| Exit code | Meaning |
| --- | --- |
| `0` | Command completed |
| `1` | Runtime or report-writing failure |
| `2` | Invalid command-line usage |
| `130` | Interrupted with SIGINT |

A completed command can contain unavailable-source messages or incomplete observations. Exit `0` does not certify that every external service responded or that every result was independently verified.

## Dependencies and results

Building requires Linux, a C++17 compiler, CMake 3.15+, Git, pkg-config, OpenSSL development files, liburing, and libcap. CMake fetches pinned c-ares, uses system curl and nlohmann/json when available, and fetches pinned fallbacks otherwise. The installer also provisions runtime helpers and wordlists.

DNS checks use `dig`; WHOIS uses `whois`. Other workflows can use `host`, `ping`, `curl`, and `openssl`. OSINT can use installed Sherlock, Maigret, Holehe, theHarvester, and PhoneInfoga executables. Missing OSINT helpers are skipped without prompting or installation.

Raw socket access uses root privileges or `CAP_NET_RAW`; the installer attempts to grant the capability to the installed executable. Connect port scans work without raw socket access. Results also depend on target responses, firewall behavior, DNS configuration, and external-source availability.

For module purposes and limitations, see the [module guide](../README.md#modules).

## Offline checks

Parser, thread pool, and terminal tests can run without fetching network dependencies or building the application:

```sh
cmake -S . -B build-cli -DDARK_NEXUS_BUILD_APP=OFF
cmake --build build-cli
ctest --test-dir build-cli --output-on-failure
```

A full build with `BUILD_TESTING` enabled also includes report and CLI integration checks. Use `-DBUILD_TESTING=OFF` when only the executable is needed.

After building the application, optionally check real TCP sockets on `127.0.0.1`:

```sh
python3 tests/loopback_smoke.py ./build/dark_nexus
```

This smoke check creates local open/closed port fixtures and checks worker/timeout overrides and JSON stdout. It uses only `127.0.0.1`, requires local socket access, and is separate from the offline checks above.
