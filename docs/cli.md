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

`dark-nexus doctor` is a separate local diagnostic command and takes no target.

Unknown options, missing values, repeated or conflicting flags, and options that do not apply to the selected module are usage errors. Validation happens before the scan starts. Options such as `--timeout` and `--threads` configure only the modules listed below; they are not global limits for every operation. `--` ends option parsing.

## Modules and targets

| Flag | Target | Purpose |
| --- | --- | --- |
| `--portscan` | Hostname or IP | TCP/UDP port discovery and service inspection |
| `--subdomain` | Domain | Subdomain enumeration and optional enrichment |
| `--dns` | Domain or IP | DNS records, bounded inspection and reverse PTR for IPs |
| `--whois` | Domain or IP | WHOIS registration/allocation fields |
| `--netscan` | IPv4 address | Host discovery and fixed-port inspection of the containing /24 |
| `--os-detect` | Hostname or IPv4 | OS fingerprint estimate |
| `--traceroute` | Hostname or IPv4 | Network path probes |
| `--ip-intel` | Hostname or IPv4 | IP context and quick port checks |
| `--site` | HTTP(S) URL or hostname | Resolve a website host and run IP intelligence |
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

## Local diagnostics

```sh
dark-nexus doctor
dark-nexus --doctor
dark-nexus --help doctor
dark-nexus doctor --json -
dark-nexus doctor --output - --format json
```

Doctor checks the running version, core runtime helpers (`dig`, `whois`, `host`, `ping`, `curl`, `openssl`, `getent`), known external DNS wordlist paths and the process's effective `CAP_NET_RAW`. It performs local file and capability checks only: no network requests, socket probes, helper execution, package installation or log files.

`ok` means a local prerequisite was detected; it does not certify that an external tool, API or network operation will succeed. Missing core helpers are marked `fail`, with the affected workflows and suggested remedies. A missing external wordlist or raw capability is a `warn`; subdomain fast mode and TCP connect mode remain available. Deep mode requires an external list unless `--passive-only` is selected. Raw capability describes the current process before any scan-specific privilege drop and does not guarantee that host/container policy will permit raw sockets.

Core executables are resolved using the runtime `PATH`. Executables must be regular files with execute permission; symlinks to suitable files are accepted. Wordlists must be regular, readable and nonempty. Doctor searches known paths without invoking `locate`.

Default output is a compact text report. `--output -` defaults to JSON; `--json -` is shorthand. The independent JSON schema includes `schema_version`, `version`, aggregate `status` and `checks`. Each check has a stable `id`, `status`, `detail`, `remedy` and `workflows`. It does not use the scan-result schema.

Doctor accepts color options and `--no-log`. Targets, scan options, `--quiet`, `--log-file`, file exports and CSV/TXT formats are usage errors. Redirect stdout if you need to save the report: `dark-nexus doctor --json - > doctor.json`.

Exit `0` means no core prerequisite was missing (warnings may remain); `1` means a core helper is missing or diagnostics/output failed; `2` means invalid arguments. Check the exit code before treating the report as complete.

## DNS and WHOIS

```sh
dark-nexus --dns example.test --timeout 3000
dark-nexus --dns 192.0.2.10 --timeout 1000
dark-nexus --whois example.test --timeout 5000 --json whois.json
```

`--timeout MS` accepts `1..60000` and limits each helper invocation. Defaults are 6000 ms for DNS and 10000 ms for WHOIS. DNS also has a 60-second total budget and checks at most eight PTR addresses, eight distinct SPF references and eight name servers for AXFR. Those optional inspections can be skipped with a warning when their limits are reached. No recursive SPF expansion or policy validation is performed.

DNS uses `dig -r` to ignore personal `.digrc` settings and parses status headers and full answer records. A CNAME is retained as a CNAME, never relabeled as an IP address. Returned owners must match the question or its CNAME chain (at most 16 links); a reply accepts at most 4096 records. Literal IPv4/IPv6 targets use reverse PTR lookup. Remote SPF and NS names are validated before becoming helper arguments.

Parsing checks reply structure, record owners, TTLs and the syntax of selected record types, including addresses, name references, MX, SRV, SOA, quoted TXT, CAA, DS and DNSKEY data. This is not a universal resource-record validator. Other record data can be retained as text without type-specific validation; an accepted record does not establish policy correctness or cryptographic validity.

NOERROR without matching data and NXDOMAIN are valid negative responses. SERVFAIL, malformed or truncated replies, nonzero helper exits and timeouts are operational failures; they do not establish that SPF/DMARC or other records are absent. DNSSEC output describes DS/DNSKEY observations, without claiming cryptographic validation. This interpretation also accounts for [dig's documented exit codes](https://bind9.readthedocs.io/en/stable/manpages.html#return-codes): a zero exit code alone does not establish a positive DNS answer.

AXFR is confirmed only after successful completion with parsed records and matching opening/closing SOA records. The same record-validation limits apply to transferred data. Refusal, timeout and incomplete or diagnostic-only output are distinct outcomes. Optional AXFR failures produce warnings and do not invalidate otherwise completed primary queries. A refusal does not certify the zone's overall security.

WHOIS retains sanitized non-comment stdout lines in `whois_records`, including unfamiliar fields and repeated keys. Recognized negative registry replies are retained as meaningful results. Known access-denial and rate-limit messages on stdout or stderr fail the operation, even with helper exit zero. WHOIS is free-form text: this checks common messages and process completion, rather than validating every registry's response format. Output beyond the capture limit (1 MiB per stream for WHOIS, 256 KiB for DNS) is reported as incomplete. WHOIS data already captured before a failure remains available in the requested export.

Both commands stop their helper process groups on cancellation. Cleanup also terminates descendants that remain in the helper's group; processes that create a separate session or group are outside this mechanism. SIGINT and SIGTERM currently return `130`; a requested export retains collected data with status `cancelled`. Partial or failed primary lookups return `1` and retain errors in the export. Invalid arguments return `2` before helpers run.

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
dark-nexus --subdomain example.test --mode deep --threads 64
dark-nexus --subdomain example.test --mode deep --passive-only --no-enrich
dark-nexus --subdomain example.test --mode fast --cname --tech
dark-nexus --subdomain example.test --mode deep --no-js --full-addresses
```

| Option | Values / default |
| --- | --- |
| `--mode fast\|deep` | Enumeration profile; default `fast`; `F` and `D` are compatibility aliases |
| `--wordlist PATH` | Explicit candidate wordlist; supported in both profiles |
| `--bruteforce` | Select a discovered external DNS wordlist in fast mode; already the default in deep; `--wordlist` takes priority |
| `--passive-only` | Skip wordlists, generated permutations and JavaScript discovery; conflicts with `--wordlist` and `--bruteforce` |
| `--threads N` | Enrichment worker count, `1..512`; default `200` |
| `--dns-concurrency N` | Maximum active candidate A/AAAA queries, `16..2000`; default `256` fast, `512` deep; adapts downward on temporary DNS failures |
| `--dns-retries N` | Additional attempts for temporary DNS failures, `0..2`; default `1`; `0` disables retries |
| `--dns-timeout MS` | Initial query timeout, `100..5000` ms; default `500`; retries use 2x/3x this value, capped at `5000` ms |
| `--permutations` / `--no-permutations` | Enable/disable bounded candidate permutations; deep default on |
| `--deep-passive` / `--no-deep-passive` | Enable/disable the additional passive-source set; deep default on |
| `--http` / `--no-http` | Enable/disable HTTP probes and metadata; both profiles default on |
| `--cname` / `--no-cname` | Enable/disable CNAME inspection; deep default on |
| `--tech` / `--no-tech` | Enable/disable technology and WAF detection; requires HTTP; deep default on |
| `--js` / `--no-js` | Enable/disable bounded page/script discovery; requires HTTP; deep default on |
| `--js-workers N` | Parallel page/script fetches, `1..8`; default `4`; does not enable the JS stage by itself |
| `--js-budget SEC` | Shared JS discovery time budget, `1..300` seconds; default `30`; subsequent DNS verification is separate |
| `--service-hints` / `--no-service-hints` | Enable/disable CNAME service hints; requires HTTP and enables CNAME; deep default on |
| `--no-enrich` | Disable HTTP, CNAME, technology/WAF, JavaScript and service-hint stages |
| `--full-addresses` | Display every observed IPv4/IPv6 address in the terminal; exports always keep all |

Fast mode uses 322 built-in words, crt.sh and lighter enrichment. Deep mode automatically selects and streams an external wordlist, plus additional passive sources, bounded permutations and richer enrichment. The installer supplies the large list. If none is readable, deep and `--bruteforce` report an actionable error before DNS work; neither silently falls back to the built-in list. `--passive-only` needs no wordlist. An explicit `--wordlist` always takes priority, including a deliberately small custom list. Passive candidates are checked first. Streaming processes the entire valid list in bounded batches; DNS batch size is not a total candidate limit. Wildcard-scope suppression can skip generation work.

Stage switches override profile defaults regardless of argument order and can enable individual deep features in fast mode. Opposite switches for the same stage are rejected. `--no-http` conflicts with explicit `--tech`, `--js` and `--service-hints`; `--no-cname` conflicts with explicit `--service-hints`; `--no-enrich` conflicts with explicitly enabled enrichment stages. `--passive-only` conflicts with explicit `--permutations` and `--js` as well as wordlist selection. Disabled dependencies also disable dependent default stages. `--threads` sets the enrichment pool, not DNS concurrency; the DNS pipeline manages its own concurrency.

Both profiles perform active DNS resolution. `--passive-only` restricts candidate discovery to passive sources, but still contacts their APIs and resolves their candidate names; optional enrichment remains enabled unless `--no-enrich` is set. `--no-enrich` does not disable candidate DNS queries or requests to passive-source APIs. Additional passive sources, enabled by deep or `--deep-passive`, can read optional `VT_API_KEY`, `ST_API_KEY`, `SHODAN_API_KEY`, and `CENSYS_API_ID`/`CENSYS_API_SECRET` environment variables. Missing credentials skip the corresponding sources. External services may be unavailable or rate limited.

DNS retries use longer query timeouts, short cancellable backoff and a shifted resolver order. Candidate and wildcard calls use one resolver per channel, so c-ares does not multiply the explicit retry budget by the resolver shard size. Only retryable A/AAAA families are queried again; completed address families and valid negative replies are preserved. Timeouts, SERVFAIL and connection refusal are eligible for retry; malformed replies and NXDOMAIN/NODATA are not. Candidate batches with actual temporary DNS failures affecting at least 5% of names halve concurrency down to 16. Fully successful batches raise it by 64 toward the configured maximum. Locally expired queued queries do not lower resolver concurrency. Retry concurrency uses the current limit capped at 256.

The 10,000-name input buffer is split into smaller DNS calls sized for concurrency and query timeout: at most five seconds of worst-case query waves, with a deadline allowing twice that time plus one second (capped at 30 seconds). Retries and wildcard probes are split independently for their timeout and concurrency. Thus decreasing concurrency also decreases the amount of queued work. This is a per-call guard, not a total scan time limit. Slow resolvers, large wordlists and optional HTTP enrichment can still take substantial time.

After three consecutive candidate batches of at least eight names each have at least 95% failed, addressless observations after retries, DNS discovery stops. Remaining wordlist/permutation/JS discovery is skipped, existing enrichment is drained, and reports preserve observations with an explicit error and `partial` or `failed` status. Cancellation remains distinct. Successful NXDOMAIN/NODATA replies do not trigger this guard; neither do partial positive address observations. After restoring resolver connectivity, start a new scan; checkpoints do not resume unfinished work.

Final unresolved checks produce one aggregate error with partial/empty counts before optional DoH fallback. These count candidate checks, not unique missing names. JSON, checkpoints and CSV metadata include `subdomain_dns` diagnostics; see [DNS degradation validation](subdomain-dns-degradation.md) for field definitions and local benchmark results. Concurrency bounds active candidate queries, not queries per second or enrichment lookups. Wildcard probes respect the configured maximum (at most 64 active queries) and retry count; inconclusive scopes remain uncertain, while scopes with two positive probes need no retry.

Subdomain scans automatically write `<domain>_subdomains.json`, `<domain>_subdomains.csv`, and `<domain>_subdomains_checkpoint.json` in the working directory. Final files are written after the CLI determines the run status and timing, including failed and cancelled runs. Automatic JSON uses the same schema `3.0` object as `--output report.json` and `--output -`: `status`, `errors`, `warnings`, metadata, `subdomains`, `subdomain_candidates` and `subdomain_counts` (`resolved`, `candidates`, `total`). Automatic CSV uses the common `record_type,target,identifier,value,details` table, including metadata, errors and warnings. Requested output files are also replaced atomically. If `--output` names an automatic file, a compatible format reuses that file; an incompatible format is rejected before scanning. Requested checkpoint paths preserve checkpoint metadata.

Migration from the previous automatic exports: JSON is now an object instead of a bare array; read confirmed observations from `report["subdomains"]` and review candidates from `report["subdomain_candidates"]`. Rows use `sub` and `ips` instead of `subdomain` and `ipv4`. In CSV, filter `record_type` for `subdomain` / `subdomain_candidate` and decode `details` for the row fields. Common CLI schema `3.0` remains compatible; newly added fields default to empty when reading older common reports. The unversioned legacy module-array and checkpoint layouts are no longer written.

Every row retains `stack`, `doh_fallback`, `http_observations` and `discovery_sources` in all structured exports. Discovery tags are `passive`, `brute` (wordlist), `permutation` and `js`; repeated observations merge their tags. The legacy summary `source` is the single tag or `both` for multiple tags. `doh_fallback` records only actual DoH providers; a JavaScript discovery is tagged `js` and does not claim DoH use. Passive tags do not distinguish individual providers.

DNS discovery checks both A and AAAA records. IPv6-only names remain available with `--no-enrich`; common JSON and CSV details include `ipv6`. Common JSON `subdomains` contains address observations whose relevant wildcard checks completed without positive random-name replies, with `dns_status: "resolved"`. Passive and JavaScript observations under wildcard or inconclusive scopes appear separately in `subdomain_candidates`, with `dns_status: "wildcard"` or `"uncertain"`; they are not counted as discoveries or used for HTTP enrichment and generated follow-ups. CSV uses separate `subdomain_candidate` rows. Module JSON/CSV retain both groups with `dns_status`. A missing row does not establish that a DNS name is nonexistent, and `resolved` does not certify a distinct website. Resolver errors are distinguished from NXDOMAIN and successful empty answers. Failed candidate lookups make the common report partial or failed and return `1`; optional passive-source and HTTP failures produce bounded warnings. A completed command does not guarantee coverage of every passive source.

DNS observations are saved before optional enrichment. SIGINT/SIGTERM stop new work and cancel active DNS/HTTP operations; the common report retains observations with status `cancelled` and exit `130`. The HTTP queue is bounded and is discarded on cancellation without losing DNS observations already returned by the current batch. Worker failures retain base records and appear in report errors.

Wildcard checks use random names in the relevant parent scopes rather than matching candidates against a sampled IP list. Two or more observed positive probes mark a scope as wildcard even when addresses rotate or other probe replies fail; `wildcard_match` identifies this parent-scope condition. A scope is clear only when every probe completes with a valid negative or empty answer. With fewer than two positive probes, any positive, missing or failed reply makes the check inconclusive. Generated names in wildcard or inconclusive scopes are suppressed regardless of their IP addresses, and the affected generation work is skipped with aggregate diagnostics. This deliberately favors conservative output and may omit real names sharing such scopes; independently sourced observations remain available as candidates for manual review. Checks are bounded to 64 parent scopes, with six probes for the scan root and three per additional scope; untested scopes remain inconclusive. Newly encountered scopes are probed together with the bounded per-batch deadline and retry policy above, separately from resolver health checks. A finite probe sample cannot prove that wildcard DNS is absent everywhere. HTTP redirects, including status 308, do not promote a candidate to a discovery. CNAME service fingerprints are inspection hints requiring manual verification; `takeover_possible` does not establish exploitability.

Enabled permutations use at most 64 sorted resolved seeds and 5000 unique generated candidates per run. Variants preserve the seed's parent branch: `api.dev.example.test` can produce `api-test.dev.example.test`. Wildcard and uncertain candidates never become seeds. `--passive-only` disables this stage and JavaScript discovery.

Interactive subdomain output accents address values, IPv6, CNAME, HTTP status and metadata in green; uncertain counts and service hints remain warnings. By default the terminal shows the first address per family with `(+N)` for additional observations. `--full-addresses` displays every address on separate detail lines. Common reports and module JSON/CSV/checkpoints always retain the complete observed address lists. Batch progress uses complete lines so worker results do not overwrite it. `--no-color`, `NO_COLOR` and redirected output preserve plain text in automatic mode; `--color always` explicitly enables colors. Structured reports never include these terminal styles.

Explicit wordlists must be readable regular files. A list without valid candidates is an error and does not silently switch to the built-in list; a list skipped because wildcard checks prevented generation is reported as skipped. Automatic report files use independent atomic replacements. If one automatic file fails, the remaining writable files are refreshed with the resulting errors and status; failed destinations preserve their previous content. A requested-output failure is also reflected in writable automatic reports. Checkpoints use the same canonical rows and metadata plus `checkpoint.final` and UTC `checkpoint.saved_at`. In-progress snapshots have `status: "running"`, an empty `end_time` and `checkpoint.final: false`; final snapshots carry the final run status and `checkpoint.final: true`. Counts use `subdomain_counts`, and `results`, `count`, `resolved_count` and `candidate_count` aliases are no longer written. Checkpoints do not implement scan resumption. Concurrent runs produce complete individual files, but the last successful writer wins and JSON/CSV/checkpoint files are not one transaction.

Passive APIs and DoH use verified TLS and bounded response capture. DoH answers must have a valid DNS status, matching address type and owner/CNAME chain. Fallback is restricted to passive candidates with operational DNS failures and no native addresses, at most 500 candidates per run. A partial native answer retains its successful family and reports the failed family; it is not combined with addresses from another DNS view. DoH addresses remain in `subdomain_candidates` with `dns_status: "uncertain"`, even when native wildcard probes were clear: those probes cannot establish wildcard behavior at the DoH provider. These candidates receive no HTTP enrichment and do not seed generated follow-ups. If a later native lookup succeeds in a clear scope, the name is moved to `subdomains`, its DoH addresses and provider label are replaced by the native observation, and enrichment can proceed. Earlier lookup failures remain in run diagnostics. JavaScript inspection uses up to 32 useful HTML pages, 64 page attempts, 50 unique script URLs and 5000 candidate names under the scan domain, including apex URLs as page or script sources; extracted names must be strict subdomains. Complete enrichment HTML is reused from a cache capped at 64 entries and 2 MiB. Cached pages and successful HTTP responses are prioritized; error responses such as 404 do not consume target slots. The successful HTTP/HTTPS scheme is preserved. Relative, root-relative, protocol-relative and absolute script links are resolved against the final page URL. HTML attribute scanning is bounded and does not execute scripts. CNAME service inspection checks at most 64 matching candidates. These limits produce warnings when remaining optional work is skipped.

The JS page/script fetch pool defaults to four workers and shares one 30-second monotonic budget. `--js-workers` and `--js-budget` adjust these limits when JS is enabled. Each request receives at most five seconds and no more than the remaining stage budget; timeout callbacks do not set the scan cancellation token. A budget stop retains names already collected for subsequent DNS verification. Progress shows page attempts, successful pages, cached pages, completed scripts and candidates. The JS stage manually follows at most three redirect hops, validating domain scope, HTTP/S scheme, credentials and loops before each request; foreign redirects are rejected. Other HTTP probes and passive APIs continue to report their requested endpoint without following redirects.

HTTP enrichment and API requests do not automatically follow redirects; their reported status and metadata describe the requested endpoint. JS discovery uses the separate scoped redirect policy above. HTTP bodies are capped at 1 MiB for API/JS requests and 50000 bytes for target probes, with a total 64 KiB header limit across response blocks. Target probes retain a bounded body prefix when the capture limit is reached. A received final HTTP status remains available even if the body is oversized, times out or is interrupted; the terminal marks such transfers as incomplete. An incomplete response is not treated as a completed download. Titles and body-based fingerprints require a complete body; header metadata requires complete final headers. Passive APIs, DoH and JavaScript discovery reject incomplete responses.

Common JSON/CSV details, module JSON/CSV and checkpoints include `http_observations`: up to two enrichment attempts in order, with `requested_url`, `effective_url`, `method`, numeric `http_code`, libcurl `transport_code`, `headers_complete`, `body_complete`, `success`, failure flags and `error`. The existing string `http_code` describes the selected attempt. `success` requires a complete 2xx response; a complete 404 therefore has `body_complete: true` and `success: false`. For HEAD, `body_complete` means the requested HEAD transfer completed; it does not mean that a GET body was downloaded. HTTPS is tried first. HTTP fallback occurs only when HTTPS produced no final HTTP status; a received HTTPS status with a truncated body is retained. HTTP enrichment remains optional: its incomplete attempts do not invalidate DNS observations or change the scan exit code, and bounded warnings carry transfer failures. Older reports without `http_observations` remain readable.

Target HTTP enrichment connects directly to the A/AAAA addresses retained by the scanner, using a libcurl resolve entry while preserving the original hostname for HTTP Host, TLS SNI and certificate verification. It does not resolve the target again through the system resolver and does not use proxy environment variables; system routing, including VPN routing, still applies. Both HTTPS and HTTP fallback use the same observed address set. `http_observations[].dns_pinned` records that this binding was configured, and `primary_ip` records the connected peer when available. A failed connection can have `dns_pinned: true` and an empty `primary_ip`. One selected address is probed, not every address in the DNS answer. API, DoH and uncached JS fetches use their own verified HTTP requests; they do not certify a target DNS/HTTP binding. Older observations default to an empty `primary_ip` and `dns_pinned: false`.

A DNS address observation does not promise a working website. HTTP 404 means the server responded but the requested path was not found; 301/302/307/308 indicate redirects, which enrichment reports without following. A TLS or connection failure describes the HTTP attempt and does not erase an independently observed DNS address. Wildcard and inconclusive names remain separate candidates regardless of HTTP status.

The existing resolver-file search includes `./resolvers.txt` and `./resolvers_trusted.txt`. Files must be readable regular files, at most 2 MiB and 100000 lines, containing IPv4/IPv6 resolver addresses with optional ports (`127.0.0.1:5353` or `[::1]:5353`); blank lines and full-line `#` comments are accepted. Resolver health checks require a positive `example.com` A response and a successful negative probe. Only passing resolvers are used; an empty or malformed file or no passing custom resolver is an error. Resolver setup has its own bounded health-check phase; candidate batches have a 30-second deadline.

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

CSV writes one table to the requested path or stdout, with columns `record_type,target,identifier,value,details`. Row types include `metadata`, `geo`, `os`, `port`, `subdomain`, `subdomain_candidate`, `trace`, `dns`, `whois`, `warning` and `error`; `details` contains a JSON object with fields for that record. This replaces the previous separate `*_ports.csv`, `*_subdomains.csv`, and similar common-report files; the subdomain module's own files are independent.

Exports contain fields populated in the shared scan result. They are not transcripts of the terminal report. DNS records use `dns_records`; WHOIS response lines use `whois_records`. Additive report fields `status` (`complete`, `partial`, `failed`, `cancelled`), `errors` and `warnings` describe command completion. Requested exports are finalized after module failures and cancellation, including partial observations. Reports written before these fields were introduced can still be read with their default values. Network-discovery and subdomain-specific output can contain additional data.

New scans use common JSON schema `3.0`: the removed identity-investigation module and its `osint` / `osint_hits` fields are no longer exported. Legacy JSON can still be deserialized for its network fields; schema `2.0` is upgraded to `3.0`, and removed fields are ignored rather than preserved when re-exporting.

| Exit code | Meaning |
| --- | --- |
| `0` | Command completed |
| `1` | Runtime or report-writing failure |
| `2` | Invalid command-line usage |
| `130` | Interrupted with SIGINT or SIGTERM |

A completed command can contain unavailable-source messages or incomplete observations. Exit `0` does not certify that every external service responded or that every result was independently verified.

## Dependencies and results

Building requires Linux, a C++17 compiler, CMake 3.15+, Git, pkg-config, OpenSSL development files, liburing, and libcap. CMake fetches pinned c-ares, uses system curl and nlohmann/json when available, and fetches pinned fallbacks otherwise. The installer also provisions runtime helpers and wordlists.

DNS checks use `dig`; WHOIS uses `whois`. Other workflows can use `host`, `ping`, `curl`, and `openssl`. The installer provisions network dependencies and the DNS wordlist; it does not install account-lookup tools or Python/Go helper environments.

Raw socket access uses root privileges or `CAP_NET_RAW`; the installer attempts to grant the capability to the installed executable. Connect port scans work without raw socket access. Results also depend on target responses, firewall behavior, DNS configuration, and external-source availability.

For module purposes and limitations, see the [module guide](../README.md#modules).

## Offline checks

Parser, process-supervisor, thread pool, and terminal tests can run without fetching network dependencies or building the application:

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
