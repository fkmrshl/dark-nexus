# Port Scanner Refactor Notes

## Summary

The port scanner was split into a cleaner architecture without changing the main CLI flow. The public entrypoints remain `port_scan(...)`, `net_scan(...)`, `guess_os_from_ports(...)`, and `os_detect(...)`.

The goal is to remove repeated OS detection work, keep the scanner fast, and reduce the amount of unrelated logic living in `src/port_scan.cpp`.

## Changed Areas

- `src/port_scan.cpp` still owns the port scan orchestration, timing profile, discovery phase, deep analysis phase, and result printing.
- `include/port_probe.hpp` and `src/port_probe.cpp` own TCP connect probing, raw SYN probing, UDP probing, target calibration, socket helpers, and timed connect handling.
- `include/port_enrich.hpp` and `src/port_enrich.cpp` own service priority, version extraction, banner validation, protocol-specific banner probes, HTTP probing, TLS inspection, and port detail printing helpers.
- `src/net_scan.cpp` now owns network scan mode instead of keeping it at the bottom of the port scanner file.
- `include/os_fingerprint.hpp` and `src/os_fingerprint.cpp` provide the shared OS fingerprint core.
- `src/os_detect.cpp` now uses the shared OS fingerprint core for verdict scoring while keeping its deeper probes and detailed output.
- `include/port_vuln.hpp` and `src/port_vuln.cpp` own CVE and security hint rules.

## Port Scanner Layout

- `src/port_scan.cpp` is now the coordinator. It selects ports, applies timing profiles, starts worker pools, merges enrichment data, writes global results, and prints the final report.
- `src/port_probe.cpp` is the low-level network probing layer. It keeps raw socket use and fallback connect behavior away from scan orchestration.
- `src/port_enrich.cpp` is the enrichment layer. It gathers banners, HTTP metadata, TLS certificate details, and stack disclosure hints after a port is already known to be open.
- `src/port_vuln.cpp` is the security hint layer. It maps observed services and metadata to practical warnings.
- `src/os_fingerprint.cpp` is the shared OS scoring layer used by both port scan and standalone OS detection.

## Output Cleanup

- Phase 3 now keeps the main port row compact: port, service, version, latency, and risk.
- Banner, HTTP, TLS, certificate, header, stack, and per-port hint details are printed as aligned child rows below the matching port.
- Long banners are clipped before display so they do not push the table columns sideways.
- Comma-separated CLI port lists such as `22,80,443` are parsed as an explicit custom list.

## OS Fingerprint Flow

Port scan no longer depends on a tiny port-only guess as its only OS hint. It now builds an `OsFingerprintInput` from already collected port scan data and sends it to the shared fingerprint core.

The standalone `--os-detect` mode remains deeper:

- It checks a fixed set of OS-relevant ports.
- It gathers banners where needed.
- It can use SMB, HTTP header analysis, TCP SYN fingerprinting, and TTL analysis.
- It uses the same scoring and verdict logic as the port scanner.

This avoids the worst option: calling the full `os_detect(...)` report from inside every port scan.

## Performance Notes

- Normal port scans reuse open port and banner data already collected during deep analysis.
- Full TTL and deep probe work stays in `--os-detect`.
- Network scan uses `tcp_probe_ms(...)` and lightweight banner checks for its summary.
- Build parallelism remains controlled by the installer and documentation, with `-j2` as the safe default.

## Suggested Test Commands

```bash
cmake -S . -B build
cmake --build build -j2
./build/dark_nexus --help
./build/dark_nexus --portscan 127.0.0.1 1
./build/dark_nexus --portscan 127.0.0.1 22,80
./build/dark_nexus --os-detect 127.0.0.1
```
