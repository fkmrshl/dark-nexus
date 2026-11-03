# Subdomain scanner benchmark

This report measures the real CLI DNS pipeline and the real HTTP-based JavaScript discovery stage on controlled local fixtures. It includes repeated measurements, correctness checks, memory observations and raw data. It is suitable for comparing these builds and configurations under the stated conditions.

The DNS comparison uses product source [`8d5a910`](https://github.com/fkmrshl/dark-nexus/commit/8d5a9109aa144f35c8d19b029b2f071b90536ffa) against the initial v2.1 hardening release [`5153980`](https://github.com/fkmrshl/dark-nexus/commit/51539803714ab24bb4aed083eb941119480d2fc2). Both are C++17 Release builds with the application's `-O2` setting and matching CMake/compiler/linker flags. The optional JS benchmark links the same production parser, scheduler and libcurl transport as the scanner.

## Results

Raw measurements: [subdomain-2026-11-03.json](subdomain-2026-11-03.json) (4 DNS scenarios, 32 measured DNS launches and 15 measured JS launches). Completed 2026-11-03T04:40:28.671184+00:00. All 47 measured launches are included; warm-ups follow the protocol below.

| DNS scenario | Samples per version | Current seconds: median (min–max) | Baseline seconds: median (min–max) | Observed outcome |
| --- | ---: | ---: | ---: | --- |
| Healthy | 5 | 0.179 (0.160–0.184) | 0.173 (0.161–0.202) | Both complete; tail record found in every run |
| Loss | 5 | 0.787 (0.784–0.796) | 0.925 (0.914–0.937) | Both complete; tail record found in every run |
| Delayed | 3 | 101.477 (101.469–101.510) | 60.175 (60.163–60.181) | Current complete; baseline incomplete and misses the tail in every run |
| Outage | 3 | 45.546 (45.537–45.548) | 60.174 (60.170–60.197) | Both report failure; current explicitly stops further discovery |

For immediate replies, the current build processes **55,849 candidate names/s** at the median; 10,000 names require 20,000 A/AAAA operations. Current and baseline timing ranges overlap. These are candidate DNS checks, predominantly successful negative replies.

| DNS scenario | Current sampled peak RSS: median / largest, MiB | Baseline sampled peak RSS: median / largest, MiB |
| --- | ---: | ---: |
| Healthy | 17.49 / 17.54 | 21.48 / 21.55 |
| Loss | 15.27 / 15.34 | 15.34 / 15.38 |
| Delayed | 16.42 / 16.44 | 26.49 / 26.51 |
| Outage | 16.98 / 16.98 | 30.80 / 30.81 |

Correctness and recovery observations:

- All three corrected delayed runs inspect all 20,000 address-family queries and find the known tail record. The baseline fixture sees 11,856 unique family queries out of 20,000 in each run; all three baseline runs miss that record. The longer corrected duration includes the work the baseline leaves unfinished.
- Loss runs recover all 143 deliberately dropped AAAA observations. Current sends 2,143 candidate query packets versus 2,286 for the baseline, preserving successful A observations.
- Every corrected outage run stops after 1,200 failed candidate checks, with an explicit reason that remaining candidates were not checked. It preserves diagnostics rather than claiming completion of the offered 10,000-name list.
- Every corrected run records zero call-deadline expirations and zero queries left unsubmitted at the deadline.

| Current JS configuration | Samples | Seconds: median (min–max) | Sampled peak RSS median, MiB | Validated work |
| --- | ---: | ---: | ---: | --- |
| 1 worker(s), uncached HTML | 5 | 1.765 (1.760–1.792) | 11.82 | 50 scripts; 50 candidate names; 32 HTML requests |
| 4 worker(s), uncached HTML | 5 | 0.493 (0.480–0.503) | 12.09 | 50 scripts; 50 candidate names; 32 HTML requests |
| 4 worker(s), cached HTML | 5 | 0.316 (0.301–0.320) | 12.01 | 50 scripts; 50 candidate names; 32 cached HTML bodies |

Four workers deliver **3.58× the throughput** of one worker in the uncached JS fixture, using median elapsed time. Both use the same source and extract the same 50 candidate names. With cached HTML, four workers take **316 ms** at the median; cache population is excluded.

### Machine and build

| Item | Recorded value |
| --- | --- |
| CPU | 13th Gen Intel(R) Core(TM) i5-13500HX|
| OS/kernel | CachyOS, Linux 7.3.0-4-cachyos, x86_64 |
| OS-reported memory | 15.31 GiB |
| Compiler | c++ (GCC) 16.2.1 20260810 |
| Python | 3.14.9 |
| c-ares | 1.28.1 (CMake pinned source) |
| libcurl / OpenSSL / liburing | 8.23.0 / 3.6.5 / 2.15 |

CMake Release supplies `-O3 -DNDEBUG`; the app and JS harness append `-O2`, which selects their optimization level. Dependencies use their Release configuration. Both product builds use matching flags. Binary SHA-256 values, harness hashes and per-run diagnostics are in the raw JSON.

The Release build and all **19 CTest targets** pass locally. Benchmark helper checks cover capture, nonzero exit, timeout cleanup and memory observations. DNS runs check query coverage and canonical exports; JS runs check every requested page/script and all 50 candidate names. Independent review of the harness found no remaining defects after corrections.

## What is measured

### DNS pipeline

Each sample launches the actual CLI in a new process, using a generated wordlist, local UDP DNS and a local non-forwarding HTTP proxy. The proxy rejects the optional certificate-log request, so passive-provider latency is excluded. Automatic JSON, CSV and checkpoint writes are included in process timing. Verification and fixture setup/teardown are excluded.

The CLI uses fast-mode defaults except for the explicit wordlist, DNS controls and disabled enrichment:

```text
--subdomain example.test --wordlist <generated-file>
--no-enrich --no-permutations --no-deep-passive --quiet
--dns-concurrency <case> --dns-timeout <case> --dns-retries 1
--output - --format json
```

Most names have valid negative replies; one dual-stack positive is at the end of each healthy/delayed/loss wordlist. Every corrected run must reach it with the expected A and AAAA addresses, inspect all candidate families, finish without DNS errors and preserve identical canonical JSON in stdout, automatic JSON and the final checkpoint. Candidate throughput includes negative observations; it is not the number of discovered websites per second.

| Scenario | Candidate names | DNS concurrency | Initial query timeout | Fixture behavior |
| --- | ---: | ---: | ---: | --- |
| Healthy | 10,000 | 256 | 500 ms | Immediate answers |
| Loss | 1,000 | 64 | 100 ms | 10 ms replies; first AAAA reply dropped for every seventh name |
| Delayed | 10,000 | 16 | 500 ms | 80 ms replies |
| Outage | 10,000 offered | 16 | 100 ms | All candidate replies dropped; resolver-health and wildcard probes still answer |

The outage sample intentionally expects an unsuccessful scan with an explicit stop reason and preserved diagnostics. Its offered wordlist size must not be mistaken for completed work. Baseline failures in the delayed/outage cases remain in raw data; no successful-throughput number is calculated for an incomplete series.

### JavaScript discovery

The harness calls production `scrape_js_subdomains`, real libcurl and the production HTML/script parser against a local HTTP server. Each network request has a controlled 20 ms service delay. There are 32 HTML pages, 50 shared script URLs and exactly 50 distinct candidate names. All scripts and names must be found within the 30-second budget.

Three configurations use the same current product source:

- One worker, uncached HTML: 32 page requests and 50 script requests.
- Four workers, uncached HTML: the same 82 requests.
- Four workers, cached HTML: 50 script requests, using the 32 supplied HTML bodies.

This compares worker/cache configurations, not releases. JS candidate extraction is measured separately from subsequent DNS validation and general HTTP enrichment. Cached results assume the scanner already obtained complete HTML; they do not include the cost of populating that cache. The server validates every requested path and counts overlapping service delays to check the worker bound.

## Measurement protocol

- Healthy/loss DNS scenarios: five measured runs per binary after one discarded warm-up per scenario and binary.
- Delayed/outage DNS scenarios: three measured runs per binary, all reported; no discarded warm-up.
- DNS binaries run in pairs; current/baseline order reverses on alternating repetitions.
- Each JS configuration: five measured runs after one discarded warm-up.
- Results show medians and minimum/maximum, rather than percentile estimates from small samples. Every individual measured run is retained in JSON.
- A failed validation aborts the series. The runner requires normal Python assertions, matching Release flags and unsanitized binaries.
- Timing covers process launch through exit, including startup and scanner exports. Both scanner versions run serially, with no concurrent compilation or competing benchmark processes intentionally started by the runner.
- Memory is the child's `/proc/PID/status` `VmHWM`, sampled every 2 ms after `exec`, in KiB. It is an observed high-water mark and can miss a peak in the final sampling interval. It excludes the running fixture process. OS `wait4` lifetime RSS is retained separately in JSON because inherited pre-exec Python memory makes it unsuitable as the scanner-RAM headline.

Loopback DNS throughput can be limited by the fixture and host scheduling. Internet DNS latency, resolver rate limits, passive-source availability, HTTP/TLS responses, wildcard behavior and wordlist size can substantially change a real deep scan. These measurements do not establish a universal deep-scan duration or compare other tools.

## Reproduce

Use the commit containing this report for the benchmark checkout. Use an ordinary Linux user and the dependencies from the repository's [build instructions](../../README.md#build-locally). Python 3 and CMake testing support are required. Fixtures do not need privileged ports or root.

Build the current source and optional JS harness:

```sh
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build-bench --parallel 2
cmake --build build-bench --target subdomain_js_benchmark --parallel 2
ctest --test-dir build-bench --output-on-failure
```

Build the two measured product revisions in separate checkouts, choosing worktree paths that do not already exist:

```sh
git worktree add --detach /tmp/dark-nexus-benchmark-baseline 51539803714ab24bb4aed083eb941119480d2fc2
cmake -S /tmp/dark-nexus-benchmark-baseline -B /tmp/dark-nexus-benchmark-baseline-build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build /tmp/dark-nexus-benchmark-baseline-build --parallel 2
git worktree add --detach /tmp/dark-nexus-benchmark-current 8d5a9109aa144f35c8d19b029b2f071b90536ffa
cmake -S /tmp/dark-nexus-benchmark-current -B /tmp/dark-nexus-benchmark-current-build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build /tmp/dark-nexus-benchmark-current-build --parallel 2
```

Run the complete repeated comparison from the repository root:

```sh
python3 tests/subdomain_benchmark.py \
  --binary /tmp/dark-nexus-benchmark-current-build/dark_nexus \
  --baseline /tmp/dark-nexus-benchmark-baseline-build/dark_nexus \
  --js-binary ./build-bench/subdomain_js_benchmark \
  --current-revision 8d5a9109aa144f35c8d19b029b2f071b90536ffa \
  --baseline-revision 51539803714ab24bb4aed083eb941119480d2fc2 \
  --output /tmp/subdomain-benchmark.json
```

The stress cases take about fifteen minutes together on the reported machine. `--quick-repetitions`, `--stress-repetitions` and `--js-repetitions` change the sample counts. A short smoke test is useful for checking the harness but should not replace the repeated protocol when reporting performance.

The JS harness is built from this benchmark checkout and uses the current product-stage code described above. If benchmarking a different product commit, update the source checkout and `--current-revision` together. The JSON records binary hashes, harness source hashes, build flags and host/toolchain details.

CI builds the optional harness and runs short DNS/JS fixture checks on Ubuntu, Arch Linux and Fedora. CI timings are not used for the performance claims in this report.
