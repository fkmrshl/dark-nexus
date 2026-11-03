# DNS degradation follow-up

## Problem and scope

A supplied deep-scan checkpoint recorded 51 minutes 45 seconds and 322,516 incomplete candidate checks. Those are operational failures, not evidence that those names do not exist. The checkpoint did not record individual stage durations, actual adaptive concurrency, or queued-versus-submitted query counts; it cannot establish the exact cause of every minute of that run.

Code inspection exposed a reproducible starvation mechanism: a fixed 10,000-name input batch retained a 30-second deadline while adaptive concurrency could fall to 16. Queued queries could expire before submission, then feed the same failure ratio that reduced concurrency again. Retrying the full candidate also repeated a successful address family. In c-ares 1.28.1, `tries=1` permits an attempt at each configured server, so a four-server channel could further multiply waiting beyond the explicit retry budget.

This follow-up changes DNS scheduling and diagnostics. Existing HTTP status preservation, address pinning, wildcard classification, bounded JS inspection, and canonical exports remain covered by the regression suite. A reachable HTTP service returning 404 is still a valid DNS observation. This work does not turn a timeout into NXDOMAIN or guarantee a particular duration for an Internet scan.

## Scheduling and retries

- The input buffer remains bounded at 10,000 names; it is not the number submitted to one engine call.
- Candidate and wildcard calls use `min(10000, concurrency * floor(5000 / timeout_ms) / 2)` names. Valid CLI limits make this at least eight names. This allocates at most five seconds of worst-case A/AAAA query waves.
- The call deadline is twice the estimated wave time plus one second, capped at 30 seconds. Scheduling slack is a guard rather than a real-time guarantee under machine overload.
- Retries are split again using their own concurrency and longer timeout. Only retryable families are submitted; completed A, AAAA, NXDOMAIN and NODATA results survive the retry.
- Checked pipeline calls use one resolver per channel. Resolver rotation changes the assignment on subsequent calls. Legacy `resolve_aaaa` and `run_ares_batch` retain their previous four-server fallback through the private implementation.
- Actual temporary failures affecting at least 5% of candidate names halve concurrency, with a floor of 16. A completely successful slice raises it by 64 toward the configured maximum. Local queue deadline expiry does not count as a resolver failure. Retry concurrency is the current limit capped at 256.
- Progress is printed between DNS slices. Checkpoint updates are considered there too, subject to the existing 60-second interval, even if DNS counters advance without new positive discoveries.

Three consecutive candidate slices with at least eight names and at least 95% failed, addressless checks after retries stop further discovery. Reports contain an explicit stop reason and retain already collected observations. Existing enrichment is drained normally. Run status becomes `partial` if observations exist, otherwise `failed`; cancellation remains `cancelled`. Unread wordlist entries are not reported as nonexistent or counted as checked.

This guard means sustained incomplete addressless observations, not proof that every resolver or both address families are unavailable. For example, a successful negative A answer with a failed AAAA query is still incomplete and addressless. A successful negative pair resets the failure streak, as does a sufficiently recovered slice. Positive partial-family observations are retained and do not count toward this addressless threshold. Optional passive APIs, DoH and HTTP work have their own timeouts; the guard is not a whole-scan deadline.

## Canonical report diagnostics

JSON, automatic reports, checkpoints and CSV metadata contain `subdomain_dns`. Old schema 3.0 reports without this additive object remain readable with zero/default values. `tool_version` now correctly identifies `dark-nexus/2.1.0` instead of the stale `dark-nexus/2.0` default.

| Field | Meaning |
| --- | --- |
| `candidate_checks` | Candidate observations processed, including repeated names across discovery stages; excludes wildcard probes |
| `incomplete_checks`, `partial_checks` | Failed observations after retries; partial means an address was retained; measured before DoH fallback |
| `retry_checks`, `recovered_checks` | Candidate retry attempts and checks completed by retry |
| `submitted_queries` | A/AAAA operations submitted to c-ares across initial and retry calls; not an exact packet counter |
| `unattempted_queries` | Selected operations whose call deadline expired while they were still queued |
| `deadline_queries` | Selected operations unfinished at the call deadline, including the queued subset |
| `temporary_failures` | Submitted operations with retryable failures, excluding call-deadline expiry |
| `batches`, `retry_batches` | Actual checked calls, separately for initial work and retries |
| `elapsed_ms` | Sum of candidate DNS call wall times; excludes wildcard probes, retry backoff, DoH, HTTP and passive/JS discovery |
| `concurrency_initial`, `concurrency_min`, `concurrency_final` | Adaptive primary-query limits; retry limits may differ |
| `stopped_early`, `stop_reason` | Explicit sustained-failure stop; distinct from user cancellation |

Operation counters are cumulative and may count multiple attempts at one family. `unattempted_queries` is a subset of `deadline_queries`; neither is a count of nonexistent names. Cancellation and initialization failures are not labeled as deadline expiry.

## Reproduction

The standalone benchmark is `tests/dns_degradation_benchmark.py`. It starts a local UDP DNS fixture and a non-forwarding loopback HTTP proxy. Queries for the fixture domain stay local, and optional passive HTTP requests are rejected by the proxy. HTTP enrichment and permutations are disabled to isolate candidate scheduling. Each healthy/delayed/loss case includes a known dual-stack name at the very end of the wordlist.

Run as an unprivileged user after building:

```sh
python3 tests/dns_degradation_benchmark.py build/dark_nexus --output /tmp/dns-fixed.json
python3 tests/dns_degradation_benchmark.py /path/to/baseline/dark_nexus --legacy --output /tmp/dns-baseline.json
```

The default cases are: 10,000 names with immediate answers; 10,000 names at concurrency 16 with 80 ms reply delay; 1,000 names with deterministic first-attempt AAAA losses; and 10,000 names with all candidate replies dropped. Health and wildcard probes still answer in the outage case so it exercises discovery-time failure. The baseline is commit `51539803714ab24bb4aed083eb941119480d2fc2`.

The delayed case deliberately exceeds the old 30-second queue deadline. It can take longer when corrected because it actually checks the remaining names. Compare coverage and the known tail observation together with duration. Single runs are recorded individually; they are not medians or percentile estimates.

## Validation results

Measured on CachyOS, Linux 7.3.0-4, with the ordinary CMake app target (`-O2`). Public CPU label supplied by the owner after measurement: Intel Core i5-13500HX; this label is not independently verified benchmark hardware metadata. Baseline and corrected runs were serial, one measured run per case. Process startup and automatic exports are included; local proxy rejection replaces passive-provider latency. This is a deterministic local stress comparison, not a public-domain scan benchmark.

| Scenario | Baseline seconds | Corrected seconds | Baseline unique A/AAAA queries | Corrected unique A/AAAA queries | Known tail record |
| --- | ---: | ---: | ---: | ---: | --- |
| Immediate replies, 10,000 names | 0.160 | 0.157 | 20,000 / 20,000 | 20,000 / 20,000 | Found by both |
| 80 ms replies, concurrency 16, 10,000 names | 60.179 | 101.578 | 11,856 / 20,000 | 20,000 / 20,000 | Missed by baseline; found after correction |
| First AAAA reply lost for every seventh name, 1,000 names | 0.932 | 0.795 | 2,000 / 2,000 | 2,000 / 2,000 | Found by both |
| All candidate replies dropped, 10,000 names | 60.186 | 45.589 | 4,768 / 20,000 | 2,400 / 20,000 | Unavailable; corrected run stops explicitly |

The delayed baseline reported 4,080 incomplete candidate checks and failed to reach the known tail record. The corrected run completed all 10,000 checks without retries or deadline expiry. Its longer duration reflects the work the baseline left unfinished.

For the loss case, the baseline sent 2,286 candidate query packets; the correction sent 2,143. All 143 lost AAAA observations recovered without repeating successful A queries. The corrected outage run stopped after 1,200 failed candidate checks, preserving a clear stop reason instead of consuming the rest of the dictionary. It did not claim the remaining 8,800 names were checked. Every corrected case recorded zero unsubmitted deadline expirations and zero call-deadline expirations.

Binary SHA-256 for reproducibility:

- Baseline: `a3b1cccbbd856885f8a80a89895e3984d1c1fad5e3ecaa81b21f3adecbbe4ad7`
- Corrected: `72b48b86de854a47e32bf0c3b4726d1301dd8c9cb7f7a054ca2670b5100fb3b2`

The driver checks canonical JSON against automatic JSON and the final checkpoint on every run. Regression tests additionally cover selective retries, legacy resolver failover, cancellation, outage recovery, successful negative answers, queue-expiry classification, progress checkpoints with no positive rows, and backward-compatible report decoding.

Final verification:

- Normal app/test build and full CTest suite: **19/19 passed** (51.73 seconds).
- ASan + UBSan full build and targeted `dns_engine`, `report_output`, `subdomain_http`, `subdomain_pipeline`, `subdomain_js`: **5/5 passed** (29.24 seconds), leak detection and halt-on-error enabled.
- TSan full build and targeted `dns_engine`, `subdomain_pipeline`, `subdomain_js`: **3/3 passed** (23.41 seconds), halt-on-error enabled.
- The pipeline suite contains 49 scenarios; the real CLI loopback suite contains 21 tests.
- Independent network/concurrency review reported no remaining blocking findings.

Compiler diagnostics remain in pre-existing numeric conversions and GCC/libstdc++ regex code; these builds are not claimed to be warning-free. No sanitizer error was reported. These local fixtures verify bounded recovery and reporting; they do not predict a fixed duration for a real Internet deep scan.
