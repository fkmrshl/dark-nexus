# Subdomain Scanner changes for v2.1

Release version: **2.1.0 (v2.1)**. CMake, `--version` and doctor text/JSON use the same release number. The initial hardening release was published as commit `51539803714ab24bb4aed083eb941119480d2fc2`. Subsequent DNS scheduling corrections and their validation are described in [DNS degradation follow-up](subdomain-dns-degradation.md). Updating an installed executable requires installing the updated source.

Source baseline was refreshed to `c97eaf22c41b80bd37566d56c70f6a88f8892161` from GitHub `main` on 2026-10-30. Its only difference from the original audit baseline `2274da1` is a README edit. The scanner changes below describe that initial v2.1 release; the linked follow-up supersedes its fixed DNS batch deadlines and retry details.

## DNS recovery

- Default active candidate-query limits are 256 in fast mode and 512 in deep mode. These limits cover A and AAAA together and bound concurrency rather than queries per second.
- Temporary errors receive one bounded retry by default, with lower concurrency, a longer query timeout and shifted resolver order. Previously successful address families are preserved.
- Candidate batches adapt their concurrency to temporary failures. `--dns-concurrency`, `--dns-retries` and `--dns-timeout` expose the relevant controls.
- Remaining failures produce an aggregate diagnostic, with separate partial and empty observations and retry/recovery counters.

## HTTP observations

- Received HTTP status survives an incomplete body, timeout or capture limit. Header completeness, body completeness and transport failures are reported separately.
- Target probes retain at most 50000 body bytes; verified API/JS downloads retain at most 1 MiB. Incomplete responses do not become passive or JavaScript evidence.
- HTTPS/HTTP attempt history is retained. A received HTTPS status does not trigger an HTTP fallback merely because its body is incomplete.
- Proxy CONNECT headers and chunked trailers do not replace origin metadata. Status 101 is retained. Client handles use RAII, and User-Agent RNG state is thread-local.

## DNS/HTTP consistency and wildcard uncertainty

- HTTP enrichment is pinned to the scanner's observed IPv4/IPv6 set. The original hostname still controls Host, SNI and TLS certificate verification; HTTPS and HTTP fallback share the same addresses. JSON/CSV/checkpoint observations retain `primary_ip` and `dns_pinned`.
- Pinned target probes connect directly and ignore proxy environment settings. API, DoH and uncached JS requests retain their own HTTP behavior. Invalid address sets and numeric-host pinning are rejected before connecting. Enrichment samples the selected peer; it does not test every DNS address.
- Wildcard probes now use configured retries for temporary failures, preserve successful families, and account for queued queries in a bounded five-to-30-second batch deadline. Completed positive wildcard evidence is never erased by a retry. Exhausted or inconsistent probes leave the scope uncertain.
- Native wildcard results do not certify another DoH provider's DNS view. DoH-only observations remain `uncertain` candidates and receive no enrichment or generated follow-ups. A later successful native lookup in a clear scope can promote the name, replacing the DoH addresses before enrichment. Partial native observations retain the successful family and report the missing family without merging another DNS view.
- A DNS observation can legitimately have HTTP 404, a redirect, or a failed HTTP connection. These are reported as separate DNS and HTTP evidence, rather than a claim that every found hostname is a working website.

The address binding uses [libcurl resolve entries](https://curl.se/libcurl/c/CURLOPT_RESOLVE.html); TLS checks remain enabled.

## Consistent exports

- Automatic JSON and CSV use the common CLI schema and final run metadata, including partial, failed and cancelled runs.
- JSON separates `subdomains` and `subdomain_candidates`, with `subdomain_counts` identifying their sizes. Rows preserve stack, DoH provider, HTTP observations and discovery tags.
- JS and permutation discoveries are distinct from wordlist discoveries. Repeated JS observations add provenance without redoing a successful DNS lookup.
- Running checkpoints use the common rows with `status: running`; final checkpoints add `checkpoint.final: true` to the final report.
- Writes replace files atomically. Export failures propagate into remaining writable reports. Compatible requested automatic paths are coalesced; incompatible formats are rejected before scanning.

The previous automatic JSON array, flat module CSV and checkpoint `results` layout are no longer written. See [migration details](cli.md#subdomains).

## Bounded JavaScript discovery

- Pages and scripts use a pool of four workers by default, configurable with `--js-workers 1..8`.
- A shared monotonic budget defaults to 30 seconds, configurable with `--js-budget 1..300`. Requests are limited by the remaining budget and a five-second per-request timeout. Reaching the JS budget does not cancel the whole scan.
- Complete useful HTML from enrichment is reused. The per-run cache is bounded by 64 entries and 2 MiB; individual enrichment captures remain bounded at 50000 bytes.
- Targets retain the successful HTTP/HTTPS scheme. Cached HTML and successful pages are prioritized; 404 and other unsuitable enrichment responses do not occupy JS target slots.
- Discovery processes up to 32 useful pages, with a separate budget of 64 page attempts, up to 50 unique script URLs and up to 5000 candidate names. Internal callers cannot exceed these ceilings. These limits are independent of the subsequent DNS verification stage.
- Redirects are followed manually, at most three hops, with scope, scheme, credential and loop checks before every request. Relative script links use the final page URL. Foreign redirects are skipped.
- Progress reports page attempts, processed pages, cache reuse, scripts and candidate counts. Budget and scope limits produce bounded diagnostics.

## Validation

Tests live in `tests/`, including transport loopback fixtures, the scan pipeline harness, report serialization and synthetic JS concurrency/deadline checks. See [validation instructions](validation.md).

Local JS-stage validation on 2026-10-30 passed all nine selected CTest suites: CLI parser/integration, DNS engine, subdomain sources, report output, HTTP transport, scan pipeline, JS discovery and subdomain CLI integration. ASan/UBSan with leak detection passed HTTP, pipeline and JS checks; after the final discovery-ceiling adjustment, pipeline and JS passed again. TSan passed pipeline and JS after the final adjustment. The pipeline suite exercised 41 cases and subdomain CLI integration exercised 19 cases. Independent code review reported no remaining findings for this stage. These results cover local fixtures, not public-target performance or distribution CI.

All five implementation stages and local regression validation completed on 2026-11-02:

| Check | Result |
| --- | --- |
| Full CTest suite | 19/19 passed |
| ASan/UBSan with leak detection: DNS, reports, HTTP, pipeline, JS | 5/5 passed |
| TSan: DNS, pipeline, JS | 3/3 passed |
| Application `--version` and doctor integration | 2.1.0 verified |
| Independent networking review | No remaining findings |

The pipeline suite covers 46 cases; HTTP transport covers 37 process checks, and DNS engine covers 40 loopback checks. The ordinary build emitted no warnings. Sanitizer builds with `-Wconversion` still report existing conversions in `include/traceroute.hpp`, legacy DNS engine timeout code and DNS fixture size conversions; no sanitizer failures were reported. These checks do not establish public-target coverage or performance, and distribution CI has not run for these local changes.

The verified application is `/tmp/dark-nexus-final-build/dark_nexus`; this temporary build does not update the system installation. Changes remain local, without a commit, push or published release.
