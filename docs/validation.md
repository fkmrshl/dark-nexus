# Build and installation checks

The [Linux workflow](../.github/workflows/build.yml) builds the project in Ubuntu 24.04, Arch Linux and Fedora 43 containers on GitHub Actions. It runs on pushes to `main`, pull requests and manual dispatch. Each job has a 40-minute limit; failed checks fail the job.

Packages are installed as root only inside disposable CI containers. An ordinary user then configures a Release build, compiles the application and runs every CTest suite, including parser, installer, report and local diagnostic checks. Tests use local fixtures and fake network helpers. They do not scan public targets.

Each job also builds and installs the project from source into a temporary prefix using `--skip-deps`, checks the installed version and help, runs `doctor`, and verifies the installed wordlist. This exercises compilation and installation without changing the runner's system installation. The installer does not provision language-package environments or additional tools.

DNS/WHOIS checks use fake `dig` and `whois` programs, including fake PTR answers; no real resolver or registry is queried. They exercise positive/negative DNS responses, malformed replies, CNAME correlation, unsafe SPF references, transfer framing, WHOIS exports, limits and cancellation. These are syntax and behavior checks, not universal resource-record, policy or cryptographic validation. Process-supervisor checks cover closed output streams, continuous output, cancellation, capture limits, concurrent helpers and cleanup of descendants that remain in the helper's process group.

Container results establish whether the project builds and passes these checks in those environments. They do not establish live external-service availability, raw-socket access on every host, or successful package-manager installation on every distribution. See the actual workflow run for results; defining a matrix does not mean its jobs have passed.

Subdomain checks use local DNS/HTTP fixtures and a pipeline harness with replaced network dependencies. They cover IPv6-only names, negative answers versus resolver failures, candidate boundaries, cancellation under queue pressure, worker exceptions, rotating wildcard replies, parent-scope checks, separated review candidates, partial reports and atomic module-file writes. DNS recovery checks exercise real timeout/retry behavior, disabled and exhausted retry budgets, lower retry concurrency, longer retry timeouts, preservation of a previously successful address family, exact A/AAAA concurrency limits and aggregate errors across batches. HTTP checks preserve observed status on capture limits and timeouts, distinguish header/body completeness, enforce decoded-body and header caps, exercise interim responses and HEAD, record HTTPS/HTTP attempt history, and reject partial JS/API evidence. TLS tests retain certificate verification; the HTTP fixture alone can load a temporary local test CA through a linker wrapper. Pipeline checks preserve HTTP diagnostics in module files, checkpoints and common reports. A wordlist fixture crosses the 10000-candidate batch boundary and verifies its final sentinel is resolved. Feature fixtures count HTTP, CNAME, technology/WAF, JavaScript and service-hint calls independently. Presentation checks retain every address in exports while compacting terminal output. CLI checks exercise automatic external selection in deep, the built-in list in fast, explicit brute-force and passive-only selection, conflicting stage flags and module scope. These checks do not contact passive providers or public resolvers.

Export checks compare automatic JSON and CSV against the common CLI output, including partial, failed, wildcard and cancelled runs. Final checkpoints match the canonical report apart from checkpoint metadata; in-progress snapshots remain `running`. Fixtures verify merged discovery tags, JS attribution without false DoH metadata, preserved stack data, legacy common-report defaults, export-failure propagation, and safe handling of requested paths that overlap automatic files.

The `subdomain_js` C++ suite uses synthetic request responses to verify actual overlapping requests, worker limits, cache reuse, HTTP-only targets, separate page-attempt limits, scoped redirects, loops, relative script bases, partial-response rejection, candidate caps and cancellation. Oversized internal options cannot exceed the page, attempt, script, candidate or redirect ceilings. Transport loopback checks cover an expired deadline without a request and in-flight expiry without setting global scan cancellation. Pipeline checks verify HTML reuse and that the successful HTTP scheme reaches script discovery. These tests measure fixture behavior; they do not benchmark external targets. See [the v2.1 change notes](Subdomain%20Scanner%20v2.1.md) for the cumulative scope.

Final consistency fixtures verify DNS-address binding across HTTPS/HTTP fallback, Host and TLS hostname preservation, selected-peer export, IPv6-only targets, multiple-address fallback, invalid address rejection and proxy behavior. Wildcard fixtures exercise disabled/exhausted/two-step retries, preservation of completed families and positive evidence, and queued-query deadlines. A DoH observation remains uncertain under a native clear scope and does not trigger enrichment. Later native recovery moves the row to confirmed results without mixing addresses or corrupting indices of remaining candidates. Legacy report observations without the new peer fields retain defaults.

To run the same application checks locally after installing build dependencies:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
./build/dark_nexus doctor
./build/dark_nexus doctor --json -
```

The diagnostic command returns `1` when core runtime helpers are missing, even if compilation and the offline tests succeeded. It prints the affected workflows and suggested remedies. A missing external wordlist and unavailable raw capabilities are warnings. See the [diagnostic contract](cli.md#local-diagnostics).

## Subdomain sanitizer checks

The v2.1 local validation used separate builds so sanitizer flags do not affect the ordinary executable. Run from the repository root with the same build dependencies:

```sh
cmake -S . -B build-asan -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -Wall -Wextra -Wconversion" \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan --parallel 2 --target dns_engine_tests output_tests subdomain_http_fixture subdomain_integration_fixture subdomain_js_tests
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-asan --output-on-failure -R '^(dns_engine|report_output|subdomain_http|subdomain_pipeline|subdomain_js)$'
```

```sh
cmake -S . -B build-tsan -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=thread -fno-omit-frame-pointer -g -Wall -Wextra -Wconversion" \
  -DCMAKE_C_FLAGS="-fsanitize=thread -fno-omit-frame-pointer -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=thread"
cmake --build build-tsan --parallel 2 --target dns_engine_tests subdomain_integration_fixture subdomain_js_tests
ctest --test-dir build-tsan --output-on-failure -R '^(dns_engine|subdomain_pipeline|subdomain_js)$'
```

Loopback socket access is required. LeakSanitizer and ThreadSanitizer also require a compatible runtime environment; a sandbox or ptrace restriction must be distinguished from a program failure. Known existing conversion warnings and the final test counts are recorded in [the v2.1 change notes](Subdomain%20Scanner%20v2.1.md).
