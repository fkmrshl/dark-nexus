# Build and installation checks

The [Linux workflow](../.github/workflows/build.yml) builds the project in Ubuntu 24.04, Arch Linux and Fedora 43 containers on GitHub Actions. It runs on pushes to `main`, pull requests and manual dispatch. Each job has a 40-minute limit; failed checks fail the job.

Packages are installed as root only inside disposable CI containers. An ordinary user then configures a Release build, compiles the application and runs every CTest suite, including parser, installer, report and local diagnostic checks. Tests use local fixtures and fake network helpers. They do not scan public targets.

Each job also builds and installs the project from source into a temporary prefix using `--skip-deps`, checks the installed version and help, runs `doctor`, and verifies the installed wordlist. This exercises compilation and installation without changing the runner's system installation. The installer does not provision language-package environments or additional tools.

DNS/WHOIS checks use fake `dig` and `whois` programs, including fake PTR answers; no real resolver or registry is queried. They exercise positive/negative DNS responses, malformed replies, CNAME correlation, unsafe SPF references, transfer framing, WHOIS exports, limits and cancellation. These are syntax and behavior checks, not universal resource-record, policy or cryptographic validation. Process-supervisor checks cover closed output streams, continuous output, cancellation, capture limits, concurrent helpers and cleanup of descendants that remain in the helper's process group.

Container results establish whether the project builds and passes these checks in those environments. They do not establish live external-service availability, raw-socket access on every host, or successful package-manager installation on every distribution. See the actual workflow run for results; defining a matrix does not mean its jobs have passed.

Subdomain checks use local DNS/HTTP fixtures and a pipeline harness with replaced network dependencies. They cover IPv6-only names, negative answers versus resolver failures, candidate boundaries, cancellation under queue pressure, worker exceptions, rotating wildcard replies, parent-scope checks, separated review candidates, partial reports and atomic module-file writes. A wordlist fixture crosses the 10000-candidate batch boundary and verifies its final sentinel is resolved. Feature fixtures count HTTP, CNAME, technology/WAF, JavaScript and service-hint calls independently. Presentation checks retain every address in exports while compacting terminal output. CLI checks exercise automatic external selection in deep, the built-in list in fast, explicit brute-force and passive-only selection, conflicting stage flags and module scope. These checks do not contact passive providers or public resolvers.

To run the same application checks locally after installing build dependencies:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
./build/dark_nexus doctor
./build/dark_nexus doctor --json -
```

The diagnostic command returns `1` when core runtime helpers are missing, even if compilation and the offline tests succeeded. It prints the affected workflows and suggested remedies. A missing external wordlist and unavailable raw capabilities are warnings. See the [diagnostic contract](cli.md#local-diagnostics).
