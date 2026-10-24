# Build and installation checks

The [Linux workflow](../.github/workflows/build.yml) builds the project in Ubuntu 24.04, Arch Linux and Fedora 43 containers on GitHub Actions. It runs on pushes to `main`, pull requests and manual dispatch. Each job has a 40-minute limit; failed checks fail the job.

Packages are installed as root only inside disposable CI containers. An ordinary user then configures a Release build, compiles the application and runs every CTest suite, including parser, installer, report and local diagnostic checks. Tests use local fixtures and fake network helpers. They do not scan public targets.

Each job also builds and installs the project from source into a temporary prefix using `--skip-deps --skip-helpers`, checks the installed version and help, runs `doctor`, and verifies the installed wordlist. This exercises compilation and installation without changing the runner's system installation. Optional OSINT helpers are not installed or executed.

Container results establish whether the project builds and passes these checks in those environments. They do not establish live external-service availability, raw-socket access on every host, or successful package-manager installation on every distribution. See the actual workflow run for results; defining a matrix does not mean its jobs have passed.

To run the same application checks locally after installing build dependencies:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
./build/dark_nexus doctor
./build/dark_nexus doctor --json -
```

The diagnostic command returns `1` when core runtime helpers are missing, even if compilation and the offline tests succeeded. It prints the affected workflows and suggested remedies. Optional helpers, a missing external wordlist and unavailable raw capabilities are warnings. See the [diagnostic contract](cli.md#local-diagnostics).
