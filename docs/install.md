# Installation

Install or update:

```sh
curl -fsSLm120 https://raw.githubusercontent.com/fkmrshl/dark-nexus/main/install.sh | sudo bash
dark-nexus --help
```

The command installs missing dependencies, downloads source, configures CMake, compiles and installs the executable, and installs the DNS wordlist. After successful completion, run `dark-nexus --help`; no manual compilation is needed. Network access, runtime helpers and raw socket permissions still depend on the selected module.

The bootstrap download has a 120-second limit. In a terminal the installer shows a compact two-line progress panel across five stages: dependencies, source, configuration, compilation and installation. It displays a current-operation indicator, elapsed time and the latest activity. Compilation includes Ninja's real completed/total task count. The bar represents completed stages and known compilation work, rather than an estimate of remaining time or download bytes. Unknown-size downloads use an animated indicator without an invented percentage.

UTF-8 terminals use a thin cyan bar; other locales use ASCII. `NO_COLOR` disables colors. Pipes, `TERM=dumb` and CI without a terminal receive plain live output. Full command output is always saved to the printed log path, and failures show recent log lines. The cursor is restored on completion, failure or cancellation.

## Previously stopped at 17%

The old animation capped its first step at 17% while the package manager ran with its output hidden. On Arch/CachyOS that step also performed a full `pacman -Syu`, so downloading repository databases or updating unrelated packages could leave the display at 17% for a long time.

The installer now checks installed packages and installs only missing dependencies. On Arch/CachyOS it uses `pacman -S --needed --noconfirm` with the existing package databases. It does not automatically upgrade the OS or refresh only the databases. If the databases or mirrors are stale, finish a normal `sudo pacman -Syu` yourself and then rerun the installation command. A broken or unreachable system mirror must be fixed in the system's package-manager configuration.

## Logs and failures

The installer prints a unique `/tmp/dark-nexus-install.<id>.log` path at startup and on failure. Terminal output is also saved there. Logs created by a root installation can be read with `sudo tail -n 80 <printed-log-path>`.

- Bootstrap/source download: 120/300 seconds.
- Debian repository refresh: 300 seconds; network requests have 30-second timeouts and one retry.
- Package installation: 1,200 seconds. Debian package-lock waiting is limited to 60 seconds. Arch refuses to start if another package operation holds its lock.
- CMake configuration and dependency download: 900 seconds.
- Compilation: 3,600 seconds, with up to two workers by default depending on available RAM. `DARK_NEXUS_JOBS=1` selects one worker when running the local script.

A failed operation names the failed step, returns a nonzero status, and prints the log location. Never delete a package-manager lock while another package operation is running; let it finish and retry. The installer cleans up only its own temporary build directory. It does not remove the user's checkout or old helper environments.

The main executable is staged and version-checked before replacing an existing installation. Installation provisions the application, its network dependencies and DNS wordlist. It does not install Python/Go packages or create language environments; existing unrelated tools and environments are left in place.

## Options

From a checkout:

```sh
sudo bash install.sh --help
sudo bash install.sh --no-progress
```

`--skip-helpers` remains accepted as a compatibility no-op for older automation.

`--no-progress` shows all live command output instead of the terminal panel. `DARK_NEXUS_PROGRESS=0` also disables animation when running the local script.

With dependencies already installed, build into a user-owned directory without running a package manager:

```sh
bash install.sh --skip-deps --prefix "$HOME/.local" --source "$PWD"
"$HOME/.local/bin/dark-nexus" --help
```

`--source DIR` builds a local checkout; otherwise the installer uses its adjacent checkout if present, or downloads the repository. A custom prefix stores the wordlist under `PREFIX/share/wordlists/dark-nexus/`; pass its path with the subdomain module's `--wordlist` option. The normal system installation uses the default `/usr/share/wordlists/dark-nexus/` path.

## Verification

`python3 tests/installer_tests.py` tests package selection, blocked/failing package managers, timeouts, child-process cleanup, piped-script startup, absence of language-package installation and preservation of existing executables and unrelated files. Pseudo-terminal checks cover five-stage completion, compilation counts, narrow terminals, plain/color-free modes, log preservation and cursor restoration on failure or cancellation. It uses fake package/build commands and temporary install directories; no root privileges, package installation or external scans are involved. These checks also run through CTest when Python is available.

See [README](../README.md#install) for manual source-build commands and the [CLI reference](cli.md) for module usage.
