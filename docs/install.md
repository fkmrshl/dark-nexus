# Installation

Install or update:

```sh
curl -fsSLm120 https://raw.githubusercontent.com/fkmrshl/dark-nexus/main/install.sh | sudo bash
dark-nexus --help
```

The bootstrap download has a 120-second limit. The installer displays actual package-manager, download and compiler output, with a separate time limit for each operation. It never presents an estimated percentage as download progress.

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
- Each optional Python OSINT package: 300 seconds, with bounded pip network retries.

A failed operation names the failed step, returns a nonzero status, and prints the log location. Never delete a package-manager lock while another package operation is running; let it finish and retry. The installer cleans up only its own temporary build directory. It does not remove the user's checkout or old helper environments.

The main executable is staged and version-checked before replacing an existing installation. Optional helper packages are attempted afterwards, reuse the managed virtual environment, and preserve unrelated executables already installed under the same helper names. Some helper packages may be incompatible with the system Python version; they are skipped with a warning.

## Options

From a checkout:

```sh
sudo bash install.sh --help
sudo bash install.sh --skip-helpers
```

`--skip-helpers` installs the core toolkit and its dependencies without optional OSINT Python/Go tools. The core installation still includes the DNS wordlist.

With dependencies already installed, build into a user-owned directory without running a package manager:

```sh
bash install.sh --skip-deps --skip-helpers --prefix "$HOME/.local" --source "$PWD"
"$HOME/.local/bin/dark-nexus" --help
```

`--source DIR` builds a local checkout; otherwise the installer uses its adjacent checkout if present, or downloads the repository. A custom prefix stores the wordlist under `PREFIX/share/wordlists/dark-nexus/`; pass its path with the subdomain module's `--wordlist` option. The normal system installation uses the default `/usr/share/wordlists/dark-nexus/` path.

## Verification

`python3 tests/installer_tests.py` tests package selection, blocked/failing package managers, timeouts, child-process cleanup, piped-script startup and preservation of an existing executable. It uses fake package/build commands and temporary install directories; no root privileges, package installation or external scans are involved. These checks also run through CTest when Python is available.

See [README](../README.md#install) for manual source-build commands and the [CLI reference](cli.md) for module usage.
