#!/usr/bin/env bash
# Sourceable for regression tests; no system changes happen until dnx_main runs.

set -Eeuo pipefail

dnx_message() { printf '%s\n' "$*"; }
dnx_warn() { printf 'Warning: %s\n' "$*" >&2; }
dnx_die() { printf 'Error: %s\n' "$1" >&2; return "${2:-1}"; }

dnx_help() {
    cat <<'HELP'
Dark Nexus installer
Usage: sudo bash install.sh [options]

  --prefix DIR    Install under DIR (default: /usr/local)
  --source DIR    Build a local checkout instead of downloading source
  --skip-deps     Use existing system dependencies; do not run a package manager
  --skip-helpers  Skip optional OSINT helpers
  -h, --help      Show this help

Download, dependency and build operations have time limits. Output is shown live
and saved to the log path printed at startup. Existing installations are replaced
only after the new binary has built and passed its version check.
HELP
}

dnx_jobs() {
    local cpus memory jobs
    if [[ -n "${DARK_NEXUS_JOBS:-}" ]]; then
        [[ "$DARK_NEXUS_JOBS" =~ ^[1-9][0-9]{0,2}$ ]] && (( DARK_NEXUS_JOBS <= 128 )) ||
            { dnx_die 'DARK_NEXUS_JOBS must be an integer from 1 to 128'; return 1; }
        printf '%s\n' "$DARK_NEXUS_JOBS"
        return
    fi
    cpus=$(nproc 2>/dev/null || printf '1')
    memory=$(awk '/MemAvailable/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)
    jobs=$(( ${memory:-1000000} / 1000000 ))
    (( jobs >= 1 )) || jobs=1
    (( jobs <= cpus )) || jobs=$cpus
    (( jobs <= 2 )) || jobs=2
    printf '%s\n' "$jobs"
}

dnx_cleanup() {
    local status=$?
    trap - EXIT
    if (( status != 0 )); then
        printf '\nInstallation failed (exit %s). Log: %s\n' "$status" "${DNX_LOG:-not created}" >&2
    fi
    if [[ -n "${DNX_PENDING_BINARY:-}" ]]; then rm -f -- "$DNX_PENDING_BINARY"; fi
    if [[ -n "${DNX_PENDING_WORDLIST:-}" ]]; then rm -f -- "$DNX_PENDING_WORDLIST"; fi
    if [[ -n "${DNX_WORK:-}" && "$DNX_WORK" == */dark-nexus-build.* && ! -L "$DNX_WORK" ]]; then
        rm -rf -- "$DNX_WORK"
    fi
    return "$status"
}

dnx_interrupt() {
    local status=$1
    trap '' INT TERM
    if [[ -n "${DNX_ACTIVE_PID:-}" ]]; then
        # timeout owns this group; never signal an unrelated package operation.
        kill -TERM -- "-$DNX_ACTIVE_PID" 2>/dev/null || kill -TERM "$DNX_ACTIVE_PID" 2>/dev/null || true
        wait "$DNX_ACTIVE_PID" 2>/dev/null || true
        DNX_ACTIVE_PID=''
    fi
    exit "$status"
}

# Keep the command PID so Ctrl-C/TERM stops its downloads before cleanup.
# The separate tee is joined as well, preserving both exit codes and all output.
dnx_run() {
    local label=$1 limit=$2 rc=0 log_rc=0 output_fd tee_pid
    shift 2
    printf '\n[%s]\n' "$label" | tee -a "$DNX_LOG" || return
    exec {output_fd}> >(tee -a "$DNX_LOG")
    tee_pid=$!
    timeout --signal=TERM --kill-after=30s "${limit}s" "$@" </dev/null >&"$output_fd" 2>&1 &
    DNX_ACTIVE_PID=$!
    wait "$DNX_ACTIVE_PID" || rc=$?
    DNX_ACTIVE_PID=''
    exec {output_fd}>&-
    wait "$tee_pid" || log_rc=$?
    (( rc != 0 )) || rc=$log_rc
    if (( rc == 124 || rc == 137 )); then
        dnx_warn "$label exceeded ${limit}s. Check the last output and network/mirror access; log: $DNX_LOG"
    elif (( rc != 0 )); then
        dnx_warn "$label failed (exit $rc); log: $DNX_LOG"
    fi
    return "$rc"
}

dnx_family() {
    local id=$1 like=${2:-}
    case " $id $like " in
        *' debian '*|*' ubuntu '*|*' kali '*) printf 'debian\n' ;;
        *' arch '*|*' cachyos '*|*' blackarch '*|*' manjaro '*|*' garuda '*) printf 'arch\n' ;;
        *' fedora '*|*' rhel '*|*' centos '*|*' rocky '*|*' almalinux '*) printf 'fedora\n' ;;
        *' opensuse '*|*' opensuse-leap '*|*' opensuse-tumbleweed '*|*' suse '*|*' sles '*) printf 'suse\n' ;;
        *) dnx_die "Unsupported distribution: $id" ;;
    esac
}

dnx_installed() {
    case "$DNX_FAMILY" in
        debian) [[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" == 'install ok installed' ]] ;;
        arch) pacman -Q "$1" >/dev/null 2>&1 ;;
        fedora|suse) rpm -q "$1" >/dev/null 2>&1 ;;
    esac
}

dnx_pacman_busy() { [[ -e /var/lib/pacman/db.lck ]]; }

dnx_packages() {
    local label=$1 package
    local -a missing=()
    shift
    for package in "$@"; do
        if ! dnx_installed "$package"; then missing+=("$package"); fi
    done
    if (( ${#missing[@]} == 0 )); then
        dnx_message "$label: dependencies already installed."
        return 0
    fi
    dnx_message "$label: installing ${missing[*]}"
    case "$DNX_FAMILY" in
        debian)
            export DEBIAN_FRONTEND=noninteractive
            local -a apt_options=(-o DPkg::Lock::Timeout=60 -o Acquire::Retries=1 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
            dnx_run 'Refresh apt metadata (up to 5 minutes)' 300 apt-get "${apt_options[@]}" update || return
            dnx_run "$label (up to 20 minutes)" 1200 apt-get "${apt_options[@]}" install -y "${missing[@]}" || return
            ;;
        arch)
            if dnx_pacman_busy; then
                dnx_die 'pacman is busy. Let the other package operation finish, then retry. Do not delete its lock file.'
                return 1
            fi
            # Use existing synchronized databases. Never launch a full OS upgrade or
            # refresh databases alone (partial Arch upgrades are unsupported).
            if ! dnx_run "$label (up to 20 minutes)" 1200 pacman -S --needed --noconfirm "${missing[@]}"; then
                dnx_warn 'If mirrors or package databases are stale, complete sudo pacman -Syu yourself, then rerun this installer.'
                return 1
            fi
            ;;
        fedora)
            local manager=dnf
            command -v dnf >/dev/null 2>&1 || manager=yum
            dnx_run "$label (up to 20 minutes)" 1200 "$manager" -y --setopt=exit_on_lock=True --setopt=timeout=30 --setopt=retries=2 install "${missing[@]}" || return
            ;;
        suse)
            dnx_run "$label (up to 20 minutes)" 1200 zypper --non-interactive install --no-recommends "${missing[@]}" || return
            ;;
    esac
}

dnx_dependencies() {
    case "$DNX_FAMILY" in
        debian) dnx_packages 'Core dependencies' build-essential cmake ninja-build pkg-config ca-certificates libssl-dev liburing-dev libcap2-bin libcap-dev git curl whois dnsutils iputils-ping ;;
        arch) dnx_packages 'Core dependencies' base-devel cmake ninja pkgconf ca-certificates openssl liburing libcap git curl whois bind iputils ;;
        fedora) dnx_packages 'Core dependencies' gcc gcc-c++ make cmake ninja-build pkgconf-pkg-config ca-certificates openssl-devel liburing-devel libcap libcap-devel git curl whois bind-utils iputils ;;
        suse) dnx_packages 'Core dependencies' gcc gcc-c++ make cmake ninja pkg-config ca-certificates libopenssl-devel liburing-devel libcap-progs libcap-devel git curl whois bind-utils iputils ;;
    esac
}

dnx_prepare_source() {
    DNX_SOURCE="$DNX_WORK/source"
    if [[ -n "$DNX_LOCAL_SOURCE" ]]; then
        [[ -f "$DNX_LOCAL_SOURCE/CMakeLists.txt" && -d "$DNX_LOCAL_SOURCE/src" && -d "$DNX_LOCAL_SOURCE/include" ]] ||
            { dnx_die "Not a project checkout: $DNX_LOCAL_SOURCE"; return 1; }
        mkdir -p "$DNX_SOURCE"
        # Copy only inputs to the application build, not old builds, nested clones,
        # credentials or unrelated files from the user's checkout.
        cp -a -- "$DNX_LOCAL_SOURCE/CMakeLists.txt" "$DNX_LOCAL_SOURCE/src" "$DNX_LOCAL_SOURCE/include" "$DNX_SOURCE/"
        if [[ -f "$DNX_LOCAL_SOURCE/best-dns-wordlist.txt" ]]; then
            cp -- "$DNX_LOCAL_SOURCE/best-dns-wordlist.txt" "$DNX_SOURCE/"
        fi
        dnx_message "Using local source: $DNX_LOCAL_SOURCE"
    else
        dnx_run 'Download source (up to 5 minutes)' 300 git clone --depth 1 https://github.com/fkmrshl/dark-nexus.git "$DNX_SOURCE" || return
    fi
}

dnx_install_binary() {
    local bin_dir="$DNX_PREFIX/bin" wordlist_dir
    if [[ "$DNX_PREFIX" == /usr/local ]]; then wordlist_dir=/usr/share/wordlists/dark-nexus
    else wordlist_dir="$DNX_PREFIX/share/wordlists/dark-nexus"; fi
    [[ -s "$DNX_SOURCE/best-dns-wordlist.txt" ]] || { dnx_die 'DNS wordlist is missing or empty'; return 1; }
    dnx_run 'Check newly built executable' 15 "$DNX_SOURCE/build/dark_nexus" --version || return
    install -d -m 755 -- "$bin_dir" "$wordlist_dir"
    DNX_PENDING_BINARY=$(mktemp "$bin_dir/.dark-nexus.XXXXXX")
    DNX_PENDING_WORDLIST=$(mktemp "$wordlist_dir/.wordlist.XXXXXX")
    install -m 755 -- "$DNX_SOURCE/build/dark_nexus" "$DNX_PENDING_BINARY"
    install -m 644 -- "$DNX_SOURCE/best-dns-wordlist.txt" "$DNX_PENDING_WORDLIST"
    if (( EUID == 0 )) && command -v setcap >/dev/null 2>&1; then
        if ! setcap cap_net_raw=eip "$DNX_PENDING_BINARY"; then
            dnx_warn 'CAP_NET_RAW could not be granted; TCP connect mode still works.'
        fi
    else
        dnx_warn 'Raw socket capabilities were not configured; TCP connect mode still works.'
    fi
    mv -f -- "$DNX_PENDING_WORDLIST" "$wordlist_dir/best-dns-wordlist.txt"
    DNX_PENDING_WORDLIST=''
    # Last operation: an existing executable stays intact if downloading/building fails.
    mv -f -- "$DNX_PENDING_BINARY" "$bin_dir/dark-nexus"
    DNX_PENDING_BINARY=''
    dnx_message "Installed: $bin_dir/dark-nexus"
    dnx_message "Wordlist: $wordlist_dir/best-dns-wordlist.txt"
}

dnx_link_helper() {
    local executable=$1 destination="$DNX_PREFIX/bin/$2" existing
    if [[ -e "$destination" || -L "$destination" ]]; then
        existing=$(readlink "$destination" 2>/dev/null || true)
        if [[ "$existing" != "$DNX_HELPERS/bin/"* ]]; then
            dnx_warn "Keeping existing $destination"
            return 0
        fi
    fi
    ln -sfn -- "$executable" "$destination"
}

dnx_helpers() {
    local entry binary package python
    if (( DNX_SKIP_HELPERS )); then dnx_message 'Optional OSINT helpers skipped.'; return 0; fi
    if (( ! DNX_SKIP_DEPS )); then
        case "$DNX_FAMILY" in
            debian) dnx_packages 'Optional Python dependencies' python3 python3-pip python3-venv || { dnx_warn 'Optional helpers skipped; Dark Nexus is already installed.'; return 0; } ;;
            arch) dnx_packages 'Optional Python dependencies' python python-pip || { dnx_warn 'Optional helpers skipped; Dark Nexus is already installed.'; return 0; } ;;
            fedora|suse) dnx_packages 'Optional Python dependencies' python3 python3-pip || { dnx_warn 'Optional helpers skipped; Dark Nexus is already installed.'; return 0; } ;;
        esac
    fi
    if ! command -v python3 >/dev/null 2>&1; then dnx_warn 'Optional Python helpers skipped: python3 is not installed.'; return 0; fi
    if [[ "$DNX_PREFIX" == /usr/local ]]; then DNX_HELPERS=/opt/dark-nexus-osint
    else DNX_HELPERS="$DNX_PREFIX/share/dark-nexus/osint-venv"; fi
    if [[ ! -x "$DNX_HELPERS/bin/python" ]]; then
        if ! dnx_run 'Create optional OSINT environment' 60 python3 -m venv "$DNX_HELPERS"; then
            dnx_warn 'Optional helpers skipped; Dark Nexus is already installed.'
            return 0
        fi
    fi
    python="$DNX_HELPERS/bin/python"
    for entry in sherlock:sherlock-project maigret:maigret holehe:holehe theHarvester:theHarvester; do
        binary=${entry%%:*}; package=${entry#*:}
        if [[ ! -x "$DNX_HELPERS/bin/$binary" ]]; then
            if ! dnx_run "Optional $binary (up to 5 minutes)" 300 "$python" -m pip install --disable-pip-version-check --no-input --retries 1 --timeout 30 "$package"; then
                dnx_warn "Optional $binary skipped; continuing."
                continue
            fi
        fi
        if [[ -x "$DNX_HELPERS/bin/$binary" ]]; then dnx_link_helper "$DNX_HELPERS/bin/$binary" "$binary" || dnx_warn "Could not link optional $binary"; fi
    done
    if command -v go >/dev/null 2>&1 && ! command -v phoneinfoga >/dev/null 2>&1 && [[ ! -e "$DNX_PREFIX/bin/phoneinfoga" && ! -L "$DNX_PREFIX/bin/phoneinfoga" ]]; then
        dnx_run 'Optional PhoneInfoga (up to 5 minutes)' 300 env GOBIN="$DNX_PREFIX/bin" go install github.com/sundowndev/phoneinfoga/v2@latest || dnx_warn 'Optional PhoneInfoga skipped.'
    fi
    return 0
}

dnx_main() {
    local script_path=${BASH_SOURCE[0]:-} family_id='' family_like='' jobs argument
    DNX_PREFIX=/usr/local
    DNX_LOCAL_SOURCE=''
    DNX_SKIP_DEPS=0
    DNX_SKIP_HELPERS=0
    DNX_WORK=''
    DNX_LOG=''
    DNX_PENDING_BINARY=''
    DNX_PENDING_WORDLIST=''
    DNX_ACTIVE_PID=''
    while (( $# )); do
        argument=$1
        case "$argument" in
            -h|--help) dnx_help; return 0 ;;
            --skip-deps) DNX_SKIP_DEPS=1 ;;
            --skip-helpers) DNX_SKIP_HELPERS=1 ;;
            --prefix|--source)
                (( $# >= 2 )) && [[ -n "$2" && "$2" != --* ]] || { dnx_die "$argument needs a value" 2; return 2; }
                if [[ "$argument" == --prefix ]]; then DNX_PREFIX=$2; else DNX_LOCAL_SOURCE=$2; fi
                shift ;;
            *) dnx_die "Unknown option: $argument" 2; return 2 ;;
        esac
        shift
    done
    [[ "$DNX_PREFIX" == /* && "$DNX_PREFIX" != / ]] || { dnx_die '--prefix must be an absolute directory other than /' 2; return 2; }
    DNX_PREFIX=$(realpath -m -- "$DNX_PREFIX")
    [[ "$DNX_PREFIX" != / ]] || { dnx_die 'Cannot use / as the install prefix' 2; return 2; }
    if (( EUID != 0 )) && { (( ! DNX_SKIP_DEPS )) || [[ "$DNX_PREFIX" == /usr/local ]]; }; then
        dnx_die 'Run with sudo, or use --skip-deps --prefix /absolute/user/directory for a local installation.'
        return 1
    fi
    command -v timeout >/dev/null 2>&1 || { dnx_die 'GNU coreutils (timeout) is required'; return 1; }
    jobs=$(dnx_jobs) || return
    if [[ -z "$DNX_LOCAL_SOURCE" && -f "$script_path" ]]; then
        local script_dir
        script_dir=$(cd -- "$(dirname -- "$script_path")" && pwd)
        if [[ -f "$script_dir/CMakeLists.txt" && -d "$script_dir/src" && -d "$script_dir/include" ]]; then DNX_LOCAL_SOURCE=$script_dir; fi
    fi
    if [[ -n "$DNX_LOCAL_SOURCE" ]]; then DNX_LOCAL_SOURCE=$(realpath -- "$DNX_LOCAL_SOURCE"); fi
    if (( ! DNX_SKIP_DEPS )); then
        # Distribution metadata is supplied by the operating system.
        if [[ ! -r /etc/os-release ]]; then dnx_die 'Cannot read /etc/os-release'; return 1; fi
        family_id=$(. /etc/os-release; printf '%s' "$ID")
        family_like=$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")
        DNX_FAMILY=$(dnx_family "$family_id" "$family_like") || return
    fi
    umask 077
    DNX_LOG=$(mktemp /tmp/dark-nexus-install.XXXXXX.log)
    DNX_WORK=$(mktemp -d /tmp/dark-nexus-build.XXXXXX)
    trap dnx_cleanup EXIT
    trap 'dnx_interrupt 130' INT
    trap 'dnx_interrupt 143' TERM
    # Package managers and helpers cannot consume the script pipe or prompt on stdin.
    exec </dev/null
    export GIT_TERMINAL_PROMPT=0
    export GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=http.lowSpeedLimit GIT_CONFIG_VALUE_0=1024 GIT_CONFIG_KEY_1=http.lowSpeedTime GIT_CONFIG_VALUE_1=60
    dnx_message "Dark Nexus installer | workers: $jobs"
    dnx_message "Log: $DNX_LOG"
    if (( ! DNX_SKIP_DEPS )); then dnx_dependencies; else dnx_message 'Using existing system dependencies.'; fi
    dnx_prepare_source
    dnx_run 'Configure build and dependencies (up to 15 minutes)' 900 cmake -S "$DNX_SOURCE" -B "$DNX_SOURCE/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DCMAKE_TLS_VERIFY=ON
    dnx_run 'Compile (up to 60 minutes)' 3600 cmake --build "$DNX_SOURCE/build" --parallel "$jobs"
    dnx_install_binary
    dnx_helpers
    printf '\nInstallation complete. Run: %s/bin/dark-nexus --help\n' "$DNX_PREFIX"
    dnx_message "Log: $DNX_LOG"
}

if [[ "${BASH_SOURCE[0]:-}" == "$0" || -z "${BASH_SOURCE[0]:-}" ]]; then
    dnx_main "$@"
fi
