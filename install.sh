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
  --skip-helpers  Accepted for compatibility; no effect
  --no-progress   Print full live output instead of the terminal progress panel
  -h, --help      Show this help

Download, dependency and build operations have time limits. A terminal shows
stage progress and recent activity; full output is saved to the printed log path.
Existing installations are replaced only after the new binary has built and
passed its version check.
HELP
}

# Only the renderer writes the animated panel. Pipes and CI keep plain logs.
dnx_ui_init() {
    DNX_UI=0 DNX_UI_UNICODE=0 DNX_UI_COLOR='' DNX_UI_RESET='' DNX_PHASE=0 DNX_PHASES=5
    DNX_STAGE_TITLE=Starting
    if [[ -t 1 && "${TERM:-dumb}" != dumb && "${DNX_NO_PROGRESS:-0}" == 0 && "${DARK_NEXUS_PROGRESS:-auto}" != 0 ]]; then
        DNX_UI=1
        if [[ ! -v NO_COLOR ]]; then DNX_UI_COLOR=$'\033[36m'; DNX_UI_RESET=$'\033[0m'; fi
        case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
            *[Uu][Tt][Ff]*8*) DNX_UI_UNICODE=1 ;;
        esac
    fi
}

dnx_stage() {
    DNX_PHASE=$1
    DNX_STAGE_TITLE=$2
    DNX_STAGE_SECONDS=$SECONDS
}

dnx_stage_done() {
    if [[ "${DNX_UI:-0}" == 1 ]]; then
        printf '  %s+%s  %s/%s  %s\n' "$DNX_UI_COLOR" "$DNX_UI_RESET" "$DNX_PHASE" "$DNX_PHASES" "$DNX_STAGE_TITLE"
    fi
}

dnx_ui_complete() {
    [[ "${DNX_UI:-0}" == 1 ]] || return 0
    local width=18 bar line
    dnx_ui_columns
    (( DNX_COLUMNS >= 60 )) || width=8
    printf -v bar '%*s' "$width" ''
    if [[ "${DNX_UI_UNICODE:-0}" == 1 ]]; then bar=${bar// /━}; else bar=${bar// /=}; fi
    line="  [$bar] $DNX_PHASES/$DNX_PHASES Complete"
    printf '\n%s%s%s\n' "$DNX_UI_COLOR" "${line:0:DNX_COLUMNS-1}" "$DNX_UI_RESET"
}

dnx_ui_columns() {
    local columns terminal_fd
    # stdin is the downloaded script pipe (then /dev/null), not the terminal.
    # Preserve stdout's TTY fd across command substitution before querying size.
    exec {terminal_fd}>&1
    columns=$(stty size <&"$terminal_fd" 2>/dev/null || true)
    exec {terminal_fd}>&-
    columns=${columns##* }
    if [[ ! "$columns" =~ ^[0-9]{1,3}$ ]]; then
        columns=$(env -u COLUMNS tput cols 2>/dev/null || printf '80')
    fi
    [[ "$columns" =~ ^[0-9]{1,3}$ ]] || columns=80
    (( columns >= 10 )) || columns=10
    DNX_COLUMNS=$columns
}

dnx_ui_clear() {
    if [[ "${DNX_UI_DRAWN:-0}" == 1 ]]; then
        printf '\r\033[2K\033[1A\r\033[2K'
        DNX_UI_DRAWN=0
    fi
}

dnx_ui_draw() {
    local tick=$1 elapsed=$(( SECONDS - DNX_STAGE_SECONDS )) width filled bar='' i glyph line detail counts=''
    local frames='|/-\' solid='=' empty='-'
    if [[ "${DNX_UI_UNICODE:-0}" == 1 ]]; then frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'; solid='━'; empty='─'; fi
    (( elapsed >= 0 )) || elapsed=0
    if (( DNX_COLUMNS >= 100 )); then width=24
    elif (( DNX_COLUMNS >= 80 )); then width=18
    elif (( DNX_COLUMNS >= 60 )); then width=12
    else width=8; fi
    # Completed stages are real progress. Only Ninja's task count advances a
    # running stage; elapsed time changes the spinner, never the completion bar.
    filled=$(( (DNX_PHASE - 1) * width / DNX_PHASES ))
    if (( DNX_TASK_TOTAL > 0 )); then
        filled=$(( ((DNX_PHASE - 1) * width + width * DNX_TASK_DONE / DNX_TASK_TOTAL) / DNX_PHASES ))
        counts="  $DNX_TASK_DONE/$DNX_TASK_TOTAL tasks"
    fi
    (( filled >= 0 )) || filled=0
    (( filled <= width )) || filled=$width
    for (( i=0; i<width; ++i )); do
        if (( i < filled )); then bar+=$solid; else bar+=$empty; fi
    done
    glyph=${frames:tick%${#frames}:1}
    (( DNX_COLUMNS >= 60 )) || counts=''
    printf -v line '  %s [%s] %s/%s %s%s  %02d:%02d' "$glyph" "$bar" "$DNX_PHASE" "$DNX_PHASES" "$DNX_STAGE_TITLE" "$counts" "$(( elapsed / 60 ))" "$(( elapsed % 60 ))"
    detail="    ${DNX_ACTIVITY:-$DNX_OPERATION}"
    line=${line:0:DNX_COLUMNS-1}
    detail=${detail:0:DNX_COLUMNS-1}
    dnx_ui_clear
    printf '\r\033[2K%s%s%s\n\r\033[2K%s' "$DNX_UI_COLOR" "$line" "$DNX_UI_RESET" "$detail"
    DNX_UI_DRAWN=1
}

dnx_ui_line() {
    local line=$1 sequence
    # Logs keep the original output; terminal status text cannot move the cursor.
    printf '%s\n' "$line" >>"$DNX_LOG" || return
    if [[ "$DNX_STAGE_TITLE" == Compile && "$line" =~ \[([0-9]+)/([0-9]+)\] ]]; then
        local done=${BASH_REMATCH[1]} total=${BASH_REMATCH[2]}
        if (( total > 0 && done >= DNX_TASK_DONE && done <= total )); then
            DNX_TASK_DONE=$done DNX_TASK_TOTAL=$total
        fi
    fi
    while [[ "$line" =~ $'\033''\[[0-?]*[ -/]*[@-~]' ]]; do
        sequence=${BASH_REMATCH[0]}
        line=${line//"$sequence"/}
    done
    line=${line//[$'\001'-$'\037'$'\177']/}
    [[ -z "$line" ]] || DNX_ACTIVITY=$line
}

dnx_ui_restore() {
    dnx_ui_clear
    printf '\033[?25h'
}

dnx_ui_stream() {
    # A process substitution must not inherit the installer's EXIT cleanup.
    trap - EXIT INT TERM
    local chunk pending='' line result tick=0 last_size_check=-1
    DNX_UI_DRAWN=0 DNX_TASK_DONE=0 DNX_TASK_TOTAL=0 DNX_ACTIVITY=$DNX_OPERATION
    trap dnx_ui_restore EXIT
    printf '\033[?25l'
    while :; do
        if (( SECONDS != last_size_check )); then
            dnx_ui_columns
            last_size_check=$SECONDS
        fi
        dnx_ui_draw "$tick"
        chunk=''
        # Read batches instead of redrawing for every compiler/download line.
        # Timed reads can return a partial chunk: retain it until its newline.
        if IFS= read -r -N 4096 -t 0.1 chunk; then result=0; else result=$?; fi
        pending+=$chunk
        while [[ "$pending" == *$'\n'* ]]; do
            line=${pending%%$'\n'*}
            pending=${pending#*$'\n'}
            dnx_ui_line "$line" || return
        done
        if (( result != 0 && result <= 128 )); then
            [[ -z "$pending" ]] || dnx_ui_line "$pending" || return
            dnx_ui_draw "$tick"
            break
        fi
        tick=$(( tick + 1 ))
    done
}

dnx_finish_output() {
    local result=0
    if [[ -n "${DNX_OUTPUT_FD:-}" ]]; then
        exec {DNX_OUTPUT_FD}>&-
        DNX_OUTPUT_FD=''
    fi
    if [[ -n "${DNX_RENDER_PID:-}" ]]; then
        wait "$DNX_RENDER_PID" || result=$?
        DNX_RENDER_PID=''
    fi
    return "$result"
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
    dnx_finish_output || true
    if [[ "${DNX_UI:-0}" == 1 ]]; then printf '%s\033[?25h' "$DNX_UI_RESET"; fi
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
    dnx_finish_output || true
    exit "$status"
}

# Keep the command PID so Ctrl-C/TERM stops its downloads before cleanup.
# The separate tee is joined as well, preserving both exit codes and all output.
dnx_run() {
    local label=$1 limit=$2 rc=0 log_rc=0
    shift 2
    DNX_OPERATION=$label
    if [[ "${DNX_UI:-0}" == 1 ]]; then
        printf '\n[%s]\n' "$label" >>"$DNX_LOG" || return
        exec {DNX_OUTPUT_FD}> >(dnx_ui_stream)
    else
        printf '\n[%s]\n' "$label" | tee -a "$DNX_LOG" || return
        exec {DNX_OUTPUT_FD}> >(tee -a "$DNX_LOG")
    fi
    DNX_RENDER_PID=$!
    timeout --signal=TERM --kill-after=30s "${limit}s" "$@" </dev/null >&"$DNX_OUTPUT_FD" 2>&1 &
    DNX_ACTIVE_PID=$!
    wait "$DNX_ACTIVE_PID" || rc=$?
    DNX_ACTIVE_PID=''
    dnx_finish_output || log_rc=$?
    (( rc != 0 )) || rc=$log_rc
    if (( rc != 0 )) && [[ "${DNX_UI:-0}" == 1 ]]; then
        printf '\nRecent output:\n' >&2
        tail -n 12 "$DNX_LOG" >&2 || true
    fi
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
        debian) dnx_packages 'Core dependencies' build-essential cmake ninja-build pkg-config ca-certificates libssl-dev openssl liburing-dev libcap2-bin libcap-dev git curl whois dnsutils iputils-ping ;;
        arch) dnx_packages 'Core dependencies' base-devel cmake ninja pkgconf ca-certificates openssl liburing libcap git curl whois bind iputils ;;
        fedora) dnx_packages 'Core dependencies' gcc gcc-c++ make cmake ninja-build pkgconf-pkg-config ca-certificates openssl-devel openssl liburing-devel libcap libcap-devel git curl whois bind-utils iputils ;;
        suse) dnx_packages 'Core dependencies' gcc gcc-c++ make cmake ninja pkg-config ca-certificates libopenssl-devel openssl liburing-devel libcap-progs libcap-devel git curl whois bind-utils iputils ;;
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

dnx_main() {
    local script_path=${BASH_SOURCE[0]:-} family_id='' family_like='' jobs argument
    DNX_PREFIX=/usr/local
    DNX_LOCAL_SOURCE=''
    DNX_SKIP_DEPS=0
    DNX_NO_PROGRESS=0
    DNX_WORK=''
    DNX_LOG=''
    DNX_PENDING_BINARY=''
    DNX_PENDING_WORDLIST=''
    DNX_ACTIVE_PID=''
    DNX_OUTPUT_FD=''
    DNX_RENDER_PID=''
    while (( $# )); do
        argument=$1
        case "$argument" in
            -h|--help) dnx_help; return 0 ;;
            --skip-deps) DNX_SKIP_DEPS=1 ;;
            --skip-helpers) : ;;
            --no-progress) DNX_NO_PROGRESS=1 ;;
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
    # Child commands cannot consume the script pipe or prompt on stdin.
    exec </dev/null
    export GIT_TERMINAL_PROMPT=0
    export NINJA_STATUS='[%f/%t] '
    export GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=http.lowSpeedLimit GIT_CONFIG_VALUE_0=1024 GIT_CONFIG_KEY_1=http.lowSpeedTime GIT_CONFIG_VALUE_1=60
    dnx_ui_init
    dnx_message "Dark Nexus / install | workers: $jobs"
    dnx_message "Log: $DNX_LOG"
    dnx_stage 1 Dependencies
    if (( ! DNX_SKIP_DEPS )); then dnx_dependencies; else dnx_message 'Using existing system dependencies.'; fi
    dnx_stage_done
    dnx_stage 2 Source
    dnx_prepare_source
    dnx_stage_done
    dnx_stage 3 Configure
    dnx_run 'Configure build and dependencies (up to 15 minutes)' 900 cmake -S "$DNX_SOURCE" -B "$DNX_SOURCE/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DCMAKE_TLS_VERIFY=ON
    dnx_stage_done
    dnx_stage 4 Compile
    dnx_run 'Compile (up to 60 minutes)' 3600 cmake --build "$DNX_SOURCE/build" --parallel "$jobs"
    dnx_stage_done
    dnx_stage 5 Install
    dnx_install_binary
    dnx_stage_done
    dnx_ui_complete
    printf '\nInstallation complete. Run: %s/bin/dark-nexus --help\n' "$DNX_PREFIX"
    dnx_message "Log: $DNX_LOG"
}

if [[ "${BASH_SOURCE[0]:-}" == "$0" || -z "${BASH_SOURCE[0]:-}" ]]; then
    dnx_main "$@"
fi
