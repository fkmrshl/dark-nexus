#!/usr/bin/env bash

[ -t 0 ] || exec 0</dev/null

set -e
trap '' PIPE

RED=$'\033[31m'
R2=$'\033[38;5;196m'
R3=$'\033[38;5;160m'
R4=$'\033[38;5;124m'
WHITE=$'\033[97m'
GRAY=$'\033[90m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
RESET=$'\033[0m'

LOG="/tmp/dark-nexus-install.log"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="/tmp/dark-nexus-build"
REPO_URL="https://github.com/fkmrshl/dark-nexus.git"
BAR_WIDTH=40

STEP_ENDS=(20 30 40 50 92 100)
STEP_LABELS=(
    "Installing dependencies..."
    "Installing OSINT helper tools..."
    "Preparing local source..."
    "Configuring build (CMake)..."
    "Compiling (Ninja)..."
    "Installing binary, setcap, wordlist..."
)

CURRENT_STEP=0
DISPLAY_PCT=0
UI_READY=0
SIMPLE_UI=0
DISTRO_LABEL=""
BUILD_NUM=0
BUILD_DEN=0
JOBS=1
export SOURCE_DIR BUILD_DIR REPO_URL

SPIN_FRAMES=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
SPIN_COUNT=${#SPIN_FRAMES[@]}

ui_put() {
    [ "$SIMPLE_UI" -eq 1 ] && return 0
    printf '%b' "$@" || true
}

ui_msg() {
    printf '%b\n' "$@" || true
}

log_mark() {
    printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$1" >>"$LOG" 2>/dev/null || true
}

get_jobs() {
    local cpus mem_kb max_by_ram jobs
    if [[ "${DARK_NEXUS_JOBS:-}" =~ ^[0-9]+$ ]] && (( DARK_NEXUS_JOBS > 0 )); then
        echo "$DARK_NEXUS_JOBS"
        return 0
    fi
    cpus=$(nproc 2>/dev/null || echo 2)
    mem_kb=$(awk '/MemAvailable/{print $2; exit}' /proc/meminfo 2>/dev/null || echo 2097152)
    if (( mem_kb < 1500000 )); then
        echo 1
        return 0
    fi
    max_by_ram=$(( mem_kb / 1000000 ))
    if (( max_by_ram < 1 )); then max_by_ram=1; fi
    jobs=$cpus
    if (( jobs > max_by_ram )); then jobs=$max_by_ram; fi
    if (( jobs > 2 )); then jobs=2; fi
    if (( jobs < 1 )); then jobs=1; fi
    echo "$jobs"
}

distro_label() {
    if [ -n "${PRETTY_NAME:-}" ]; then
        DISTRO_LABEL="$PRETTY_NAME"
    elif [ -n "${OS:-}" ]; then
        DISTRO_LABEL="${OS^}"
    else
        DISTRO_LABEL="unknown"
    fi
}

ui_hide_cursor() {
    [ "$SIMPLE_UI" -eq 1 ] && return 0
    ui_put '\033[?25l'
}

ui_show_cursor() {
    [ "$SIMPLE_UI" -eq 1 ] && return 0
    ui_put '\033[?25h'
}

ui_clear_line() {
    [ "$SIMPLE_UI" -eq 1 ] && return 0
    ui_put '\033[K'
}

ui_goto() {
    [ "$SIMPLE_UI" -eq 1 ] && return 0
    ui_put "\033[${1};0H"
}

step_start_pct() {
    if [ "$CURRENT_STEP" -eq 0 ]; then echo 0; else echo "${STEP_ENDS[$((CURRENT_STEP - 1))]}"; fi
}

step_end_pct() { echo "${STEP_ENDS[$CURRENT_STEP]}"; }

clamp_pct() {
    local v=$1
    if (( v < 0 )); then v=0; fi
    if (( v > 100 )); then v=100; fi
    echo "$v"
}

set_display_pct() {
    local next
    next=$(clamp_pct "$1")
    if (( next > DISPLAY_PCT )); then DISPLAY_PCT=$next; fi
}

render_bar() {
    local pct=$1 tick=$2
    local fill=$(( pct * BAR_WIDTH / 100 ))
    if (( fill > BAR_WIDTH )); then fill=$BAR_WIDTH; fi
    if (( fill < 0 )); then fill=0; fi

    local i out=""
    local pidx=$(( tick % 4 ))
    local heads=('►' '▶' '►' '▶')
    local head="${heads[$pidx]}"
    local hcolors=("$R2" "$R3" "$R2" "$R4")
    local hc="${hcolors[$pidx]}"

    for ((i = 0; i < fill; i++)); do
        local dist=$(( fill - 1 - i ))
        if (( pct < 100 )); then
            case $dist in
                0) out+="${hc}${head}" ;;
                *) out+="${RED}═" ;;
            esac
        else
            out+="${R2}═"
        fi
    done

    out+="${WHITE}"
    for ((i = fill; i < BAR_WIDTH; i++)); do
        out+="─"
    done
    out+="${RESET}"

    printf '%s' "$out"
}

init_ui() {
    if [ "$SIMPLE_UI" -eq 1 ]; then
        ui_msg "${RED}${BOLD}Dark Nexus Installer${RESET}"
        ui_msg "${WHITE}Distribution: ${RED}${DISTRO_LABEL}${RESET}"
        UI_READY=1
        return 0
    fi

    ui_put '\033[2J\033[H'
    ui_put "${RED}${BOLD}  Dark Nexus Installer${RESET}\n"
    ui_put "${RED}  ========================================${RESET}\n\n"
    ui_put "${WHITE}[*] Detecting distribution... ${RED}${DISTRO_LABEL}${RESET}\n\n"
    UI_READY=1
}

update_ui() {
    local label="$1" status="$2" tick="${3:-0}"

    if [ "$UI_READY" -eq 0 ]; then init_ui; fi

    if [ "$SIMPLE_UI" -eq 1 ]; then
        ui_msg "${WHITE}[${DISPLAY_PCT}%] ${label} - ${status}${RESET}"
        return 0
    fi

    local bar spin
    bar=$(render_bar "$DISPLAY_PCT" "$tick")
    spin="${SPIN_FRAMES[$(( tick % SPIN_COUNT ))]}"

    ui_goto 7;  ui_clear_line
    ui_put "${WHITE}  ${label}${RESET}"

    ui_goto 8;  ui_clear_line
    ui_put "${RED}  [${bar}${RED}]  ${WHITE}${DISPLAY_PCT}%${RESET}"

    ui_goto 9;  ui_clear_line
    ui_put "${RED}  ${spin} ${DIM}${status}${RESET}"

    ui_goto 10; ui_clear_line
    ui_put "${DIM}  log: ${LOG}${RESET}"

    ui_goto 11; ui_clear_line
}

fail() {
    log_mark "FAILED"
    ui_show_cursor
    ui_put '\033[2J\033[H'
    ui_msg "${RED}${BOLD}  [!] Installation failed${RESET}"
    ui_msg "${WHITE}  Log: ${LOG}${RESET}"
    ui_msg "${DIM}  --- last lines ---${RESET}"
    tail -n 25 "$LOG" 2>/dev/null | while IFS= read -r line; do ui_msg "${line}"; done
    exit 1
}

tick_subprogress() {
    local tick=$1
    local start end span sub target
    start=$(step_start_pct)
    end=$(step_end_pct)
    span=$(( end - start ))

    if [ "$BUILD_DEN" -gt 0 ]; then
        sub=$(( BUILD_NUM * 100 / BUILD_DEN ))
        if (( sub > 98 )); then sub=98; fi
    else
        sub=$(( tick * 2 ))
        if (( sub > 88 )); then sub=88; fi
    fi

    target=$(( start + span * sub / 100 ))
    set_display_pct "$target"
}

poll_build_progress() {
    local last
    last=$(grep -oE '\[[0-9]+/[0-9]+\]' "$LOG" 2>/dev/null | tail -1 || true)
    if [ -z "$last" ]; then return 0; fi
    BUILD_NUM="${last#[}"
    BUILD_NUM="${BUILD_NUM%/*}"
    BUILD_DEN="${last#*/}"
    BUILD_DEN="${BUILD_DEN%]*}"
}

run_step() {
    local label="$1"
    shift
    local tick=0

    log_mark "STEP: ${label}"
    BUILD_NUM=0
    BUILD_DEN=0
    set_display_pct "$(step_start_pct)"
    update_ui "$label" "starting..." 0

    "$@" >>"$LOG" 2>&1 &
    local pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        tick_subprogress "$tick"
        update_ui "$label" "working" "$tick"
        tick=$(( tick + 1 ))
        sleep 0.12
    done

    if ! wait "$pid"; then fail; fi

    set_display_pct "$(step_end_pct)"
    update_ui "$label" "done" "$tick"
    CURRENT_STEP=$(( CURRENT_STEP + 1 ))
    log_mark "DONE: ${label}"
    sleep 0.2
}

run_build_step() {
    local label="$1"
    local tick=0

    log_mark "STEP: ${label}"
    BUILD_NUM=0
    BUILD_DEN=0
    set_display_pct "$(step_start_pct)"
    update_ui "$label" "starting compile..." 0

    (cd "$BUILD_DIR" && cmake --build build -j "$JOBS" >>"$LOG" 2>&1) &
    local pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        poll_build_progress
        tick_subprogress "$tick"
        local status_msg="compiling"
        if [ "$BUILD_DEN" -gt 0 ]; then
            status_msg="compiling ${BUILD_NUM}/${BUILD_DEN}"
        fi
        update_ui "$label" "$status_msg" "$tick"
        tick=$(( tick + 1 ))
        sleep 0.25
    done

    if ! wait "$pid"; then fail; fi

    BUILD_NUM=0
    BUILD_DEN=0
    set_display_pct "$(step_end_pct)"
    update_ui "$label" "compile done" "$tick"
    CURRENT_STEP=$(( CURRENT_STEP + 1 ))
    log_mark "DONE: ${label}"
    sleep 0.2
}

trap 'ui_show_cursor' EXIT

say() {
    if [ -w /dev/tty ] 2>/dev/null; then
        printf '%b\n' "$1" >/dev/tty
    else
        printf '%b\n' "$1" >&2
    fi
}

if [ "$EUID" -ne 0 ]; then
    say "${RED}[!] Please run the installer as root (use sudo)${RESET}"
    exit 1
fi

if [ -w /dev/tty ] 2>/dev/null; then
    exec >/dev/tty 2>&1
else
    SIMPLE_UI=1
fi

: >"$LOG" 2>/dev/null || true

if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    OS=$ID
    OS_LIKE=$ID_LIKE
else
    ui_msg "${RED}[!] Cannot determine OS. Unsupported distribution.${RESET}"
    exit 1
fi

distro_label
JOBS=$(get_jobs)
log_mark "START distro=${OS} label=${DISTRO_LABEL} jobs=${JOBS} simple=${SIMPLE_UI} tty=$([ -t 1 ] && echo yes || echo no)"

ui_hide_cursor
init_ui
set_display_pct 0
update_ui "Preparing installer..." "initializing..." 0
log_mark "UI ready"
sleep 0.35

if [[ "$OS" == "debian" || "$OS" == "ubuntu" || "$OS" == "kali" || \
      "$OS_LIKE" == *"debian"* || "$OS_LIKE" == *"ubuntu"* ]]; then
    run_step "${STEP_LABELS[0]}" bash -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq \
            build-essential cmake ninja-build g++ libssl-dev liburing-dev \
            whois dnsutils traceroute iputils-ping git libcap2-bin libcap-dev curl \
            python3 python3-pip python3-venv
    '
elif [[ "$OS" == "arch" || "$OS" == "blackarch" || "$OS_LIKE" == *"arch"* ]]; then
    run_step "${STEP_LABELS[0]}" bash -c '
        pacman -Syu --noconfirm --needed \
            base-devel cmake ninja openssl liburing whois bind traceroute iputils git libcap curl \
            python python-pip
    '
else
    ui_show_cursor
    ui_msg "${RED}[!] Unsupported OS. Please install dependencies manually.${RESET}"
    exit 1
fi

run_step "${STEP_LABELS[1]}" bash -c '
    set +e
    PY_ROOT=/opt/dark-nexus-osint
    rm -rf "$PY_ROOT"
    mkdir -p "$PY_ROOT"
    python3 -m venv "$PY_ROOT"
    if [ $? -ne 0 ]; then
        echo "[warn] python venv unavailable, skipping OSINT helper tools"
        exit 0
    fi
    "$PY_ROOT/bin/python" -m pip install --upgrade pip wheel
    for entry in "sherlock:sherlock-project" "maigret:maigret" "holehe:holehe" "theHarvester:theHarvester"; do
        tool="${entry%%:*}"
        package="${entry#*:}"
        "$PY_ROOT/bin/python" -m pip install "$package"
        if [ $? -ne 0 ]; then
            echo "[warn] failed to install $tool package $package"
        fi
        if [ -x "$PY_ROOT/bin/$tool" ]; then
            ln -sf "$PY_ROOT/bin/$tool" "/usr/local/bin/$tool"
        else
            echo "[warn] $tool executable not found in $PY_ROOT/bin"
        fi
        if [ -x "/usr/local/bin/$tool" ]; then
            echo "[info] verified $tool"
        else
            echo "[warn] $tool is not executable after install"
        fi
    done

    if command -v go >/dev/null 2>&1; then
        GOBIN=/usr/local/bin go install github.com/sundowndev/phoneinfoga/v2@latest
        if [ $? -ne 0 ]; then
            echo "[warn] optional phoneinfoga go install failed"
        elif [ -x /usr/local/bin/phoneinfoga ]; then
            echo "[info] verified phoneinfoga"
        else
            echo "[warn] optional phoneinfoga binary was not created"
        fi
    else
        echo "[warn] go not found, skipping optional phoneinfoga"
    fi
    exit 0
'

run_step "${STEP_LABELS[2]}" bash -c '
    set -e
    rm -rf "$BUILD_DIR"
    if [ -f "$SOURCE_DIR/CMakeLists.txt" ] && [ -d "$SOURCE_DIR/src" ] && [ -d "$SOURCE_DIR/include" ]; then
        mkdir -p "$BUILD_DIR"
        cp -a "$SOURCE_DIR"/. "$BUILD_DIR"/
        rm -rf "$BUILD_DIR/build" "$BUILD_DIR/.git"
        echo "[info] using local source: $SOURCE_DIR"
    else
        if [ -z "${REPO_URL:-}" ]; then
            echo "[error] REPO_URL is empty"
            exit 1
        fi
        git clone --quiet --depth 1 "$REPO_URL" "$BUILD_DIR"
        echo "[info] using remote source: $REPO_URL"
    fi
'

run_step "${STEP_LABELS[3]}" bash -c '
    set -e
    cd "$BUILD_DIR"
    cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
'

run_build_step "${STEP_LABELS[4]}"

run_step "${STEP_LABELS[5]}" bash -c '
    set -e
    cd "$BUILD_DIR"
    rm -f /usr/local/bin/dark-nexus
    cp build/dark_nexus /usr/local/bin/dark-nexus
    chmod 755 /usr/local/bin/dark-nexus
    setcap cap_net_raw=eip /usr/local/bin/dark-nexus
    mkdir -p /usr/share/wordlists/dark-nexus
    if [ -f "best-dns-wordlist.txt" ]; then
        cp best-dns-wordlist.txt /usr/share/wordlists/dark-nexus/
    else
        curl -fsSL "https://raw.githubusercontent.com/fkmrshl/dark-nexus/main/best-dns-wordlist.txt" \
            -o /usr/share/wordlists/dark-nexus/best-dns-wordlist.txt
    fi
    chmod 644 /usr/share/wordlists/dark-nexus/best-dns-wordlist.txt
'

set_display_pct 100
update_ui "Installation complete" "all steps finished" 0
log_mark "FINISHED OK"
ui_show_cursor

if [ "$SIMPLE_UI" -eq 0 ]; then
    ui_goto 13; ui_clear_line
    ui_put "${RED}${BOLD}  [+] Installation Complete!${RESET}\n"
    ui_goto 14; ui_clear_line
    ui_put "${WHITE}  Run from anywhere (no sudo):${RESET}\n"
    ui_goto 15; ui_clear_line
    ui_put "${RED}  dark-nexus --help${RESET}\n\n"
else
    ui_msg "${RED}${BOLD}[+] Installation Complete!${RESET}"
    ui_msg "${WHITE}Run: ${RED}dark-nexus --help${RESET}"
fi
