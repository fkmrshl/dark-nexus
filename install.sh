#!/usr/bin/env bash

[ -t 0 ] || exec 0</dev/null

set -e

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
BAR_WIDTH=40

STEP_ENDS=(22 30 42 92 100)
STEP_LABELS=(
    "Installing dependencies..."
    "Fetching source from GitHub..."
    "Configuring build (CMake)..."
    "Compiling (Ninja)..."
    "Installing binary, setcap, wordlist..."
)

CURRENT_STEP=0
DISPLAY_PCT=0
UI_READY=0
DISTRO_LABEL=""
BUILD_NUM=0
BUILD_DEN=0

SPIN_FRAMES=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
SPIN_COUNT=${#SPIN_FRAMES[@]}

: >"$LOG"


get_jobs() {
    local cpus mem_kb max_by_ram jobs
    cpus=$(nproc 2>/dev/null || echo 2)
    mem_kb=$(awk '/MemAvailable/{print $2; exit}' /proc/meminfo 2>/dev/null || echo 2097152)
    max_by_ram=$(( mem_kb / 1400000 ))
    (( max_by_ram < 1 )) && max_by_ram=1
    jobs=$cpus
    (( jobs > max_by_ram )) && jobs=$max_by_ram
    (( jobs < 1 )) && jobs=1
    echo "$jobs"
}

JOBS=$(get_jobs)

distro_label() {
    if [ -n "${PRETTY_NAME:-}" ]; then
        DISTRO_LABEL="$PRETTY_NAME"
    else
        DISTRO_LABEL="${OS^}"
    fi
}

ui_hide_cursor() { printf '\033[?25l'; }
ui_show_cursor() { printf '\033[?25h'; }
ui_clear_line()  { printf '\033[K'; }
ui_goto()        { printf '\033[%d;0H' "$1"; }

step_start_pct() {
    [ "$CURRENT_STEP" -eq 0 ] && echo 0 || echo "${STEP_ENDS[$((CURRENT_STEP - 1))]}"
}
step_end_pct() { echo "${STEP_ENDS[$CURRENT_STEP]}"; }

clamp_pct() {
    local v=$1
    (( v < 0   )) && v=0
    (( v > 100 )) && v=100
    echo "$v"
}

set_display_pct() {
    local next
    next=$(clamp_pct "$1")
    (( next > DISPLAY_PCT )) && DISPLAY_PCT=$next
}


render_bar() {
    local pct=$1 tick=$2
    local fill=$(( pct * BAR_WIDTH / 100 ))
    (( fill > BAR_WIDTH )) && fill=$BAR_WIDTH
    (( fill < 0 )) && fill=0

    local i out=""
    local pidx=$(( tick % 4 ))

    local heads=('►' '▶' '►' '▸')
    local head="${heads[$pidx]}"

    local hcolors=("$R2" "$R3" "$R2" "$R4")
    local hc="${hcolors[$pidx]}"

    for ((i = 0; i < fill; i++)); do
        local dist=$(( fill - 1 - i ))
        if (( pct < 100 )); then
            case $dist in
                0) out+="${hc}${head}" ;;  
                1) out+="${R3}▓" ;;         
                2) out+="${R4}▒" ;;         
                *) out+="${RED}═" ;;        
            esac
        else
            out+="${R2}═"
        fi
    done

    out+="${GRAY}"
    for ((i = fill; i < BAR_WIDTH; i++)); do
        out+="─"
    done
    out+="${RESET}"

    printf '%s' "$out"
}

init_ui() {
    printf '\033[2J\033[H'
    printf '%s%s  Dark Nexus Installer%s\n' "$RED" "$BOLD" "$RESET"
    printf '%s  ════════════════════════════════════════%s\n' "$RED" "$RESET"
    printf '\n'
    printf '%s[*] Detecting distribution... %s%s%s\n' \
        "$WHITE" "$RED" "$DISTRO_LABEL" "$RESET"
    printf '\n'
    UI_READY=1
}

update_ui() {
    local label="$1" status="$2" tick="${3:-0}"

    [ "$UI_READY" -eq 0 ] && init_ui

    local bar spin
    bar=$(render_bar "$DISPLAY_PCT" "$tick")
    spin="${SPIN_FRAMES[$(( tick % SPIN_COUNT ))]}"

    ui_goto 7
    ui_clear_line
    printf '%s  %-40s%s' "$WHITE" "$label" "$RESET"

    ui_goto 8
    ui_clear_line
    printf '%s  [%s%s]  %s%3d%%%s' \
        "$RED" "$bar" "$RED" "$WHITE" "$DISPLAY_PCT" "$RESET"

    ui_goto 9
    ui_clear_line
    printf '%s  %s %s%s%s' "$RED" "$spin" "$DIM" "$status" "$RESET"

    ui_goto 10
    ui_clear_line
    printf '%s  log: %s%s' "$DIM" "$LOG" "$RESET"

    ui_goto 11
    ui_clear_line
}
 
fail() {
    ui_show_cursor
    printf '\033[2J\033[H'
    printf '%s%s  [!] Installation failed%s\n' "$RED" "$BOLD" "$RESET"
    printf '%s  Log: %s%s\n\n' "$WHITE" "$LOG" "$RESET"
    printf '%s  --- last lines ---%s\n' "$DIM" "$RESET"
    tail -n 25 "$LOG" 2>/dev/null || true
    printf '\n'
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
        (( sub > 98 )) && sub=98
    else
        sub=$(( tick * 2 ))
        (( sub > 88 )) && sub=88
    fi

    target=$(( start + span * sub / 100 ))
    set_display_pct "$target"
}

poll_build_progress() {
    local last
    last=$(grep -oE '\[[0-9]+/[0-9]+\]' "$LOG" 2>/dev/null | tail -1 || true)
    [ -z "$last" ] && return
    BUILD_NUM="${last#[}"
    BUILD_NUM="${BUILD_NUM%/*}"
    BUILD_DEN="${last#*/}"
    BUILD_DEN="${BUILD_DEN%]*}"
}

run_step() {
    local label="$1"
    shift
    local tick=0

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
    sleep 0.2
}

run_build_step() {
    local label="$1"
    local tick=0

    BUILD_NUM=0
    BUILD_DEN=0
    set_display_pct "$(step_start_pct)"
    update_ui "$label" "starting compile..." 0

    (cd /tmp/dark-nexus && cmake --build build -j "$JOBS" >>"$LOG" 2>&1) &
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
        sleep 0.12
    done

    if ! wait "$pid"; then fail; fi

    BUILD_NUM=0
    BUILD_DEN=0
    set_display_pct "$(step_end_pct)"
    update_ui "$label" "compile done" "$tick"
    CURRENT_STEP=$(( CURRENT_STEP + 1 ))
    sleep 0.2
}

trap 'ui_show_cursor' EXIT

if [ "$EUID" -ne 0 ]; then
    printf '%s[!] Please run the installer as root (use sudo)%s\n' "$RED" "$RESET"
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_LIKE=$ID_LIKE
else
    printf '%s[!] Cannot determine OS. Unsupported distribution.%s\n' "$RED" "$RESET"
    exit 1
fi

distro_label
printf 'distro=%s label=%s jobs=%s\n' "$OS" "$DISTRO_LABEL" "$JOBS" >>"$LOG"

ui_hide_cursor
init_ui
set_display_pct 0
update_ui "Preparing installer..." "initializing..." 0
sleep 0.35

if [[ "$OS" == "debian" || "$OS" == "ubuntu" || "$OS" == "kali" || \
      "$OS_LIKE" == *"debian"* || "$OS_LIKE" == *"ubuntu"* ]]; then
    run_step "${STEP_LABELS[0]}" bash -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq \
            build-essential cmake ninja-build g++ libssl-dev liburing-dev \
            whois dnsutils traceroute iputils-ping git libcap2-bin libcap-dev curl
    '
elif [[ "$OS" == "arch" || "$OS" == "blackarch" || "$OS_LIKE" == *"arch"* ]]; then
    run_step "${STEP_LABELS[0]}" bash -c '
        pacman -Syu --noconfirm --needed \
            base-devel cmake ninja openssl liburing whois bind traceroute iputils git libcap curl
    '
else
    ui_show_cursor
    printf '%s[!] Unsupported OS. Please install dependencies manually.%s\n' "$RED" "$RESET"
    exit 1
fi

run_step "${STEP_LABELS[1]}" bash -c '
    rm -rf /tmp/dark-nexus
    git clone --quiet --depth 1 https://github.com/fkmrshl/dark-nexus.git /tmp/dark-nexus
'

run_step "${STEP_LABELS[2]}" bash -c '
    cd /tmp/dark-nexus
    cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
'

run_build_step "${STEP_LABELS[3]}"

run_step "${STEP_LABELS[4]}" bash -c '
    cd /tmp/dark-nexus
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
ui_show_cursor

ui_goto 13
ui_clear_line
printf '%s%s  [+] Installation Complete!%s\n' "$RED" "$BOLD" "$RESET"
ui_goto 14
ui_clear_line
printf '%s  Run from anywhere (no sudo):%s\n' "$WHITE" "$RESET"
ui_goto 15
ui_clear_line
printf '%s  dark-nexus --help%s\n' "$RED" "$RESET"
printf '\n'