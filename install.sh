#!/usr/bin/env bash

set -e

RED="\033[31m"
WHITE="\033[97m"
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"

LOG="/tmp/dark-nexus-install.log"
BAR_WIDTH=42

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

PULSE_CHARS=('█' '▓' '▒' '▓')

: >"$LOG"

distro_label() {
    if [ -n "${PRETTY_NAME:-}" ]; then
        DISTRO_LABEL="$PRETTY_NAME"
    else
        DISTRO_LABEL="${OS^}"
    fi
}

ui_hide_cursor() {
    printf '\033[?25l'
}

ui_show_cursor() {
    printf '\033[?25h'
}

ui_clear_line() {
    printf '\033[K'
}

ui_goto() {
    printf '\033[%d;0H' "$1"
}

step_start_pct() {
    if [ "$CURRENT_STEP" -eq 0 ]; then
        echo 0
    else
        echo "${STEP_ENDS[$((CURRENT_STEP - 1))]}"
    fi
}

step_end_pct() {
    echo "${STEP_ENDS[$CURRENT_STEP]}"
}

clamp_pct() {
    local v=$1
    if [ "$v" -lt 0 ]; then v=0; fi
    if [ "$v" -gt 100 ]; then v=100; fi
    echo "$v"
}

set_display_pct() {
    local next
    next=$(clamp_pct "$1")
    if [ "$next" -gt "$DISPLAY_PCT" ]; then
        DISPLAY_PCT=$next
    fi
}

render_bar() {
    local pct=$1
    local tick=$2
    local fill=$(( pct * BAR_WIDTH / 100 ))
    if [ "$fill" -gt "$BAR_WIDTH" ]; then fill=$BAR_WIDTH; fi
    if [ "$fill" -lt 0 ]; then fill=0; fi

    local pulse="${PULSE_CHARS[$(( tick % ${#PULSE_CHARS[@]} ))]}"
    local i
    local out=""

    for ((i = 0; i < fill; i++)); do
        if [ "$i" -eq $((fill - 1)) ] && [ "$fill" -gt 0 ] && [ "$pct" -lt 100 ]; then
            out+="$pulse"
        else
            out+="#"
        fi
    done
    for ((i = fill; i < BAR_WIDTH; i++)); do
        out+="-"
    done
    echo "$out"
}

init_ui() {
    printf '\033[2J\033[H'
    echo -e "${RED}${BOLD}  Dark Nexus Installer${RESET}"
    echo -e "${RED}  ========================================${RESET}"
    echo ""
    echo -e "${WHITE}[*] Detecting distribution... ${RED}${DISTRO_LABEL}${RESET}"
    echo ""
    UI_READY=1
}

update_ui() {
    local label="$1"
    local status="$2"
    local tick="${3:-0}"

    if [ "$UI_READY" -eq 0 ]; then
        init_ui
    fi

    local bar
    bar=$(render_bar "$DISPLAY_PCT" "$tick")

    ui_goto 7
    ui_clear_line
    echo -ne "${WHITE}  ${label}${RESET}"

    ui_goto 8
    ui_clear_line
    echo -ne "${RED}  [${WHITE}${bar}${RED}]${RESET} ${WHITE}${DISPLAY_PCT}%${RESET}"

    ui_goto 9
    ui_clear_line
    echo -ne "${DIM}  ${status}${RESET}"

    ui_goto 10
    ui_clear_line
    echo -ne "${DIM}  log: ${LOG}${RESET}"

    ui_goto 11
    ui_clear_line
}

fail() {
    ui_show_cursor
    printf '\033[2J\033[H'
    echo -e "${RED}${BOLD}  [!] Installation failed${RESET}"
    echo -e "${WHITE}  Log: ${LOG}${RESET}\n"
    echo -e "${DIM}  --- last lines ---${RESET}"
    tail -n 25 "$LOG" 2>/dev/null || true
    echo ""
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
        if [ "$sub" -gt 98 ]; then sub=98; fi
    else
        sub=$(( tick * 2 ))
        if [ "$sub" -gt 88 ]; then sub=88; fi
    fi

    target=$(( start + span * sub / 100 ))
    set_display_pct "$target"
}

poll_build_progress() {
    local last
    last=$(grep -oE '\[[0-9]+/[0-9]+\]' "$LOG" 2>/dev/null | tail -1 || true)
    if [ -z "$last" ]; then
        return
    fi
    BUILD_NUM=${last#[}
    BUILD_NUM=${BUILD_NUM%/*}
    BUILD_DEN=${last#*/}
    BUILD_DEN=${BUILD_DEN%]*}
}

run_step() {
    local label="$1"
    shift
    local tick=0
    local spin="|/-\\"

    BUILD_NUM=0
    BUILD_DEN=0
    set_display_pct "$(step_start_pct)"
    update_ui "$label" "starting..." 0

    "$@" >>"$LOG" 2>&1 &
    local pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        tick_subprogress "$tick"
        local ch="${spin:$(( tick % 4 )):1}"
        update_ui "$label" "working ${ch}" "$tick"
        tick=$((tick + 1))
        sleep 0.12
    done

    if ! wait "$pid"; then
        fail
    fi

    set_display_pct "$(step_end_pct)"
    update_ui "$label" "done" "$tick"
    CURRENT_STEP=$((CURRENT_STEP + 1))
    sleep 0.2
}

run_build_step() {
    local label="$1"
    local tick=0
    local spin="|/-\\"

    BUILD_NUM=0
    BUILD_DEN=0
    set_display_pct "$(step_start_pct)"
    update_ui "$label" "starting compile..." 0

    (cd /tmp/dark-nexus && cmake --build build >>"$LOG" 2>&1) &
    local pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        poll_build_progress
        tick_subprogress "$tick"
        local status="compiling"
        if [ "$BUILD_DEN" -gt 0 ]; then
            status="compiling ${BUILD_NUM}/${BUILD_DEN}  ${spin:$(( tick % 4 )):1}"
        else
            status="compiling ${spin:$(( tick % 4 )):1}"
        fi
        update_ui "$label" "$status" "$tick"
        tick=$((tick + 1))
        sleep 0.12
    done

    if ! wait "$pid"; then
        fail
    fi

    BUILD_NUM=0
    BUILD_DEN=0
    set_display_pct "$(step_end_pct)"
    update_ui "$label" "compile done" "$tick"
    CURRENT_STEP=$((CURRENT_STEP + 1))
    sleep 0.2
}

trap 'ui_show_cursor' EXIT

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run the installer as root (use sudo)${RESET}"
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_LIKE=$ID_LIKE
else
    echo -e "${RED}[!] Cannot determine OS. Unsupported distribution.${RESET}"
    exit 1
fi

distro_label
echo "distro=$OS label=$DISTRO_LABEL" >>"$LOG"

ui_hide_cursor
init_ui
set_display_pct 0
update_ui "Preparing installer..." "initializing..." 0
sleep 0.35

if [[ "$OS" == "debian" || "$OS" == "ubuntu" || "$OS" == "kali" || "$OS_LIKE" == *"debian"* || "$OS_LIKE" == *"ubuntu"* ]]; then
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
    echo -e "${RED}[!] Unsupported OS. Please install dependencies manually.${RESET}"
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
echo -e "${RED}${BOLD}  [+] Installation Complete!${RESET}"
ui_goto 14
ui_clear_line
echo -e "${WHITE}  Run from anywhere (no sudo):${RESET}"
ui_goto 15
ui_clear_line
echo -e "${RED}  dark-nexus --help${RESET}"
echo ""
