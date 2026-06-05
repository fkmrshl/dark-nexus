#!/usr/bin/env bash

set -e

RED="\033[31m"
WHITE="\033[97m"
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"

LOG="/tmp/dark-nexus-install.log"
TOTAL_STEPS=5
CURRENT_STEP=0
BAR_WIDTH=42
DISTRO_LABEL=""
BUILD_NUM=0
BUILD_DEN=0

: >"$LOG"

distro_label() {
    if [ -n "${PRETTY_NAME:-}" ]; then
        DISTRO_LABEL="$PRETTY_NAME"
    else
        DISTRO_LABEL="${OS^}"
    fi
}

draw_ui() {
    local label="$1"
    local state="$2"
    local tick="${3:-0}"

    local filled=0
    local pct=0

    if [ "$state" = "run" ]; then
        local base=$(( CURRENT_STEP * BAR_WIDTH / TOTAL_STEPS ))
        local zone=$(( BAR_WIDTH / TOTAL_STEPS ))
        if [ "$zone" -lt 4 ]; then zone=4; fi
        local pulse=$(( tick % zone ))
        filled=$(( base + pulse ))
        if [ "$filled" -gt "$BAR_WIDTH" ]; then filled=$BAR_WIDTH; fi

        if [ "$BUILD_DEN" -gt 0 ]; then
            local compile=$(( BUILD_NUM * (BAR_WIDTH - base) / BUILD_DEN ))
            filled=$(( base + compile ))
            pct=$(( CURRENT_STEP * 100 / TOTAL_STEPS + compile * 100 / BUILD_DEN / TOTAL_STEPS ))
        else
            pct=$(( filled * 100 / BAR_WIDTH ))
        fi
    else
        filled=$(( CURRENT_STEP * BAR_WIDTH / TOTAL_STEPS ))
        pct=$(( CURRENT_STEP * 100 / TOTAL_STEPS ))
    fi

    local bar=""
    local i
    for ((i = 0; i < filled; i++)); do bar+="#"; done
    for ((i = filled; i < BAR_WIDTH; i++)); do bar+="-"; done

    local spin="|/-\\"
    local ch="${spin:$(( tick % 4 )):1}"

    printf "\033[2J\033[H"
    echo -e "${RED}${BOLD}  Dark Nexus Installer${RESET}"
    echo -e "${RED}  ========================================${RESET}\n"
    echo -e "${WHITE}[*] Detecting distribution... ${RED}${DISTRO_LABEL}${RESET}\n"
    echo -e "${WHITE}  ${label}${RESET}"
    echo -e "${RED}  [${WHITE}${bar}${RED}]${RESET} ${WHITE}${pct}%${RESET}"
    if [ "$state" = "run" ]; then
        if [ "$BUILD_DEN" -gt 0 ]; then
            echo -e "${DIM}  compiling ${BUILD_NUM}/${BUILD_DEN}  ${ch}${RESET}"
        else
            echo -e "${DIM}  working ${ch}${RESET}"
        fi
    elif [ "$state" = "ok" ]; then
        echo -e "${WHITE}  step complete${RESET}"
    fi
    echo -e "${DIM}  log: ${LOG}${RESET}\n"
}

fail() {
    printf "\033[2J\033[H"
    echo -e "${RED}${BOLD}  [!] Installation failed${RESET}"
    echo -e "${WHITE}  Log: ${LOG}${RESET}\n"
    echo -e "${DIM}  --- last lines ---${RESET}"
    tail -n 25 "$LOG" 2>/dev/null || true
    echo ""
    exit 1
}

run_step() {
    local label="$1"
    shift
    local tick=0

    "$@" >>"$LOG" 2>&1 &
    local pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        draw_ui "$label" "run" "$tick"
        tick=$((tick + 1))
        sleep 0.09
    done

    if ! wait "$pid"; then
        fail
    fi

    CURRENT_STEP=$((CURRENT_STEP + 1))
    draw_ui "$label" "ok" 0
    sleep 0.12
}

run_build_step() {
    local label="$1"
    local tick=0
    BUILD_NUM=0
    BUILD_DEN=0

    (cd /tmp/dark-nexus && cmake --build build 2>&1 | tee -a "$LOG") &
    local pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        local last
        last=$(grep -oE '\[[0-9]+/[0-9]+\]' "$LOG" 2>/dev/null | tail -1 || true)
        if [ -n "$last" ]; then
            BUILD_NUM=${last#[}
            BUILD_NUM=${BUILD_NUM%/*}
            BUILD_DEN=${last#*/}
            BUILD_DEN=${BUILD_DEN%]*}
        fi
        draw_ui "$label" "run" "$tick"
        tick=$((tick + 1))
        sleep 0.09
    done

    if ! wait "$pid"; then
        fail
    fi

    BUILD_NUM=0
    BUILD_DEN=0
    CURRENT_STEP=$((CURRENT_STEP + 1))
    draw_ui "$label" "ok" 0
    sleep 0.12
}

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run the installer as root (use sudo)${RESET}"
    exit 1
fi

if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    OS=$ID
    OS_LIKE=$ID_LIKE
else
    echo -e "${RED}[!] Cannot determine OS. Unsupported distribution.${RESET}"
    exit 1
fi

distro_label
echo "distro=$OS label=$DISTRO_LABEL" >>"$LOG"

draw_ui "Preparing installer..." "run" 0
sleep 0.4
CURRENT_STEP=0

if [[ "$OS" == "debian" || "$OS" == "ubuntu" || "$OS" == "kali" || "$OS_LIKE" == *"debian"* || "$OS_LIKE" == *"ubuntu"* ]]; then
    run_step "Installing dependencies (apt update + packages)..." bash -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq \
            build-essential cmake ninja-build g++ libssl-dev liburing-dev \
            whois dnsutils traceroute iputils-ping git libcap2-bin libcap-dev curl
    '
elif [[ "$OS" == "arch" || "$OS" == "blackarch" || "$OS_LIKE" == *"arch"* ]]; then
    run_step "Installing dependencies (Pacman)..." bash -c '
        pacman -Syu --noconfirm --needed \
            base-devel cmake ninja openssl liburing whois bind traceroute iputils git libcap curl
    '
else
    echo -e "${RED}[!] Unsupported OS. Please install dependencies manually.${RESET}"
    exit 1
fi

run_step "Fetching source from GitHub..." bash -c '
    rm -rf /tmp/dark-nexus
    git clone --quiet --depth 1 https://github.com/fkmrshl/dark-nexus.git /tmp/dark-nexus
'

run_step "Configuring build (CMake)..." bash -c '
    cd /tmp/dark-nexus
    cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
'

run_build_step "Compiling (Ninja)..."

run_step "Installing binary, setcap, wordlist..." bash -c '
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

CURRENT_STEP=$TOTAL_STEPS
draw_ui "Installation complete" "ok" 0

echo -e "${RED}${BOLD}  [+] Installation Complete!${RESET}"
echo -e "${WHITE}  Run from anywhere (no sudo):${RESET}"
echo -e "${RED}  dark-nexus --help${RESET}\n"
