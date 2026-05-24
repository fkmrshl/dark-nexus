#!/usr/bin/env bash

set -e

RED="\033[31m"
WHITE="\033[97m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "${RED}${BOLD}  Dark Nexus Installer${RESET}"
echo -e "${RED}  ========================================${RESET}\n"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run the installer as root (use sudo)${RESET}"
  kill -TERM $$
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_LIKE=$ID_LIKE
else
    echo -e "${RED}[!] Cannot determine OS. Unsupported distribution.${RESET}"
    kill -TERM $$
fi

echo -e "${WHITE}[*] Detecting distribution... ${RED}$OS${RESET}"

if [[ "$OS" == "debian" || "$OS" == "ubuntu" || "$OS" == "kali" || "$OS_LIKE" == *"debian"* || "$OS_LIKE" == *"ubuntu"* ]]; then
    echo -e "${WHITE}[*] Installing dependencies via APT...${RESET}"
    apt update
    apt install -y build-essential cmake ninja-build g++ libssl-dev liburing-dev whois dnsutils traceroute iputils-ping git libcap2-bin libcap-dev
elif [[ "$OS" == "arch" || "$OS" == "blackarch" || "$OS_LIKE" == *"arch"* ]]; then
    echo -e "${WHITE}[*] Installing dependencies via Pacman...${RESET}"
    pacman -Syu --noconfirm --needed base-devel cmake ninja openssl liburing whois bind traceroute iputils git libcap
else
    echo -e "${RED}[!] Unsupported package manager for OS: $OS. Please install dependencies manually.${RESET}"
    kill -TERM $$
fi

if [ ! -f "CMakeLists.txt" ]; then
    echo -e "${WHITE}[*] Cloning repository...${RESET}"
    rm -rf /tmp/dark-nexus
    git clone https://github.com/fkmrshl/dark-nexus.git /tmp/dark-nexus
    cd /tmp/dark-nexus
fi

echo -e "${WHITE}[*] Building Dark Nexus with CMake and Ninja...${RESET}"
cmake -B build -G Ninja
cmake --build build

echo -e "${WHITE}[*] Installing binary to /usr/local/bin/dark-nexus...${RESET}"
ln -sf $(pwd)/build/dark_nexus /usr/local/bin/dark-nexus
chmod +x /usr/local/bin/dark-nexus

echo -e "\n${RED}${BOLD}  [+] Installation Complete!${RESET}"
echo -e "${WHITE}  You can now run the tool from anywhere using:${RESET}"
echo -e "${RED}  dark-nexus --help${RESET}\n"
