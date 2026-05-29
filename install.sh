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
    apt install -y build-essential cmake ninja-build g++ libssl-dev liburing-dev whois dnsutils traceroute iputils-ping git libcap2-bin libcap-dev curl
elif [[ "$OS" == "arch" || "$OS" == "blackarch" || "$OS_LIKE" == *"arch"* ]]; then
    echo -e "${WHITE}[*] Installing dependencies via Pacman...${RESET}"
    pacman -Syu --noconfirm --needed base-devel cmake ninja openssl liburing whois bind traceroute iputils git libcap curl
else
    echo -e "${RED}[!] Unsupported OS. Please install dependencies manually.${RESET}"
    kill -TERM $$
fi

echo -e "${WHITE}[*] Cloning repository...${RESET}"
rm -rf /tmp/dark-nexus
git clone https://github.com/fkmrshl/dark-nexus.git /tmp/dark-nexus
cd /tmp/dark-nexus

echo -e "${WHITE}[*] Building Dark Nexus with CMake and Ninja...${RESET}"
cmake -B build -G Ninja
cmake --build build

echo -e "${WHITE}[*] Installing binary to system...${RESET}"

cp build/dark_nexus /usr/local/bin/dark-nexus
chmod 755 /usr/local/bin/dark-nexus

echo -e "${WHITE}[*] Applying network capabilities (cap_net_raw)...${RESET}"
setcap cap_net_raw=eip /usr/local/bin/dark-nexus

echo -e "${WHITE}[*] Installing global DNS wordlist...${RESET}"
mkdir -p /usr/share/wordlists/dark-nexus
if [ -f "best-dns-wordlist.txt" ]; then
    cp best-dns-wordlist.txt /usr/share/wordlists/dark-nexus/
else
    curl -sL "https://raw.githubusercontent.com/fkmrshl/dark-nexus/main/best-dns-wordlist.txt" -o /usr/share/wordlists/dark-nexus/best-dns-wordlist.txt
fi
chmod 644 /usr/share/wordlists/dark-nexus/best-dns-wordlist.txt

echo -e "\n${RED}${BOLD}  [+] Installation Complete!${RESET}"
echo -e "${WHITE}  You can now run the tool from anywhere WITHOUT sudo using:${RESET}"
echo -e "${RED}  dark-nexus --help${RESET}\n"
