#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║     Reconboard v5 — Distributed Kali Recon       ║${NC}"
echo -e "${RED}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${RED}║  ${CYAN}Kali Linux + All Recon Tools Pre-installed${RED}      ║${NC}"
echo -e "${RED}║  ${CYAN}Worker scaling via Redis job queue${RED}              ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Tool availability check ───
echo -e "${CYAN}[*] Verifying tool installation...${NC}"

TOOLS=(
    "nmap" "masscan" "enum4linux" "smbclient" "smbmap"
    "crackmapexec" "netexec" "gobuster" "feroxbuster" "nikto" "wpscan"
    "whatweb" "curl" "dig" "dnsrecon" "dnsenum" "hydra"
    "redis-cli" "rpcclient" "ldapsearch" "searchsploit"
    "impacket-GetNPUsers" "impacket-GetUserSPNs" "impacket-smbclient"
    "medusa" "snmpwalk" "nuclei" "httpx" "subfinder" "naabu"
    "sqlmap" "hashcat" "john" "testssl.sh" "sslscan" "sslyze"
    "onesixtyone" "smtp-user-enum" "wafw00f" "nbtscan" "fping"
    "theharvester" "recon-ng" "responder" "evil-winrm"
)

AVAILABLE=0
MISSING=0
MISSING_LIST=""

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        AVAILABLE=$((AVAILABLE + 1))
    else
        MISSING=$((MISSING + 1))
        MISSING_LIST="${MISSING_LIST} ${tool}"
    fi
done

echo -e "  ${GREEN}Available: ${AVAILABLE}${NC} | ${RED}Missing: ${MISSING}${NC}"
if [ -n "$MISSING_LIST" ]; then
    echo -e "  ${YELLOW}Missing:${MISSING_LIST}${NC}"
fi

# ─── Wordlist check ───
echo ""
echo -e "${CYAN}[*] Checking wordlists...${NC}"
WORDLISTS=(
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt"
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    "/usr/share/seclists/Usernames/Names/names.txt"
    "/usr/share/wordlists/rockyou.txt"
    "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
)

for wl in "${WORDLISTS[@]}"; do
    if [ -f "$wl" ]; then
        echo -e "  ${GREEN}[✓]${NC} $(basename $wl)"
    else
        echo -e "  ${YELLOW}[~]${NC} $(basename $wl) — not found"
    fi
done

# ─── Ensure data directories ───
mkdir -p /opt/redrecon/data/scans

# ─── Redis check ───
echo ""
echo -e "${CYAN}[*] Checking Redis connection...${NC}"
if redis-cli -u "${REDIS_URL:-redis://127.0.0.1:6379/0}" ping 2>/dev/null | grep -q PONG; then
    echo -e "  ${GREEN}[✓]${NC} Redis connected"
    echo -e "  ${CYAN}Mode: ${WORKER_MODE:-local}${NC}"
else
    echo -e "  ${YELLOW}[~]${NC} Redis not available, using local execution mode"
fi

# ─── Network info ───
echo ""
echo -e "${CYAN}[*] Network interfaces:${NC}"
ip -4 addr show 2>/dev/null | grep -E "inet " | awk '{print "  " $NF ": " $2}' || echo "  Could not detect interfaces"

# ─── Show access URLs ───
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown")
PORT=${REDRECON_PORT:-8443}

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  ${GREEN}Server starting...${RED}                               ║${NC}"
echo -e "${RED}║                                                  ║${NC}"
echo -e "${RED}║  ${CYAN}Local:   http://localhost:${PORT}${RED}                  ║${NC}"
echo -e "${RED}║  ${CYAN}Network: http://${LOCAL_IP}:${PORT}${RED}              ║${NC}"
echo -e "${RED}║                                                  ║${NC}"
echo -e "${RED}║  ${YELLOW}Scale workers: docker compose up --scale worker=5${RED}║${NC}"
echo -e "${RED}║  ${YELLOW}State persists in ./data/ on the host${RED}           ║${NC}"
echo -e "${RED}║                                                  ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
echo ""

exec python3 /opt/redrecon/recon_server.py "$@"
