#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Reconboard v5 — Setup & Launch (Bare Metal Kali)
# ═══════════════════════════════════════════════════════════
# Run: chmod +x setup.sh && sudo ./setup.sh
#
# For Docker deployment, use: docker compose up -d --scale worker=3

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║         Reconboard v5 — Setup                    ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Not running as root. SYN scans and some features require root.${NC}"
    echo -e "${YELLOW}    Recommend: sudo ./setup.sh${NC}"
    echo ""
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[✗] Python 3 not found. Install it first.${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Python 3 found: $(python3 --version)${NC}"

# Install Python deps
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
pip3 install flask redis --break-system-packages 2>/dev/null || pip3 install flask redis
echo -e "${GREEN}[✓] Python deps installed${NC}"

# Check for Redis
echo ""
echo -e "${CYAN}[*] Checking Redis...${NC}"
if command -v redis-server &> /dev/null; then
    echo -e "${GREEN}[✓] Redis installed${NC}"
    if ! pgrep redis-server > /dev/null; then
        echo -e "${YELLOW}[*] Starting Redis...${NC}"
        redis-server --daemonize yes 2>/dev/null || true
    fi
    if redis-cli ping 2>/dev/null | grep -q PONG; then
        echo -e "${GREEN}[✓] Redis running${NC}"
    fi
else
    echo -e "${YELLOW}[~] Redis not installed. Install with: apt install redis-server${NC}"
    echo -e "${YELLOW}    Server will run in local mode (no worker distribution)${NC}"
fi

# Check core tools
echo ""
echo -e "${CYAN}[*] Checking Kali tools...${NC}"
TOOLS=("nmap" "masscan" "enum4linux-ng" "enum4linux" "smbclient" "smbmap"
       "crackmapexec" "netexec" "gobuster" "feroxbuster" "nikto" "wpscan" "whatweb"
       "curl" "dig" "dnsrecon" "hydra" "redis-cli" "rpcclient" "ldapsearch"
       "searchsploit" "nuclei" "httpx" "subfinder" "naabu" "sqlmap"
       "testssl.sh" "sslscan" "onesixtyone" "snmpwalk" "medusa")

AVAILABLE=0
MISSING=0
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "  ${GREEN}[✓]${NC} $tool"
        ((AVAILABLE++))
    else
        echo -e "  ${RED}[✗]${NC} $tool"
        ((MISSING++))
    fi
done
echo ""
echo -e "${GREEN}Available: $AVAILABLE${NC} | ${RED}Missing: $MISSING${NC}"

if [ $MISSING -gt 5 ]; then
    echo ""
    echo -e "${YELLOW}[*] Install missing tools with:${NC}"
    echo -e "    sudo apt update && sudo apt install -y nmap masscan enum4linux smbclient smbmap"
    echo -e "    sudo apt install -y netexec gobuster feroxbuster nikto wpscan whatweb"
    echo -e "    sudo apt install -y dnsrecon dnsenum hydra redis-tools ldap-utils"
    echo -e "    sudo apt install -y exploitdb seclists sqlmap testssl.sh sslscan"
fi

mkdir -p data/scans

LOCAL_IP=$(hostname -I | awk '{print $1}')
PORT=${1:-8443}

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  Starting Reconboard v4 Server                   ║${NC}"
echo -e "${RED}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${RED}║  ${CYAN}Local:   http://localhost:${PORT}${RED}                  ║${NC}"
echo -e "${RED}║  ${CYAN}Network: http://${LOCAL_IP}:${PORT}${RED}              ║${NC}"
echo -e "${RED}║  ${YELLOW}Share the network URL with your team${RED}           ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
echo ""

# Symlink testssl if needed
[ -f /usr/bin/testssl ] && [ ! -f /usr/bin/testssl.sh ] && ln -s /usr/bin/testssl /usr/bin/testssl.sh

python3 recon_server.py --port "$PORT" --host 0.0.0.0
