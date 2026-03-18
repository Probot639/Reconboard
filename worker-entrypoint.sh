#!/bin/bash
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

WORKER_ID="worker-$(hostname)-$(cat /proc/sys/kernel/random/uuid | cut -c1-8)"
export WORKER_ID

echo ""
echo -e "${CYAN}[*] Reconboard v4 Worker starting...${NC}"
echo -e "  ID:          ${GREEN}${WORKER_ID}${NC}"
echo -e "  Concurrency: ${GREEN}${CONCURRENCY:-3}${NC}"
echo -e "  Redis:       ${GREEN}${REDIS_URL:-redis://redis:6379/0}${NC}"

# Wait for Redis
echo -e "${CYAN}[*] Waiting for Redis...${NC}"
for i in $(seq 1 30); do
    if redis-cli -u "${REDIS_URL:-redis://127.0.0.1:6379/0}" ping 2>/dev/null | grep -q PONG; then
        echo -e "  ${GREEN}[✓] Redis connected${NC}"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "  ${YELLOW}[!] Redis not available after 30s, starting anyway${NC}"
    fi
    sleep 1
done

# Tool count
AVAILABLE=$(compgen -c 2>/dev/null | sort -u | grep -cE '^(nmap|masscan|gobuster|nikto|hydra|nuclei|httpx|feroxbuster|wpscan)$' 2>/dev/null || echo "?")
echo -e "  Tools:       ${GREEN}${AVAILABLE} core tools available${NC}"

mkdir -p /opt/redrecon/data/scans
echo ""

# Symlink testssl if needed
[ -f /usr/bin/testssl ] && [ ! -f /usr/bin/testssl.sh ] && ln -s /usr/bin/testssl /usr/bin/testssl.sh

exec python3 /opt/redrecon/worker.py --concurrency "${CONCURRENCY:-3}"
