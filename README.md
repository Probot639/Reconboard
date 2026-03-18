# Reconboard v5 — Distributed Kali Recon Server

Self-hosted automated reconnaissance dashboard with **distributed worker scaling**. Offload heavy scanning workloads across multiple Docker containers via a Redis job queue.

## Quick Start

```bash
cd redrecon

# Build and start with 3 workers (first run ~15-20 min to pull Kali + install tools)
docker compose up -d --scale worker=3

# Or use the Makefile:
make run              # 2 workers (default)
make run-scaled N=5   # 5 workers
```

Dashboard: `http://localhost:8443`

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Browser UI                    │
│              http://localhost:8443              │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│              Reconboard Server                  │
│         Flask API + Orchestrator                │
│                                                 │
│  • Web dashboard & REST API                     │
│  • Scan profile generation                      │
│  • Result parsing & integration                 │
│  • Can also execute scans locally               │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│                Redis Queue                      │
│           Job dispatch & coordination           │
│                                                 │
│  • redrecon:jobs      (pending scan queue)      │
│  • redrecon:result:*  (completed results)       │
│  • redrecon:workers   (heartbeat registry)      │
└────────────────────┬────────────────────────────┘
                     │
         ┌───────────┼───────────┐
         ▼           ▼           ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  Worker #1   │ │  Worker #2   │ │  Worker #N   │
│  (Kali box)  │ │  (Kali box)  │ │  (Kali box)  │
│              │ │              │ │              │
│ Pulls jobs   │ │ Pulls jobs   │ │ Pulls jobs   │
│ Runs scans   │ │ Runs scans   │ │ Runs scans   │
│ Pushes       │ │ Pushes       │ │ Pushes       │
│ results back │ │ results back │ │ results back │
└──────────────┘ └──────────────┘ └──────────────┘
```

## What's In The Container

Based on `kalilinux/kali-rolling` with **50+ recon tools** pre-installed:

| Category | Tools |
|----------|-------|
| **Port Scanning** | nmap, masscan, naabu |
| **SMB/AD** | enum4linux, smbclient, smbmap, crackmapexec/netexec, rpcclient, ldapsearch, evil-winrm, bloodhound |
| **Web** | gobuster, feroxbuster, dirb, nikto, wpscan, whatweb, httpx, wafw00f, katana |
| **DNS** | dig, dnsrecon, dnsenum, subfinder |
| **Vuln Scanning** | nuclei, sqlmap, searchsploit, testssl.sh, sslscan, sslyze |
| **Credential** | hydra, medusa, hashcat, john |
| **Database** | redis-cli |
| **Network** | nbtscan, fping, hping3, arping, arp-scan, netdiscover, tcpdump, ngrep, p0f |
| **SNMP** | snmpwalk, onesixtyone |
| **SMTP** | swaks, smtp-user-enum |
| **Impacket** | GetNPUsers, GetUserSPNs, smbclient, secretsdump, certipy-ad |
| **OSINT** | theharvester, recon-ng, whois |
| **Wordlists** | SecLists, dirbuster, rockyou |

## Worker Scaling

Scale workers dynamically — each worker pulls jobs from the Redis queue independently:

```bash
# Scale to 5 workers
docker compose up -d --scale worker=5

# Scale to 10 workers
docker compose up -d --scale worker=10

# Scale back to 1
docker compose up -d --scale worker=1

# Check worker status
make workers
make status
```

Each worker runs up to 3 concurrent scans by default (`WORKER_CONCURRENCY`).

## Execution Modes

Toggle via the Workers tab in the UI or environment variable:

- **Local** (`WORKER_MODE=local`): All scans run on the main server. No Redis needed.
- **Distributed** (`WORKER_MODE=distributed`): Scans dispatched to workers via Redis queue. Falls back to local if Redis is unavailable.

## Docker Commands

```bash
docker compose up -d --scale worker=3   # Start with 3 workers
docker compose logs -f                   # View all logs
docker compose logs -f worker            # View only worker logs
docker exec -it redrecon bash            # Shell into server
docker compose exec worker bash          # Shell into a worker
docker compose down                      # Stop everything
docker compose build --no-cache          # Full rebuild
```

## Makefile Shortcuts

```bash
make run              # Build + start (2 workers)
make run-scaled N=5   # Build + start with N workers
make scale N=10       # Scale to N workers
make workers          # Show worker status + queue depth
make status           # Full system status
make down             # Stop everything
make logs             # Follow all logs
make logs-server      # Follow server logs
make logs-workers     # Follow worker logs
make shell            # Bash into server
make shell-worker     # Bash into a worker
make tools            # Check all tool availability
make rebuild          # Full rebuild (no cache)
make rebuild-workers  # Rebuild only worker image
make flush-queue      # Clear pending jobs
make export           # Export recon data
make local            # Run in local mode (no workers)
make clean            # Stop + delete all data (DESTRUCTIVE)
```

## Network Configuration

Uses `network_mode: "host"` by default so containers directly reach competition targets. Runs `privileged` for SYN scans and raw sockets.

For isolated/bridged networking, edit `docker-compose.yml`:
```yaml
# Comment out network_mode: "host" and privileged: true, then:
ports:
  - "8443:8443"
cap_add:
  - NET_RAW
  - NET_ADMIN
```

## Persistent Data

All data persists in `./data/` on the host:
```
data/
├── store.json      # Targets, findings, creds, notes
└── scans/          # Raw tool output files
```

Shared across server and all workers via volume mount. Survives restarts.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDRECON_PORT` | `8443` | Server port |
| `WORKER_MODE` | `distributed` | `local` or `distributed` |
| `MAX_CONCURRENT_SCANS` | `5` | Max parallel scans on server |
| `WORKER_CONCURRENCY` | `3` | Max parallel scans per worker |
| `SCAN_TIMEOUT` | `1800` | Per-scan timeout (seconds) |
| `REDIS_URL` | `redis://127.0.0.1:6379/0` | Redis connection string |
| `REDRECON_API_KEY` | *(empty)* | Optional API key for auth |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/state` | Full application state |
| GET | `/api/health` | Health check + version |
| POST | `/api/targets` | Add target |
| DELETE | `/api/targets/:id` | Delete target |
| GET | `/api/targets/:id/profiles` | Available scan profiles |
| POST | `/api/scan` | Start single scan |
| POST | `/api/scan/batch` | Start multiple scans |
| POST | `/api/scan/all` | Scan all targets with IPs |
| POST | `/api/scan/:id/stop` | Stop a scan |
| GET | `/api/workers` | Worker status + queue depth |
| POST | `/api/workers/mode` | Set execution mode |
| POST | `/api/workers/queue/flush` | Clear job queue |
| POST | `/api/import` | Import tool output |
| GET | `/api/export` | Export all data |
| GET | `/api/tools` | Check installed tools |

## Scan Profiles

Scans are organized in 4 phases, each with required/recommended/optional priority:

1. **Discovery** — Port scanning (nmap, masscan, naabu)
2. **Service Enumeration** — Service-specific probes (SMB, FTP, Web, DNS, Redis, MySQL, SNMP, SMTP, SSH, VNC, MongoDB)
3. **Vulnerability Assessment** — Vuln scanning (nmap vuln scripts, nuclei)
4. **Credential Attacks** — Brute force (hydra, medusa)

Profiles are auto-generated based on detected services and open ports.
