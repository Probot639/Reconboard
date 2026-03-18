.PHONY: build up down logs shell tools rebuild clean workers scale status

# ─── Build all containers ───
build:
	docker compose build

# ─── Start everything (foreground) ───
up:
	docker compose up

# ─── Start in background with default 2 workers ───
start:
	docker compose up -d --scale worker=2
	@echo ""
	@echo "Reconboard v4 running."
	@echo "  Dashboard:  http://localhost:8443"
	@echo "  Workers:    2 (use 'make scale N=5' to change)"
	@echo "  Logs:       make logs"
	@echo "  Stop:       make down"

# ─── Stop everything ───
down:
	docker compose down

# ─── Follow logs ───
logs:
	docker compose logs -f

# ─── Follow only server logs ───
logs-server:
	docker compose logs -f redrecon

# ─── Follow only worker logs ───
logs-workers:
	docker compose logs -f worker

# ─── Shell into the main server container ───
shell:
	docker exec -it reconboard /bin/bash

# ─── Shell into a worker container ───
shell-worker:
	docker compose exec worker /bin/bash

# ─── Scale workers: make scale N=5 ───
N ?= 3
scale:
	docker compose up -d --scale worker=$(N)
	@echo "Scaled to $(N) worker(s)"

# ─── Check worker status ───
workers:
	@echo "=== Worker Containers ==="
	@docker compose ps worker 2>/dev/null || echo "No workers running"
	@echo ""
	@echo "=== Redis Queue Depth ==="
	@docker exec reconboard-redis redis-cli LLEN redrecon:jobs 2>/dev/null || echo "Redis not available"
	@echo ""
	@echo "=== Worker Heartbeats ==="
	@docker exec reconboard-redis redis-cli HGETALL redrecon:workers 2>/dev/null || echo "No heartbeats"

# ─── Check tool availability inside main container ───
tools:
	docker exec -it reconboard bash -c '\
		for t in nmap masscan enum4linux smbclient smbmap crackmapexec netexec \
		         gobuster feroxbuster nikto wpscan whatweb curl dig \
		         dnsrecon dnsenum hydra redis-cli rpcclient ldapsearch \
		         searchsploit impacket-GetNPUsers medusa snmpwalk \
		         nuclei httpx subfinder naabu sqlmap hashcat john \
		         testssl.sh sslscan sslyze onesixtyone smtp-user-enum \
		         wafw00f nbtscan fping theharvester recon-ng responder \
		         evil-winrm katana; do \
			if command -v $$t &>/dev/null; then \
				echo "  [✓] $$t"; \
			else \
				echo "  [✗] $$t"; \
			fi; \
		done'

# ─── Show system status ───
status:
	@echo "=== Containers ==="
	@docker compose ps
	@echo ""
	@echo "=== Health ==="
	@curl -s http://localhost:8443/api/health 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "Server not responding"
	@echo ""
	@echo "=== Workers ==="
	@curl -s http://localhost:8443/api/workers 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "Cannot reach API"

# ─── Rebuild from scratch (no cache) ───
rebuild:
	docker compose build --no-cache

# ─── Rebuild only workers (faster iteration) ───
rebuild-workers:
	docker compose build --no-cache worker

# ─── Clean up data (DESTRUCTIVE) ───
clean:
	docker compose down -v
	rm -rf data/

# ─── Export recon data ───
export:
	@mkdir -p exports
	@cp data/store.json exports/recon-export-$$(date +%s).json 2>/dev/null && \
		echo "Exported to exports/" || echo "No data to export"

# ─── Flush the Redis job queue ───
flush-queue:
	docker exec reconboard-redis redis-cli DEL redrecon:jobs
	@echo "Job queue flushed"

# ─── Quick run: build + start with 2 workers ───
run: build start

# ─── Quick run with custom worker count: make run-scaled N=5 ───
run-scaled: build
	docker compose up -d --scale worker=$(N)
	@echo "Running with $(N) worker(s)"

# ─── Local mode (no workers, single container) ───
local:
	WORKER_MODE=local docker compose up -d redrecon redis
	@echo "Running in local mode (no workers)"
