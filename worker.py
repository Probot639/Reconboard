#!/usr/bin/env python3
"""
Reconboard v4 — Worker Process
==============================
Runs inside worker containers. Pulls scan jobs from the Redis
queue, executes them, and pushes results back.

Usage:
    python3 worker.py [--concurrency 3]

Env vars:
    REDIS_URL       Redis connection string (default: redis://redis:6379/0)
    WORKER_ID       Unique worker identifier (auto-generated if not set)
    CONCURRENCY     Max parallel scans per worker (default: 3)
    SCAN_TIMEOUT    Per-scan timeout in seconds (default: 1800)
    SCAN_OUTPUT_DIR Scan output directory (default: /opt/redrecon/data/scans)
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

try:
    import redis
except ImportError:
    subprocess.run(["pip3", "install", "redis", "--break-system-packages"], check=True)
    import redis

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
WORKER_ID = os.environ.get("WORKER_ID", f"worker-{socket.gethostname()}-{uuid.uuid4().hex[:6]}")
CONCURRENCY = int(os.environ.get("CONCURRENCY", 3))
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", 1800))
SCAN_OUTPUT_DIR = Path(os.environ.get("SCAN_OUTPUT_DIR", "/opt/redrecon/data/scans"))
SCAN_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

QUEUE_NAME = "redrecon:jobs"
RESULT_PREFIX = "redrecon:result:"
WORKER_HEARTBEAT = "redrecon:workers"
CANCEL_PREFIX = "redrecon:cancel:"

# ══════════════════════════════════════════════════════════════
# WORKER STATE
# ══════════════════════════════════════════════════════════════

active_scans = {}  # scan_id -> {"proc": Popen, "profile": ..., "started": ...}
scan_semaphore = threading.Semaphore(CONCURRENCY)
shutdown_event = threading.Event()
rdb = None
stats = {
    "started_at": datetime.now().isoformat(),
    "scans_completed": 0,
    "scans_failed": 0,
    "scans_running": 0,
}


def get_redis():
    global rdb
    while not shutdown_event.is_set():
        try:
            if rdb is None:
                rdb = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=5)
            rdb.ping()
            return rdb
        except Exception as e:
            print(f"[!] Redis connection failed: {e}, retrying in 3s...")
            rdb = None
            time.sleep(3)
    return None


def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"info": "•", "success": "✓", "error": "✗", "system": "⚙"}
    print(f"  [{ts}] [{prefix.get(level, '•')}] {msg}")


# ══════════════════════════════════════════════════════════════
# HEARTBEAT
# ══════════════════════════════════════════════════════════════

def heartbeat_loop():
    """Send periodic heartbeats to Redis so the server knows we're alive."""
    while not shutdown_event.is_set():
        try:
            r = get_redis()
            if r:
                info = {
                    "worker_id": WORKER_ID,
                    "hostname": socket.gethostname(),
                    "concurrency": CONCURRENCY,
                    "active_scans": len(active_scans),
                    "scans_completed": stats["scans_completed"],
                    "scans_failed": stats["scans_failed"],
                    "last_heartbeat": datetime.utcnow().isoformat(),
                    "started_at": stats["started_at"],
                    "status": "active",
                }
                r.hset(WORKER_HEARTBEAT, WORKER_ID, json.dumps(info))
                r.expire(WORKER_HEARTBEAT, 60)
        except Exception as e:
            log(f"Heartbeat error: {e}", "error")
        time.sleep(5)


# ══════════════════════════════════════════════════════════════
# SCAN EXECUTION
# ══════════════════════════════════════════════════════════════

def execute_scan(job):
    """Execute a single scan job."""
    scan_semaphore.acquire()
    scan_id = job["scan_id"]
    profile = job["profile"]
    target = job["target"]

    try:
        log(f"Starting: {profile['name']} → {target['hostname']} ({target['ip']})", "system")
        stats["scans_running"] += 1

        # Check for cancellation
        r = get_redis()
        if r and r.get(f"{CANCEL_PREFIX}{scan_id}"):
            log(f"Scan cancelled before start: {scan_id}", "system")
            push_result(scan_id, "stopped", "", "Cancelled before execution", 0, profile)
            return

        proc = subprocess.Popen(
            profile["cmd"], shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, preexec_fn=os.setsid
        )
        active_scans[scan_id] = {"proc": proc, "profile": profile, "started": datetime.now()}

        output_lines = []
        try:
            for line in proc.stdout:
                output_lines.append(line)
                # Periodic cancellation check
                if r and r.get(f"{CANCEL_PREFIX}{scan_id}"):
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    log(f"Scan cancelled mid-execution: {scan_id}", "system")
                    push_result(scan_id, "stopped", ''.join(output_lines), "Cancelled", proc.returncode, profile)
                    return
            proc.wait(timeout=SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            log(f"Scan timed out: {profile['name']}", "error")

        output = ''.join(output_lines)
        returncode = proc.returncode or 0

        status = "completed" if returncode == 0 else "error"
        parsed_summary = f"{len(output)} bytes of output"

        push_result(scan_id, status, output, parsed_summary, returncode, profile)

        if status == "completed":
            stats["scans_completed"] += 1
            log(f"Completed: {profile['name']} ({len(output)} bytes)", "success")
        else:
            stats["scans_failed"] += 1
            log(f"Failed: {profile['name']} (rc={returncode})", "error")

    except Exception as e:
        stats["scans_failed"] += 1
        log(f"Scan error: {profile['name']} — {e}", "error")
        push_result(scan_id, "error", "", str(e), 1, profile)
    finally:
        active_scans.pop(scan_id, None)
        stats["scans_running"] = max(0, stats["scans_running"] - 1)
        scan_semaphore.release()


def push_result(scan_id, status, output, parsed_summary, returncode, profile):
    """Push scan results back to Redis for the server to pick up."""
    r = get_redis()
    if not r:
        log(f"Cannot push result for {scan_id}: Redis unavailable", "error")
        return

    result = {
        "scan_id": scan_id,
        "worker_id": WORKER_ID,
        "status": status,
        "output": output[-10000:] if output else "",
        "parsed_summary": parsed_summary,
        "returncode": returncode,
        "completed_at": datetime.now().isoformat(),
        "profile_name": profile.get("name", ""),
    }

    try:
        r.set(f"{RESULT_PREFIX}{scan_id}", json.dumps(result), ex=3600)
    except Exception as e:
        log(f"Failed to push result: {e}", "error")


# ══════════════════════════════════════════════════════════════
# JOB CONSUMER LOOP
# ══════════════════════════════════════════════════════════════

def consume_jobs():
    """Main loop: pull jobs from Redis queue and spawn execution threads."""
    log(f"Worker {WORKER_ID} started, concurrency={CONCURRENCY}", "system")

    while not shutdown_event.is_set():
        try:
            r = get_redis()
            if not r:
                time.sleep(2)
                continue

            # Blocking pop from queue (5s timeout to check shutdown)
            result = r.brpop(QUEUE_NAME, timeout=5)
            if not result:
                continue

            _, raw = result
            try:
                job = json.loads(raw)
            except json.JSONDecodeError as e:
                log(f"Invalid job data: {e}", "error")
                continue

            scan_id = job.get("scan_id")
            if not scan_id:
                log("Job missing scan_id, skipping", "error")
                continue

            # Notify server that scan is running
            try:
                run_info = json.dumps({
                    "scan_id": scan_id,
                    "worker_id": WORKER_ID,
                    "status": "running",
                    "started_at": datetime.now().isoformat(),
                })
                r.set(f"{RESULT_PREFIX}{scan_id}:status", run_info, ex=3600)
            except:
                pass

            # Execute in a thread
            thread = threading.Thread(target=execute_scan, args=(job,), daemon=True)
            thread.start()

        except Exception as e:
            log(f"Consumer error: {e}", "error")
            time.sleep(2)


# ══════════════════════════════════════════════════════════════
# GRACEFUL SHUTDOWN
# ══════════════════════════════════════════════════════════════

def shutdown_handler(signum, frame):
    log("Shutdown signal received, finishing active scans...", "system")
    shutdown_event.set()

    # Kill active processes
    for scan_id, info in active_scans.items():
        proc = info.get("proc")
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except:
                pass

    # Remove ourselves from heartbeat
    try:
        r = get_redis()
        if r:
            r.hdel(WORKER_HEARTBEAT, WORKER_ID)
    except:
        pass

    log("Worker shutdown complete", "system")
    sys.exit(0)


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reconboard v4 Worker")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help="Max parallel scans")
    args = parser.parse_args()
    CONCURRENCY = args.concurrency

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    print(f"\n╔══════════════════════════════════════════════╗")
    print(f"║       Reconboard v4 — Worker Node             ║")
    print(f"╠══════════════════════════════════════════════╣")
    print(f"║  ID:          {WORKER_ID:<30}║")
    print(f"║  Concurrency: {CONCURRENCY:<30}║")
    print(f"║  Redis:       {REDIS_URL:<30}║")
    print(f"╚══════════════════════════════════════════════╝\n")

    # Start heartbeat thread
    hb = threading.Thread(target=heartbeat_loop, daemon=True)
    hb.start()

    # Start job consumer
    consume_jobs()
