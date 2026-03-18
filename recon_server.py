#!/usr/bin/env python3
"""
Reconboard v5 — Distributed Kali Reconnaissance Server
======================================================
Self-hosted recon dashboard with worker container scaling.
Distributes scan workloads across multiple Docker containers
via a Redis job queue. Session-based auth for browser access.

Usage:
    sudo python3 recon_server.py [--port 8443] [--host 0.0.0.0]

Requires: Python 3.10+, Flask, Redis
Must run as root for SYN scans and privileged nmap.
"""

import argparse
import glob
import json
import os
import re
import signal
import subprocess
import threading
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

try:
    from flask import (
        Flask, jsonify, request, render_template, send_from_directory,
        Response, session, redirect, url_for
    )
except ImportError:
    subprocess.run(["pip3", "install", "flask", "--break-system-packages"], check=True)
    from flask import (
        Flask, jsonify, request, render_template, send_from_directory,
        Response, session, redirect, url_for
    )

try:
    import redis
except ImportError:
    subprocess.run(["pip3", "install", "redis", "--break-system-packages"], check=True)
    import redis

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════

DATA_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).parent / "data"))
DATA_DIR.mkdir(exist_ok=True)
SCAN_OUTPUT_DIR = DATA_DIR / "scans"
SCAN_OUTPUT_DIR.mkdir(exist_ok=True)

MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", 5))
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", 1800))
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
API_KEY = os.environ.get("REDRECON_API_KEY", "")  # optional auth
WORKER_MODE = os.environ.get("WORKER_MODE", "local")  # local | distributed

app = Flask(__name__, template_folder="templates", static_folder="static")
# Secret key: use env var if non-empty, otherwise generate one at startup
_sk = os.environ.get("SECRET_KEY", "")
app.secret_key = _sk if _sk else uuid.uuid4().hex + uuid.uuid4().hex
app.permanent_session_lifetime = timedelta(hours=12)

AUTH_PASSWORD = os.environ.get("REDRECON_PASSWORD", "")  # REQUIRED — set this or anyone can log in

# ══════════════════════════════════════════════════════════════
# REDIS CONNECTION
# ══════════════════════════════════════════════════════════════

rdb = None

def get_redis():
    global rdb
    if rdb is None:
        try:
            rdb = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=5)
            rdb.ping()
            print(f"[+] Redis connected: {REDIS_URL}")
        except Exception as e:
            print(f"[!] Redis unavailable ({e}), falling back to local mode")
            rdb = None
    return rdb

def redis_available():
    r = get_redis()
    if r is None:
        return False
    try:
        r.ping()
        return True
    except:
        return False

# ══════════════════════════════════════════════════════════════
# IN-MEMORY DATA STORE (persisted to JSON)
# ══════════════════════════════════════════════════════════════

store_lock = threading.Lock()

store = {
    "targets": [
        {"id": "blue-1", "hostname": "svc-ad-01", "ip": "", "os": "Windows Server 2022", "role": "Service", "services": ["AD/DNS"], "team": "blue", "status": "pending", "openPorts": [], "scanHistory": [], "detectedOs": ""},
        {"id": "blue-2", "hostname": "svc-smb-01", "ip": "", "os": "Windows 11", "role": "Service", "services": ["SMB"], "team": "blue", "status": "pending", "openPorts": [], "scanHistory": [], "detectedOs": ""},
        {"id": "blue-3", "hostname": "svc-ftp-01", "ip": "", "os": "Ubuntu 24.04", "role": "Service", "services": ["VSFTPD"], "team": "blue", "status": "pending", "openPorts": [], "scanHistory": [], "detectedOs": ""},
        {"id": "blue-4", "hostname": "svc-redis-01", "ip": "", "os": "Ubuntu 24.04", "role": "Service", "services": ["Redis", "Flask", "Nginx Web App"], "team": "blue", "status": "pending", "openPorts": [], "scanHistory": [], "detectedOs": ""},
        {"id": "blue-5", "hostname": "svc-database-01", "ip": "", "os": "Ubuntu 24.04", "role": "Service", "services": ["Redis", "Nginx DB"], "team": "blue", "status": "pending", "openPorts": [], "scanHistory": [], "detectedOs": ""},
        {"id": "blue-6", "hostname": "svc-amazin-01", "ip": "", "os": "Ubuntu 24.04", "role": "Service", "services": ["Wordpress"], "team": "blue", "status": "pending", "openPorts": [], "scanHistory": [], "detectedOs": ""},
        {"id": "blue-7", "hostname": "svc-samba-01", "ip": "", "os": "Ubuntu 24.04", "role": "Service", "services": ["LAMP stack"], "team": "blue", "status": "pending", "openPorts": [], "scanHistory": [], "detectedOs": ""},
    ],
    "findings": [],
    "notes": [],
    "creds": [],
    "scans": [],
    "workers": [],
    "log": [
        {"time": datetime.now().isoformat(), "msg": "Reconboard v5 server started", "type": "system"},
    ],
}


def save_store():
    with store_lock:
        path = DATA_DIR / "store.json"
        with open(path, "w") as f:
            json.dump(store, f, indent=2, default=str)


def load_store():
    global store
    path = DATA_DIR / "store.json"
    if path.exists():
        try:
            with open(path) as f:
                loaded = json.load(f)
            for key in store:
                if key not in loaded:
                    loaded[key] = store[key]
            store = loaded
            print(f"[+] Loaded saved state: {len(store['targets'])} targets, {len(store['findings'])} findings")
        except Exception as e:
            print(f"[!] Failed to load state: {e}")


def add_log(msg, log_type="info"):
    with store_lock:
        store["log"].append({"time": datetime.now().isoformat(), "msg": msg, "type": log_type})
        if len(store["log"]) > 500:
            store["log"] = store["log"][-500:]


# ══════════════════════════════════════════════════════════════
# AUTH MIDDLEWARE
# ══════════════════════════════════════════════════════════════

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # No password set = wide open (for dev only, not recommended)
        if not AUTH_PASSWORD:
            return f(*args, **kwargs)
        # Check API key header (for workers, scripts, curl)
        api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if api_key and api_key == API_KEY and API_KEY:
            return f(*args, **kwargs)
        # Check session cookie (for browser)
        if session.get("authenticated"):
            return f(*args, **kwargs)
        # Check basic auth (for curl convenience)
        auth = request.authorization
        if auth and auth.password == AUTH_PASSWORD:
            return f(*args, **kwargs)
        # API routes return 401 JSON, page routes redirect to login
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect("/login")
    return decorated


@app.before_request
def check_auth():
    # Whitelist: login page, static assets, health check
    open_paths = ["/login", "/static/", "/api/health"]
    if any(request.path.startswith(p) for p in open_paths):
        return
    if request.path == "/favicon.ico":
        return
    if not AUTH_PASSWORD:
        return
    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if api_key and api_key == API_KEY and API_KEY:
        return
    if session.get("authenticated"):
        return
    auth = request.authorization
    if auth and auth.password == AUTH_PASSWORD:
        return
    if request.path.startswith("/api/"):
        return jsonify({"error": "Unauthorized"}), 401
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.json if request.is_json else request.form
        password = data.get("password", "")
        if password == AUTH_PASSWORD:
            session["authenticated"] = True
            session.permanent = True
            if request.is_json:
                return jsonify({"status": "ok"})
            return redirect("/")
        if request.is_json:
            return jsonify({"error": "Invalid password"}), 401
        return render_template("login.html", error="Invalid password")
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ══════════════════════════════════════════════════════════════
# OUTPUT PARSERS
# ══════════════════════════════════════════════════════════════

def parse_nmap_text(text):
    results = []
    blocks = re.split(r'Nmap scan report for ', text)
    for block in blocks[1:]:
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', block)
        if not ip_match:
            continue
        ip = ip_match.group(1)
        hostname_match = re.match(r'^([^\s(]+)', block)
        hostname = hostname_match.group(1) if hostname_match and hostname_match.group(1) != ip else ""
        ports = []
        for m in re.finditer(r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)', block):
            ports.append({
                "port": int(m.group(1)), "protocol": m.group(2),
                "state": m.group(3), "service": m.group(4),
                "version": m.group(5).strip()
            })
        os_match = re.search(r'OS details?:\s*(.+)', block, re.I) or re.search(r'Running:\s*(.+)', block, re.I)
        results.append({
            "ip": ip, "hostname": hostname, "ports": ports,
            "os": os_match.group(1).strip() if os_match else ""
        })
    return results


def parse_nmap_xml(text):
    import xml.etree.ElementTree as ET
    results = []
    try:
        root = ET.fromstring(text)
        for host in root.findall('.//host'):
            addr = host.find('address[@addrtype="ipv4"]')
            ip = addr.get('addr', '') if addr is not None else ''
            hn = host.find('.//hostname')
            hostname = hn.get('name', '') if hn is not None else ''
            ports = []
            for p in host.findall('.//port'):
                state_el = p.find('state')
                svc_el = p.find('service')
                ports.append({
                    "port": int(p.get('portid', 0)),
                    "protocol": p.get('protocol', ''),
                    "state": state_el.get('state', '') if state_el is not None else '',
                    "service": svc_el.get('name', '') if svc_el is not None else '',
                    "version": ' '.join(filter(None, [
                        svc_el.get('product', '') if svc_el is not None else '',
                        svc_el.get('version', '') if svc_el is not None else '',
                        svc_el.get('extrainfo', '') if svc_el is not None else '',
                    ]))
                })
            scripts = []
            for script in host.findall('.//script'):
                sid = script.get('id', '')
                sout = script.get('output', '')
                if sid and sout:
                    scripts.append({"id": sid, "output": sout})
            os_match = host.find('.//osmatch')
            result = {
                "ip": ip, "hostname": hostname, "ports": ports,
                "os": os_match.get('name', '') if os_match is not None else ""
            }
            if scripts:
                result["scripts"] = scripts
            results.append(result)
    except Exception as e:
        add_log(f"XML parse error: {e}", "error")
    return results


def parse_enum4linux(text):
    result = {"shares": [], "users": [], "groups": [], "info": {}}
    for m in re.finditer(r'username:\s*(\S+)', text, re.I):
        if m.group(1) not in result["users"]:
            result["users"].append(m.group(1))
    for m in re.finditer(r'group:\[([^\]]+)\]', text, re.I):
        result["groups"].append(m.group(1))
    for m in re.finditer(r'\s+(\\\\[^\s]+)\s+Mapping:\s+(\w+),\s+Listing:\s+(\w+)', text):
        result["shares"].append({"name": m.group(1), "mapping": m.group(2), "listing": m.group(3)})
    os_match = re.search(r'OS:\s*(.+)', text)
    if os_match:
        result["info"]["os"] = os_match.group(1).strip()
    return result


def parse_gobuster(text):
    paths = []
    for m in re.finditer(r'^(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?', text, re.M):
        paths.append({"path": m.group(1), "status": int(m.group(2)), "size": int(m.group(3)) if m.group(3) else None})
    for m in re.finditer(r'^(\d{3})\s+\w+\s+(\d+)l\s+\d+w\s+(\d+)c\s+(https?://\S+)', text, re.M):
        paths.append({"path": m.group(4), "status": int(m.group(1)), "size": int(m.group(3))})
    return paths


def parse_nikto(text):
    findings = []
    skip_patterns = [
        r'Target IP:', r'Target Hostname:', r'Target Port:', r'Start Time:', r'End Time:',
        r'host\(s\) tested', r'requests:', r'No CGI Directories', r'Nikto v',
    ]
    for m in re.finditer(r'^\+\s+(.+?):\s+(.+)', text, re.M):
        label = m.group(1).strip()
        detail = m.group(2).strip()
        # Skip metadata lines
        if any(re.search(pat, label + ': ' + detail, re.I) for pat in skip_patterns):
            continue
        if label.startswith('Server') or label.startswith('Root page'):
            continue
        # Score severity
        detail_lower = detail.lower()
        if any(w in detail_lower for w in ['directory indexing', 'config', '.git', '.env', '.htaccess', 'backup', 'source code']):
            sev = "high"
        elif 'OSVDB' in label:
            sev = "medium"
        elif any(w in detail_lower for w in ['default file', 'readme', 'license', 'robots.txt']):
            sev = "low"
        elif any(w in detail_lower for w in ['x-frame', 'x-content-type', 'httponly', 'secure flag', 'clickjack']):
            sev = "low"
        elif any(w in detail_lower for w in ['sql', 'injection', 'rce', 'remote code', 'command execution', 'traversal', 'lfi', 'rfi']):
            sev = "critical"
        elif any(w in detail_lower for w in ['xss', 'cross-site', 'csrf', 'redirect', 'open redirect']):
            sev = "high"
        else:
            sev = "medium"
        findings.append({"id": label, "detail": detail, "severity": sev})
    return findings


def parse_wpscan(text):
    result = {"version": "", "users": [], "vulns": [], "plugins": [], "themes": []}
    vm = re.search(r'WordPress version\s+([\d.]+)', text, re.I)
    if vm:
        result["version"] = vm.group(1)
    for m in re.finditer(r'\|\s+(\S+)', text):
        val = m.group(1)
        if val and not val.startswith(('http', '|', '-', '+', '[', 'Title', 'Fixed')):
            if val not in result["users"]:
                result["users"].append(val)
    for m in re.finditer(r'Title:\s+(.+)', text):
        result["vulns"].append(m.group(1).strip())
    return result


def parse_redis_info(text):
    info = {}
    for line in text.split('\n'):
        if ':' in line and not line.startswith('#'):
            k, v = line.split(':', 1)
            info[k.strip()] = v.strip()
    return info


def parse_smbmap(text):
    shares = []
    for m in re.finditer(r'^\s+(\S+)\s+(READ|WRITE|NO ACCESS|READ, WRITE)\s+(.*)$', text, re.M):
        shares.append({"name": m.group(1), "access": m.group(2), "comment": m.group(3).strip()})
    return shares


def parse_whatweb(text):
    techs = []
    for m in re.finditer(r'\[([^\]]+)\]', text):
        techs.append(m.group(1))
    return techs


def parse_nuclei(text):
    findings = []
    for line in text.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        m = re.match(r'\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)', line)
        if m:
            findings.append({
                "severity": m.group(1).lower(),
                "template": m.group(2),
                "protocol": m.group(3),
                "url": m.group(4).strip(),
            })
        else:
            try:
                j = json.loads(line)
                findings.append({
                    "severity": j.get("info", {}).get("severity", "info"),
                    "template": j.get("template-id", j.get("template", "")),
                    "protocol": j.get("type", ""),
                    "url": j.get("matched-at", j.get("host", "")),
                    "name": j.get("info", {}).get("name", ""),
                    "description": j.get("info", {}).get("description", ""),
                })
            except json.JSONDecodeError:
                continue
    return findings


def parse_testssl(text):
    findings = []
    for m in re.finditer(r'(VULNERABLE|NOT\s+ok|WARN|INFO|OK)\s+(.+)', text, re.I):
        findings.append({"status": m.group(1).strip(), "detail": m.group(2).strip()})
    for m in re.finditer(r'(CVE-\d{4}-\d+)\s+(.+)', text):
        findings.append({"cve": m.group(1), "detail": m.group(2).strip()})
    return findings


def parse_subfinder(text):
    subs = []
    for line in text.strip().split('\n'):
        line = line.strip()
        if line and not line.startswith('#') and '.' in line:
            subs.append(line)
    return list(set(subs))


def parse_snmpwalk(text):
    entries = []
    for line in text.strip().split('\n'):
        m = re.match(r'([\w:.]+)\s+=\s+(\S+):\s*(.*)', line)
        if m:
            entries.append({"oid": m.group(1), "type": m.group(2), "value": m.group(3).strip()})
    return entries


def auto_detect_and_parse(text):
    text_stripped = text.strip()
    if text_stripped.startswith('<?xml') or '<nmaprun' in text_stripped[:500]:
        return "nmap_xml", parse_nmap_xml(text)
    if 'Nmap scan report for' in text or ('PORT' in text and 'STATE' in text and 'SERVICE' in text):
        return "nmap_text", parse_nmap_text(text)
    if 'enum4linux' in text.lower() or ('Sharename' in text and 'Mapping' in text):
        return "enum4linux", parse_enum4linux(text)
    if '(Status:' in text:
        return "gobuster", parse_gobuster(text)
    if 'Nikto' in text or 'OSVDB' in text:
        return "nikto", parse_nikto(text)
    if 'WPScan' in text or '[+] WordPress' in text:
        return "wpscan", parse_wpscan(text)
    if 'redis_version' in text or 'redis_mode' in text:
        return "redis", parse_redis_info(text)
    if 'READ' in text and 'NO ACCESS' in text:
        return "smbmap", parse_smbmap(text)
    if 'WhatWeb' in text or (text.count('[') > 3 and 'http' in text.lower()):
        return "whatweb", parse_whatweb(text)
    if '[critical]' in text.lower() or '[high]' in text.lower() or 'template-id' in text:
        return "nuclei", parse_nuclei(text)
    if 'testssl' in text.lower() or 'VULNERABLE' in text:
        return "testssl", parse_testssl(text)
    if 'SNMPv2-MIB' in text or 'iso.' in text:
        return "snmpwalk", parse_snmpwalk(text)
    return "unknown", text


def integrate_nmap_results(parsed, source="nmap"):
    updated = 0
    created = 0
    new_findings = 0
    with store_lock:
        for result in parsed:
            ip = result.get("ip", "")
            if not ip:
                continue
            target = None
            for t in store["targets"]:
                if t["ip"] and t["ip"] == ip:
                    target = t
                    break
                if result.get("hostname") and t["hostname"].lower() == result["hostname"].lower():
                    target = t
                    break
            if target:
                if ip:
                    target["ip"] = ip
                if result.get("os"):
                    target["detectedOs"] = result["os"]
                target["status"] = "scanned"
                target["lastScan"] = datetime.now().isoformat()
                target["openPorts"] = [p for p in result["ports"] if p["state"] == "open"]
                target["scanHistory"].append({
                    "tool": source, "time": datetime.now().isoformat(),
                    "summary": f"{len(target['openPorts'])} open ports"
                })
                updated += 1
            else:
                new_target = {
                    "id": f"disc-{uuid.uuid4().hex[:8]}",
                    "hostname": result.get("hostname") or ip,
                    "ip": ip, "os": result.get("os") or "Unknown",
                    "role": "Discovered", "services": [], "team": "unknown",
                    "status": "scanned", "lastScan": datetime.now().isoformat(),
                    "openPorts": [p for p in result["ports"] if p["state"] == "open"],
                    "scanHistory": [{"tool": source, "time": datetime.now().isoformat(), "summary": "Initial scan"}],
                    "detectedOs": result.get("os", ""),
                }
                store["targets"].append(new_target)
                created += 1
            crit_ports = {21, 23, 445, 3389, 5985, 6379}
            high_ports = {53, 88, 135, 139, 389, 636, 1433, 3306, 5432, 5900, 11211, 27017}
            for port in result["ports"]:
                if port["state"] != "open":
                    continue
                fid = f"f-{ip}-{port['port']}-{port['protocol']}"
                if not any(f["id"] == fid for f in store["findings"]):
                    sev = "high" if port["port"] in crit_ports else "medium" if port["port"] in high_ports else "info"
                    store["findings"].append({
                        "id": fid, "targetIp": ip, "port": port["port"],
                        "protocol": port["protocol"], "service": port["service"],
                        "version": port["version"], "severity": sev,
                        "timestamp": datetime.now().isoformat(), "source": source,
                    })
                    new_findings += 1
    return updated, created, new_findings


# ══════════════════════════════════════════════════════════════
# SCAN EXECUTION ENGINE
# ══════════════════════════════════════════════════════════════

scan_semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)
active_processes = {}

def check_tool(tool_name):
    return subprocess.run(["which", tool_name], capture_output=True).returncode == 0

TOOL_CHECKS_CACHE = {}

def is_tool_available(tool_name):
    if tool_name not in TOOL_CHECKS_CACHE:
        TOOL_CHECKS_CACHE[tool_name] = check_tool(tool_name)
    return TOOL_CHECKS_CACHE[tool_name]


def get_scan_profiles(target):
    ip = target["ip"]
    h = target["hostname"]
    svcs = [s.lower() for s in target.get("services", [])]
    open_ports = [p["port"] for p in target.get("openPorts", [])]
    profiles = []

    # ── PHASE 1: Discovery ──
    profiles.append({
        "id": "nmap_quick", "name": "Nmap Quick Scan",
        "desc": "SYN scan with version detection, scripts, OS detection",
        "tool": "nmap", "phase": 1, "mitre": ["T1595.001", "T1046"],
        "cmd": f"nmap -sS -sV -sC -O -T4 {ip} -oN {SCAN_OUTPUT_DIR}/{h}_quick.txt -oX {SCAN_OUTPUT_DIR}/{h}_quick.xml",
        "parser": "nmap", "priority": "required",
    })
    profiles.append({
        "id": "nmap_full", "name": "Nmap Full TCP",
        "desc": "All 65535 TCP ports",
        "tool": "nmap", "phase": 1, "mitre": ["T1595.001"],
        "cmd": f"nmap -sS -p- -T4 --min-rate=1000 {ip} -oN {SCAN_OUTPUT_DIR}/{h}_alltcp.txt -oX {SCAN_OUTPUT_DIR}/{h}_alltcp.xml",
        "parser": "nmap", "priority": "required",
    })
    profiles.append({
        "id": "nmap_udp", "name": "Nmap UDP Top 50",
        "desc": "Top 50 UDP ports",
        "tool": "nmap", "phase": 1, "mitre": ["T1595.001"],
        "cmd": f"nmap -sU --top-ports 50 -T4 {ip} -oN {SCAN_OUTPUT_DIR}/{h}_udp.txt -oX {SCAN_OUTPUT_DIR}/{h}_udp.xml",
        "parser": "nmap", "priority": "recommended",
    })
    if is_tool_available("masscan"):
        profiles.append({
            "id": "masscan_full", "name": "Masscan Full TCP",
            "desc": "Ultra-fast all-port scan (verify with nmap after)",
            "tool": "masscan", "phase": 1, "mitre": ["T1595.001"],
            "cmd": f"masscan -p1-65535 {ip} --rate=1000 -oL {SCAN_OUTPUT_DIR}/{h}_masscan.txt",
            "parser": "masscan", "priority": "optional",
        })
    if is_tool_available("naabu"):
        profiles.append({
            "id": "naabu_fast", "name": "Naabu Fast Port Scan",
            "desc": "SYN port scan with naabu (fast, modern)",
            "tool": "naabu", "phase": 1, "mitre": ["T1595.001"],
            "cmd": f"naabu -host {ip} -top-ports 1000 -silent -o {SCAN_OUTPUT_DIR}/{h}_naabu.txt 2>&1",
            "parser": "raw", "priority": "optional",
        })

    # ── PHASE 2: Service-Specific ──

    # AD/DNS
    if any(s in ' '.join(svcs) for s in ['ad', 'dns']) or 53 in open_ports or 88 in open_ports:
        if is_tool_available("dig"):
            profiles.append({
                "id": "dig_axfr", "name": "DNS Zone Transfer",
                "desc": "Attempt zone transfer", "tool": "dig", "phase": 2,
                "mitre": ["T1018"],
                "cmd": f"dig axfr @{ip} 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_dig.txt",
                "parser": "raw", "priority": "required",
            })
        if is_tool_available("dnsrecon"):
            profiles.append({
                "id": "dnsrecon", "name": "DNSRecon Enum",
                "desc": "DNS enumeration with brute force", "tool": "dnsrecon", "phase": 2,
                "mitre": ["T1018"],
                "cmd": f"dnsrecon -n {ip} -t std,brt 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_dnsrecon.txt",
                "parser": "raw", "priority": "recommended",
            })
        if is_tool_available("dnsenum"):
            profiles.append({
                "id": "dnsenum", "name": "DNSEnum Brute",
                "desc": "DNS enumeration with brute force subdomain discovery", "tool": "dnsenum", "phase": 2,
                "mitre": ["T1018"],
                "cmd": f"dnsenum --dnsserver {ip} --enum 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_dnsenum.txt",
                "parser": "raw", "priority": "optional",
            })
        if is_tool_available("ldapsearch"):
            profiles.append({
                "id": "ldap_anon", "name": "LDAP Anonymous Bind",
                "desc": "Test anonymous LDAP access", "tool": "ldapsearch", "phase": 2,
                "mitre": ["T1087.002"],
                "cmd": f"ldapsearch -x -H ldap://{ip} -s base namingContexts 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_ldap.txt",
                "parser": "raw", "priority": "required",
            })
        if is_tool_available("rpcclient"):
            profiles.append({
                "id": "rpc_null", "name": "RPC Null Session",
                "desc": "Enumerate users/groups via null session", "tool": "rpcclient", "phase": 2,
                "mitre": ["T1087.002", "T1069"],
                "cmd": f'rpcclient -U "" -N {ip} -c "enumdomusers;enumdomgroups;getdompwinfo" 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_rpc.txt',
                "parser": "raw", "priority": "required",
            })
        if is_tool_available("crackmapexec") or is_tool_available("netexec"):
            cme = "netexec" if is_tool_available("netexec") else "crackmapexec"
            profiles.append({
                "id": "cme_enum", "name": "NetExec/CME Enum",
                "desc": "SMB null auth enumeration", "tool": cme, "phase": 2,
                "mitre": ["T1135", "T1087.002"],
                "cmd": f"{cme} smb {ip} -u '' -p '' --shares --users --groups 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_cme.txt",
                "parser": "raw", "priority": "required",
            })
        profiles.append({
            "id": "nmap_kerb", "name": "Kerberos User Enum",
            "desc": "Enumerate valid usernames via Kerberos", "tool": "nmap", "phase": 2,
            "mitre": ["T1087.002"],
            "cmd": f"nmap -p 88 --script=krb5-enum-users --script-args='krb5-enum-users.realm=\"YOURDOMAIN\",userdb=/usr/share/seclists/Usernames/Names/names.txt' {ip} -oN {SCAN_OUTPUT_DIR}/{h}_kerb.txt",
            "parser": "raw", "priority": "recommended",
        })
        if is_tool_available("impacket-GetNPUsers"):
            profiles.append({
                "id": "asrep_roast", "name": "AS-REP Roasting",
                "desc": "Find accounts without Kerberos pre-auth", "tool": "impacket-GetNPUsers", "phase": 2,
                "mitre": ["T1558.004"],
                "cmd": f"impacket-GetNPUsers -dc-ip {ip} -no-pass -usersfile /usr/share/seclists/Usernames/Names/names.txt YOURDOMAIN/ 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_asrep.txt",
                "parser": "raw", "priority": "recommended",
            })

    # SMB / Samba
    if any(s in ' '.join(svcs) for s in ['smb', 'samba']) or 445 in open_ports or 139 in open_ports:
        if is_tool_available("enum4linux-ng") or is_tool_available("enum4linux"):
            e4l = "enum4linux-ng" if is_tool_available("enum4linux-ng") else "enum4linux"
            profiles.append({
                "id": "e4l_full", "name": "enum4linux Full Enum",
                "desc": "Complete SMB/RPC enumeration", "tool": e4l, "phase": 2,
                "mitre": ["T1135", "T1087.002", "T1069"],
                "cmd": f"{e4l} -A {ip} 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_e4l.txt",
                "parser": "enum4linux", "priority": "required",
            })
        if is_tool_available("smbclient"):
            profiles.append({
                "id": "smb_shares", "name": "SMB List Shares",
                "desc": "Null-auth share listing", "tool": "smbclient", "phase": 2,
                "mitre": ["T1135"],
                "cmd": f"smbclient -L //{ip} -N 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_smbclient.txt",
                "parser": "raw", "priority": "required",
            })
        if is_tool_available("smbmap"):
            profiles.append({
                "id": "smbmap", "name": "SMBMap Permissions",
                "desc": "Map share access levels", "tool": "smbmap", "phase": 2,
                "mitre": ["T1135"],
                "cmd": f"smbmap -H {ip} -u '' -p '' 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_smbmap.txt",
                "parser": "smbmap", "priority": "required",
            })
        profiles.append({
            "id": "nmap_smb", "name": "Nmap SMB Vulns",
            "desc": "SMB vulnerability scripts (EternalBlue etc.)", "tool": "nmap", "phase": 2,
            "mitre": ["T1595.002"],
            "cmd": f"nmap -p 445 --script=smb-vuln*,smb-enum-shares,smb-enum-users,smb-os-discovery {ip} -oN {SCAN_OUTPUT_DIR}/{h}_smb_vuln.txt",
            "parser": "nmap", "priority": "required",
        })

    # FTP
    if any('ftp' in s or 'vsftpd' in s for s in svcs) or 21 in open_ports:
        profiles.append({
            "id": "nmap_ftp", "name": "FTP Script Scan",
            "desc": "FTP anon, bounce, VSFTPD backdoor checks", "tool": "nmap", "phase": 2,
            "mitre": ["T1046", "T1595.002"],
            "cmd": f"nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 {ip} -oN {SCAN_OUTPUT_DIR}/{h}_ftp.txt",
            "parser": "nmap", "priority": "required",
        })
        profiles.append({
            "id": "ftp_anon", "name": "FTP Anonymous Login",
            "desc": "Test anonymous FTP access", "tool": "curl", "phase": 2,
            "mitre": ["T1046"],
            "cmd": f"curl -s --max-time 10 ftp://{ip}/ --user anonymous:anonymous --list-only 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_ftp_anon.txt",
            "parser": "raw", "priority": "required",
        })
        if is_tool_available("searchsploit"):
            profiles.append({
                "id": "ss_vsftpd", "name": "SearchSploit VSFTPD",
                "desc": "Check ExploitDB for VSFTPD vulns", "tool": "searchsploit", "phase": 2,
                "mitre": ["T1595.002"],
                "cmd": f"searchsploit vsftpd 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_ss_vsftpd.txt",
                "parser": "raw", "priority": "required",
            })

    # Web services
    has_web = any(s in ' '.join(svcs) for s in ['web', 'nginx', 'flask', 'lamp', 'apache', 'http', 'wordpress', 'dvwa', 'webgoat', 'juice', 'tomcat', 'iis', 'caddy', 'lighttpd', 'httpd', 'php', 'node', 'rails', 'django', 'spring', 'meshkit', 'webapp', 'cms', 'joomla', 'drupal', 'magento', 'prestashop', 'moodle', 'gitlab', 'jenkins', 'grafana', 'kibana', 'nextcloud', 'owncloud', 'roundcube', 'phpmyadmin', 'adminer'])
    if has_web or any(p in open_ports for p in [80, 443, 8080, 8443]):
        if is_tool_available("whatweb"):
            profiles.append({
                "id": "whatweb", "name": "WhatWeb Fingerprint",
                "desc": "Identify web technologies", "tool": "whatweb", "phase": 2,
                "mitre": ["T1082"],
                "cmd": f"whatweb -a 3 http://{ip} 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_whatweb.txt",
                "parser": "whatweb", "priority": "required",
            })
        if is_tool_available("httpx"):
            profiles.append({
                "id": "httpx_probe", "name": "HTTPX Probe",
                "desc": "HTTP probe with tech detection, status, title", "tool": "httpx", "phase": 2,
                "mitre": ["T1082"],
                "cmd": f"echo '{ip}' | httpx -silent -title -tech-detect -status-code -follow-redirects -o {SCAN_OUTPUT_DIR}/{h}_httpx.txt 2>&1",
                "parser": "raw", "priority": "recommended",
            })
        profiles.append({
            "id": "curl_headers", "name": "HTTP Headers",
            "desc": "Grab response headers", "tool": "curl", "phase": 2,
            "mitre": ["T1082"],
            "cmd": f"curl -sI http://{ip} 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_headers.txt",
            "parser": "raw", "priority": "required",
        })
        profiles.append({
            "id": "curl_robots", "name": "Robots.txt",
            "desc": "Check for robots.txt", "tool": "curl", "phase": 2,
            "mitre": ["T1082"],
            "cmd": f"curl -s http://{ip}/robots.txt 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_robots.txt",
            "parser": "raw", "priority": "required",
        })
        if is_tool_available("nikto"):
            profiles.append({
                "id": "nikto", "name": "Nikto Scan",
                "desc": "Web vulnerability scanner", "tool": "nikto", "phase": 2,
                "mitre": ["T1595.002"],
                "cmd": f"nikto -h http://{ip} -o {SCAN_OUTPUT_DIR}/{h}_nikto.txt 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_nikto_full.txt",
                "parser": "nikto", "priority": "required",
            })
        if is_tool_available("gobuster"):
            profiles.append({
                "id": "gobuster", "name": "Gobuster Dir Scan",
                "desc": "Directory brute force", "tool": "gobuster", "phase": 2,
                "mitre": ["T1595.003"],
                "cmd": f"gobuster dir -u http://{ip} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt,bak -o {SCAN_OUTPUT_DIR}/{h}_gobuster.txt 2>&1",
                "parser": "gobuster", "priority": "required",
            })
        elif is_tool_available("feroxbuster"):
            profiles.append({
                "id": "feroxbuster", "name": "Feroxbuster Dir Scan",
                "desc": "Recursive content discovery", "tool": "feroxbuster", "phase": 2,
                "mitre": ["T1595.003"],
                "cmd": f"feroxbuster -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt -d 3 -o {SCAN_OUTPUT_DIR}/{h}_ferox.txt 2>&1",
                "parser": "gobuster", "priority": "required",
            })
        profiles.append({
            "id": "nmap_http", "name": "Nmap HTTP Vulns",
            "desc": "HTTP vulnerability scripts", "tool": "nmap", "phase": 2,
            "mitre": ["T1595.002"],
            "cmd": f"nmap -p 80,443,8080,8443 --script=http-vuln*,http-enum,http-headers,http-methods,http-shellshock {ip} -oN {SCAN_OUTPUT_DIR}/{h}_http_vuln.txt",
            "parser": "nmap", "priority": "recommended",
        })
        profiles.append({
            "id": "git_check", "name": "Git Exposure Check",
            "desc": "Check for exposed .git directory", "tool": "curl", "phase": 2,
            "mitre": ["T1082"],
            "cmd": f"curl -sI http://{ip}/.git/HEAD 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_git.txt",
            "parser": "raw", "priority": "recommended",
        })
        profiles.append({
            "id": "sensitive_files", "name": "Sensitive File Check",
            "desc": "Check .env, .htaccess, config backups, etc.", "tool": "curl", "phase": 2,
            "mitre": ["T1082"],
            "cmd": f'bash -c \'for f in .env .htaccess wp-config.php.bak config.php.bak server-status phpinfo.php info.php .DS_Store web.config crossdomain.xml sitemap.xml; do echo "--- $f: $(curl -s -o /dev/null -w "%{{http_code}}" http://{ip}/$f)"; done\' 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_sensitive.txt',
            "parser": "raw", "priority": "recommended",
        })
        if is_tool_available("testssl.sh") or is_tool_available("testssl"):
            tssl = "testssl.sh" if is_tool_available("testssl.sh") else "testssl"
            profiles.append({
                "id": "testssl", "name": "TestSSL Analysis",
                "desc": "Full SSL/TLS vulnerability assessment", "tool": tssl, "phase": 2,
                "mitre": ["T1082"],
                "cmd": f"{tssl} --quiet --color 0 https://{ip} 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_testssl.txt",
                "parser": "testssl", "priority": "recommended",
            })
        profiles.append({
            "id": "ssl_enum", "name": "Nmap SSL Enum",
            "desc": "Enumerate SSL ciphers and check vulns", "tool": "nmap", "phase": 2,
            "mitre": ["T1082"],
            "cmd": f"nmap -p 443 --script=ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-dh-params {ip} -oN {SCAN_OUTPUT_DIR}/{h}_ssl.txt",
            "parser": "nmap", "priority": "recommended",
        })

    # Wordpress
    if 'wordpress' in ' '.join(svcs):
        if is_tool_available("wpscan"):
            profiles.append({
                "id": "wpscan_enum", "name": "WPScan Full Enum",
                "desc": "Plugins, themes, users", "tool": "wpscan", "phase": 2,
                "mitre": ["T1595.002", "T1087.001"],
                "cmd": f"wpscan --url http://{ip} --enumerate ap,at,u,tt,cb,dbe --plugins-detection aggressive -o {SCAN_OUTPUT_DIR}/{h}_wpscan.txt 2>&1",
                "parser": "wpscan", "priority": "required",
            })
        profiles.append({
            "id": "wp_rest_api", "name": "WP REST API Users",
            "desc": "Enumerate users via REST API", "tool": "curl", "phase": 2,
            "mitre": ["T1087.001"],
            "cmd": f"curl -s http://{ip}/wp-json/wp/v2/users 2>&1 | python3 -m json.tool | tee {SCAN_OUTPUT_DIR}/{h}_wp_users.txt",
            "parser": "raw", "priority": "required",
        })
        profiles.append({
            "id": "wp_xmlrpc", "name": "WP XML-RPC Check",
            "desc": "Test xmlrpc.php availability", "tool": "curl", "phase": 2,
            "mitre": ["T1082"],
            "cmd": f'''curl -s -X POST http://{ip}/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_xmlrpc.txt''',
            "parser": "raw", "priority": "required",
        })

    # Redis
    if any('redis' in s for s in svcs) or 6379 in open_ports:
        if is_tool_available("redis-cli"):
            profiles.append({
                "id": "redis_info", "name": "Redis INFO",
                "desc": "Dump Redis server info (no auth)", "tool": "redis-cli", "phase": 2,
                "mitre": ["T1046"],
                "cmd": f"redis-cli -h {ip} INFO 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_redis_info.txt",
                "parser": "redis", "priority": "required",
            })
            profiles.append({
                "id": "redis_keys", "name": "Redis Key Dump",
                "desc": "Scan all keys", "tool": "redis-cli", "phase": 2,
                "mitre": ["T1046"],
                "cmd": f"redis-cli -h {ip} --scan --pattern '*' 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_redis_keys.txt",
                "parser": "raw", "priority": "required",
            })
            profiles.append({
                "id": "redis_config", "name": "Redis CONFIG",
                "desc": "Dump Redis configuration", "tool": "redis-cli", "phase": 2,
                "mitre": ["T1082"],
                "cmd": f"redis-cli -h {ip} CONFIG GET '*' 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_redis_config.txt",
                "parser": "raw", "priority": "required",
            })
        profiles.append({
            "id": "nmap_redis", "name": "Nmap Redis Scripts",
            "desc": "Redis info and brute force", "tool": "nmap", "phase": 2,
            "mitre": ["T1046", "T1210"],
            "cmd": f"nmap -p 6379 --script=redis-info,redis-brute {ip} -oN {SCAN_OUTPUT_DIR}/{h}_nmap_redis.txt",
            "parser": "nmap", "priority": "required",
        })

    # LAMP / MySQL
    if 'lamp' in ' '.join(svcs) or 3306 in open_ports:
        profiles.append({
            "id": "nmap_mysql", "name": "MySQL Scan",
            "desc": "MySQL enumeration and vuln check", "tool": "nmap", "phase": 2,
            "mitre": ["T1046", "T1595.002"],
            "cmd": f"nmap -p 3306 --script=mysql-info,mysql-enum,mysql-empty-password,mysql-vuln-cve2012-2122 {ip} -oN {SCAN_OUTPUT_DIR}/{h}_mysql.txt",
            "parser": "nmap", "priority": "required",
        })
        profiles.append({
            "id": "phpmyadmin", "name": "PHPMyAdmin Check",
            "desc": "Check for PHPMyAdmin", "tool": "curl", "phase": 2,
            "mitre": ["T1082"],
            "cmd": f"curl -sI http://{ip}/phpmyadmin/ 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_pma.txt",
            "parser": "raw", "priority": "required",
        })

    # SNMP
    if 161 in open_ports:
        if is_tool_available("snmpwalk"):
            profiles.append({
                "id": "snmpwalk", "name": "SNMP Walk",
                "desc": "SNMP v1/v2c community string enum", "tool": "snmpwalk", "phase": 2,
                "mitre": ["T1082"],
                "cmd": f"snmpwalk -v2c -c public {ip} 2>&1 | head -200 | tee {SCAN_OUTPUT_DIR}/{h}_snmpwalk.txt",
                "parser": "snmpwalk", "priority": "required",
            })
        if is_tool_available("onesixtyone"):
            profiles.append({
                "id": "onesixtyone", "name": "SNMP Community Brute",
                "desc": "Brute force SNMP community strings", "tool": "onesixtyone", "phase": 2,
                "mitre": ["T1046"],
                "cmd": f"onesixtyone {ip} -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_snmp_brute.txt",
                "parser": "raw", "priority": "recommended",
            })

    # SMTP
    if 25 in open_ports or 587 in open_ports:
        profiles.append({
            "id": "nmap_smtp", "name": "SMTP Enum",
            "desc": "SMTP user enumeration and relay check", "tool": "nmap", "phase": 2,
            "mitre": ["T1087.001"],
            "cmd": f"nmap -p 25,587 --script=smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-open-relay,smtp-commands {ip} -oN {SCAN_OUTPUT_DIR}/{h}_smtp.txt",
            "parser": "nmap", "priority": "required",
        })
        if is_tool_available("smtp-user-enum"):
            profiles.append({
                "id": "smtp_user_enum", "name": "SMTP User Enum",
                "desc": "Enumerate valid SMTP users", "tool": "smtp-user-enum", "phase": 2,
                "mitre": ["T1087.001"],
                "cmd": f"smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t {ip} 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_smtp_users.txt",
                "parser": "raw", "priority": "recommended",
            })

    # SSH
    if 22 in open_ports:
        profiles.append({
            "id": "ssh_audit", "name": "SSH Audit",
            "desc": "SSH config and algorithm analysis", "tool": "nmap", "phase": 2,
            "mitre": ["T1082"],
            "cmd": f"nmap -p 22 --script=ssh2-enum-algos,ssh-auth-methods,ssh-hostkey {ip} -oN {SCAN_OUTPUT_DIR}/{h}_ssh_audit.txt",
            "parser": "nmap", "priority": "recommended",
        })

    # VNC
    if 5900 in open_ports or 5901 in open_ports:
        profiles.append({
            "id": "nmap_vnc", "name": "VNC Scan",
            "desc": "VNC info and brute force", "tool": "nmap", "phase": 2,
            "mitre": ["T1046"],
            "cmd": f"nmap -p 5900,5901 --script=vnc-info,vnc-brute {ip} -oN {SCAN_OUTPUT_DIR}/{h}_vnc.txt",
            "parser": "nmap", "priority": "required",
        })

    # MongoDB
    if 27017 in open_ports:
        profiles.append({
            "id": "nmap_mongo", "name": "MongoDB Scan",
            "desc": "MongoDB info and database enum", "tool": "nmap", "phase": 2,
            "mitre": ["T1046"],
            "cmd": f"nmap -p 27017 --script=mongodb-info,mongodb-databases {ip} -oN {SCAN_OUTPUT_DIR}/{h}_mongo.txt",
            "parser": "nmap", "priority": "required",
        })

    # ── PHASE 3: Vuln assessment ──
    profiles.append({
        "id": "nmap_vuln_all", "name": "Nmap Vuln Scripts",
        "desc": "Run all nmap vuln scripts", "tool": "nmap", "phase": 3,
        "mitre": ["T1595.002"],
        "cmd": f"nmap --script vuln -sV {ip} -oN {SCAN_OUTPUT_DIR}/{h}_vuln_all.txt -oX {SCAN_OUTPUT_DIR}/{h}_vuln_all.xml",
        "parser": "nmap", "priority": "required",
    })
    if is_tool_available("nuclei"):
        profiles.append({
            "id": "nuclei_scan", "name": "Nuclei Vuln Scan",
            "desc": "Template-based vulnerability scanning", "tool": "nuclei", "phase": 3,
            "mitre": ["T1595.002"],
            "cmd": f"nuclei -u http://{ip} -t /root/nuclei-templates/ -severity critical,high,medium -jsonl -o {SCAN_OUTPUT_DIR}/{h}_nuclei.txt 2>&1",
            "parser": "nuclei", "priority": "required",
        })
        profiles.append({
            "id": "nuclei_cves", "name": "Nuclei CVE Scan",
            "desc": "Nuclei CVE-specific templates", "tool": "nuclei", "phase": 3,
            "mitre": ["T1595.002"],
            "cmd": f"nuclei -u http://{ip} -t /root/nuclei-templates/ -tags cve -severity critical,high -jsonl -o {SCAN_OUTPUT_DIR}/{h}_nuclei_cves.txt 2>&1",
            "parser": "nuclei", "priority": "recommended",
        })

    # ── PHASE 4: Cred attacks ──
    if is_tool_available("hydra"):
        if 22 in open_ports or any('ssh' in s for s in svcs):
            profiles.append({
                "id": "hydra_ssh", "name": "Hydra SSH Brute",
                "desc": "SSH password brute force", "tool": "hydra", "phase": 4,
                "mitre": ["T1110.001"],
                "cmd": f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt {ip} ssh -t 4 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_hydra_ssh.txt",
                "parser": "raw", "priority": "recommended",
            })
        if 21 in open_ports:
            profiles.append({
                "id": "hydra_ftp", "name": "Hydra FTP Brute",
                "desc": "FTP password brute force", "tool": "hydra", "phase": 4,
                "mitre": ["T1110.001"],
                "cmd": f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt {ip} ftp -t 4 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_hydra_ftp.txt",
                "parser": "raw", "priority": "recommended",
            })
        if 3306 in open_ports:
            profiles.append({
                "id": "hydra_mysql", "name": "Hydra MySQL Brute",
                "desc": "MySQL password brute force", "tool": "hydra", "phase": 4,
                "mitre": ["T1110.001"],
                "cmd": f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt {ip} mysql -t 4 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_hydra_mysql.txt",
                "parser": "raw", "priority": "recommended",
            })
        if 5432 in open_ports:
            profiles.append({
                "id": "hydra_pg", "name": "Hydra PostgreSQL Brute",
                "desc": "PostgreSQL password brute force", "tool": "hydra", "phase": 4,
                "mitre": ["T1110.001"],
                "cmd": f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt {ip} postgres -t 4 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_hydra_pg.txt",
                "parser": "raw", "priority": "recommended",
            })

    if is_tool_available("medusa"):
        if 22 in open_ports:
            profiles.append({
                "id": "medusa_ssh", "name": "Medusa SSH Brute",
                "desc": "SSH brute force with medusa", "tool": "medusa", "phase": 4,
                "mitre": ["T1110.001"],
                "cmd": f"medusa -h {ip} -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt -M ssh -t 4 2>&1 | tee {SCAN_OUTPUT_DIR}/{h}_medusa_ssh.txt",
                "parser": "raw", "priority": "optional",
            })

    return profiles


def execute_scan(scan_id, profile, target):
    scan_semaphore.acquire()
    try:
        add_log(f"Starting: {profile['name']} against {target['hostname']} ({target['ip']})", "system")
        with store_lock:
            scan = next((s for s in store["scans"] if s["id"] == scan_id), None)
            if scan:
                scan["status"] = "running"
                scan["startedAt"] = datetime.now().isoformat()
                scan["worker"] = "local"
        proc = subprocess.Popen(
            profile["cmd"], shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, preexec_fn=os.setsid
        )
        active_processes[scan_id] = proc
        output_lines = []
        try:
            for line in proc.stdout:
                output_lines.append(line)
            proc.wait(timeout=SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            add_log(f"Scan timed out: {profile['name']}", "error")
        output = ''.join(output_lines)
        returncode = proc.returncode
        process_scan_results(scan_id, profile, target, output, returncode)
    except Exception as e:
        add_log(f"Scan error: {profile['name']} — {e}", "error")
        with store_lock:
            scan = next((s for s in store["scans"] if s["id"] == scan_id), None)
            if scan:
                scan["status"] = "error"
                scan["error"] = str(e)
    finally:
        active_processes.pop(scan_id, None)
        scan_semaphore.release()


def process_scan_results(scan_id, profile, target, output, returncode):
    parsed_summary = ""
    parser_type = profile.get("parser", "raw")

    if parser_type == "nmap":
        xml_path = None
        for part in profile.get('cmd', '').split():
            if part.endswith('.xml'):
                xml_path = part
                break
        parsed = []
        if xml_path and os.path.exists(xml_path):
            with open(xml_path) as f:
                parsed = parse_nmap_xml(f.read())
        if not parsed:
            parsed = parse_nmap_text(output)
        if parsed:
            u, c, f = integrate_nmap_results(parsed, profile.get("tool", "nmap"))
            parsed_summary = f"{len(parsed)} hosts, {u} updated, {c} new, {f} findings"

    elif parser_type == "enum4linux":
        r = parse_enum4linux(output)
        parsed_summary = f"{len(r['shares'])} shares, {len(r['users'])} users, {len(r['groups'])} groups"
        with store_lock:
            for s in r['shares']:
                fid = f"f-e4l-{s['name'].replace(os.sep, '_')}"
                if not any(f["id"] == fid for f in store["findings"]):
                    store["findings"].append({
                        "id": fid, "targetIp": target["ip"], "port": 445, "protocol": "tcp",
                        "service": f"SMB: {s['name']}", "version": f"map:{s['mapping']} list:{s['listing']}",
                        "severity": "high" if s['mapping'] == "OK" else "medium",
                        "timestamp": datetime.now().isoformat(), "source": "enum4linux",
                    })
            if r['users']:
                add_log(f"Users found: {', '.join(r['users'])}", "info")

    elif parser_type == "gobuster":
        paths = parse_gobuster(output)
        parsed_summary = f"{len(paths)} paths discovered"
        with store_lock:
            for p in paths:
                fid = f"f-gb-{target['ip']}-{p['path']}"
                if not any(f["id"] == fid for f in store["findings"]):
                    store["findings"].append({
                        "id": fid, "targetIp": target["ip"], "port": 80, "protocol": "tcp",
                        "service": f"Path: {p['path']}", "version": f"Status {p['status']}",
                        "severity": "medium" if p['status'] == 200 else "info",
                        "timestamp": datetime.now().isoformat(), "source": "gobuster",
                    })

    elif parser_type == "nikto":
        nk = parse_nikto(output)
        parsed_summary = f"{len(nk)} findings"
        with store_lock:
            for n in nk:
                fid = f"f-nk-{target['ip']}-{hashlib.md5((n['id']+n['detail']).encode()).hexdigest()[:10]}"
                if not any(f["id"] == fid for f in store["findings"]):
                    store["findings"].append({
                        "id": fid, "targetIp": target["ip"], "port": 80, "protocol": "tcp",
                        "service": n["id"], "version": n["detail"],
                        "severity": n.get("severity", "medium"),
                        "timestamp": datetime.now().isoformat(), "source": "nikto",
                    })

    elif parser_type == "wpscan":
        wp = parse_wpscan(output)
        parsed_summary = f"WP v{wp['version']}, {len(wp['users'])} users, {len(wp['vulns'])} vulns"
        if wp['users']:
            add_log(f"WP users: {', '.join(wp['users'])}", "info")
        for v in wp['vulns']:
            add_log(f"WP vuln: {v}", "info")

    elif parser_type == "redis":
        info = parse_redis_info(output)
        parsed_summary = f"Redis v{info.get('redis_version', '?')}, {info.get('connected_clients', '?')} clients"

    elif parser_type == "nuclei":
        findings = parse_nuclei(output)
        # Also try reading the output file for better data
        cmd = profile.get('cmd', '')
        for part in cmd.split():
            if part.startswith(str(SCAN_OUTPUT_DIR)) and part.endswith('.txt'):
                try:
                    if os.path.exists(part):
                        with open(part) as fh:
                            file_findings = parse_nuclei(fh.read())
                            if len(file_findings) > len(findings):
                                findings = file_findings
                except:
                    pass
        parsed_summary = f"{len(findings)} vulnerabilities found"
        with store_lock:
            for nf in findings:
                fid = f"f-nuclei-{target['ip']}-{nf.get('template', '')}"
                if not any(f["id"] == fid for f in store["findings"]):
                    store["findings"].append({
                        "id": fid, "targetIp": target["ip"], "port": 80, "protocol": "tcp",
                        "service": nf.get("template", "nuclei"), "version": nf.get("name", nf.get("url", "")),
                        "severity": nf.get("severity", "info"),
                        "timestamp": datetime.now().isoformat(), "source": "nuclei",
                    })

    elif parser_type == "testssl":
        tls = parse_testssl(output)
        vulns = [f for f in tls if 'VULNERABLE' in f.get('status', '').upper()]
        parsed_summary = f"{len(tls)} checks, {len(vulns)} vulnerable"
        with store_lock:
            for tf in vulns:
                fid = f"f-tls-{target['ip']}-{hashlib.md5(tf['detail'].encode()).hexdigest()[:8]}"
                if not any(f["id"] == fid for f in store["findings"]):
                    store["findings"].append({
                        "id": fid, "targetIp": target["ip"], "port": 443, "protocol": "tcp",
                        "service": "TLS Vuln", "version": tf["detail"][:200],
                        "severity": "high",
                        "timestamp": datetime.now().isoformat(), "source": "testssl",
                    })

    elif parser_type == "snmpwalk":
        entries = parse_snmpwalk(output)
        parsed_summary = f"{len(entries)} SNMP entries"

    else:
        parsed_summary = f"{len(output)} bytes of output"

    with store_lock:
        scan = next((s for s in store["scans"] if s["id"] == scan_id), None)
        if scan:
            scan["status"] = "completed" if returncode == 0 else "error"
            scan["completedAt"] = datetime.now().isoformat()
            scan["output"] = output[-10000:]
            scan["parsedSummary"] = parsed_summary
            scan["returncode"] = returncode

    add_log(f"Completed: {profile['name']} → {parsed_summary}", "success")
    save_store()


# ══════════════════════════════════════════════════════════════
# WORKER QUEUE (Redis-based distributed scanning)
# ══════════════════════════════════════════════════════════════

QUEUE_NAME = "redrecon:jobs"
RESULT_PREFIX = "redrecon:result:"
WORKER_HEARTBEAT = "redrecon:workers"

def dispatch_to_worker(scan_id, profile, target):
    r = get_redis()
    if not r:
        add_log("Redis unavailable, falling back to local execution", "error")
        thread = threading.Thread(target=execute_scan, args=(scan_id, profile, target), daemon=True)
        thread.start()
        return
    job = {
        "scan_id": scan_id,
        "profile": profile,
        "target": {
            "id": target["id"],
            "ip": target["ip"],
            "hostname": target["hostname"],
        },
        "queued_at": datetime.now().isoformat(),
    }
    try:
        with store_lock:
            scan = next((s for s in store["scans"] if s["id"] == scan_id), None)
            if scan:
                scan["status"] = "running"
        r.lpush(QUEUE_NAME, json.dumps(job))
        add_log(f"Dispatched to worker queue: {profile['name']} -> {target['hostname']}", "system")
    except Exception as e:
        add_log(f"Queue dispatch failed ({e}), falling back to local", "error")
        thread = threading.Thread(target=execute_scan, args=(scan_id, profile, target), daemon=True)
        thread.start()


def poll_worker_results():
    while True:
        try:
            r = get_redis()
            if not r:
                time.sleep(5)
                continue

            keys = [k for k in r.keys(f"{RESULT_PREFIX}*") if ":status" not in k]
            for key in keys:
                try:
                    data = r.get(key)
                    if not data:
                        continue
                    result = json.loads(data)
                    scan_id = result.get("scan_id")

                    with store_lock:
                        scan = next((s for s in store["scans"] if s["id"] == scan_id), None)
                        if scan and scan["status"] in ("running", "queued"):
                            scan["status"] = result.get("status", "completed")
                            scan["completedAt"] = result.get("completed_at", datetime.now().isoformat())
                            scan["output"] = result.get("output", "")[-10000:]
                            scan["parsedSummary"] = result.get("parsed_summary", "")
                            scan["returncode"] = result.get("returncode", 0)
                            scan["worker"] = result.get("worker_id", "unknown")

                    # Re-process output through parsers on server side
                    with store_lock:
                        scan = next((s for s in store["scans"] if s["id"] == scan_id), None)
                        target = None
                        profile = {"name": "", "tool": "", "cmd": "", "parser": "raw"}
                        if scan:
                            target = next((t for t in store["targets"] if t["id"] == scan.get("targetId")), None)
                            profile = {
                                "name": scan.get("profileName", ""),
                                "tool": scan.get("tool", ""),
                                "cmd": scan.get("cmd", ""),
                                "parser": scan.get("parser", "raw"),
                            }

                    if target and profile["parser"] != "raw":
                        output = result.get("output", "")
                        returncode = result.get("returncode", 0)
                        cmd = scan.get("cmd", "") if scan else ""
                        for part in cmd.split():
                            if part.startswith(str(SCAN_OUTPUT_DIR)) and (part.endswith('.xml') or part.endswith('.txt')):
                                try:
                                    if os.path.exists(part):
                                        with open(part) as fh:
                                            file_output = fh.read()
                                            if len(file_output) > len(output):
                                                output = file_output
                                except:
                                    pass
                        process_scan_results(scan_id, profile, target, output, returncode)
                    else:
                        add_log(f"Worker result received: {scan_id}", "success")
                        save_store()

                    r.delete(key)
                except Exception as e:
                    add_log(f"Error processing worker result: {e}", "error")

            # Collect worker heartbeats and purge stale
            try:
                worker_data = r.hgetall(WORKER_HEARTBEAT)
                with store_lock:
                    store["workers"] = []
                    for wid, wdata in worker_data.items():
                        try:
                            w = json.loads(wdata)
                            last_seen = datetime.fromisoformat(w.get("last_heartbeat", "2000-01-01"))
                            age = (datetime.utcnow() - last_seen).total_seconds()
                            if age > 60:
                                r.hdel(WORKER_HEARTBEAT, wid)
                                continue
                            elif age > 15:
                                w["status"] = "stale"
                            store["workers"].append(w)
                        except:
                            r.hdel(WORKER_HEARTBEAT, wid)
            except:
                pass

        except Exception as e:
            pass
        time.sleep(2)


# ══════════════════════════════════════════════════════════════
# API ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/state")
def get_state():
    with store_lock:
        return jsonify(store)

@app.route("/api/targets", methods=["GET"])
def get_targets():
    with store_lock:
        return jsonify(store["targets"])

@app.route("/api/targets", methods=["POST"])
def add_target():
    data = request.json
    target = {
        "id": f"t-{uuid.uuid4().hex[:8]}",
        "hostname": data.get("hostname", ""),
        "ip": data.get("ip", ""),
        "os": data.get("os", "Unknown"),
        "role": data.get("role", "Manual"),
        "services": data.get("services", []),
        "team": data.get("team", "blue"),
        "status": "pending",
        "openPorts": [],
        "scanHistory": [],
        "detectedOs": "",
    }
    with store_lock:
        store["targets"].append(target)
    add_log(f"Target added: {target['hostname']} ({target['ip']})", "success")
    save_store()
    return jsonify(target), 201

@app.route("/api/targets/<target_id>", methods=["DELETE"])
def delete_target(target_id):
    with store_lock:
        store["targets"] = [t for t in store["targets"] if t["id"] != target_id]
    add_log(f"Target deleted: {target_id}", "system")
    save_store()
    return jsonify({"status": "deleted"})

@app.route("/api/targets/<target_id>", methods=["PATCH"])
def update_target(target_id):
    data = request.json
    with store_lock:
        target = next((t for t in store["targets"] if t["id"] == target_id), None)
        if not target:
            return jsonify({"error": "Not found"}), 404
        for key in ["ip", "hostname", "os", "status", "services", "role", "team"]:
            if key in data:
                target[key] = data[key]
    save_store()
    return jsonify(target)

@app.route("/api/targets/<target_id>/profiles")
def get_profiles(target_id):
    with store_lock:
        target = next((t for t in store["targets"] if t["id"] == target_id), None)
    if not target:
        return jsonify({"error": "Not found"}), 404
    if not target["ip"]:
        return jsonify({"error": "Target has no IP assigned"}), 400
    profiles = get_scan_profiles(target)
    return jsonify(profiles)

@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.json
    target_id = data.get("targetId")
    profile_id = data.get("profileId")
    with store_lock:
        target = next((t for t in store["targets"] if t["id"] == target_id), None)
    if not target:
        return jsonify({"error": "Target not found"}), 404
    if not target["ip"]:
        return jsonify({"error": "Assign an IP first"}), 400
    profiles = get_scan_profiles(target)
    profile = next((p for p in profiles if p["id"] == profile_id), None)
    if not profile:
        return jsonify({"error": "Profile not found"}), 404
    with store_lock:
        running = [s for s in store["scans"] if s["targetId"] == target_id and s["profileId"] == profile_id and s["status"] == "running"]
        if running:
            return jsonify({"error": "Already running"}), 409
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    scan_record = {
        "id": scan_id, "targetId": target_id, "profileId": profile_id,
        "profileName": profile["name"], "tool": profile["tool"],
        "cmd": profile["cmd"], "status": "queued",
        "queuedAt": datetime.now().isoformat(),
        "startedAt": None, "completedAt": None,
        "output": "", "parsedSummary": "", "returncode": None,
        "worker": None, "parser": profile.get("parser", "raw"),
    }
    with store_lock:
        store["scans"].append(scan_record)
        target["status"] = "scanning"
    use_workers = WORKER_MODE == "distributed" and redis_available()
    if use_workers:
        dispatch_to_worker(scan_id, profile, target)
    else:
        thread = threading.Thread(target=execute_scan, args=(scan_id, profile, target), daemon=True)
        thread.start()
    return jsonify(scan_record), 202

@app.route("/api/scan/<scan_id>/stop", methods=["POST"])
def stop_scan(scan_id):
    proc = active_processes.get(scan_id)
    if proc:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        with store_lock:
            scan = next((s for s in store["scans"] if s["id"] == scan_id), None)
            if scan:
                scan["status"] = "stopped"
        add_log(f"Scan stopped: {scan_id}", "system")
        return jsonify({"status": "stopped"})
    r = get_redis()
    if r:
        try:
            r.set(f"redrecon:cancel:{scan_id}", "1", ex=300)
            with store_lock:
                scan = next((s for s in store["scans"] if s["id"] == scan_id), None)
                if scan:
                    scan["status"] = "stopped"
            return jsonify({"status": "cancel_requested"})
        except:
            pass
    return jsonify({"error": "Not found or not running"}), 404

@app.route("/api/scan/batch", methods=["POST"])
def batch_scan():
    data = request.json
    target_id = data.get("targetId")
    profile_ids = data.get("profileIds", [])
    with store_lock:
        target = next((t for t in store["targets"] if t["id"] == target_id), None)
    if not target or not target["ip"]:
        return jsonify({"error": "Invalid target"}), 400
    profiles = get_scan_profiles(target)
    started = []
    use_workers = WORKER_MODE == "distributed" and redis_available()
    for pid in profile_ids:
        profile = next((p for p in profiles if p["id"] == pid), None)
        if not profile:
            continue
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        scan_record = {
            "id": scan_id, "targetId": target_id, "profileId": pid,
            "profileName": profile["name"], "tool": profile["tool"],
            "cmd": profile["cmd"], "status": "queued",
            "queuedAt": datetime.now().isoformat(),
            "startedAt": None, "completedAt": None,
            "output": "", "parsedSummary": "", "returncode": None,
            "worker": None, "parser": profile.get("parser", "raw"),
        }
        with store_lock:
            store["scans"].append(scan_record)
        if use_workers:
            dispatch_to_worker(scan_id, profile, target)
        else:
            thread = threading.Thread(target=execute_scan, args=(scan_id, profile, target), daemon=True)
            thread.start()
        started.append(scan_record)
    with store_lock:
        target["status"] = "scanning"
    return jsonify(started), 202

@app.route("/api/scan/all", methods=["POST"])
def scan_all_targets():
    data = request.json or {}
    phase = data.get("phase", 1)
    started = []
    with store_lock:
        targets = [t for t in store["targets"] if t["ip"]]
    for target in targets:
        profiles = get_scan_profiles(target)
        required = [p for p in profiles if p["phase"] <= phase and p["priority"] == "required"]
        for profile in required:
            scan_id = f"scan-{uuid.uuid4().hex[:8]}"
            scan_record = {
                "id": scan_id, "targetId": target["id"], "profileId": profile["id"],
                "profileName": profile["name"], "tool": profile["tool"],
                "cmd": profile["cmd"], "status": "queued",
                "queuedAt": datetime.now().isoformat(),
                "startedAt": None, "completedAt": None,
                "output": "", "parsedSummary": "", "returncode": None,
                "worker": None, "parser": profile.get("parser", "raw"),
            }
            with store_lock:
                store["scans"].append(scan_record)
            use_workers = WORKER_MODE == "distributed" and redis_available()
            if use_workers:
                dispatch_to_worker(scan_id, profile, target)
            else:
                thread = threading.Thread(target=execute_scan, args=(scan_id, profile, target), daemon=True)
                thread.start()
            started.append(scan_record)
    return jsonify({"started": len(started), "scans": started}), 202

@app.route("/api/scan/<scan_id>/output")
def get_scan_output(scan_id):
    with store_lock:
        scan = next((s for s in store["scans"] if s["id"] == scan_id), None)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"output": scan.get("output", ""), "status": scan["status"]})

@app.route("/api/scans")
def get_scans():
    with store_lock:
        return jsonify(store["scans"])

@app.route("/api/findings", methods=["GET"])
def get_findings():
    with store_lock:
        return jsonify(store["findings"])

@app.route("/api/findings/<finding_id>", methods=["PATCH"])
def update_finding(finding_id):
    data = request.json
    with store_lock:
        f = next((f for f in store["findings"] if f["id"] == finding_id), None)
        if not f:
            return jsonify({"error": "Not found"}), 404
        if "severity" in data:
            f["severity"] = data["severity"]
        if "notes" in data:
            f["notes"] = data["notes"]
    save_store()
    return jsonify(f)

@app.route("/api/creds", methods=["GET"])
def get_creds():
    with store_lock:
        return jsonify(store["creds"])

@app.route("/api/creds", methods=["POST"])
def add_cred():
    data = request.json
    cred = {
        "id": f"c-{uuid.uuid4().hex[:8]}",
        "targetId": data.get("targetId", ""),
        "username": data.get("username", ""),
        "password": data.get("password", ""),
        "hash": data.get("hash", ""),
        "service": data.get("service", ""),
        "note": data.get("note", ""),
        "timestamp": datetime.now().isoformat(),
    }
    with store_lock:
        store["creds"].append(cred)
    add_log(f"Cred logged: {cred['username']}@{cred['service']}", "success")
    save_store()
    return jsonify(cred), 201

@app.route("/api/notes", methods=["GET"])
def get_notes():
    with store_lock:
        return jsonify(store["notes"])

@app.route("/api/notes", methods=["POST"])
def add_note():
    data = request.json
    note = {
        "id": f"n-{uuid.uuid4().hex[:8]}",
        "targetId": data.get("targetId", ""),
        "title": data.get("title", ""),
        "content": data.get("content", ""),
        "severity": data.get("severity", "info"),
        "author": data.get("author", "operator"),
        "timestamp": datetime.now().isoformat(),
    }
    with store_lock:
        store["notes"].append(note)
    add_log(f"Note: {note['title']}", "info")
    save_store()
    return jsonify(note), 201

@app.route("/api/import", methods=["POST"])
def import_output():
    data = request.json
    text = data.get("text", "")
    forced_format = data.get("format")
    if forced_format and forced_format != "auto":
        fmt = forced_format
        parsers = {
            "nmap_text": parse_nmap_text, "nmap_xml": parse_nmap_xml,
            "enum4linux": parse_enum4linux, "gobuster": parse_gobuster,
            "nikto": parse_nikto, "wpscan": parse_wpscan,
            "redis": parse_redis_info, "nuclei": parse_nuclei,
            "testssl": parse_testssl, "subfinder": parse_subfinder,
            "snmpwalk": parse_snmpwalk,
        }
        if fmt in parsers:
            result = parsers[fmt](text)
            if fmt in ("nmap_text", "nmap_xml"):
                u, c, f = integrate_nmap_results(result)
                save_store()
                return jsonify({"format": fmt, "summary": f"{len(result)} hosts, {u} updated, {c} new, {f} findings"})
            return jsonify({"format": fmt, "result": result if isinstance(result, (list, dict)) else str(result)})
    else:
        fmt, result = auto_detect_and_parse(text)
        if fmt in ("nmap_text", "nmap_xml"):
            u, c, f = integrate_nmap_results(result)
            save_store()
            return jsonify({"format": fmt, "summary": f"{len(result)} hosts, {u} updated, {c} new, {f} findings"})
        return jsonify({"format": fmt, "result": result if isinstance(result, (list, dict)) else str(result)[:5000]})

@app.route("/api/log")
def get_log():
    with store_lock:
        return jsonify(store["log"][-100:])

@app.route("/api/tools")
def check_tools():
    tools = [
        "nmap", "masscan", "enum4linux-ng", "enum4linux", "smbclient", "smbmap",
        "crackmapexec", "netexec", "gobuster", "feroxbuster", "dirb", "nikto",
        "wpscan", "whatweb", "curl", "dig", "dnsrecon", "dnsenum", "hydra",
        "redis-cli", "rpcclient", "ldapsearch", "impacket-GetNPUsers",
        "impacket-GetUserSPNs", "impacket-smbclient", "impacket-secretsdump",
        "searchsploit", "netcat", "snmpwalk", "medusa", "nuclei", "naabu",
        "httpx", "subfinder", "amass", "testssl.sh", "testssl", "sqlmap", "hashcat",
        "john", "onesixtyone", "smtp-user-enum", "sslscan", "sslyze",
        "responder", "evil-winrm", "bloodhound", "certipy-ad",
    ]
    results = {}
    for t in tools:
        results[t] = check_tool(t)
    return jsonify(results)

# ─── Worker Management ───

@app.route("/api/workers")
def get_workers():
    with store_lock:
        workers = store.get("workers", [])
    queue_depth = 0
    r = get_redis()
    if r:
        try:
            queue_depth = r.llen(QUEUE_NAME)
        except:
            pass
    return jsonify({
        "workers": workers,
        "queue_depth": queue_depth,
        "mode": WORKER_MODE,
        "redis_connected": redis_available(),
    })

@app.route("/api/workers/mode", methods=["POST"])
def set_worker_mode():
    global WORKER_MODE
    data = request.json
    mode = data.get("mode", "local")
    if mode not in ("local", "distributed"):
        return jsonify({"error": "Invalid mode"}), 400
    WORKER_MODE = mode
    add_log(f"Worker mode set to: {mode}", "system")
    return jsonify({"mode": WORKER_MODE})

@app.route("/api/workers/queue/flush", methods=["POST"])
def flush_queue():
    r = get_redis()
    if r:
        try:
            count = r.llen(QUEUE_NAME)
            r.delete(QUEUE_NAME)
            add_log(f"Queue flushed: {count} jobs removed", "system")
            return jsonify({"flushed": count})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Redis not available"}), 503

# ─── Purge ───

@app.route("/api/purge", methods=["POST"])
def purge_data():
    """Purge selected data stores."""
    data = request.json or {}
    targets = data.get("targets", False)
    findings = data.get("findings", False)
    scans = data.get("scans", False)
    creds = data.get("creds", False)
    notes = data.get("notes", False)
    everything = data.get("all", False)

    purged = []
    with store_lock:
        if everything or targets:
            store["targets"] = []
            purged.append("targets")
        if everything or findings:
            store["findings"] = []
            purged.append("findings")
        if everything or scans:
            store["scans"] = []
            purged.append("scans")
        if everything or creds:
            store["creds"] = []
            purged.append("creds")
        if everything or notes:
            store["notes"] = []
            purged.append("notes")
        if everything:
            store["log"] = []
            purged.append("log")

    add_log(f"Purged: {', '.join(purged)}", "system")
    save_store()

    # Clear scan output files if scans were purged
    if everything or scans:
        for f in glob.glob(str(SCAN_OUTPUT_DIR / "*")):
            try:
                os.remove(f)
            except:
                pass

    return jsonify({"purged": purged})

@app.route("/api/export")
def export_data():
    with store_lock:
        return jsonify({
            **store,
            "exportedAt": datetime.now().isoformat(),
            "scans": [{k: v for k, v in s.items() if k != "output"} for s in store["scans"]]
        })

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "version": "5.0.0",
        "redis": redis_available(),
        "mode": WORKER_MODE,
        "targets": len(store["targets"]),
        "findings": len(store["findings"]),
    })


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reconboard v5 Server")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=8443, help="Listen port")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()

    load_store()

    print("\n╔══════════════════════════════════════════════════╗")
    print("║     Reconboard v5 — Distributed Kali Recon       ║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"║  Server: http://{args.host}:{args.port}              ║")
    print(f"║  Mode:   {WORKER_MODE:<39}  ║")
    print(f"║  Redis:  {REDIS_URL:<39}  ║")
    print("╚══════════════════════════════════════════════════╝\n")

    core_tools = ["nmap", "curl", "gobuster", "nikto", "hydra", "searchsploit", "nuclei"]
    for t in core_tools:
        status = "✓" if check_tool(t) else "✗"
        print(f"  [{status}] {t}")

    print(f"\n  Targets loaded: {len(store['targets'])}")
    print(f"  Run as root for SYN scans and privileged features.\n")

    if WORKER_MODE == "distributed" or redis_available():
        poller = threading.Thread(target=poll_worker_results, daemon=True)
        poller.start()
        print("  [+] Worker result polling started")

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)