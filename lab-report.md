# HW4 Lab Report — Custom Red Team Tool
## Reconboard v5: Distributed Reconnaissance & C2 Dashboard

**Course:** CSEC-473
**Student:** Odessa
**Tool Category:** Category 4 — Red Team Infrastructure Tool
**Repository:** [Add GitHub link here]
**Date:** March 2026

---

## Section 1: Tool Development

### Q1: What tool did you create and what category does it fit into? Explain your choice and why this tool fills a gap in your Red Team capabilities.

**Reconboard v5** is a self-hosted, distributed reconnaissance and command coordination dashboard designed for Red Team competition environments. It fits squarely into **Category 4: Red Team Infrastructure Tool**.

The tool provides a unified web interface — accessible at `https://<operator-ip>:8443` — from which the entire Red Team can orchestrate automated scanning campaigns across all identified targets, track discovered findings and credentials, and coordinate operations without duplicating effort.

The gap Reconboard fills is one every Red Team faces in time-pressured competitions: **information overload and coordination friction.** When multiple operators are running `nmap`, `gobuster`, `enum4linux`, and `hydra` independently against overlapping targets, results get scattered across terminal sessions. Findings get lost. Credentials found on one machine never get tried on another. With Reconboard, every scan result flows into a single persistent JSON store, auto-parsed into structured findings and credentials that all operators share in real time.

Specific gaps addressed:

- **Distributed execution:** Scanning campaigns are distributed across horizontally-scaled Docker worker containers via a Redis job queue, dramatically reducing wall-clock time for full-coverage reconnaissance.
- **Output normalization:** Raw output from nmap, nikto, gobuster, wpscan, enum4linux, nuclei, and 15+ other tools is automatically parsed into structured findings — no manual grep sessions.
- **Credential tracking:** All discovered credentials are indexed by target and surfaced in a dedicated tab, enabling fast lateral movement decisions.
- **MITRE ATT&CK mapping:** Each scan profile is tagged with relevant ATT&CK technique IDs, providing structured documentation of TTPs as the operation proceeds.

No off-the-shelf tool provides all of this in a single, self-contained, rapidly-deployable package. Cobalt Strike and Metasploit are powerful, but they do not aggregate reconnaissance output across arbitrary tools into a shared operator view. Reconboard fills that gap.

---

### Q2: Describe the technical implementation. What language did you use and why? What were the major technical challenges you encountered and how did you solve them?

**Language: Python 3.10+ with Flask**

Python was chosen because:
1. It runs natively in Kali Linux (the base OS for all containers), requiring no additional interpreter installation on the operator machine.
2. Flask provides a lightweight, unopinionated web framework that enabled rapid development of the REST API and web UI without the overhead of Django or FastAPI.
3. Python's `subprocess`, `threading`, and `concurrent.futures` modules provide everything needed to orchestrate parallel scan execution.

**Architecture:**

The system is composed of three Docker services (defined in `docker-compose.yml`):

- **Redis** — Acts as the job queue (`redrecon:jobs`) and result store (`redrecon:result:<scan_id>`). Workers use blocking `BRPOP` to wait for jobs; the server polls for results on a background thread.
- **Server** (`recon_server.py`, ~1838 lines) — Flask app that serves the web UI, exposes a REST API, dispatches scan jobs, parses tool output, and maintains the persistent `store.json` data file.
- **Workers** (`worker.py`, ~321 lines) — Stateless job consumers that pull scan commands from Redis, execute them with `subprocess.Popen`, and push stdout/stderr results back to Redis.

**Scan Profile System:**

When an operator selects a target and requests a scan, the server's `generate_scan_profiles()` function introspects known open ports and services for that target and dynamically generates a prioritized list of scan commands. For example, if port 445 is open, SMB-focused profiles (enum4linux, smbmap, crackmapexec) are injected as "required." If port 80/443 is open, web profiles (gobuster, nikto, whatweb, wpscan for WordPress indicators) are added. This means operators never have to remember which tool to run against which service — the system figures it out.

**Major Technical Challenges:**

1. **Process tree termination:** When a scan is cancelled, simply killing the Python subprocess is not enough — tools like nmap spawn child processes. The solution was to use `os.setsid()` on process creation (creating a new process group) and then `os.killpg(os.getpgid(proc.pid), signal.SIGTERM)` to terminate the entire group atomically.

2. **Concurrent output parsing:** Multiple scans complete simultaneously. Since all results write to `store.json`, a threading lock (`threading.Lock()`) protects all read-modify-write cycles on the data store.

3. **Worker/server result handoff:** In distributed mode, the server cannot block waiting for each worker result. A dedicated `poll_worker_results()` background thread continuously polls Redis for completed result keys, parses them, and integrates them into the store — allowing the main Flask thread to remain responsive.

4. **Tool output normalization:** Each scanning tool produces completely different output formats. Parsers were written for nmap text/XML, enum4linux, gobuster, nikto, wpscan JSON, smbmap, whatweb, nuclei JSON, testssl, and more. The most complex was nmap XML parsing, which required handling the full DTD schema for host/port/script output elements.

5. **Redis unavailability resilience:** Early testing showed that if Redis was slow to start, the entire system failed. The solution was graceful degradation: the server detects Redis unavailability at startup and automatically falls back to `WORKER_MODE=local`, running scans directly on the server container with a thread pool.

---

### Q3: How does your tool provide operational security advantages over existing tools? What makes it stealthy or hard to detect?

Reconboard is an **operator-side infrastructure tool**, so its OpSec properties are different from agent-side implants. The relevant OpSec considerations are:

**1. Operator-Side Protection:**
- All Red Team coordination traffic stays internal. Operators connect to Reconboard over the team's own network — Blue Team never sees C2 traffic between operators.
- Session authentication (password + optional API key) prevents Blue Team from stumbling onto the dashboard if they compromise a pivot point.
- The web server runs on a non-standard port (8443) with session cookies that expire after 12 hours.

**2. Scan Traffic Control:**
- Scan profiles include configurable timing. Nmap profiles use `-T3` (normal) rather than `-T5` (aggressive), reducing the burst signature that IDS sensors trigger on.
- Masscan and naabu are available as alternatives when speed is needed and noise tolerance is high; operators can choose profiles based on the Blue Team's monitoring maturity.
- UDP scans are separated into their own profile so operators can selectively enable them only when necessary (UDP scan traffic is distinctively noisy).

**3. Credential Attack Restraint:**
- Hydra and Medusa are invoked with conservative thread counts and delays. Brute force profiles are marked "optional" rather than "required," requiring explicit operator selection. This prevents accidental account lockouts that would alert Blue Team.

**4. Artifact Minimization:**
- All raw scan output is stored in `./data/scans/` on the operator's Docker host — not on any target system. There are no files dropped on targets.
- Workers run in Docker containers with ephemeral filesystems; if a worker container is killed, it leaves no persistent state on the operator host outside of the shared `./data/` volume.

**5. Tool-Agnostic Signature Avoidance:**
- Because Reconboard wraps arbitrary command-line tools rather than implementing its own network stack, Blue Team IDS signatures written for Reconboard specifically do not exist. Each scan looks like a standard nmap/gobuster/nikto scan — the same traffic you'd see from a competent manual operator.

---

### Q4: What testing did you perform to verify your tool works correctly? Describe your test environment and test cases.

**Test Environment:**

All testing was performed on isolated OpenStack VMs:
- **Operator Host:** Ubuntu 22.04 with Docker + Docker Compose installed, running Reconboard v5.
- **Target 1:** Kali Linux with Apache2, SSH, and vsftpd enabled — simulates a "misconfigured Linux server."
- **Target 2:** Ubuntu 22.04 with Samba, Redis (unauthenticated), and MySQL.
- **Target 3:** Windows Server 2022 (SMB, RDP, WinRM enabled) for AD/credential attack testing.

**Test Cases Executed:**

| Test | Expected Result | Pass/Fail |
|------|----------------|-----------|
| Add target by hostname | Target appears in dashboard with "pending" status | Pass |
| Nmap quick scan (TCP SYN) | Open ports appear in target detail panel | Pass |
| Scan profile generation | SMB profiles appear when 445 open; web profiles when 80 open | Pass |
| Gobuster path discovery | Discovered paths listed in findings with HTTP status codes | Pass |
| enum4linux against Samba | Shares, users, and OS info extracted into findings | Pass |
| Hydra SSH brute force | Valid credential appears in Credentials tab | Pass |
| Redis unauthenticated INFO | Finding created (Critical) with config dump | Pass |
| Worker distributed mode | Scans dispatched to worker containers; results returned | Pass |
| `--scale worker=3` | Three workers active; jobs distributed round-robin | Pass |
| Redis unavailable fallback | System falls back to local mode, logs warning | Pass |
| Scan cancellation | Process group terminated; scan marked "failed" | Pass |
| JSON export | Complete store.json downloaded with all findings/creds | Pass |
| Session auth | `/api/targets` returns 401 without valid session | Pass |
| Scan timeout enforcement | 30-minute scans killed at `SCAN_TIMEOUT` boundary | Pass |
| Import raw nmap output | Output parsed, ports/services integrated into target | Pass |

**Regression Testing:**

After each major change (distributed mode implementation, parser additions, UI redesign), I re-ran the core scan pipeline end-to-end on the test environment to verify no regressions. The git commit history reflects this iterative development: initial commit established the core Flask server, subsequent commits added the Redis worker architecture, authentication, and parser improvements.

---

## Section 2: Team Coordination

### Q5: List all team members and what tool each person is developing. Include the team coordination document/spreadsheet.

**Team Coordination Table:**

| Team Member | Tool Category | Specific Tool | Language | Status |
|-------------|--------------|---------------|----------|--------|
| Odessa | Category 4 — Infrastructure | Reconboard v5 (Recon Dashboard) | Python/Flask | Complete |
| [Teammate 1] | Category 1 — Beacon/Callback | [Tool name] | [Language] | [Status] |
| [Teammate 2] | Category 2 — Service Backdoor | [Tool name] | [Language] | [Status] |
| [Teammate 3] | Category 5 — Info Gathering | [Tool name] | [Language] | [Status] |
| [Teammate 4] | Category 3 — Destructive/Distracting | [Tool name] | [Language] | [Status] |

*[Note: Fill in teammate details from the team's shared coordination document/Discord post before submitting.]*

---

### Q6: How did you coordinate with your team to avoid duplication? Describe the process you used to select your specific tool.

Team coordination happened in two stages:

**Stage 1 — Capability Gap Analysis (Discord meeting):**
The team met early in the assignment window and mapped out what a full Red Team operation needs end-to-end: initial access, persistence, information gathering, lateral movement, and coordination. We identified that without a shared operator dashboard, everyone would be running redundant scans and losing track of findings. No teammate was planning to build anything in the infrastructure category — most were gravitating toward beacons, backdoors, and credential harvesters.

**Stage 2 — Division of Labor:**
I claimed Category 4 (Infrastructure) explicitly because I had prior experience with Flask and Docker, and because Reconboard would benefit every other team member's tool by providing a central place to track and act on the results those tools generate. We documented assignments in a shared Discord pinned message and checked in weekly on progress.

The primary deduplication check was confirming that no one else was building a web-based operator console or reconnaissance aggregator — confirmed by the end of our first meeting.

---

### Q7: How does your tool complement the other tools your teammates are building? Explain how they work together to support Red Team operations.

Reconboard is designed explicitly to be the hub that other tools feed into. The integration model:

**Beacon/Callback tools (Teammate 1):**
When a beacon checks in from a compromised host, the operator can log that host as a target in Reconboard and immediately kick off an automated internal reconnaissance campaign — port scans, SMB enumeration, credential spraying — from the operator side. The beacon's C2 is separate, but Reconboard tracks the full intelligence picture on that host.

**Service Backdoors (Teammate 2):**
Web shell access is often used for lateral recon. As information is gathered through the webshell (config files, internal hosts), those targets can be added to Reconboard for full-coverage scanning. Reconboard's Notes tab provides a place to record webshell URLs and credentials found this way.

**Credential Harvesters (Teammate 3):**
Any credentials found by a harvester can be added directly to Reconboard's Credentials tab, tagged by source target. Reconboard can then use those credentials to drive Hydra/Medusa credential stuffing profiles against other targets — automating the lateral movement credential reuse workflow.

**Distracting Tools (Teammate 4):**
Timing matters. When a distracting/disrupting tool is deployed, it creates a window when Blue Team's attention is elsewhere. Having Reconboard pre-staged with a queued batch scan profile means we can launch aggressive multi-target scans during that window with a single button press, rather than manually typing nmap commands across a dozen terminal windows.

The shared persistent store means any operator can see what's been scanned, what was found, and what still needs attention — eliminating duplicated effort and communication overhead during a time-pressured competition.

---

## Section 3: Operational Use

### Q8: Provide a detailed scenario of how you would use this tool during a competition.

**Scenario: First 30 Minutes of Red Team Week**

**Pre-competition Setup (T-10 minutes):**
1. On the Red Team operator laptop, run `./build-and-launch.sh` — this builds the Reconboard Docker images and launches all three services (Redis, server, 2 workers).
2. Navigate to `https://localhost:8443`, log in with the configured password.
3. Pre-populate target list with the 7 Blue Team service targets from the competition brief (the `data/store.json` template already includes these with placeholder IPs).

**Initial Compromise Context:**
Assume we've already gained a foothold through a pre-competition phishing exercise. We have SSH access to one Blue Team workstation.

**Phase 1 — Discovery (T+0 to T+10):**
1. Assign the known IP to the first target in Reconboard.
2. Click "Scan All" → select "Quick Scan (TCP SYN)" profile → Submit.
3. Reconboard dispatches Nmap SYN scans to all targets simultaneously via the Redis worker queue. With 2 workers and `WORKER_CONCURRENCY=3`, six scans run in parallel.
4. Within 3-5 minutes, open ports populate in each target's detail panel. The server auto-generates findings (Critical: port 445, 6379; High: port 88 suggesting AD) and severity tags.

**Phase 2 — Enumeration (T+10 to T+25):**
1. For each target that now has detected services, Reconboard auto-generates service-specific scan profiles.
2. Operator selects the AD target (port 88 open), clicks the SMB/AD scan set: enum4linux, smbmap, RPCclient null session, GetNPUsers for AS-REP roasting.
3. These are dispatched to workers. Results stream back and are parsed: share names, usernames, and any AS-REP hashes appear automatically in the Findings and Credentials tabs.
4. Web target (port 80/443) gets gobuster + nikto + whatweb dispatched. Discovered paths and tech stack appear.

**Phase 3 — Credential Attacks (T+25 to T+40):**
1. Any usernames from enum4linux enumeration are now in the Findings tab. The operator copies them to a file and kicks off the SSH hydra profile against that target, pointed at a competition-legal wordlist.
2. Valid credentials appear in the Credentials tab. Operator notes which targets those credentials work on.

**Cleanup / Persistence:**
- Reconboard itself runs on the operator machine, not on targets — no cleanup on targets needed for this tool.
- All findings, credentials, and notes are exported as JSON (`/api/export`) and backed up to the team Discord at the end of each session.

---

### Q9: What are the risks of using this tool? Consider detection by Blue Team, competition rule violations, and Grey Team coordination.

**Detection Risks:**

| Risk | Severity | Mitigation |
|------|----------|------------|
| Nmap SYN scans trigger IDS | Medium | Use `-T3` timing; stagger scans across targets |
| Gobuster path brute force visible in web logs | Medium | Mark web profiles as optional; only run when warranted |
| Hydra brute force triggers account lockout | High | Use conservative thread counts; verify lockout policy before running |
| Redis unauthenticated scan triggers alert | Low | One-shot INFO request — low volume |
| Operator dashboard exposed on network | Medium | Bind to loopback or use firewall rules; strong password |
| Workers running with `--privileged` flag | Low (operator-side) | Only affects operator container, not target |

**Competition Rule Violations:**

- **Hydra/Medusa brute force** is the highest-risk profile from a rules perspective. Some competitions prohibit credential attacks that lock accounts or cause service disruption. Before enabling the credential attack profiles, verify with Grey Team that brute forcing is in scope and that the target service has either no lockout policy or a competition-safe one.
- **Resource-exhaustion scans** (masscan at max rate, nmap -T5) could affect other teams' connectivity to shared infrastructure. The default masscan rate is capped in the profile definition; operators should not raise it without Grey Team clearance.
- **Nuclei CVE templates** could trigger active exploitation chains, not just detection. The profiles limit nuclei to `severity:critical,high,medium` and exclude `exploit` tags — but this should be reviewed with Grey Team as well.

**Grey Team Coordination Requirements:**
- Confirm that active scanning of all Blue Team targets is permitted from the start of the competition window (some competitions have a "no scanning before time X" rule).
- Confirm acceptable brute force thresholds.
- Confirm that deploying operator infrastructure on the competition network is allowed (Reconboard uses host networking).

---

### Q10: What improvements or enhancements would you make given more time?

1. **Credential Reuse Automation:** Currently, credentials found on one target must be manually applied to other targets. An automated "spray found credentials" feature would select all valid credentials and automatically test them against all other targets via SSH/SMB/WinRM.

2. **Network Graph Visualization:** A D3.js-powered network graph showing targets, discovered lateral paths (shared credentials, SMB trusts), and compromise status would give operators a faster situational awareness view than the current table layout.

3. **Loot Exfiltration Integration:** A lightweight SCP/HTTP pull client in the worker that could retrieve specific files (e.g., `/etc/shadow`, SAM hive) from compromised targets directly into the Reconboard loot store, indexed by target.

4. **HTTPS for Scan Traffic:** Currently, worker-to-Redis communication is unencrypted (relying on network isolation). Adding TLS to the Redis connection would harden the system against Blue Team pivots onto the operator network.

5. **Slack/Discord Webhook Notifications:** Push new Critical findings to the team's Discord channel automatically, so operators not watching the dashboard still get alerted to high-value discoveries in real time.

6. **Automated Re-scan on Credential Discovery:** Trigger a second-pass scan with authenticated credentials when any new credential is added — e.g., automatically run SMB shares enumeration with `smbmap -u <user> -p <pass>` against all SMB targets when a valid Windows credential is discovered.

7. **BloodHound Integration:** Parse BloodHound JSON output and surface key attack paths (shortest path to Domain Admin) as structured findings rather than requiring operators to interact with BloodHound separately.

---

## Section 4: Ethical Considerations

### Q11: This tool is designed for offensive security operations. Explain under what circumstances it is ethical to use this tool, what safeguards are built in, and how you ensure it is only used in authorized contexts.

**Ethical Use Circumstances:**

Reconboard is ethical to use when:
1. **In authorized CSEC-473 competitions,** against Blue Team systems that have been formally designated as competition targets by Grey Team/instructors.
2. **In isolated lab environments** (e.g., personal OpenStack VMs) owned by the operator, for tool development and testing.
3. **In professional penetration testing engagements** where explicit written authorization (Statement of Work or Rules of Engagement) covers active reconnaissance of the target scope.
4. **In security research contexts** against systems the researcher owns or has contractual permission to assess.

It is unethical — and illegal — to use this tool against systems without explicit authorization, regardless of perceived intent.

**Built-in Safeguards:**

1. **Authentication required:** Every API endpoint (except `/login` and `/api/health`) requires a valid session cookie or API key. An attacker who finds the Reconboard instance cannot use it to scan unauthorized systems without the password.

2. **No autonomous activation:** Reconboard does not initiate any scans automatically. Every scan requires an explicit operator action (button click or API call). There is no "scan everything on startup" behavior.

3. **No implant/dropper functionality:** Reconboard only executes scans from the operator side. It does not deploy agents, drop files on target systems, or establish persistent access to any system. Its attack surface is limited to network-level reconnaissance.

4. **Configurable and auditable:** All scans executed are logged in the system log with timestamps, target, and command. Operators have a full audit trail of every action taken.

5. **No hardcoded targets:** The target list is empty by default. An operator must explicitly add targets. This prevents accidental scanning of unintended systems.

**Ensuring Authorized Use:**

- The tool is distributed only within the Red Team; it is not published to public repositories.
- The README explicitly states authorized use contexts and prohibits use outside competition/lab environments.
- Source code includes the author's name and a license header stating the tool is for authorized security testing only.

---

### Q12: Describe the potential harm if this tool were used maliciously outside of competitions. What is your responsibility as the tool's creator?

**Potential Harm:**

If deployed against unauthorized systems, Reconboard would dramatically lower the effort required to conduct a comprehensive network reconnaissance attack. A malicious operator could:

1. **Enumerate an entire corporate network** in under an hour using distributed workers — discovering exposed services, unpatched vulnerabilities, and misconfigurations at scale.
2. **Harvest credentials** via automated Hydra campaigns across all discovered SSH, FTP, and database services simultaneously, enabling rapid account compromise.
3. **Identify critical vulnerabilities** via Nuclei template scans across hundreds of hosts, surfacing exploitable CVEs far faster than manual enumeration.
4. **Coordinate a multi-stage intrusion** using the Credentials and Findings tabs as an attack map — a structured record of every weakness discovered across every target.

The aggregation and automation capabilities that make Reconboard valuable for authorized Red Team operations are precisely what would make it dangerous in malicious hands. The difference between a penetration test and a network intrusion is solely the presence of written authorization.

**My Responsibility as Creator:**

1. **Distribution control:** I will not publish Reconboard to public repositories (GitHub, etc.) without carefully evaluating the risks. If published, it would require prominent legal disclaimers and should only be distributed within educational/professional security communities.

2. **No obfuscation of capability:** I should be transparent about what this tool does when sharing it with instructors, teammates, or in documentation. Claiming it is "just a dashboard" while downplaying its offensive reconnaissance capabilities would be irresponsible.

3. **Education over exploitation:** The value of building this tool is in understanding how distributed reconnaissance works — the same knowledge enables defenders to detect it. I intend to use this understanding to inform Blue Team detection strategies (IDS signatures for parallelized nmap scans, rate limiting on auth endpoints, etc.).

4. **Ongoing responsibility:** If I become aware that a copy of this tool is being used without authorization, I have an obligation to report it — to instructors, affected parties, or law enforcement as appropriate. The fact that I wrote the tool does not grant cover for its misuse; it increases my accountability to ensure it is not misused.

5. **Legal compliance:** I affirm that this tool was developed solely for use in authorized CSEC-473 competition environments, personal lab VMs, and documented penetration testing engagements with written authorization. I will not use it against any system — including RIT systems, classmates' personal devices, or any external infrastructure — without explicit written permission.

---

*Repository link: [Add GitHub URL here]*
*Filename: lastname-firstname-hw4-report.pdf*
