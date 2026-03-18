FROM kalilinux/kali-rolling

LABEL maintainer="Red Team"
LABEL description="Reconboard v5 — Distributed Kali Reconnaissance Server"

# ─── Avoid interactive prompts ───
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_BREAK_SYSTEM_PACKAGES=1

# ─── Layer 1: Base system & Python ───
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    curl \
    wget \
    git \
    ca-certificates \
    dnsutils \
    net-tools \
    iputils-ping \
    jq \
    tmux \
    libpcap-dev\ 
    && rm -rf /var/lib/apt/lists/*

# ─── Layer 2: Core scanning tools ───
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    enum4linux \
    smbclient \
    smbmap \
    netexec \
    gobuster \
    dirb \
    nikto \
    wpscan \
    whatweb \
    dnsrecon \
    dnsenum \
    hydra \
    redis-tools \
    samba-common-bin \
    ldap-utils \
    netcat-traditional \
    snmp \
    snmp-mibs-downloader \
    medusa \
    pipx \
    && rm -rf /var/lib/apt/lists/*

# ─── Layer 3: Advanced recon & vuln tools ───
RUN apt-get update && apt-get install -y \
    sqlmap \
    hashcat \
    john \
    onesixtyone \
    smtp-user-enum \
    sslscan \
    sslyze \
    testssl.sh \
    responder \
    nbtscan \
    ike-scan \
    arping \
    hping3 \
    fping \
    p0f \
    theharvester \
    recon-ng \
    wafw00f \
    lbd \
    swaks \
    whois \
    traceroute \
    tcpdump \
    ngrep \
    netdiscover \
    arp-scan \
    && rm -rf /var/lib/apt/lists/*

# ─── Layer 4: Impacket & AD tools ───
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-impacket \
    impacket-scripts \
    evil-winrm \
    bloodhound \
    && rm -rf /var/lib/apt/lists/* \
    || pip3 install impacket

# ─── Layer 5: Go-based tools (nuclei, httpx, subfinder, naabu) ───
RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true && \
    cp ${GOPATH}/bin/* /usr/local/bin/ 2>/dev/null || true && \
    rm -rf ${GOPATH}/pkg ${GOPATH}/src /root/.cache/go-build

RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    cp ${GOPATH}/bin/naabu /usr/local/bin/ || true

# ─── Layer 5b: Missing tools fixup ───
RUN apt-get update && apt-get install -y --no-install-recommends \
    enum4linux-ng \
    amass \
    testssl.sh \
    vim-common \
    && rm -rf /var/lib/apt/lists/*

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# ─── Layer 6: Feroxbuster ───
RUN apt-get update && apt-get install -y feroxbuster \
    && rm -rf /var/lib/apt/lists/* \
    || (curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin)

# ─── Layer 7: CrackMapExec / certipy ───
RUN pipx install crackmapexec 2>/dev/null || true && \
    pipx install certipy-ad 2>/dev/null || true && \
    pipx ensurepath || true

# ─── Layer 8: ExploitDB / searchsploit ───
RUN apt-get update && apt-get install -y --no-install-recommends \
    exploitdb \
    && rm -rf /var/lib/apt/lists/*

# ─── Layer 9: Wordlists ───
RUN apt-get update && apt-get install -y --no-install-recommends \
    seclists \
    wordlists \
    && rm -rf /var/lib/apt/lists/* \
    && [ -f /usr/share/wordlists/rockyou.txt.gz ] && gunzip /usr/share/wordlists/rockyou.txt.gz || true

# ─── Layer 10: Python deps ───
RUN pip3 install flask redis requests

# ─── Application setup ───
WORKDIR /opt/redrecon

COPY recon_server.py .
COPY worker.py .
COPY templates/ templates/
COPY static/ static/

RUN mkdir -p data/scans

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8443/api/health || exit 1

EXPOSE 8443

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--port", "8443", "--host", "0.0.0.0"]
