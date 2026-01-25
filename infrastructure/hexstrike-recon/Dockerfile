# Agent Opulence - HexStrike Container
# Privileged container with offensive security tools
FROM docker.io/kalilinux/kali-last-release
# Using kali-last-release for stable versioned releases
# (kali-rolling updates continuously and can break unexpectedly)

LABEL maintainer="Agent Opulence"
LABEL description="HexStrike-AI with offensive security tools"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install base tools and Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Kali metapackages for security tools
# Using specific packages instead of full metapackages to keep image smaller
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network reconnaissance
    nmap \
    masscan \
    # rustscan - not in Kali repos, install via cargo if needed
    amass \
    subfinder \
    # Web tools
    gobuster \
    feroxbuster \
    dirb \
    ffuf \
    nikto \
    sqlmap \
    wpscan \
    nuclei \
    httpx-toolkit \
    whatweb \
    # Enumeration
    enum4linux \
    smbclient \
    smbmap \
    nbtscan \
    dnsrecon \
    impacket-scripts \
    # SNMP tools
    snmp \
    onesixtyone \
    # SSL/TLS
    sslscan \
    # VoIP
    sipvicious \
    # Database tools
    oscanner \
    tnscmd10g \
    redis-tools \
    # Password attacks
    hydra \
    john \
    hashcat \
    # Binary analysis (lighter set)
    binwalk \
    checksec \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Pre-download nuclei templates (avoids first-run delay)
# Templates stored in /root/nuclei-templates
RUN nuclei -update-templates -silent

# Install AutoRecon via pipx (isolated environment)
RUN apt-get update && apt-get install -y --no-install-recommends pipx seclists && \
    rm -rf /var/lib/apt/lists/* && \
    pipx ensurepath && \
    pipx install git+https://github.com/Tib3rius/AutoRecon.git

# Ensure pipx binaries are in PATH
ENV PATH="/root/.local/bin:${PATH}"

# Create AutoRecon config directory and copy HTB config
# VERSION file prevents "outdated config" warning
RUN mkdir -p /root/.config/AutoRecon
COPY autorecon-htb.toml /root/.config/AutoRecon/config.toml
RUN touch /root/.config/AutoRecon/VERSION-2.0.36

WORKDIR /app

# Clone HexStrike-AI
RUN git clone --depth 1 https://github.com/0x4m4/HexStrike-AI.git /app/hexstrike

# Install Python dependencies from HexStrike requirements
# --ignore-installed needed for Kali system packages without RECORD files
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed \
    # Core framework
    flask>=2.3.0 \
    requests>=2.31.0 \
    psutil>=5.9.0 \
    fastmcp>=0.2.0 \
    # Web scraping & automation
    beautifulsoup4>=4.12.0 \
    selenium>=4.15.0 \
    webdriver-manager>=4.0.0 \
    # Async & networking
    aiohttp>=3.8.0 \
    # Proxy
    mitmproxy>=9.0.0 \
    # Binary analysis (uses system bcrypt)
    pwntools>=4.10.0

WORKDIR /app/hexstrike

ENV PYTHONUNBUFFERED=1
ENV HEXSTRIKE_HOST=0.0.0.0
ENV HEXSTRIKE_PORT=8888

# Copy and set up entrypoint
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Copy recon scripts
COPY run-recon.sh /usr/local/bin/
COPY run-autorecon.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run-recon.sh /usr/local/bin/run-autorecon.sh

# Expose Flask API port
EXPOSE 8888

# Entrypoint handles HTB_TARGET/HTB_HOSTNAME for /etc/hosts
ENTRYPOINT ["docker-entrypoint.sh"]

# Start the backend server
CMD ["python3", "hexstrike_server.py"]
