# Agent Opulence - HexStrike Container
# Privileged container with offensive security tools
FROM docker.io/kalilinux/kali-rolling:latest

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
    nbtscan \
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

WORKDIR /app

# Clone HexStrike-AI
RUN git clone --depth 1 https://github.com/0x4m4/HexStrike-AI.git /app/hexstrike

# Install Python dependencies from HexStrike requirements
RUN pip3 install --no-cache-dir --break-system-packages \
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

# Copy recon script
COPY run-recon.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run-recon.sh

# Expose Flask API port
EXPOSE 8888

# Entrypoint handles HTB_TARGET/HTB_HOSTNAME for /etc/hosts
ENTRYPOINT ["docker-entrypoint.sh"]

# Start the backend server
CMD ["python3", "hexstrike_server.py"]
