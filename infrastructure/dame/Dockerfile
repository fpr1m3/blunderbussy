FROM kalilinux/kali-rolling

# Target platform: linux or windows (controls which tool groups to install)
ARG TARGET_PLATFORM=linux

# =============================================================================
# CORE TOOLS (always installed)
# =============================================================================
# Networking basics, shells, utilities needed regardless of target OS
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd iputils-ping traceroute wget \
    socat rlwrap git jq ftp telnet sshpass \
    dnsutils proxychains4 \
    html2text lynx \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# RECON & EXPLOITATION TOOLS (platform-agnostic)
# =============================================================================
# Recon is done upfront by AutoRecon - these are for exploitation phase
# Includes credential tools (hydra) for CAS-recommended attacks
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dnsrecon nbtscan onesixtyone snmp \
    gobuster feroxbuster ffuf whatweb sqlmap nikto \
    enum4linux smbmap smbclient impacket-scripts \
    crackmapexec hydra \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# LINUX TARGET TOOLS
# =============================================================================
# Tools specifically useful when attacking Linux targets
RUN if [ "$TARGET_PLATFORM" = "linux" ]; then \
    apt-get update && apt-get install -y --no-install-recommends \
        exploitdb \
    && rm -rf /var/lib/apt/lists/*; \
    fi

# =============================================================================
# WINDOWS/AD TARGET TOOLS
# =============================================================================
# Tools for Windows/Active Directory environments
RUN if [ "$TARGET_PLATFORM" = "windows" ]; then \
    apt-get update && apt-get install -y --no-install-recommends \
        evil-winrm responder ldap-utils bloodhound \
    && rm -rf /var/lib/apt/lists/*; \
    fi

# Install base dependencies:
# - nodejs/npm: For gemini-cli (Kali has Node 22.x in repos)
# - python3 stack: For pwncat-cs and Python-based tools
# - build deps: For pwncat-cs netifaces native compilation
# - iproute2: For split tunnel routing to gluetun VPN
# - tmux: For persistent session management
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm \
    python3 python3-pip python3-venv python3-dev \
    gcc libc-dev libffi-dev \
    tmux curl ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install uv (provides uvx for mcp-server-qdrant)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Install pwncat-cs for pwncat MCP server
# pwncat-cs pins packaging<21 which requires distutils (removed in Python 3.13)
# Use Python 3.11 explicitly for pwncat-cs until upstream fixes the dep
RUN uv tool install pwncat-cs --python 3.11

# Install git-dumper for exposed .git repository exploitation
# Referenced by CAS attack guidance for web targets
RUN uv tool install git-dumper

# =============================================================================
# MEMORY SYSTEM DEPENDENCIES
# =============================================================================
# Required for session_state.py and session_memory.py hooks
# Using apt for Kali's externally managed Python environment
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pydantic python3-requests \
    && rm -rf /var/lib/apt/lists/*

# Install gemini-cli globally
RUN npm install -g @google/gemini-cli

WORKDIR /app

COPY docker-entrypoint.sh /usr/local/bin/
COPY settings.json /etc/gemini/settings.json
COPY tmux.conf /root/.tmux.conf
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["tmux", "attach", "-t", "dame"]
