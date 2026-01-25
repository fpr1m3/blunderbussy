# Agent Opulence (Blunderbussy)

> **"Dumb Tools Scan, Smart Agents Plan"**

Autonomous offensive security orchestration engine. Automated pipelines handle reconnaissance, AI agents handle exploitation.

---

## Overview

Agent Opulence strictly separates **deterministic scanning** from **strategic decision-making**:

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1: AUTOMATED RECONNAISSANCE (Deterministic)          │
│  nmap → httpx → nuclei → feroxbuster → nikto → whatweb     │
│  Outputs: XML/JSON raw scans → /artifacts/raw/              │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  ENRICHMENT PIPELINE (Parsers, Enrichers, CAS Formatter)    │
│  Watcher detects files → Parse to JSON → Enrich with CVEs   │
│  Format to YAML → Initialize PTT                            │
│  Output: /artifacts/{target}/context.yaml + ptt.yaml        │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 2: AI-DRIVEN EXPLOITATION (Strategic)                │
│  Dame (AI Agent) loads PTT → Executes → Adapts → Escalates  │
│  Tools: msfconsole, searchsploit, pwncat-cs, manual exploits│
└─────────────────────────────────────────────────────────────┘
```

**The AI does NOT:**
- Run nmap, nuclei, feroxbuster, or any routine scanning
- Discover services or enumerate targets

**The AI DOES:**
- Analyze complete CAS (Context-Aware Summary) documents
- Make strategic exploitation decisions
- Execute exploits and adapt when they fail
- Perform privilege escalation

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     DAME CONTAINER                           │
│  Kali Linux + gemini-cli + pwncat-cs                        │
│  Dame (AI): Reads CAS, exploits, privesc                    │
├─────────────────────────────────────────────────────────────┤
│                   ENRICHMENT PIPELINE                        │
│  watcher.py → Parsers → Enrichers → CAS Formatter           │
├─────────────────────────────────────────────────────────────┤
│                  HEXSTRIKE (Recon Tools)                     │
│  AutoRecon, nmap, nuclei, feroxbuster, 150+ tools           │
├─────────────────────────────────────────────────────────────┤
│                   C2 FRAMEWORKS (MSF + Sliver)               │
│  msf (msfrpcd) + msf-bridge + sliver daemon                  │
├─────────────────────────────────────────────────────────────┤
│                 NETWORK ISOLATION (GLUETUN)                  │
│  VPN tunnel + killswitch, all traffic through HTB VPN       │
└─────────────────────────────────────────────────────────────┘
```

### Main Components

| Component | Container | Purpose |
|-----------|-----------|---------|
| `gluetun` | VPN gateway | Mandatory VPN with killswitch, network isolation |
| `enrichment` | Python 3.11 | Watches raw scans, parses, enriches, outputs CAS |
| `hexstrike-recon` | 150+ tools | Automated recon (nmap, nuclei, feroxbuster, etc.) |
| `dame` | Kali + gemini-cli | AI exploitation agent with full offensive toolkit |
| `qdrant` | Vector DB | Technique library for exploitation knowledge |
| `pwncat-mcp` | Python | Post-exploitation framework MCP server |
| `msf` | Metasploit | Metasploit Framework with msfrpcd for exploitation |
| `msf-bridge` | Go HTTP API | HTTP bridge for MSFRPC communication |
| `sliver` | Sliver C2 | Sliver implant server for C2 operations |

### Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DAME CONTAINER                            │
│  Split tunnel: HTB subnets via VPN, else direct internet    │
│  - 10.10.0.0/16 → gluetun VPN                               │
│  - 10.129.0.0/16 → gluetun VPN                              │
│  - Everything else → direct (OAuth, APIs, web)              │
├─────────────────────────────────────────────────────────────┤
│                     GLUETUN CONTAINER                        │
│  VPN tunnel (HTB) + killswitch + DNS leak protection        │
│  - Only HTB network accessible when VPN connected           │
│  - Killswitch blocks all traffic if VPN drops               │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Podman + podman-compose (or Docker)
- HTB VPN config (`.ovpn` file)
- Google Gemini API credentials (for gemini-cli)

### 1. Start Infrastructure

```bash
cd ~/Projects/blunderbussy

# Copy and configure environment
cp .env.example .env
# Edit .env and set MSF_PASS and other required values

# Copy HTB VPN config
cp /path/to/lab.ovpn infrastructure/gluetun/htb.ovpn

# Start core services
podman-compose up -d gluetun enrichment qdrant

# Verify VPN
podman exec gluetun wget -qO- ifconfig.me
# Expected: HTB VPN IP (10.10.x.x)
```

### 2. Run Reconnaissance

```bash
# Start hexstrike-recon (recon container)
HTB_TARGET=10.10.10.3 podman-compose up -d hexstrike-recon

# Run AutoRecon
podman exec hexstrike-recon /opt/run-autorecon.sh 10.10.10.3

# Watch for CAS generation
watch ls artifacts/10.10.10.3/
# Wait for context.yaml
```

### 3. Launch Dame (AI Agent)

```bash
# Start Dame container
podman-compose up -d dame

# Attach to Dame's tmux session
podman exec -it dame tmux attach -t dame

# Launch gemini-cli
gemini

# Engage target
/attack 10.10.10.3
```

---

## Project Structure

```
blunderbussy/
├── infrastructure/
│   ├── enrichment/           # Enrichment pipeline
│   │   ├── watcher.py        # File system watcher
│   │   ├── format-cas.py     # CAS YAML formatter
│   │   ├── init-ptt.py       # PTT initializer (CAS → PTT)
│   │   ├── parsers/          # 24+ tool parsers
│   │   └── enrichers/        # CVE lookup, service analysis
│   ├── dame/                  # Kali + gemini-cli container
│   │   ├── Dockerfile        # Multi-platform build
│   │   └── docker-entrypoint.sh  # Split tunnel setup
│   ├── PrEP/                  # Gemini-CLI extension + MCP servers
│   │   ├── servers/
│   │   │   ├── pwncat-server.py  # Pwncat MCP (14 tools)
│   │   │   ├── msf-server.py     # MSF MCP (11 tools)
│   │   │   ├── sliver-server.py  # Sliver MCP (11 tools)
│   │   │   └── msf-bridge/       # Go HTTP-to-MSFRPC bridge
│   │   ├── gemini-extension.json
│   │   ├── GEMINI.md         # Dame's system prompt
│   │   ├── ptt.py            # Pentesting Task Tree module
│   │   └── commands/         # /attack command
│   ├── hexstrike-recon/      # 150+ security tools
│   ├── gluetun/              # VPN configuration
│   ├── pwncat/               # Pwncat MCP server
│   ├── msf/                  # Metasploit MCP server
│   └── sliver/               # Sliver C2 MCP server
├── artifacts/                # Runtime (mounted volume)
│   ├── raw/                  # Raw scan output
│   └── {target}/             # Per-target directories
│       ├── context.yaml      # CAS document
│       ├── ptt.yaml          # Task tree
│       └── loot/             # Flags, creds
├── tests/                    # Test suite
│   ├── parsers/              # Parser unit tests
│   ├── fixtures/             # Test data
│   └── integration/          # Integration tests
├── docker-compose.yml        # Stack definition
├── CLAUDE.md                 # Development instructions
├── GEMINI.md                 # Implementation guide
└── AGENTS.md                 # Agent work instructions
```

---

## Enrichment Pipeline

### Supported Parsers (24+)

| Category | Parsers |
|----------|---------|
| **Network** | nmap, dnsrecon, onesixtyone, snmpwalk |
| **Web** | httpx, feroxbuster, gobuster, dirsearch, ffuf, nikto, whatweb, wpscan, nuclei, sslscan |
| **SMB/Enum** | smbmap, enum4linux, showmount |
| **Specialized** | subfinder, rpcdump, dirb, redis-cli, dig, manual-commands |

### Pipeline Flow

```
Raw scan file detected (inotify)
    ↓
Watcher matches file to parser (pattern matching)
    ↓
Parser converts to JSON (host/port/service/vuln objects)
    ↓
Enrichers add context:
  - CVE lookup (NVD API with caching)
  - Service vulnerability scoring
  - Web technology detection
    ↓
CAS Formatter outputs YAML
    ↓
PTT Initializer transforms CAS → PTT (deterministic)
    ↓
Result: /artifacts/{target}/context.yaml + ptt.yaml
```

---

## Data Schemas

### CAS (Context-Aware Summary)

```yaml
# /artifacts/{target}/context.yaml
meta:
  target: 10.10.10.3
  scan_time: 2026-01-20T12:00:00Z
  tools_run: [nmap, httpx, nuclei, feroxbuster]

summary:
  open_ports: 5
  services: [ftp, ssh, http, smb]
  critical_findings: 2

services:
  - port: 21
    service: ftp
    version: vsftpd 2.3.4
    vulns:
      - cve: CVE-2011-2523
        severity: critical
        epss: 9.8
        exploit_available: true

attack_guidance:
  quick_wins: []        # Default creds, anon access
  priority_targets: []  # High-value services
```

### PTT (Pentesting Task Tree)

```yaml
# /artifacts/{target}/ptt.yaml
engagement:
  target: 10.10.10.3
  hosts:
    - ip: 10.10.10.3
      services:
        - port: 21
          service: ftp
          techniques:
            - name: anonymous_ftp_login
              status: pending|in_progress|success|failed
              attempts: 0
```

---

## Security Model

### Three-Layer Protection

1. **Network Isolation (Primary/Hard Boundary)**
   - All traffic through gluetun VPN
   - Killswitch blocks non-VPN traffic
   - Even container crash maintains isolation

2. **Scope Definition (Secondary/Soft)**
   - `/artifacts/scope.yaml` defines allowed targets
   - Dame instructed to respect scope in system prompt
   - Parsers filter out-of-scope results

3. **AI Guardrails (Tertiary)**
   - Dame's system prompt: "Only operate on targets in CAS"
   - "No reconnaissance beyond provided CAS"
   - "Document all attempts and findings"

---

## Dame Container Builds

Build with `TARGET_PLATFORM` arg for platform-specific tools:

```bash
# Linux targets (default) - includes searchsploit
podman build --build-arg TARGET_PLATFORM=linux -t dame:linux \
  -f infrastructure/dame/Dockerfile infrastructure/dame/

# Windows/AD targets - includes evil-winrm, bloodhound, ldap-utils
podman build --build-arg TARGET_PLATFORM=windows -t dame:windows \
  -f infrastructure/dame/Dockerfile infrastructure/dame/
```

**Core tools (all builds):** nc, nmap, feroxbuster, ffuf, gobuster, whatweb, sqlmap, nikto, enum4linux, smbmap, smbclient, impacket-scripts, crackmapexec, pwncat-cs

---

## Development

### Python Tooling

Use `uv` for Python package management:

```bash
uv pip install <package>   # Install packages
uv run pytest              # Run tests
uv run python script.py    # Run scripts
```

### Container Tooling

Use `podman` and `podman-compose`:

```bash
podman-compose up -d       # Start services
podman-compose ps          # List containers
podman exec -it <name> sh  # Execute in container
```

### Running Tests

```bash
cd ~/Projects/blunderbussy
uv run pytest tests/parsers/  # Parser unit tests
uv run pytest tests/ -v       # All tests
```

---

## Task Tracking

This project uses **beads** (`bd`) for issue tracking:

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status=in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

---

## Status

**Current Phase:** Production-ready PoC

- [x] Docker environment + network isolation (gluetun VPN)
- [x] Enrichment pipeline (24+ parsers, enrichers, CAS formatter)
- [x] Dame container (Kali + gemini-cli + pwncat-cs)
- [x] Opulence extension (MCP servers, task tree, error handling)
- [x] HexStrike recon container (AutoRecon integration)
- [x] Test framework (pytest with fixtures)
- [x] Issue tracking (Beads)
- [x] MCP server modernization (FastMCP, Pydantic, 172 tests)
- [x] C2 framework integration (MSF + Sliver via gluetun VPN)
- [ ] E2E testing on additional HTB machines
- [ ] Multi-target parallelization

---

## License

Private project. Not for distribution.
