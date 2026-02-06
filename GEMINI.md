# GEMINI.md - Agent Opulence Implementation Guide (v5.0)

> **Design Documentation:** `$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/`

## Core Philosophy: "Dumb Tools Scan, Smart Agents Plan"

Agent Opulence strictly separates **automated reconnaissance** from **AI-driven exploitation**:

```
┌─────────────────────────────────────────────────────────────┐
│         AUTOMATED PIPELINE (No AI, Deterministic)           │
│  HexStrike: nmap → httpx → nuclei → feroxbuster → etc.     │
│         ↓                                                   │
│  Enrichment: Faraday (80+ parsers) → Enrichers → CAS       │
│         ↓                                                   │
│  Output: /artifacts/{target}/context.yaml + ptt.yaml        │
└──────────────────────────┬──────────────────────────────────┘
                           ↓ (CAS + PTT ready)
┌─────────────────────────────────────────────────────────────┐
│            DAME (gemini-cli, Strategic AI)                   │
│  Reads CAS → Plans attack → Executes exploit → Privesc      │
│  Tools: pwncat-cs, msfconsole, sliver, searchsploit         │
└─────────────────────────────────────────────────────────────┘
```

**The AI does NOT:** Run nmap, nuclei, gobuster, or any routine scanning
**The AI DOES:** Analyze CAS, select exploits, execute, adapt, escalate

---

## Technical Stack

### Runtime Environment

| Component | Technology | Purpose |
|-----------|------------|---------|
| AI Runtime | `gemini-cli` + opulence extension | Dame's brain |
| Tool Container | `dame` (Kali + gemini-cli) | Exploitation environment |
| Network Isolation | `gluetun` | VPN tunnel + killswitch |
| Data Pipeline | `enrichment` container | CAS/PTT generation via Faraday |
| C2 Frameworks | `msf` + `msf-bridge` + `sliver` | Exploitation backends |
| Post-Exploitation | `pwncat-mcp` | Shell management via MCP |
| Vector DB | `qdrant` | Technique library for exploitation knowledge |

### Dame Container Builds

Build with `TARGET_PLATFORM` arg for platform-specific tools:

```bash
# Linux targets (default)
podman build --build-arg TARGET_PLATFORM=linux -t dame:linux \
  -f infrastructure/dame/Dockerfile infrastructure/dame/

# Windows/AD targets
podman build --build-arg TARGET_PLATFORM=windows -t dame:windows \
  -f infrastructure/dame/Dockerfile infrastructure/dame/
```

**Core tools (all builds):** nc, ping, traceroute, wget, socat, rlwrap, git, jq, dig, proxychains4, nbtscan, onesixtyone, snmpwalk, nmap, dnsrecon, gobuster, feroxbuster, ffuf, whatweb, sqlmap, nikto, enum4linux, smbmap, smbclient, impacket-scripts, crackmapexec, hydra, tmux, ripgrep

**Linux-specific:** searchsploit (exploitdb)

**Windows-specific:** evil-winrm, responder, ldap-utils, bloodhound

### Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      DAME CONTAINER                          │
│  gemini-cli (Dame) + Full Kali toolset                       │
│  Split tunnel: HTB subnets via VPN, else direct internet     │
│  - 10.10.0.0/16 → gluetun VPN                               │
│  - 10.129.0.0/16 → gluetun VPN                              │
│  - Everything else → direct (OAuth, APIs, web)               │
├─────────────────────────────────────────────────────────────┤
│                      GLUETUN CONTAINER                       │
│  VPN tunnel (HTB) + killswitch + DNS leak protection         │
│  C2 traffic also routes through VPN (MSF, Sliver, pwncat)   │
└─────────────────────────────────────────────────────────────┘
```

---

## Automated Recon Pipeline

### Tool Stack

Recon tools run in the `hexstrike-recon` container. Scan output is parsed by **Faraday** (80+ built-in parsers) — no custom parsers needed.

| Tool | Purpose |
|------|---------|
| nmap -sCV | Port/service/version scan |
| httpx | HTTP probing |
| nuclei | Vulnerability scanning |
| feroxbuster | Directory brute force |
| nikto | Web vulnerability scan |
| whatweb | Technology fingerprint |
| gobuster / ffuf | Additional directory/vhost enumeration |

### Execution

```bash
# Start hexstrike-recon container
HTB_TARGET=10.10.10.3 podman-compose up -d hexstrike-recon

# Run AutoRecon (hostname first enables vhost enumeration)
podman exec hexstrike-recon /opt/run-autorecon.sh lame.htb 10.10.10.3

# Outputs to /artifacts/raw/
# Watcher uploads to Faraday → enrichment pipeline → CAS + PTT
# CAS generated at /artifacts/10.10.10.3/context.yaml
# PTT generated at /artifacts/10.10.10.3/ptt.yaml
```

---

## CAS (Context-Aware Summary)

The CAS is the complete picture of a target, ready for AI analysis:

```yaml
# /artifacts/10.10.10.3/context.yaml
meta:
  target: 10.10.10.3
  scan_time: 2026-01-16T20:00:00Z
  tools_run: [nmap, httpx, nuclei, gobuster, nikto, whatweb]

summary:
  open_ports: 5
  services: [ftp, ssh, netbios, smb]
  critical_findings: 1

services:
  - port: 21
    service: ftp
    version: vsftpd 2.3.4
    vulns:
      - cve: CVE-2011-2523
        severity: critical
        exploit_available: true

attack_guidance:
  source: "gemini"  # or "heuristic" fallback
  quick_wins: []
  priority_targets: []
  recommended_commands: []
```

---

## Dame (gemini-cli Extension)

### Extension Structure

```
infrastructure/PrEP/
├── gemini-extension.json      # Extension manifest (MCP servers, metadata)
├── GEMINI.md                  # Dame's system prompt
├── ptt.py                     # Pentesting Task Tree module
├── session_state.py           # Session state management
├── session_memory.py          # Memory persistence
├── agents/                    # Subagents (delegate_to_agent)
│   ├── archivist.md           # Multi-step research (saves context window)
│   ├── code-analysis-recon.md
│   ├── code-analysis-triage.md
│   ├── code-analysis-analysis.md
│   └── code-analysis-validation.md
├── skills/                    # Skills (activate_skill)
│   ├── SCHEMA.md              # Skill schema documentation
│   ├── code-vuln-analysis/    # Multi-agent vulnerability analysis
│   ├── initial-access/
│   ├── pentest-checklist/
│   ├── pentest-commands/
│   ├── red-team-tactics/
│   ├── scanning-tools/
│   ├── sql-injection-testing/
│   ├── api-fuzzing-bug-bounty/
│   └── vulnerability-scanner/
├── commands/
│   └── attack.toml            # /attack {target}
├── hooks/                     # Tool execution hooks
│   ├── hooks.json
│   ├── session_start.py       # SessionStart: load state + inject memory
│   ├── before_tool.py         # BeforeTool: query cache dedup
│   ├── after_tool.py          # AfterTool: output processing + cred extraction
│   ├── file_size_gate.py      # BeforeTool: block oversized file reads
│   ├── autorecon_dedup.py     # BeforeTool: block redundant scans
│   ├── shellcheck_validator.py # BeforeTool: validate shell syntax
│   ├── command_utils.py       # Shared command parsing utilities
│   └── loop_detector.py       # AfterTool: MinHash similarity loop detection
├── servers/                   # MCP servers
│   ├── pwncat-server.py       # Post-exploitation (FastMCP, 14 tools)
│   ├── msf-server.py          # Metasploit Framework (FastMCP, 11 tools)
│   ├── sliver-server.py       # Sliver C2 (FastMCP, 11 tools)
│   └── msf-bridge/            # Go HTTP-to-MSFRPC bridge
├── schemas/                   # Data schemas
│   ├── PTT_SCHEMA.md
│   └── SESSION_SCHEMA.md
├── protocol/                  # IPC protocol definitions
├── tests/                     # PrEP-specific tests (pipeline gate, etc.)
└── ERROR_HANDLING.md          # Error classification reference
```

### Dame's Role

1. Read `/artifacts/{target}/context.yaml` (CAS) and `ptt.yaml` (PTT)
2. Identify attack vectors from CAS findings
3. Research exploits (searchsploit, msfconsole search, qdrant)
4. Execute exploitation (pwncat, MSF, Sliver, manual exploits)
5. Stabilize shell
6. Escalate privileges
7. Capture flags

### Engagement

```bash
# Inside dame container
gemini
/attack 10.10.10.3
```

---

## Security Model

### Network Isolation (Primary)

- All HTB traffic routes through gluetun VPN
- Killswitch blocks non-VPN traffic
- Container crash = isolation maintained
- Split tunnel: only HTB subnets through VPN

### Scope (Soft Enforcement)

- Defined in `/artifacts/scope.yaml`
- Dame instructed via GEMINI.md to respect scope
- Network-level is the hard boundary

---

## Workflow: Single Target E2E

```bash
# 1. Start infrastructure
podman-compose up -d gluetun enrichment qdrant

# 2. Run automated recon
HTB_TARGET=10.10.10.3 podman-compose up -d hexstrike-recon
podman exec hexstrike-recon /opt/run-autorecon.sh lame.htb 10.10.10.3

# 3. Wait for CAS + PTT
watch ls artifacts/10.10.10.3/

# 4. Start Dame
podman-compose up -d dame
podman exec -it dame tmux attach -t dame
gemini
/attack 10.10.10.3

# 5. Dame exploits, escalates, captures flags
```

---

## Design Documentation Reference

All design documentation: `$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/`

| Topic | File |
|-------|------|
| Architecture | `Architecture/Agents.md` |
| Infrastructure | `Architecture/INFRASTRUCTURE_DESIGN.md` |
| Workflows | `Architecture/WORKFLOW_DESIGN.md` |
| Enrichment | `Implementation/ENRICHMENT_PIPELINE.md` |
| Context | `Implementation/CONTEXT_DESIGN.md` |
| Schemas | `Data/schemas/*.md` |
| Future | `Future/FUTURE_ARCHITECTURE.md` |

---

## Current Status

**Phase:** Production-ready PoC

- [x] Gluetun VPN + killswitch
- [x] Enrichment pipeline (Faraday 80+ parsers, enrichers, CAS formatter)
- [x] Dame container (Kali + gemini-cli + pwncat-cs)
- [x] Opulence extension (MCP servers, task tree, error handling)
- [x] HexStrike recon container (AutoRecon integration)
- [x] MCP server modernization (FastMCP, Pydantic, ~425 tests)
- [x] C2 framework integration (MSF + Sliver via gluetun VPN)
- [x] Test framework (pytest with fixtures)
- [x] Issue tracking (Beads)
- [ ] E2E testing on additional HTB machines
- [ ] Multi-target parallelization
