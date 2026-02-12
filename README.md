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

## Quick Start

### Prerequisites

- Podman + podman-compose (or Docker)
- HTB VPN config (`.ovpn` file)
- Google Gemini API credentials (for gemini-cli)

### 1. Start Infrastructure

```bash
cd $PROJECT_ROOT  # root of blunderbussy repo

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

# Run AutoRecon (hostname first enables vhost enumeration)
podman exec hexstrike-recon /opt/run-autorecon.sh lame.htb 10.10.10.3

# Watch for CAS generation
watch ls artifacts/10.10.10.3/
# Wait for context.yaml
```

### 3. Launch Dame (AI Agent)

```bash
# Start Dame container
podman-compose up -d dame

# Attach to Dame's tmux session (gemini-cli starts automatically)
podman exec -it dame tmux attach -t dame

# First run: gemini-cli will prompt for authentication (OAuth or API key)
# Follow the on-screen instructions to complete setup

# Engage target (gemini-cli is already running)
/attack 10.10.10.3
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Container stack, component table, network topology |
| [Enrichment Pipeline](docs/enrichment-pipeline.md) | Faraday integration, 80+ parsers, pipeline flow |
| [Data Schemas](docs/data-schemas.md) | CAS and PTT YAML formats with examples |
| [Security Model](docs/security-model.md) | Four-layer protection: network, volume, scope, AI guardrails |
| [Dame Builds](docs/dame-builds.md) | Platform-specific builds and tool inventory |
| [Project Structure](docs/project-structure.md) | Full directory tree with annotations |
| [Gemini CLI Agents](docs/gemini-cli-agents.md) | Extension system internals and agent reference |

---

## Status

**Current Phase:** Active development — testing against HTB machines of increasing difficulty (currently hill-climbing on a medium-difficulty Linux box)

- [x] Docker environment + network isolation (gluetun VPN)
- [x] Enrichment pipeline (Faraday 80+ parsers, enrichers, CAS formatter)
- [x] Dame container (Kali + gemini-cli + pwncat-cs)
- [x] Opulence extension (MCP servers, task tree, error handling)
- [x] HexStrike recon container (AutoRecon integration)
- [x] Test framework (pytest with fixtures, ~425 unit tests)
- [x] Issue tracking (Beads)
- [x] MCP server modernization (FastMCP, Pydantic validation)
- [ ] C2 framework integration (MSF + Sliver defined, not yet tested against HTB)
- [ ] E2E testing on additional HTB machines
- [ ] Multi-target parallelization

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
