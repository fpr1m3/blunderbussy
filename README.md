# Agent Opulence

> **"Dumb Tools Scan, Smart Agents Plan"** - The Gay Agenda v4.0

Autonomous offensive security orchestration engine. Automated pipelines handle reconnaissance, AI agents handle exploitation.

---

## Overview

Agent Opulence strictly separates **deterministic scanning** from **strategic decision-making**:

```
┌─────────────────────────────────────────────────────────────┐
│         AUTOMATED PIPELINE (No AI, Deterministic)           │
│  nmap → httpx → nuclei → gobuster → nikto → whatweb        │
│         ↓                                                   │
│  Enrichment → CVE lookup → CAS Document                    │
└──────────────────────────┬──────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│            DAME (AI, Strategic Decisions)                   │
│  Reads CAS → Plans exploitation → Executes → Privesc       │
└─────────────────────────────────────────────────────────────┘
```

**The AI does NOT:**
- Run nmap, nuclei, gobuster, or any routine scanning
- Discover services or enumerate targets

**The AI DOES:**
- Analyze complete CAS documents
- Make strategic exploitation decisions
- Execute exploits and adapt when they fail
- Perform privilege escalation

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    KALI + GEMINI-CLI                         │
│  Dame (AI): Reads CAS, exploits, privesc                    │
│  Tools: msfconsole, searchsploit, manual exploitation       │
├─────────────────────────────────────────────────────────────┤
│                  AUTOMATED RECON PIPELINE                    │
│  run-recon.sh → Parsers → Enrichers → CAS Formatter         │
├─────────────────────────────────────────────────────────────┤
│                  NETWORK ISOLATION (GLUETUN)                 │
│  VPN tunnel + killswitch, all traffic through HTB VPN       │
└─────────────────────────────────────────────────────────────┘
```

| Component | Purpose |
|-----------|---------|
| `gluetun` | Mandatory VPN with killswitch, network isolation |
| `enrichment` | Watches raw scans, parses, enriches, outputs CAS |
| `kali-gemini` | Kali Linux + gemini-cli, runs Dame for exploitation |
| `run-recon.sh` | Automated recon script (nmap, httpx, nuclei, etc.) |

---

## Security Model

### Network Isolation (Primary)

All traffic routes through gluetun VPN tunnel:
- Killswitch blocks all non-VPN traffic
- Only HTB network accessible
- Container crash = network isolation maintained

### Scope Definition

Scope defined in `/mission/scope.yaml`:
```yaml
target: 10.10.10.3
cidrs: ["10.10.10.3/32"]
domains: ["*.htb"]
```

### AI Guardrails

Dame is instructed via GEMINI.md:
- Only operate on targets in CAS
- No reconnaissance (already complete)
- Document all exploitation attempts

---

## Project Structure

```
blunderbussy/
├── infrastructure/
│   ├── enrichment/          # Parsers, enrichers, CAS formatter, watcher
│   ├── recon/               # Automated recon script (run-recon.sh)
│   ├── kali-gemini/         # Dockerfile for Kali + gemini-cli
│   └── opulence-extension/  # gemini-cli extension (Dame)
│       ├── GEMINI.md        # Dame's context/personality
│       ├── commands/        # /opulence:* commands
│       └── skills/          # Exploitation, privesc methodology
├── artifacts/               # Mission artifacts (runtime)
│   ├── raw/                 # Raw tool output (XML, JSON)
│   └── {target}/            # Per-target CAS documents
├── mission/                 # Mission state (runtime)
│   ├── scope.yaml           # Target scope definition
│   └── loot/                # Captured flags, creds, notes
├── docker-compose.yml       # Stack definition
├── IMPLEMENTATION_PLAN.md   # Build plan
├── TEST_PLAN.md             # Testing strategy
└── GEMINI.md                # Quick reference guide
```

---

## Getting Started

### Prerequisites

- Docker + Docker Compose
- HTB VPN config (`.ovpn` file)
- Gemini API key

### Quick Start

```bash
# 1. Start infrastructure
cd $HOME/Projects/blunderbussy
cp /path/to/lab.ovpn infrastructure/gluetun/
docker compose up -d gluetun enrichment

# 2. Verify VPN
docker compose exec gluetun wget -qO- ifconfig.me
# Expected: 10.10.x.x (HTB IP)

# 3. Run automated recon against target
./infrastructure/recon/run-recon.sh 10.10.10.3

# 4. Wait for CAS generation
watch ls artifacts/10.10.10.3/
# Wait for context.yaml

# 5. Start Kali + gemini-cli container
docker compose up -d kali-gemini
docker compose exec -it kali-gemini bash

# 6. Launch gemini-cli and engage Dame
gemini
/opulence:engage 10.10.10.3
```

For detailed setup, see [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md).

---

## Documentation

Design documentation lives at:
```
$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/
```

### Quick Reference

| Topic | File | Description |
|-------|------|-------------|
| Architecture | `Architecture/Agents.md` | System design philosophy |
| Infrastructure | `Architecture/INFRASTRUCTURE_DESIGN.md` | Docker stack, network isolation |
| Workflows | `Architecture/WORKFLOW_DESIGN.md` | OODA loop, mission flow |
| Enrichment | `Implementation/ENRICHMENT_PIPELINE.md` | Data pipeline, parsers |
| Plugins | `Implementation/PLUGIN_DESIGN.md` | Scope enforcement |
| Context | `Implementation/CONTEXT_DESIGN.md` | Token efficiency |
| Security | `Security/SECURITY_HARDENING.md` | Killswitch, hardening |
| Schemas | `Data/schemas/*.md` | CAS, SHP, Manifest, Scope |
| Future | `Future/FUTURE_ARCHITECTURE.md` | Post-PoC specialist agents |

### Project Docs

| File | Purpose |
|------|---------|
| [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) | Parallelized build streams with task references |
| [TEST_PLAN.md](./TEST_PLAN.md) | Unit, integration, and E2E test strategy |
| [GEMINI.md](./GEMINI.md) | Implementation quick reference |

---

## Status

**Current Phase:** PoC - Single Target End-to-End

- [x] Docker environment configured
- [x] Gluetun VPN container active
- [x] Killswitch verified
- [x] Enrichment pipeline (parsers, enrichers, CAS formatter)
- [ ] Automated recon script
- [ ] Missing parsers (gobuster, nikto, whatweb)
- [ ] Kali + gemini-cli container
- [ ] gemini-cli extension (Dame)
- [ ] E2E test on Lame (10.10.10.3)

Full task breakdown: `$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/TASK_LIST.md`

---

## License

Private project. Not for distribution.
