# GEMINI.md - Agent Opulence Implementation Guide (v4.0)

> **Design Documentation:** `$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/`

## Core Philosophy: "Dumb Tools Scan, Smart Agents Plan"

Agent Opulence strictly separates **automated reconnaissance** from **AI-driven exploitation**:

```
┌─────────────────────────────────────────────────────────────┐
│         AUTOMATED PIPELINE (No AI, Deterministic)           │
│  run-recon.sh: nmap → httpx → nuclei → gobuster → etc.     │
│         ↓                                                   │
│  Enrichment: Parsers → CVE lookup → CAS Formatter          │
│         ↓                                                   │
│  Output: /artifacts/{target}/context.yaml                  │
└──────────────────────────┬──────────────────────────────────┘
                           ↓ (CAS ready)
┌─────────────────────────────────────────────────────────────┐
│            DAME (gemini-cli, Strategic AI)                  │
│  Reads CAS → Plans attack → Executes exploit → Privesc     │
└─────────────────────────────────────────────────────────────┘
```

**The AI does NOT:** Run nmap, nuclei, gobuster, or any routine scanning
**The AI DOES:** Analyze CAS, select exploits, execute, adapt, escalate

---

## Technical Stack

### Runtime Environment

| Component | Technology | Purpose |
|-----------|------------|---------|
| AI Runtime | `gemini-cli` + extension | Dame's brain |
| Tool Container | `kali-gemini` (Kali + gemini-cli) | Exploitation environment |
| Network Isolation | `gluetun` | VPN tunnel + killswitch |
| Data Pipeline | `enrichment` container | CAS generation |

### Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    KALI-GEMINI CONTAINER                     │
│  gemini-cli (Dame) + Full Kali toolset                      │
│         │                                                    │
│         │ network_mode: service:gluetun                     │
├─────────┼───────────────────────────────────────────────────┤
│         ▼                                                    │
│                      GLUETUN CONTAINER                       │
│  VPN tunnel (HTB) + killswitch + DNS leak protection        │
│         │                                                    │
│         ▼                                                    │
│                      HTB NETWORK                             │
│  10.10.10.0/24 (targets)                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Automated Recon Pipeline

### Tool Stack

| Tool | Purpose | Parser |
|------|---------|--------|
| nmap -sCV | Port/service/version scan | parse-nmap.py |
| httpx | HTTP probing | parse-httpx.py |
| nuclei | Vulnerability scanning | parse-nuclei.py |
| gobuster | Directory brute force | parse-gobuster.py |
| nikto | Web vulnerability scan | parse-nikto.py |
| whatweb | Technology fingerprint | parse-whatweb.py |

### Execution

```bash
# Run full recon against target
./infrastructure/recon/run-recon.sh 10.10.10.3

# Outputs to /artifacts/raw/
# Watcher triggers enrichment pipeline
# CAS generated at /artifacts/10.10.10.3/context.yaml
```

---

## CAS (Consolidated Artifact Schema)

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

findings:
  critical:
    - "vsftpd 2.3.4 backdoor (CVE-2011-2523)"
```

---

## Dame (gemini-cli Extension)

### Extension Structure

```
infrastructure/opulence-extension/
├── gemini-extension.json      # Extension manifest
├── GEMINI.md                  # Dame's context/personality
├── commands/
│   └── engage.toml            # /opulence:engage {target}
└── skills/
    ├── exploitation/
    │   └── SKILL.md           # Exploit methodology
    └── privesc/
        └── SKILL.md           # Privilege escalation
```

### Dame's Role

1. Read `/artifacts/{target}/context.yaml`
2. Identify attack vectors from CAS findings
3. Research exploits (searchsploit, msfconsole search)
4. Execute exploitation
5. Stabilize shell
6. Escalate privileges
7. Capture flags

### Engagement

```bash
# Inside kali-gemini container
gemini
/opulence:engage 10.10.10.3
```

---

## Security Model

### Network Isolation (Primary)

- All traffic routes through gluetun VPN
- Killswitch blocks non-VPN traffic
- Container crash = isolation maintained

### Scope (Soft Enforcement)

- Defined in `/mission/scope.yaml`
- Dame instructed via GEMINI.md to respect scope
- Network-level is the hard boundary

---

## Workflow: Single Target E2E

```bash
# 1. Start infrastructure
docker compose up -d gluetun enrichment

# 2. Run automated recon
./infrastructure/recon/run-recon.sh 10.10.10.3

# 3. Wait for CAS
watch ls artifacts/10.10.10.3/

# 4. Start Dame
docker compose up -d kali-gemini
docker compose exec -it kali-gemini bash
gemini
/opulence:engage 10.10.10.3

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

**Phase:** PoC - Single Target E2E on Lame (10.10.10.3)

- [x] Gluetun VPN + killswitch
- [x] Enrichment pipeline (parsers, enrichers, CAS)
- [ ] Automated recon script
- [ ] Missing parsers (gobuster, nikto, whatweb)
- [ ] Kali + gemini-cli container
- [ ] Dame extension
- [ ] E2E test
