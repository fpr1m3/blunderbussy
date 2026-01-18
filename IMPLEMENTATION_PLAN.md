# Agent Opulence: Focused PoC Implementation Plan (v4.0)

> **Project:** Agent Opulence - Autonomous Offensive Security Orchestration
> **Philosophy:** "Automated Scans, Focused Exploitation" - The Gay Agenda v4.0
> **Target:** Lame (10.10.10.3)
> **Generated:** 2026-01-16

---

## How to Use This Plan (Agent Instructions)

**This plan organizes work into parallel streams. The detailed task instructions live in TASK_LIST.md.**

### Efficient Reading Strategy

When working on a stream, **only read the relevant sections** of TASK_LIST.md to save context:

```
# Example: Working on Stream B (Enrichment Pipeline)
# Read ONLY lines 382-505 instead of the entire 1267-line file:

Read tool:
  file_path: /home/fprime/Notes/Obsidian/10 - PROJECTS/Agent Opulence/TASK_LIST.md
  offset: 382
  limit: 124
```

**Never read the entire TASK_LIST.md at once** - it's 1267 lines and will saturate context.

### v4 Architecture Changes

**Key Differences from v3:**

| Aspect | v3 | v4 |
|--------|----|----|
| Recon | MCP-based (slow) | Automated pipeline (run-recon.sh) |
| Plugin | OpenCode PrEP (PII) | gemini-cli extension in Kali |
| MCP Servers | HexStrike/MetaMCP | Removed from PoC |
| Scope Firewall | MCP-based | Network-level (gluetun) + instructions |
| Agents | Dame + 2 subagents | Dame alone (PoC simplification) |
| Target | Dynamic scope | Single target: Lame (10.10.10.3) |

### Line Number Reference (v3 - for reference)

| Stream | Status | Notes |
|--------|--------|-------|
| **A** Infrastructure | Keep | Gluetun VPN still required |
| **B** Enrichment | Keep | Parsers → Enrichers → CAS formatter |
| **C** MCP Servers | Removed | Not in PoC |
| **D** PrEP | Replaced | → gemini-cli extension |
| **E** Tool Containers | Updated | → run-recon.sh in Kali container |
| **F** Agents | Simplified | → Dame only (no subagents) |
| **G** Integration | Updated | → Automated recon → CAS → Dame exploits |

### Design Doc Quick Reference

When you need architectural context (not task steps), read these from `$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/`:

| Topic | File | Key Sections |
|-------|------|--------------|
| Overall Architecture | `Architecture/Agents.md` | §1-3 |
| Infrastructure Layers | `Architecture/INFRASTRUCTURE_DESIGN.md` | Full |
| Workflow/OODA | `Architecture/WORKFLOW_DESIGN.md` | Full |
| Enrichment Pipeline | `Implementation/ENRICHMENT_PIPELINE.md` | Full |
| Plugin Implementation | `Implementation/PLUGIN_DESIGN.md` | §1-6 |
| Context Management | `Implementation/CONTEXT_DESIGN.md` | Full |
| Audit System | `Implementation/AUDIT_DESIGN.md` | Full |
| Data Schemas | `Data/DATA_DEFINITIONS.md` | Index |
| Security Hardening | `Security/SECURITY_HARDENING.md` | Full |
| Plugin Crypto | `Security/PLUGIN_CRYPTO.md` | Full |
| Future Enhancements | `Future/FUTURE_ENHANCEMENTS.md` | Roadmap |
| Specialist Agents | `Future/FUTURE_ARCHITECTURE.md` | POST-POC |

**Schema Definitions** (`$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/Data/schemas/`):
- `CAS_SCHEMA.md` - Consolidated Artifact Schema
- `SHP_SCHEMA.md` - Session Handoff Protocol
- `AGENT_RETURNS.md` - Agent return value contracts
- `MANIFEST_SCHEMA.md` - Manifest structure
- `SCOPE_SCHEMA.md` - Scope definition format

---

## v4 Architecture: Simplified Pipeline

```
┌────────────────────────────────────────────────────────────────┐
│              V4 PROOF OF CONCEPT ARCHITECTURE                  │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Infrastructure Layer:                                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  gluetun (VPN) → Kali Container → target (Lame)        │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                                │
│  Automated Recon Pipeline:                                    │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  run-recon.sh:                                          │ │
│  │  - nmap (OS fingerprint, port scan)                     │ │
│  │  - httpx (HTTP probing)                                 │ │
│  │  - nuclei (vulnerability detection)                     │ │
│  │  - gobuster (directory enumeration)                     │ │
│  │  - nikto (web server scanning)                          │ │
│  │  - whatweb (technology detection)                       │ │
│  └─────────────────────────────────────────────────────────┘ │
│                          │                                     │
│  Enrichment Pipeline:                                         │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Raw scan output → Parsers → Enrichers → CAS formatter │ │
│  └─────────────────────────────────────────────────────────┘ │
│                          │                                     │
│  Dame (Gemini in Kali):                                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Read CAS → Decide exploitation path → Execute → PrivEsc│ │
│  │  (Single agent orchestrator - no subagents)             │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                                │
└────────────────────────────────────────────────────────────────┘

Timeline: 2-3 weeks (simplified from multi-month v3 plan)
```

---

## Stream A: Infrastructure (The Clean Room)

**TASK_LIST.md:** Lines 123-233 (Phase 1)
```
Read: offset=123, limit=111
```

**Design Doc:** `$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/Architecture/INFRASTRUCTURE_DESIGN.md`

### Current Status (Pre-completed)
- [x] §1.1.1 Docker verified
- [x] §1.1.2 Network subnet (172.19.0.0/16)
- [x] §1.2.1-1.2.4 Gluetun base setup

### Remaining Sections
| Section | Lines | Focus |
|---------|-------|-------|
| §1.2.5-1.2.6 | 161-170 | Killswitch validation, health checks |
| §1.3 | 171-192 | Sentinel Proxy (**DEFERRED** to post-PoC) |
| §1.4 | 193-233 | Artifact Sidecar persistence |

**Victory:** All containers healthy, VPN tunnel stable, no IP leaks.

---

## Stream B: Enrichment Pipeline (Dumb Layer)

**TASK_LIST.md:** Lines 382-505 (Phase 3)
```
Read: offset=382, limit=124
```

**Design Doc:** `$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/Implementation/ENRICHMENT_PIPELINE.md`

### Sections
| Section | Lines | Focus |
|---------|-------|-------|
| §3.1 | 384-405 | File watcher (inotify container) |
| §3.2 | 406-428 | Parser scripts (nmap, nuclei, httpx, subfinder) |
| §3.3 | 429-456 | Enrichment scripts (CVE→CVSS, services, web) |
| §3.4 | 457-477 | CAS formatting (YAML output) |
| §3.5 | 478-505 | Manifest update + key findings extraction |

**Victory:** Raw scan → CAS document in < 30 seconds.

---

## Stream C: MCP Servers (REMOVED - Not in v4 PoC)

**Status:** Not required for focused PoC.

**Rationale:** MCP servers added architectural complexity in v3. v4 simplifies to:
- Direct CLI tools in Kali container
- Instruction-based scope enforcement
- CAS files (YAML) instead of MCP artifacts

**Future:** Will re-introduce in v5 for multi-agent orchestration.

---

## Stream D: Plugin (Updated - gemini-cli extension)

**v4 Changes:**

Instead of OpenCode PrEP (heavy infrastructure), we use:

1. **gemini-cli extension** (installed in Kali container)
   - gemini-cli reads from stdin/files
   - Processes CAS format natively
   - No heavy Python plugin infrastructure
   - No PII concerns (CAS is read-only context)

2. **Scope Enforcement:**
   - Network-level: gluetun restricts outbound to Lame only
   - Instruction-based: System prompt instructs Dame to focus on Lame
   - No interactive firewall queries needed

3. **Key Features:**
   - CAS reading (vulnerability analysis)
   - Exploitation planning (MSF/Sliver commands)
   - Privilege escalation strategy
   - Report generation

**Victory:** Dame can read CAS and plan exploitation without manual prompts.

---

## Stream E: Automated Recon Pipeline (run-recon.sh)

**Depends On:** Stream A (gluetun healthy)

### v4 Implementation:

Create single script: `/home/fprime/Projects/blunderbussy/run-recon.sh`

**Tools to install in Kali container:**
| Tool | Purpose | Output |
|------|---------|--------|
| nmap | Port discovery, OS fingerprint | .nmap files |
| httpx | HTTP service enumeration | JSON |
| nuclei | Vulnerability scanning | JSON |
| gobuster | Directory/subdomain brute-force | text |
| nikto | Web server vulnerabilities | text |
| whatweb | Technology detection | text |

**Pipeline Flow:**
```bash
./run-recon.sh 10.10.10.3
  ↓ (raw output → /tmp/recon/)
Parser scripts (nmap.py, httpx.py, etc.)
  ↓ (parsed JSON/structured data)
Enrichment scripts (cve_enrich.py, service_detect.py)
  ↓ (enriched data)
cas_formatter.py
  ↓
CAS document (YAML) → /tmp/recon/Lame_consolidated.yaml
```

**Victory:** Lame scan → CAS document in < 2 minutes.

---

## Stream F: Agent Implementation (Dame only)

**Depends On:** Streams D, E complete

### v4 Implementation: Single Agent

**Agent:** Dame (the-dame)
- Role: Orchestrator + Exploitation Specialist
- Context: CAS document (vulnerability details)
- Tools:
  - Metasploit Framework (local execution)
  - Sliver C2 (optional, for persistence)
  - Custom bash scripts (privilege escalation)

**No Subagents (v4 PoC Simplification):**
- v3 had: date-planner (exploitation) + party-line-operator (C2)
- v4: Dame does both in-line within her OODA loop

**Dame's Workflow:**
```
1. Read CAS document from /tmp/recon/Lame_consolidated.yaml
2. Analyze vulnerability landscape
3. Select exploitation path (e.g., CVE-2007-2447 for Samba)
4. Generate MSF/bash commands
5. Execute exploitation
6. Attempt privilege escalation
7. Report findings and proof of compromise
```

**Victory:** Dame pwns Lame without human intervention.

---

## Stream G: Integration & E2E Testing

**Depends On:** All streams complete

### v4 E2E Test: Automated Recon → Exploitation

**Test Flow:**
```bash
# 1. Start infrastructure
docker compose up -d

# 2. Run automated recon
./run-recon.sh 10.10.10.3
# Output: /tmp/recon/Lame_consolidated.yaml

# 3. Invoke Dame
gemini-cli << EOF
You are Dame, an offensive security specialist.
Read this CAS document and exploit Lame (10.10.10.3).
Report when you have root access.

[CAS document contents]
EOF

# 4. Verify success
# Expected: Dame reports proof of compromise (root shell, /root/proof.txt, etc.)
```

**Success Criteria:**
| Criterion | Target |
|-----------|--------|
| Infrastructure | Gluetun healthy, Kali container online |
| Recon | CAS document generated in < 2 minutes |
| Exploitation | Root access obtained (proof via command output) |
| Time | Full cycle < 10 minutes |
| Repeatability | Can run test 3x without manual intervention |

**Victory:** Automated pipeline → Dame → Root on Lame.

---

## v4 Dependency Graph (Simplified)

```
Stream A (Infrastructure) ──┐
                            ├──► Stream E (Recon Script) ──┐
Stream B (Enrichment) ──────┤                             │
                            │                             ├──► Stream G (E2E Test)
Stream D (Dame/gemini-cli) ─┴─────────────────────────── Stream F (Dame Implementation)
```

**Parallel Opportunities:**
- **A, B** can start immediately (no dependencies)
- **D** can start after B complete (needs CAS format understanding)
- **E** requires only A.gluetun healthy
- **F** requires D, E complete
- **G** requires A, B, D, E, F complete

**Sequence (2-3 weeks):**
1. Week 1: A + B in parallel (infrastructure + enrichment foundations)
2. Week 2: D + E in parallel (Dam + recon script); F starts with Dame logic
3. Week 3: F + G (integrate and test against Lame)

---

## v4 Success Criteria

| Criteria | v3 | v4 PoC | Status |
|----------|----|------------|--------|
| Infrastructure | All containers, VPN stable | Gluetun + Kali | Must pass |
| Enrichment | Raw → CAS < 30 sec | Raw → CAS < 2 min | Must pass |
| Recon | MCP-based orchestration | run-recon.sh automation | Must pass |
| Plugin | OpenCode PrEP | gemini-cli extension | Must pass |
| Agents | Dame + 2 subagents | Dame only | Must pass |
| Scope | MCP firewall | Network + instructions | Must pass |
| E2E | Init → root, ASK prompts | Automated recon → root | Must pass |
| Timeline | 3+ months | 2-3 weeks | Must deliver |
| Target | Any HTB machine | Lame only | Locked |

**Victory Condition:** `./run-recon.sh 10.10.10.3` + `gemini-cli` = root shell proof

---

## v4 Quick Start

### Week 1: Setup (A + B)
```bash
cd ~/Projects/blunderbussy

# Stream A: Start infrastructure
docker compose up -d
docker compose ps  # Verify gluetun + kali healthy

# Stream B: Verify enrichment pipeline exists
ls -la infrastructure/enrichment/
# Should have: parsers/, enrichers/, cas_formatter.py
```

### Week 2: Automation + Dame (D + E + F)
```bash
# Stream E: Create and test recon script
./run-recon.sh 10.10.10.3
cat /tmp/recon/Lame_consolidated.yaml  # Verify CAS output

# Stream D: Install gemini-cli in Kali
docker exec kali apt-get install -y gemini-cli

# Stream F: Implement Dame (leverages CAS format)
# Create: /home/fprime/Projects/blunderbussy/dame.py
# Or: gemini-cli prompt script
```

### Week 3: Integration (G)
```bash
# Full E2E test
./run-recon.sh 10.10.10.3
gemini-cli < /tmp/recon/Lame_consolidated.yaml
# Should output: proof of root access
```

---

## v4 File Structure

| Item | Path | v3→v4 |
|------|------|-------|
| **Implementation Plan** | `/home/fprime/Projects/blunderbussy/IMPLEMENTATION_PLAN.md` | Updated |
| **Recon Script** | `/home/fprime/Projects/blunderbussy/run-recon.sh` | New |
| **Enrichment** | `/home/fprime/Projects/blunderbussy/infrastructure/enrichment/` | Kept |
| **Dame Agent** | `/home/fprime/Projects/blunderbussy/dame.py` | Simplified (no subagents) |
| **Docker Compose** | `/home/fprime/Projects/blunderbussy/docker-compose.yml` | Remove MSF/Sliver services, add Kali base |

---

## What Changed from v3 to v4

**Removed:**
- Custom MCP servers (opulence-artifacts, opulence-manifest, opulence-scope)
- OpenCode PrEP plugin framework
- MetaMCP + HexStrike wrappers
- date-planner subagent (exploitation specialist)
- party-line-operator subagent (C2 operator)
- Multi-target scope (dynamic CIDR expansion)

**Added:**
- run-recon.sh (automated recon pipeline)
- gemini-cli extension (lightweight AI interface)
- Single-target focus (Lame: 10.10.10.3)
- Network-level scope enforcement (gluetun)
- Instruction-based safety guardrails

**Kept:**
- gluetun VPN infrastructure
- Enrichment pipeline (parsers → enrichers → CAS formatter)
- CAS format for vulnerability documentation
- Dame orchestrator (simplified to single agent)

---

**Last Updated:** 2026-01-16
**Version:** v4.0 (PoC)
**Status:** Ready for implementation
