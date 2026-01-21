# Changelog

All notable changes to the Agent Opulence (Blunderbussy) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added - 2026-01-20

#### PTT Integration into Enrichment Pipeline

**Major architectural change:** Moved PTT (Pentesting Task Tree) generation from AI runtime to enrichment pipeline as a deterministic transformation.

**Rationale:** PTT initialization doesn't require LLM reasoning - it's a pure data transformation from CAS to structured task tree. Moving it to the enrichment pipeline:
- Eliminates LLM token usage for initialization (cost reduction)
- Removes latency - PTT is ready when Dame attaches
- Enables real-time PTT regeneration on new scans
- Separates concerns: enrichment = transformations, Dame = execution

**Changes:**
- Created `infrastructure/enrichment/init-ptt.py` - Deterministic CAS → PTT transformer (120 lines)
  - Transforms context.yaml to ptt.yaml automatically
  - Populates engagement tree with hosts, services, attack vectors, techniques
  - Non-blocking: warns on failure but doesn't stop enrichment pipeline

- Modified `infrastructure/enrichment/watcher.py`
  - Added PTT initialization calls after CAS generation (2 locations)
  - Integrated into both AutoRecon and manual scan processing paths
  - Logs PTT summary (hosts, services, pending techniques)

- Updated `infrastructure/enrichment/Dockerfile`
  - Changed build context from `./infrastructure/enrichment` to `./infrastructure`
  - Allows copying from multiple subdirectories (enrichment/, PrEP/)
  - Added COPY statements for ptt.py and init-ptt.py

- Updated `docker-compose.yml`
  - Changed enrichment service build context to `./infrastructure`
  - Updated dockerfile path to `enrichment/Dockerfile`

**Files Added:**
- `infrastructure/enrichment/init-ptt.py` - PTT initializer script
- `infrastructure/PrEP/ptt.py` - PTT module (extracted from PrEP extension)
- `infrastructure/PrEP/ERROR_HANDLING.md` - Error classification decision tree

**Documentation Updates:**
- `README.md` - Updated pipeline flow diagram to include PTT generation
- `infrastructure/PrEP/GEMINI.md` - Updated to reflect PTT is pre-generated, not manually created
- `infrastructure/PrEP/schemas/PTT_SCHEMA.md` - Updated integration points

**Testing:**
- Verified with target 10.129.1.76 (expressway.htb)
- Confirmed automatic PTT generation with 7 attack vectors
- Validated PTT structure: 1 host, 1 service (SSH), proper priority scoring

**Related Beads Issues:**
- blunderbussy-9bq [P2] - Integrate PTT generation into enrichment pipeline ✅
- blunderbussy-clt [P2] - Create init-ptt.py script ✅
- blunderbussy-nnb [P2] - Update enrichment Dockerfile ✅
- blunderbussy-skq [P2] - Modify watcher.py to call init-ptt.py ✅

---

#### Infrastructure Cleanup

**Removed:**
- `infrastructure/metamcp-old-custom/` - Old MetaMCP implementation superseded by metamcp-real
- `infrastructure/mcp-servers/` - Orphaned MCP servers (artifact, manifest, scope) superseded by enrichment pipeline

**Added as Git Submodule:**
- `infrastructure/htb-mcp` - HTB platform MCP server for programmatic machine control

**Committed Untracked Files:**
- PTT system: `ptt.py`, `ERROR_HANDLING.md`
- Parsers: `parse-feroxbuster.py`, `parse-manual-commands.py`, `parse-smbmap.py`
- Infrastructure configs: `dame/tmux.conf`, `gluetun/post-rules.txt`, `hexstrike/autorecon-htb.toml`, `hexstrike/run-autorecon.sh`
- Test infrastructure: `tests/conftest.py`, parser test fixtures, integration tests

**Related Beads Issues Created:**
- blunderbussy-ptt [P3] - Implement real Metasploit MSFRPC backend
- blunderbussy-65g [P3] - Implement real Sliver gRPC backend
- blunderbussy-51q [P4] - Clean up gluetun DNS leak
- blunderbussy-13z [P2] - Integrate htb-mcp tools

---

## Previous Work

See git history for changes prior to 2026-01-20.
