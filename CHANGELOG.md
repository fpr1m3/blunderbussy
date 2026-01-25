# Changelog

All notable changes to the Agent Opulence (Blunderbussy) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added - 2026-01-24

#### MCP Server Modernization

**Major refactor:** All MCP servers converted to FastMCP with Pydantic validation.

**Changes:**
- **pwncat-server.py** - Refactored to FastMCP, now 14 tools with full Pydantic models
  - Added enumerate, privesc, persist tools
  - ResponseFormat enum for JSON/Markdown output
  - Type-safe input validation with field validators

- **msf-server.py** - Refactored to FastMCP, now 11 tools
  - Uses httpx client to call msf-bridge HTTP API
  - ResponseFormat support for sessions, jobs, status

- **sliver-server.py** - Complete rewrite using sliver-py gRPC
  - 11 tools: listeners, sessions, beacons, execute, download, upload, portfwd, socks
  - Real gRPC integration with Sliver daemon

- **msf-bridge/** - New Go HTTP bridge for MSFRPC
  - Uses go-msf-rpc library for msgpack RPC
  - Exposes REST API on port 9997
  - Deployed via gluetun network for VPN routing

- **tests/mcp/** - New pytest test suite
  - 172 tests for input validation (pwncat: 66, msf: 47, sliver: 59)
  - Runs without backends via mocked imports

**Related Beads Issues:**
- blunderbussy-dqe2 - Refactor pwncat-server to FastMCP ✅
- blunderbussy-d80m - Implement MSF go-msf-rpc bridge ✅
- blunderbussy-hnzs - Add new pwncat tools ✅
- blunderbussy-8pj6 - Implement Sliver backend ✅
- blunderbussy-w4m2 - Add response formats ✅
- blunderbussy-frx7 - Create test suite ✅

---

#### C2 Framework Containers

**Added real C2 backends** with VPN routing through gluetun.

**Changes:**
- **docker-compose.yml** - Enabled MSF and Sliver containers
  - `msf` service: Metasploit Framework with msfrpcd
  - `msf-bridge` service: Go HTTP API for MSFRPC
  - `sliver` service: Sliver C2 daemon
  - All use `network_mode: "service:gluetun"` for HTB VPN routing
  - Exposed ports: 4444, 4445 (MSF callbacks), 9997 (bridge), 31337 (Sliver)

- **.env.example** - Created with required configuration
  - MSF_PASS (required)
  - FARADAY_DB_PASSWORD
  - HTB target settings
  - LHOST for payload callbacks

**Network Architecture:**
All C2 traffic routes through gluetun VPN for HTB target access.

---

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
