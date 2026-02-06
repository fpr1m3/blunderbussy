# Enrichment Pipeline

Automated scan data processing pipeline that transforms raw tool output into structured attack surface summaries via Faraday vulnerability management.

## Overview

The enrichment pipeline:
1. Watches for raw scan files
2. Uploads to Faraday for parsing (80+ built-in parsers)
3. Enriches with service analysis and web technology detection
4. Generates CAS (Context-Aware Summary) in YAML
5. Generates attack guidance via Gemini CLI (with heuristic fallback)
6. Initializes PTT (Pentesting Task Tree) automatically

**Migration:** As of 2026-01-23, custom parsers were replaced with Faraday integration. See [MIGRATION.md](./MIGRATION.md) for details.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              WATCHER (faraday_watcher.py)                   │
│  Monitors /artifacts/raw/ and /artifacts/results/          │
│  Uploads scan files to Faraday API for parsing             │
│  HTTP healthcheck on port 8080                             │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                  FARADAY (faraday_client.py)                │
│  80+ built-in parsers (nmap, nuclei, nikto, etc.)          │
│  Built-in CVE database                                     │
│  Vulnerability aggregation and deduplication               │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│              ENRICHERS (enrichers/*.py)                     │
│  Add context to Faraday data:                              │
│  • Service priority scoring and default credentials        │
│  • Web technology detection and attack vectors             │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│             CAS FORMATTER (format-cas.py)                   │
│  Aggregates enriched data → YAML summary                   │
│  Generates attack guidance via Gemini CLI                  │
│  Output: /artifacts/{target}/context.yaml                  │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│            PTT INITIALIZER (init-ptt.py)                    │
│  Transforms CAS → Pentesting Task Tree                     │
│  • Extracts hosts, services, vulnerabilities               │
│  • Generates attack vectors based on service types         │
│  • Prioritizes techniques (P1 quick wins first)            │
│  Output: /artifacts/{target}/ptt.yaml                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Components

### faraday_watcher.py

**Purpose:** File system monitor and Faraday uploader (main entry point)

**Key Responsibilities:**
- Watch `/artifacts/raw/` and `/artifacts/results/` for new scan files using inotify
- Upload files to Faraday API (auto-parsed by 80+ built-in plugins)
- Wait for Faraday processing to complete
- Trigger CAS and PTT generation
- Serve HTTP healthcheck endpoint on port 8080

**Configuration (WatcherConfig):**
```python
FARADAY_URL        # Faraday server URL (default: http://faraday-server:5985)
FARADAY_USER       # Faraday username
FARADAY_PASSWORD   # Faraday password
FARADAY_WORKSPACE  # Default workspace name
RAW_DIR            # Watch directory for raw scans
RESULTS_DIR        # Watch directory for processed results
POLL_INTERVAL      # Filesystem poll interval (default: 30s)
FILE_STABLE_SECONDS # Wait time before processing (default: 4s)
GENERATE_CAS       # Auto-generate CAS (default: true)
GENERATE_PTT       # Auto-generate PTT (default: true)
```

---

### faraday_client.py

**Purpose:** REST API client for Faraday vulnerability management

**Key Features:**
- Retry logic with exponential backoff (tenacity: 3 attempts)
- Session management and authentication
- Report upload with automatic parser detection

**Key Methods:**
- `upload_report()` - Upload scan files for parsing
- Query methods for hosts, services, vulnerabilities

---

### Enrichers (enrichers/*.py)

**Purpose:** Add context and intelligence to Faraday data

**Enrichment Types:**

1. **Service Analysis** (`enrich-services.py`)
   - Service priority scoring (SMB=3, FTP=1, SSH=1)
   - Default credentials database
   - Known vulnerabilities by service/version
   - Attack vectors (username_enum, null_session, etc.)
   - Services covered: SSH, FTP, SMB, NetBIOS, HTTP, MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Elasticsearch, etc.

2. **Web Technology** (`enrich-web.py`)
   - Framework detection (WordPress, Drupal, Laravel, Django, Spring, Express)
   - Server identification (Apache, Nginx, IIS, Tomcat)
   - Vulnerability patterns per technology
   - Recommended tools (wpscan, droopescan, nuclei)
   - Security header analysis
   - Attack surface scoring

**Note:** CVE enrichment is now handled by Faraday's built-in CVE database.

---

### format-cas.py

**Purpose:** Generate Context-Aware Summary (CAS) in YAML

**Input:** Faraday data (hosts, services, vulnerabilities)
**Output:** `/artifacts/{target}/context.yaml`

**Key Features:**
- Faraday data mappers for hosts, services, vulnerabilities
- Attack guidance generation via `gemini-cli` (non-interactive)
- Heuristic fallback when Gemini unavailable

**CAS Structure (v1.2):**
```yaml
meta:
  target: "10.10.10.3"
  scan_time: "2026-01-20T12:00:00Z"
  tools_run: ["nmap", "httpx", "nuclei"]

summary:
  open_ports: 5
  services: ["ftp", "ssh", "http", "smb"]
  critical_findings: 2

hosts:
  - ip: "10.10.10.3"
    hostname: "target.htb"
    os: "Linux 4.15 - 5.19"
    ports:
      - port: 22
        service: "ssh"
        version: "OpenSSH 8.9p1"
        vectors: ["private_key_disclosure", "username_enum"]

attack_guidance:
  source: "gemini"  # or "heuristic"
  quick_wins: ["Check default creds on FTP"]
  priority_targets: ["HTTP service has SQLi"]
  recommended_commands: ["hydra -L users.txt ssh://10.10.10.3"]
```

---

### init-ptt.py

**Purpose:** Initialize Pentesting Task Tree from CAS

**Rationale:**
PTT initialization is a **deterministic transformation**, not strategic decision-making:
- No LLM reasoning required
- Pure data structure mapping: CAS → PTT
- Benefits: zero LLM tokens, instant availability, real-time regeneration

**Process:**
1. Load CAS from `/artifacts/{target}/context.yaml`
2. Parse engagement metadata (target, platform)
3. Create host nodes from CAS hosts
4. Create service nodes from CAS ports
5. Generate attack vectors based on:
   - Service type (SSH → credential attacks, HTTP → web exploits)
   - Known vulnerabilities from CAS
   - Quick wins from attack_guidance
6. Prioritize techniques (P1-P4 based on impact/complexity)
7. Save to `/artifacts/{target}/ptt.yaml`

**Example Transformation:**

**Input (CAS):**
```yaml
hosts:
  - ip: "10.129.1.76"
    hostname: "expressway.htb"
    ports:
      - port: 22
        service: "ssh"
        version: "OpenSSH 10.0p2"
        vectors: ["private_key_disclosure", "username_enum"]
```

**Output (PTT):**
```yaml
engagement:
  target: "10.129.1.76"
  platform: "linux"
  hosts:
    - ip: "10.129.1.76"
      services:
        - port: 22
          service: "ssh"
          vectors:
            - name: "quick_win_medusa"
              priority: 1
              techniques:
                - name: "SSH Default Creds - Medusa"
                  status: "pending"
            - name: "private_key_disclosure"
              priority: 2
            - name: "username_enum"
              priority: 3
```

**Non-blocking:** Logs warnings on failure but doesn't stop enrichment pipeline.

---

### update-manifest.py

**Purpose:** Update global manifest with scan findings

**Key Features:**
- Manages manifest with file locking
- Tracks sessions, targets, key_findings, scan_history
- Attack progress tracking (phase, completed_steps, next_steps)
- Supports `scan_type: faraday`

---

### prompts/attack_guidance.md

**Purpose:** Gemini prompt template for attack guidance generation

**Analysis Process:**
1. Target prioritization (exploitability 40%, impact 30%, ease 30%)
2. Quick win identification (anonymous access, default creds, exposed paths)
3. Command generation (searchsploit, hydra, nmap, nuclei, etc.)

**Output Fields:**
- `priority_targets[]` - Scored targets (1-10 scale)
- `quick_wins[]` - Trivially exploitable targets
- `recommended_commands[]` - Executable commands with priority

---

## Data Flow

### Typical Processing Flow

```
1. Scanner outputs to /artifacts/raw/10.10.10.3/
   └─> nmap.xml, nuclei.json, etc.

2. Watcher detects new files
   └─> Uploads to Faraday API

3. Faraday parses all scan formats
   ├─> 80+ built-in parsers
   ├─> CVE database lookup
   └─> Vulnerability aggregation

4. Enrichers add context
   ├─> Service analysis (default creds, vectors)
   └─> Web technology detection

5. CAS Formatter aggregates
   ├─> Generates facts from Faraday data
   ├─> Calls Gemini CLI for attack guidance
   └─> /artifacts/10.10.10.3/context.yaml

6. PTT Initializer transforms
   └─> /artifacts/10.10.10.3/ptt.yaml

7. Dame loads both files
   └─> Begins exploitation phase
```

---

## Configuration

### Environment Variables

```bash
# Faraday Connection
FARADAY_URL=http://faraday-server:5985
FARADAY_USER=faraday
FARADAY_PASSWORD=changeme
FARADAY_WORKSPACE=pentest

# Paths
RAW_DIR=/artifacts/raw
RESULTS_DIR=/artifacts/results
LOGS_DIR=/artifacts/logs

# Processing
POLL_INTERVAL=30              # Seconds between filesystem polls
FILE_STABLE_SECONDS=4         # Wait time before processing new file
AUTORECON_POLL_INTERVAL=30    # AutoRecon completion check interval
GENERATE_CAS=true             # Auto-generate CAS after processing
GENERATE_PTT=true             # Auto-generate PTT after CAS

# Health
HEALTHCHECK_PORT=8080
```

### Volume Mounts

```yaml
volumes:
  - artifacts:/artifacts           # Shared scan data
```

---

## Testing

### Unit Tests

```bash
cd /home/fprime/Projects/blunderbussy

# Test Faraday client
uv run pytest infrastructure/enrichment/tests/test_faraday_client.py -v

# Test CAS integration
uv run pytest infrastructure/enrichment/tests/test_faraday_cas_integration.py -v
```

### Fixtures

Test data located in `tests/fixtures/`

---

## Troubleshooting

### Pipeline Not Processing Files

**Check:**
1. Container is running: `podman ps | grep enrichment`
2. Watcher logs: `podman logs enrichment`
3. Faraday is accessible: `curl http://faraday-server:5985/`
4. Healthcheck: `curl http://localhost:8080/health`

**Common Issues:**
- Faraday not running → Start Faraday container first
- Authentication failed → Check FARADAY_USER/FARADAY_PASSWORD
- Workspace doesn't exist → Faraday watcher auto-creates workspaces
- File created before watcher started → Move file to trigger re-detection

### PTT Not Generated

**Check:**
1. CAS exists: `ls /artifacts/{target}/context.yaml`
2. init-ptt.py present: `podman exec enrichment ls /app/init-ptt.py`
3. ptt.py module: `podman exec enrichment ls /app/ptt.py`
4. Logs: `podman logs enrichment | grep -i ptt`

**Known Issues:**
- Invalid CAS format → PTT init logs warning, doesn't fail pipeline
- Missing service data → PTT creates empty structure (valid)

**Fix:** Rebuild enrichment container:
```bash
podman stop enrichment && podman rm enrichment
podman-compose up -d enrichment
```

### Attack Guidance Missing

**Symptoms:** CAS generated but `attack_guidance.source` is "heuristic" instead of "gemini"

**Causes:**
1. Gemini CLI not installed or configured
2. OAuth not set up
3. Network issues

**Check:**
```bash
podman exec enrichment gemini-cli --version
podman exec enrichment ls /app/settings.json
```

**Note:** Heuristic fallback is valid - guidance is still generated based on severity ranking.

---

## Performance

Processing is significantly faster after Faraday migration:
- No custom parser execution
- No NVD API calls (Faraday has built-in CVE database)
- Parallel processing handled by Faraday

### Optimization Tips

1. **Scope Scans** - Don't scan unnecessary ports
2. **Parallel AutoRecon** - Use `-ct` flag for concurrent scans
3. **Faraday Caching** - Faraday caches CVE data internally

---

## Directory Structure

```
infrastructure/enrichment/
├── Dockerfile
├── faraday_watcher.py      # Main entry point
├── faraday_client.py       # Faraday API client
├── format-cas.py           # CAS generator
├── init-ptt.py             # PTT generator
├── regenerate-cas.py       # Regenerate CAS from existing Faraday data
├── update-manifest.py      # Manifest updater
├── requirements.txt
├── settings.json           # Gemini CLI config
├── MIGRATION.md            # Migration notes
├── enrichers/
│   ├── enrich-services.py  # Service analysis
│   └── enrich-web.py       # Web technology detection
├── prompts/
│   └── attack_guidance.md  # Gemini prompt template
├── tests/
│   ├── test_faraday_client.py
│   ├── test_faraday_cas_integration.py
│   └── fixtures/
└── archive/
    └── watcher.py.bak      # Original custom watcher
```

---

## See Also

- [MIGRATION.md](./MIGRATION.md) - Migration from custom parsers to Faraday
- [PTT Schema](../PrEP/schemas/PTT_SCHEMA.md) - Task tree structure
- [GEMINI.md](../PrEP/GEMINI.md) - Dame's exploitation workflow
- [ERROR_HANDLING.md](../PrEP/ERROR_HANDLING.md) - Error classification
- [CHANGELOG.md](../../CHANGELOG.md) - Project history
