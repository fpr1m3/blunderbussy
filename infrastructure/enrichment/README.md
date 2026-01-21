# Enrichment Pipeline

Automated scan data processing pipeline that transforms raw tool output into structured attack surface summaries.

## Overview

The enrichment pipeline is a **deterministic transformation system** that:
1. Watches for raw scan files
2. Parses tool-specific formats to JSON
3. Enriches with CVE data and service analysis
4. Generates CAS (Context-Aware Summary) in YAML
5. Initializes PTT (Pentesting Task Tree) automatically

**No LLM required** - all transformations are rule-based and deterministic.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WATCHER (watcher.py)                      │
│  Monitors /artifacts/raw/ for new scan files (inotify)      │
│  Routes files to appropriate parser based on pattern        │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                PARSERS (parsers/*.py)                        │
│  24+ parsers convert tool output → JSON objects             │
│  • Network: nmap, dnsrecon, onesixtyone, snmpwalk          │
│  • Web: httpx, feroxbuster, nikto, whatweb, nuclei         │
│  • SMB: smbmap, enum4linux, showmount                       │
│  • Custom: manual-commands, autorecon                       │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│              ENRICHERS (enrichers/*.py)                      │
│  Add context to parsed data:                                │
│  • CVE lookup (NVD API with local caching)                  │
│  • Service vulnerability scoring (EPSS)                     │
│  • Web technology detection                                 │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│             CAS FORMATTER (format-cas.py)                    │
│  Aggregates enriched data → YAML summary                    │
│  Output: /artifacts/{target}/context.yaml                   │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│            PTT INITIALIZER (init-ptt.py)                     │
│  Transforms CAS → Pentesting Task Tree                      │
│  • Extracts hosts, services, vulnerabilities                │
│  • Generates attack vectors based on service types          │
│  • Prioritizes techniques (P1 quick wins first)             │
│  Output: /artifacts/{target}/ptt.yaml                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Components

### watcher.py

**Purpose:** File system monitor and orchestrator

**Key Responsibilities:**
- Watch `/artifacts/raw/` for new scan files using inotify
- Match files to parsers using regex patterns
- Queue jobs for processing (in-memory)
- Handle both individual scans and AutoRecon results
- Trigger CAS generation when all scans complete
- Call PTT initializer after CAS creation

**Processing Modes:**
1. **Individual Scans** - Single tool output (e.g., `nmap-10.10.10.3.xml`)
2. **AutoRecon Results** - Complete scan directory with multiple tools

**Key Functions:**
- `_run_cas_formatter()` - Generate CAS and initialize PTT
- `AutoReconProcessor.process_target()` - Handle AutoRecon output

---

### Parsers (parsers/*.py)

**Purpose:** Convert tool-specific output to normalized JSON

**Supported Parsers (24+):**

| Category | Parsers |
|----------|---------|
| **Network** | nmap, dnsrecon, onesixtyone, snmpwalk |
| **Web** | httpx, feroxbuster, gobuster, dirsearch, ffuf, nikto, whatweb, wpscan, nuclei, sslscan |
| **SMB/Enum** | smbmap, enum4linux, showmount |
| **Specialized** | subfinder, rpcdump, dirb, redis-cli, dig, manual-commands, autorecon |

**Parser Interface:**
Each parser must implement:
```python
def parse_file(file_path: str) -> dict:
    """
    Parse tool output and return normalized data.

    Returns:
        {
            "hosts": [{"ip": str, "hostname": str, "os": str}],
            "ports": [{"port": int, "proto": str, "service": str, "version": str}],
            "vulns": [{"cve": str, "severity": str, "description": str}],
            "findings": [{"type": str, "value": str, "location": str}]
        }
    """
```

**Testing:**
All parsers have unit tests in `tests/parsers/test_parse_*.py` with fixture data in `tests/fixtures/`

---

### Enrichers (enrichers/*.py)

**Purpose:** Add context and intelligence to parsed data

**Enrichment Types:**

1. **CVE Enrichment** (`enrich_cve.py`)
   - NVD API integration
   - Local caching (avoids rate limits)
   - EPSS scoring for exploit likelihood
   - CISA KEV (Known Exploited Vulnerabilities) flagging

2. **Service Analysis** (`enrich_services.py`)
   - Version-based vulnerability lookup
   - Known default credentials
   - Common misconfigurations

3. **Web Technology** (`enrich_web.py`)
   - Framework detection
   - CMS identification
   - Technology stack mapping

**Caching:**
- CVE data cached in `/artifacts/cache/cve/`
- Cache TTL: 7 days
- Reduces NVD API calls, prevents rate limiting

---

### format-cas.py

**Purpose:** Generate Context-Aware Summary (CAS) in YAML

**Input:** Enriched JSON from parsers
**Output:** `/artifacts/{target}/context.yaml`

**CAS Structure:**
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
  quick_wins: ["Check default creds on FTP"]
  priority_targets: ["HTTP service has SQLi"]
  recommended_commands: ["hydra -L users.txt ssh://10.10.10.3"]
```

---

### init-ptt.py

**Purpose:** Initialize Pentesting Task Tree from CAS

**Added:** 2026-01-20 (replaces manual PTT creation via gemini-cli)

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

**Integration:**
Called automatically by watcher.py after CAS generation:
- Line 399-421 in `_run_cas_formatter()`
- Line 684-704 in `AutoReconProcessor.process_target()`

**Non-blocking:** Logs warnings on failure but doesn't stop enrichment pipeline.

---

## Data Flow

### Typical Processing Flow

```
1. AutoRecon scans 10.10.10.3
   └─> Outputs to /artifacts/raw/10.10.10.3/

2. Watcher detects new directory
   └─> AutoReconProcessor processes all scans

3. Parsers extract data
   ├─> parse-nmap.py → hosts, ports, services
   ├─> parse-httpx.py → web technologies
   ├─> parse-nuclei.py → vulnerabilities
   └─> parse-whatweb.py → web fingerprints

4. Enrichers add context
   ├─> CVE lookup for known versions
   ├─> EPSS scoring for vulnerabilities
   └─> Service analysis for misconfigs

5. CAS Formatter aggregates
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
# Logging
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR

# Paths
ARTIFACTS_DIR=/artifacts
RAW_DIR=/artifacts/raw
MANIFEST_PATH=/artifacts/manifest.yaml

# External APIs
NVD_API_KEY=<optional>  # For faster CVE lookups
```

### Volume Mounts

```yaml
volumes:
  - artifacts:/artifacts           # Shared scan data
  - enrichment-cache:/artifacts/cache  # CVE cache persistence
```

---

## Testing

### Unit Tests

```bash
cd /home/fprime/Projects/blunderbussy

# Test all parsers
uv run pytest tests/parsers/ -v

# Test specific parser
uv run pytest tests/parsers/test_parse_nmap.py -v

# Test with coverage
uv run pytest tests/ --cov=infrastructure/enrichment
```

### Integration Tests

```bash
# Test full pipeline with AutoRecon fixtures
uv run pytest tests/integration/test_autorecon_processor.py -v
```

### Fixtures

Test data located in `tests/fixtures/`:
- `autorecon/` - Complete AutoRecon scan results
- `nmap/` - Nmap XML samples
- `feroxbuster/` - Web directory enumeration
- `nuclei/` - Vulnerability scan results

---

## Troubleshooting

### Pipeline Not Processing Files

**Check:**
1. Container is running: `podman ps | grep enrichment`
2. Watcher logs: `podman logs enrichment`
3. File permissions: Files must be readable by container UID
4. Volume mount: `/artifacts` correctly mounted

**Common Issues:**
- File created before watcher started → Move file to trigger re-detection
- Incomplete scan → Watcher waits for completion marker
- Parser crashed → Check logs for stack trace

### PTT Not Generated

**Check:**
1. CAS exists: `ls /artifacts/{target}/context.yaml`
2. init-ptt.py present: `podman exec enrichment ls /app/init-ptt.py`
3. ptt.py module: `podman exec enrichment ls /app/ptt.py`
4. Logs: `podman logs enrichment | grep -i ptt`

**Known Issues:**
- Invalid CAS format → PTT init logs warning, doesn't fail pipeline
- Missing service data → PTT creates empty structure (valid)
- Enrichment container rebuilt without new Dockerfile → Missing init-ptt.py

**Fix:** Rebuild enrichment container with correct Dockerfile:
```bash
podman stop enrichment && podman rm enrichment
podman-compose up -d enrichment
```

### CVE Enrichment Slow

**Symptoms:** Long processing times for scans with many services

**Causes:**
1. NVD API rate limiting (no API key)
2. Cache miss (first run)
3. Many CVEs to lookup

**Solutions:**
- Set `NVD_API_KEY` environment variable for 5x faster requests
- Subsequent runs use cache (7-day TTL)
- Consider pre-warming cache with common CVEs

---

## Performance

### Benchmarks

| Target Size | Scan Time | Parse Time | Enrich Time | Total |
|-------------|-----------|------------|-------------|-------|
| 5 ports | 2 min | 2 sec | 5 sec | ~2:07 |
| 20 ports | 8 min | 8 sec | 20 sec | ~8:30 |
| 50 ports | 30 min | 30 sec | 60 sec | ~31:30 |

*Scan time = AutoRecon, Parse/Enrich = Enrichment pipeline*

### Optimization Tips

1. **Use NVD API Key** - 5x faster CVE lookups
2. **Pre-warm Cache** - Bulk load common CVEs
3. **Scope Scans** - Don't scan unnecessary ports
4. **Parallel AutoRecon** - Use `-ct` flag for concurrent scans

---

## Future Enhancements

**Tracked in Beads:**
- [ ] Parallel parser execution (currently sequential)
- [ ] Incremental enrichment (re-process only changed data)
- [ ] Parser plugin system (dynamic parser discovery)
- [ ] Enrichment confidence scoring
- [ ] Multi-target batch processing
- [ ] Real-time streaming (process as scans complete)

---

## See Also

- [PTT Schema](../PrEP/schemas/PTT_SCHEMA.md) - Task tree structure
- [GEMINI.md](../PrEP/GEMINI.md) - Dame's exploitation workflow
- [ERROR_HANDLING.md](../PrEP/ERROR_HANDLING.md) - Error classification
- [CHANGELOG.md](../../CHANGELOG.md) - Project history
