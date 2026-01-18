# Agent Opulence Test Plan

## Test Philosophy

**Three-layer testing:**
1. **Unit Tests** - Individual components in isolation
2. **Integration Tests** - Components working together
3. **E2E Tests** - Full mission simulation on HTB machines

---

## Related Design Documentation

All design documentation is located at `$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/`.

### Relevant Docs by Test Area

| Test Area | Design Doc | Why It Matters |
|-----------|------------|----------------|
| **Parser Tests** | `Implementation/ENRICHMENT_PIPELINE.md` | Defines expected parse output formats |
| **Enricher Tests** | `Implementation/ENRICHMENT_PIPELINE.md`, `Data/DATA_DEFINITIONS.md` | CVE enrichment logic, data structures |
| **CAS Formatter** | `Data/schemas/CAS_SCHEMA.md` | Schema validation requirements |
| **Scope Validation** | `Data/schemas/SCOPE_SCHEMA.md` | CIDR/domain matching rules |
| **Docker Stack** | `Architecture/INFRASTRUCTURE_DESIGN.md` | Container health requirements |
| **VPN/Killswitch** | `Security/SECURITY_HARDENING.md` | Security validation criteria |
| **E2E Tests** | `Architecture/WORKFLOW_DESIGN.md` | OODA loop and mission flow |
| **Context Management** | `Implementation/CONTEXT_DESIGN.md` | CAS reading and direct exploitation |

### Schema Files (for validation)

Located at `$HOME/Notes/Obsidian/10 - PROJECTS/Agent Opulence/Data/schemas/`:
- `CAS_SCHEMA.md` - Validate CAS formatter output
- `SHP_SCHEMA.md` - Validate agent handoff data
- `MANIFEST_SCHEMA.md` - Validate manifest structure
- `SCOPE_SCHEMA.md` - Validate scope definitions
- `AGENT_RETURNS.md` - Validate agent return contracts

---

## Phase 1: Unit Tests (Can Run Now)

### Stream B: Enrichment Pipeline

#### 1.1 Parser Tests
```bash
# Create test fixtures
mkdir -p tests/fixtures

# Test nmap parser
python infrastructure/enrichment/parsers/parse-nmap.py tests/fixtures/sample_nmap.xml --pretty

# Test nuclei parser
python infrastructure/enrichment/parsers/parse-nuclei.py tests/fixtures/sample_nuclei.json --pretty

# Test httpx parser
python infrastructure/enrichment/parsers/parse-httpx.py tests/fixtures/sample_httpx.json --pretty
```

**Test Cases:**
| Parser | Input | Expected Output |
|--------|-------|-----------------|
| parse-nmap | Valid XML with 3 hosts, 10 ports | JSON with hosts[], ports[], stats |
| parse-nmap | Empty scan | JSON with empty hosts[], stats.hosts_up=0 |
| parse-nmap | Malformed XML | Error exit code, stderr message |
| parse-nuclei | JSONL with 5 findings | JSON with vulnerabilities[], severity counts |
| parse-httpx | JSON with tech detection | JSON with web_services[], technologies |

#### 1.2 Enricher Tests
```bash
# Test CVE enricher (requires network or mock)
echo '{"vulnerabilities": [{"cves": ["CVE-2021-44228"]}]}' | \
  python infrastructure/enrichment/enrichers/enrich-cves.py

# Test service enricher
echo '{"hosts": [{"ports": [{"service": "ssh", "version": "OpenSSH 7.2"}]}]}' | \
  python infrastructure/enrichment/enrichers/enrich-services.py
```

**Test Cases:**
| Enricher | Input | Expected Output |
|----------|-------|-----------------|
| enrich-cves | CVE-2021-44228 | CVSS 10.0, exploit_available=true, in_cisa_kev=true |
| enrich-cves | CVE-9999-99999 | Graceful handling, no crash |
| enrich-services | OpenSSH 7.2 | known_vulns populated, priority_score calculated |
| enrich-web | WordPress 5.0 | tech_vulns populated, recommended_tools |

#### 1.3 CAS Formatter Tests
```bash
# Test CAS formatting
echo '{"target": "10.10.10.5", "data": {"hosts": []}}' | \
  python infrastructure/enrichment/format-cas.py /tmp/test_cas.yaml

cat /tmp/test_cas.yaml
```

**Test Cases:**
| Scenario | Expected |
|----------|----------|
| Empty data | Valid YAML with summary.hosts_discovered=0 |
| Large output (1000 hosts) | Truncated to max_items_per_section |
| Merge with existing | New data appended, no duplicates |

---

## Phase 2: Integration Tests (After Stream A)

### 4.1 Docker Stack Health
```bash
cd ~/Projects/blunderbussy

# Start stack
docker compose up -d

# Wait for health
docker compose ps

# Expected: All containers healthy
# - gluetun: healthy (VPN connected)
# - enrichment: healthy (watcher running)
```

### 4.2 VPN Validation
```bash
# Check VPN IP
docker exec gluetun wget -qO- ifconfig.me
# Expected: HTB VPN IP (10.10.x.x)

# Check killswitch
docker exec gluetun sh -c "ip route | grep default"
# Expected: Routes only through tun0

# Test leak (should fail/timeout)
docker exec gluetun sh -c "curl --interface eth0 ifconfig.me" 2>&1
# Expected: Timeout or connection refused
```

### 4.3 Enrichment Pipeline Integration
```bash
# Create test raw scan
cat > /tmp/test_nmap.xml << 'EOF'
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 10.10.10.5">
  <host>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.41"/>
      </port>
    </ports>
  </host>
</nmaprun>
EOF

# Copy to artifacts/raw
cp /tmp/test_nmap.xml artifacts/raw/nmap_10.10.10.5.xml

# Watch enrichment logs
docker logs -f enrichment

# Expected output within 30 seconds:
# - artifacts/10.10.10.5/context.yaml created
# - manifest.yaml updated
# - Logs show: "Successfully processed ... -> /artifacts/10.10.10.5/context.yaml"

# Verify CAS
cat artifacts/10.10.10.5/context.yaml
```

---

## Phase 3: E2E Tests (After Streams E, F)

### 5.1 HTB Easy Machine Test
**Target:** Lame (10.10.10.3) - vsftpd backdoor (CVE-2011-2523)

**Test Flow:**
```bash
# 1. Start infrastructure
cd ~/Projects/blunderbussy
docker compose up -d gluetun enrichment

# 2. Run recon pipeline
./infrastructure/recon/run-recon.sh 10.10.10.3

# 3. Wait for CAS generation
wait_for_file artifacts/10.10.10.3/context.yaml 120

# 4. Start kali-gemini container
docker compose up -d kali-gemini

# 5. Launch gemini-cli and engage
docker exec -it kali-gemini gemini-cli
> /opulence:engage 10.10.10.3

# 6. Dame reads CAS and exploits vsftpd directly
#    Expected: Dame reads /artifacts/10.10.10.3/context.yaml
#    Expected: Dame identifies CVE-2011-2523 in CAS
#    Expected: Dame runs exploit without additional scanning
#    Expected: Root shell obtained

# 7. Verify success
cat /root/root.txt
```

**Success Criteria:**
- Automated recon completes without manual intervention
- CAS generated at `/artifacts/10.10.10.3/context.yaml`
- CAS contains CVE-2011-2523 (vsftpd backdoor) detection
- Dame exploits vulnerability directly without spawning sub-agents
- Root shell obtained and root.txt captured
- No additional MCP calls for scope expansion or artifact reads beyond CAS

### 5.2 Context Management Test
```
Test Sequence:
1. Generate large nmap output (100+ hosts)
2. Enrichment produces large CAS
3. Dame reads CAS via cat/file operations (no MCP calls)
4. Verify efficient context usage:
   - Dame extracts only relevant CVEs
   - No full data bloat in token count
   - Key findings preserved

Victory: Context window used efficiently, Dame exploits without bloat
```

### 5.3 Failure Recovery Test
```
Test Sequence:
1. Mid-mission, kill enrichment container
2. Docker restarts it (restart: unless-stopped)
3. Pipeline resumes, no data lost
4. Kill gluetun - verify killswitch activates
5. Restart gluetun - VPN reconnects
6. Mission continues

Victory: System resilient to container failures
```

---

## Test Fixtures Needed

```
tests/
├── fixtures/
│   ├── nmap/
│   │   ├── sample_basic.xml       # 1 host, 3 ports
│   │   ├── sample_large.xml       # 50 hosts
│   │   ├── sample_scripts.xml     # With NSE output
│   │   └── sample_malformed.xml   # Invalid XML
│   ├── nuclei/
│   │   ├── sample_basic.json
│   │   ├── sample_critical.json   # Has critical findings
│   │   └── sample_empty.json
│   ├── httpx/
│   │   ├── sample_basic.json
│   │   └── sample_tech.json       # With tech detection
│   ├── scope/
│   │   ├── htb_basic.yaml         # Standard HTB scope
│   │   └── htb_restricted.yaml    # With exclusions
│   └── manifest/
│       └── sample_manifest.yaml
└── mocks/
    └── nvd_responses/             # Cached NVD API responses
        ├── CVE-2021-44228.json
        └── CVE-2023-1234.json
```

---

## Test Execution Order

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: Unit Tests (Now)                                       │
│  ├── Parser tests (no deps)                                      │
│  ├── Enricher tests (mock NVD or use cache)                     │
│  └── CAS formatter tests                                         │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 2: Integration Tests (After Stream A)                     │
│  ├── Docker stack health                                         │
│  ├── VPN validation + killswitch                                │
│  └── Enrichment pipeline end-to-end                             │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 3: E2E Tests (After Streams E, F)                        │
│  ├── HTB Easy machine (Lame - vsftpd exploitation)              │
│  ├── Context management and file reading                         │
│  └── Failure recovery                                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## CI/CD Considerations (Future)

```yaml
# .github/workflows/test.yml (conceptual)
jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v5
      - name: Install deps
        run: pip install -r infrastructure/enrichment/requirements.txt
      - name: Run parser tests
        run: python -m pytest tests/unit/parsers/
      - name: Run enricher tests (mocked)
        run: python -m pytest tests/unit/enrichers/

  integration-tests:
    runs-on: self-hosted  # Needs Docker
    steps:
      - name: Start stack
        run: docker compose up -d
      - name: Wait for health
        run: ./scripts/wait-for-health.sh
      - name: Run integration tests
        run: python -m pytest tests/integration/
```

---

## Manual Test Checklist

### Pre-HTB Testing
- [ ] All parsers handle malformed input gracefully
- [ ] CVE enricher works with NVD API (or cached)
- [ ] CAS formatter produces valid YAML
- [ ] Scope validation correctly handles CIDR/domain

### HTB Machine Testing (Lame - vsftpd backdoor)
- [ ] VPN connects and stays stable
- [ ] Killswitch blocks traffic when VPN drops
- [ ] Recon pipeline completes without manual intervention
- [ ] CAS appears at `/artifacts/10.10.10.3/context.yaml` within 30 seconds
- [ ] CAS contains CVE-2011-2523 (vsftpd backdoor detection)
- [ ] Dame reads CAS directly with file operations
- [ ] Dame exploits vulnerability without spawning sub-agents
- [ ] Root shell obtained and root.txt captured
- [ ] Manifest updated with successful exploitation

### Edge Cases
- [ ] Empty scan results don't crash pipeline
- [ ] Very large outputs are truncated appropriately
- [ ] Network timeouts handled gracefully
- [ ] Concurrent scans don't corrupt manifest
- [ ] Container restart doesn't lose state
- [ ] Dame handles malformed CAS gracefully
