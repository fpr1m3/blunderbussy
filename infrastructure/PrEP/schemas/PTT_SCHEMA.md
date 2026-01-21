# Pentesting Task Tree (PTT) Schema

**Version:** 1.0
**Purpose:** Hierarchical task tracking for Dame agent exploitation workflow

## Overview

The PTT is a stateful tree structure that tracks Dame's exploitation progress from CAS input through initial access. It prevents repetitive actions, enables re-prioritization based on results, and maintains context across the engagement.

## Tree Structure

```
PTT
├── engagement (root)
│   ├── host_1 (Level 1: Hosts from CAS)
│   │   ├── service_1 (Level 2: Services/Ports)
│   │   │   ├── vector_1 (Level 3: Attack Vectors)
│   │   │   │   ├── technique_1 (Level 4: Specific Techniques)
│   │   │   │   └── technique_2
│   │   │   └── vector_2
│   │   └── service_2
│   └── host_2
```

## Schema Definition

```yaml
ptt_version: "1.0"
generated_at: "ISO-8601 timestamp"
last_updated: "ISO-8601 timestamp"

engagement:
  id: "engagement_uuid"
  target: "10.129.x.x or hostname"
  session_id: "from CAS"
  status: "pending | in_progress | success | failed"
  platform: "linux | windows | unknown"

  # Global findings propagate up from child nodes
  findings:
    credentials: []      # username:password or hashes
    access_gained: []    # shell sessions, access levels
    loot: []            # flags, sensitive files (see Flag Capture below)

  # Iteration tracking
  iteration_stats:
    total_attempts: 0
    successful_techniques: 0
    failed_techniques: 0
    skipped_techniques: 0

  hosts: []  # Level 1 nodes
```

## Node Types

### Host Node (Level 1)

```yaml
- id: "host_uuid"
  ip: "10.129.x.x"
  hostname: "target.htb"
  os: "Linux 4.15 - 5.19"
  status: "pending | in_progress | partial | compromised | skipped"
  priority: 7  # from CAS, 1-10 scale

  # Host-level findings
  findings:
    users_discovered: []
    credentials: []
    access_level: "none | user | root"

  services: []  # Level 2 nodes
```

### Service Node (Level 2)

```yaml
- id: "service_uuid"
  port: 22
  proto: "tcp"
  service: "ssh"
  version: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.13"
  status: "pending | in_progress | exploited | failed | skipped"

  # Priority calculation: (EPSS × Impact × Reliability) / Complexity
  priority_score: 7.5
  epss_score: 0.0  # If CVE known

  # From CAS enrichment
  known_vulns: []
  cves: []

  # Tracking
  attempts: 0
  max_attempts: 5  # Before marking as exhausted

  vectors: []  # Level 3 nodes
```

### Vector Node (Level 3)

Attack vector categories for the service.

```yaml
- id: "vector_uuid"
  name: "credential_attack"  # or "cve_exploit", "misconfig", "default_creds"
  category: "quick_win | known_vuln | brute_force | custom"
  status: "pending | in_progress | success | failed | skipped"
  priority: 1  # 1=quick_win, 2=known_vuln, 3=brute, 4=custom

  # Vector-level tracking
  techniques_total: 3
  techniques_completed: 0

  techniques: []  # Level 4 nodes
```

### Technique Node (Level 4)

Specific exploitation technique/command.

```yaml
- id: "technique_uuid"
  name: "SSH Default Credentials"
  source: "skills_db | manual | cas_recommendation"
  skill_ref: "ssh-default-creds"  # Reference to skills DB

  status: "pending | in_progress | success | failed | skipped"

  # Execution details
  command: "hydra -L users.txt -P pass.txt ssh://10.129.x.x"
  tool: "hydra"

  # Tracking
  attempts: 0
  max_attempts: 3
  last_attempt: "ISO-8601 timestamp"

  # Results
  findings:
    - type: "credential"
      value: "admin:password123"

  # Error tracking for adaptive recovery
  error_history:
    - attempt: 1
      timestamp: "ISO-8601"
      error_type: "connection_failure"  # See Error Taxonomy
      error_message: "Connection refused"
      recovery_action: "retry_after_delay"

  # For research loop
  research_queries: []  # Web searches performed
  research_results: []  # Relevant findings
```

## Status States

### Engagement Status
- `pending` - Not started
- `in_progress` - Active exploitation
- `success` - Initial access achieved
- `failed` - All vectors exhausted without access

### Host Status
- `pending` - Not yet attempted
- `in_progress` - Currently targeting
- `partial` - Some access gained (e.g., user shell)
- `compromised` - Full access (root/SYSTEM)
- `skipped` - Deprioritized or out of scope

### Service/Vector/Technique Status
- `pending` - Queued for attempt
- `in_progress` - Currently executing
- `success` - Exploitation successful
- `failed` - All attempts exhausted
- `skipped` - Deprioritized based on results

## Error Taxonomy

Classify failures for adaptive recovery:

| Error Type | Description | Recovery Action |
|------------|-------------|-----------------|
| `connection_failure` | Timeout, refused, unreachable | `retry_after_delay`, `try_alternate_port` |
| `version_mismatch` | Exploit incompatible with target | `re_fingerprint`, `find_correct_exploit` |
| `payload_blocked` | AV/EDR detection | `encode_payload`, `try_fileless` |
| `network_blocked` | Reverse shell fails | `try_port_443`, `try_bind_shell` |
| `auth_failure` | Invalid credentials | `try_next_wordlist`, `check_lockout` |
| `exploit_crash` | Service became unresponsive | `wait_recovery`, `try_stable_variant` |
| `permission_denied` | Insufficient privileges | `try_privesc`, `find_alternate_path` |
| `unknown` | Unclassified error | `log_and_research` |

## Priority Calculation

### Service Priority Score

```
priority_score = (epss × impact × reliability) / complexity

Where:
- epss: EPSS score (0-1), default 0.5 if unknown
- impact: 0.3 (info), 0.6 (user), 1.0 (root/SYSTEM)
- reliability: 0-1 based on exploit maturity
- complexity: 1 (trivial) to 5 (complex)
```

### Quick Win Detection

Services/vectors marked as quick wins (priority 1) if:
- Default credentials likely (CAS `attack_guidance.quick_wins`)
- Anonymous access possible
- Known Metasploit module exists
- CISA KEV CVE present

## Iteration Rules

### Per-Technique
- Max 3 attempts before marking `failed`
- Apply error-specific recovery between attempts
- Research loop on 2nd failure

### Per-Service
- Max 5 techniques before marking exhausted
- Re-evaluate priority after each technique

### Per-Engagement
- After 10 total failures: trigger deep re-enumeration
- Periodic holistic review every 5 techniques

## CAS to PTT Transformation

### Initialization (Enrichment Pipeline)

**PTT is automatically generated by the enrichment pipeline** after CAS creation. The `init-ptt.py` script runs as the final step in the pipeline:

1. Parse CAS `hosts` → create Host nodes
2. For each host, parse `ports` → create Service nodes
3. Generate attack vectors for each service based on type and vulnerabilities
4. Apply CAS `attack_guidance.quick_wins` as priority 1 vectors
5. Apply CAS `attack_guidance.recommended_commands` as techniques
6. Save to `/artifacts/{target}/ptt.yaml`

This deterministic transformation ensures PTT is ready before Dame starts exploitation, with zero LLM tokens required for initialization.

### Example Transformation

**CAS Input:**
```yaml
hosts:
- ip: 10.129.4.182
  hostname: conversor.htb
  ports:
  - port: 22
    service: ssh
    version: OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
    vectors:
    - private_key_disclosure
    - username_enum
    - version_specific_exploits
  - port: 80
    service: http
    version: Apache httpd 2.4.52

attack_guidance:
  quick_wins:
  - hydra Bruteforce logins on ssh:22
```

**PTT Output:**
```yaml
engagement:
  target: "10.129.4.182"
  platform: "linux"
  hosts:
  - ip: "10.129.4.182"
    hostname: "conversor.htb"
    services:
    - port: 22
      service: "ssh"
      version: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.13"
      vectors:
      - name: "credential_attack"
        category: "quick_win"
        priority: 1
        techniques:
        - name: "SSH Bruteforce - Hydra"
          source: "cas_recommendation"
          command: "hydra -L users.txt -P pass.txt ssh://10.129.4.182"
      - name: "private_key_disclosure"
        category: "misconfig"
        priority: 2
      - name: "version_specific_exploits"
        category: "cve_exploit"
        priority: 3
```

## Update Patterns

### On Technique Success
```python
technique.status = "success"
technique.findings.append(result)
# Propagate findings up
vector.status = "success"
service.status = "exploited"
host.findings.credentials.extend(technique.findings.credentials)
engagement.findings.access_gained.append(access_info)
```

### On Technique Failure
```python
technique.attempts += 1
technique.error_history.append(error_info)

if technique.attempts >= technique.max_attempts:
    technique.status = "failed"
    # Try next technique in vector
else:
    # Apply recovery action
    recovery = get_recovery_action(error_info.error_type)
    apply_recovery(recovery)
```

### Re-prioritization
```python
# After each technique completion
def reprioritize(ptt):
    for host in ptt.hosts:
        for service in host.services:
            # Boost priority if partial success nearby
            if has_related_success(service):
                service.priority_score *= 1.2

            # Demote if multiple failures
            failure_rate = service.failed_techniques / service.total_techniques
            if failure_rate > 0.5:
                service.priority_score *= 0.7
```

## File Location

PTT is stored alongside CAS:
```
/artifacts/{target}/
├── context.yaml      # CAS (input)
└── ptt.yaml         # PTT (state tracking)
```

## Flag Capture

HTB flags are 32-character hexadecimal MD5 hashes. Record captured flags in the `loot` array.

### Flag Loot Structure

```yaml
loot:
  - type: "flag"
    name: "user_flag"       # or "root_flag"
    value: "a1b2c3d4e5f6789012345678abcdef12"
    location: "/home/user/user.txt"
    captured_at: "2026-01-20T10:30:00Z"
    captured_by: "technique_uuid"  # Reference to technique that enabled capture
```

### Flag Capture Status Updates

| Flag Captured | Host Status | Access Level |
|---------------|-------------|--------------|
| user_flag | `partial` | `user` |
| root_flag | `compromised` | `root` |

### Validation

Flags must match regex `^[a-f0-9]{32}$`. Invalid content indicates:
- Wrong file path
- Decoy file
- Box needs reset

## Integration Points

1. **Enrichment pipeline creates CAS** → Runs init-ptt.py → Generates PTT
2. **Dame loads PTT** → Reads pre-populated task tree
3. **Dame queries skills DB** → Enriches technique nodes with execution details
4. **Dame executes technique** → Updates PTT status
5. **Dame encounters error** → Classifies, logs, applies recovery
6. **Dame achieves success** → Propagates findings up tree
7. **Flag captured** → Records in loot, updates host status
8. **Session ends** → PTT persists for continuation
