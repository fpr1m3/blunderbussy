# Phase Skill Schema

This document defines the structure for Dame's phase-based skill system.

## Directory Structure

```
skills/
├── SCHEMA.md                 # This file
├── initial-access/
│   ├── PHASE.md              # Phase-level guidance
│   └── workflows/
│       ├── web-server.md     # HTTP/HTTPS services
│       ├── ssh.md            # SSH services
│       ├── smb.md            # SMB/CIFS services
│       ├── ftp.md            # FTP services
│       └── database.md       # Database services
├── privesc/
│   ├── PHASE.md
│   └── workflows/
│       ├── linux.md
│       └── windows.md
└── lateral-movement/
    ├── PHASE.md
    └── workflows/
        └── ...
```

## Progressive Disclosure Flow

```
1. CAS Parsed
   └── Determine current phase (initial-access if no shell, privesc if low-priv shell)

2. Load PHASE.md
   └── High-level guidance for the phase

3. Service Detected in CAS
   └── Match service to workflow file via triggers

4. Load Workflow
   └── Attack tree with ordered techniques

5. Technique Needs Specifics
   └── Query vector DB: "qdrant-find {service} {version} {technique}"

6. Technique Fails
   └── Query vector DB for alternatives: "qdrant-find {service} bypass {error_type}"
```

## Workflow File Schema

Each workflow file uses YAML frontmatter followed by markdown guidance.

### Frontmatter Structure

```yaml
---
service: <service_name>           # Canonical name (http, ssh, smb, ftp, mysql, etc.)
version: "1.0"

# Triggers determine when this workflow loads
triggers:
  ports: [80, 443, 8080, 8443]    # Port numbers that activate this workflow
  services:                        # Nmap service names
    - http
    - https
    - http-proxy
    - ssl/http
  banners:                         # Banner regex patterns (optional)
    - "Apache.*"
    - "nginx.*"
    - "IIS.*"

# Attack tree defines technique ordering
attack_tree:
  - id: quick_wins
    name: "Quick Wins"
    gate: OR                       # OR = any child success is sufficient
    priority: 1                    # Lower = try first
    children:
      - id: default_creds
        name: "Default Credentials"
        technique: "Try common default credentials for detected application"
        tools: [hydra, curl]
        indicators:                # Success indicators
          - "Login successful"
          - "Welcome"
          - "Dashboard"
        vector_db_query: null      # No DB query needed

      - id: known_cve
        name: "Known CVE Exploitation"
        technique: "Exploit known vulnerabilities for detected version"
        tools: [searchsploit, metasploit]
        indicators:
          - "shell"
          - "reverse connection"
        vector_db_query: "{cms} {version} exploit RCE"  # Query pattern

  - id: auth_bypass
    name: "Authentication Bypass"
    gate: OR
    priority: 2
    depends_on: [quick_wins]       # Only try after quick_wins exhausted
    children:
      - id: sqli_login
        name: "SQL Injection in Login"
        technique: "Test login form for SQL injection"
        tools: [sqlmap, manual]
        indicators:
          - "syntax error"
          - "mysql"
          - "Login successful"
        vector_db_query: "sql injection authentication bypass {backend}"

# Escalation rules
escalation:
  on_success:
    - "Log credentials to session state"
    - "Update PTT with successful vector"
    - "Transition to post-exploitation or privesc phase"
  on_failure:
    - "After 3 failed techniques in a node, move to next node"
    - "After all nodes exhausted, query vector DB for alternative approaches"
    - "If vector DB returns no results, mark service as hardened"
---
```

### Gate Types

| Gate | Behavior |
|------|----------|
| `OR` | Any child technique succeeding completes the node |
| `AND` | All children must succeed (rare, used for multi-step exploits) |
| `SEQUENCE` | Children must be tried in order (dependency chain) |

### Priority Ordering

Lower priority numbers are tried first:
- `priority: 1` - Quick wins, low-hanging fruit
- `priority: 2` - Standard exploitation techniques
- `priority: 3` - Complex or time-consuming attacks
- `priority: 4` - Hail mary attempts

### Vector DB Query Patterns

Query templates use placeholders from CAS context:
- `{service}` - Service name (apache, nginx, tomcat)
- `{version}` - Detected version number
- `{cms}` - CMS name if detected (wordpress, drupal, joomla)
- `{backend}` - Backend technology (php, asp, java)
- `{os}` - Operating system
- `{error_type}` - Error classification from failed attempt

## PHASE.md Structure

Phase files provide high-level guidance:

```markdown
---
phase: initial-access
description: "Gain first foothold on target system"
entry_conditions:
  - "No existing shell access"
  - "External network position"
exit_conditions:
  - "Shell obtained (any privilege level)"
  - "Valid credentials discovered"
---

# Initial Access Phase

## Objective
Establish first foothold on target from external position.

## Workflow Selection
Based on CAS services, load appropriate workflow:
- HTTP/HTTPS detected → `workflows/web-server.md`
- SSH detected → `workflows/ssh.md`
- SMB detected → `workflows/smb.md`

## General Principles
1. Start with quick wins (default creds, known CVEs)
2. Progress to active exploitation only after passive fails
3. Document all credentials and access paths
4. Query vector DB when version-specific technique needed
```

## Integration Points

### CAS to Workflow Matching

```python
def select_workflow(cas: dict, phase: str) -> str:
    """Select workflow based on CAS services and current phase."""
    for service in cas['services']:
        port = service['port']
        name = service['name']

        for workflow in load_workflows(phase):
            if port in workflow['triggers']['ports']:
                return workflow
            if name in workflow['triggers']['services']:
                return workflow

    return None  # No matching workflow
```

### PTT Integration

Attack tree nodes map to PTT vectors:
- `attack_tree[].id` → PTT vector ID
- `attack_tree[].children[].id` → PTT technique ID
- Success/failure updates PTT status

### Session State Integration

- Discovered credentials → `session/credentials.yaml`
- Attack hypotheses → `session/hypotheses.yaml`
- Technique outcomes → `session/attack_log.jsonl`
