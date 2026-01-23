# Session State Schema

**Version:** 1.0
**Module:** `infrastructure/PrEP/session_state.py`

This document defines the session state schema for Dame's runtime exploitation workflow.

## Overview

Session state complements the PTT (Pentesting Task Tree) by tracking **runtime information** during exploitation:

| Component | Purpose | Location |
|-----------|---------|----------|
| PTT | What to do (techniques, vectors) | `/artifacts/{target}/ptt.yaml` |
| Session State | How it's going (shells, creds) | `/artifacts/{target}/session/` |

## Directory Structure

```
/artifacts/{target}/session/
├── state.yaml          # Core session state (always loaded)
├── credentials.yaml    # Credential store (file-level security)
├── hypotheses.yaml     # Attack path hypotheses
├── attack_log.jsonl    # Append-only action audit log
├── query_cache.yaml    # Query deduplication cache
├── files/              # Analyzed file cache
│   └── {sha256}.yaml   # Individual file analysis
└── memory_block.md     # Pre-formatted context injection
```

## Core Schemas

### SessionState (state.yaml)

```yaml
version: "1.0"
target: "10.129.5.135"
session_id: "sess-a1b2c3d4e5f6"
created_at: "2026-01-23T10:30:00"
updated_at: "2026-01-23T11:45:00"
current_access_level: "user"  # none | user | root | system
flags_captured:
  user: "a1b2c3d4e5f6789012345678abcdef12"
shells:
  - session_id: "pwncat-1"
    session_type: "reverse_shell"
    user: "www-data"
    host: "10.129.5.135"
    access_level: "user"
    established_at: "2026-01-23T11:00:00"
    technique_id: "uuid-of-ptt-technique"
web_sessions:
  - id: "web-1"
    target_url: "http://10.129.5.135/admin"
    cookie_file: "/tmp/cookies.txt"
    session_token: "PHPSESSID=abc123"
    expires_at: "2026-01-23T12:00:00"
    status: "active"
```

### CredentialStore (credentials.yaml)

```yaml
version: "1.0"
credentials:
  - id: "cred-a1b2c3d4"
    username: "admin"
    secret: "password123"
    secret_type: "password"  # password | hash | ssh_key | token | cookie
    domain: null  # or "CORP" for AD environments
    source: "hydra bruteforce ssh:22"
    discovered_at: "2026-01-23T10:45:00"
    valid_for:
      - "ssh"
      - "mysql"
    verified: true
  - id: "cred-e5f6g7h8"
    username: "backup"
    secret: "$6$rounds=5000$..."
    secret_type: "hash"
    source: "/etc/shadow"
    discovered_at: "2026-01-23T11:00:00"
    valid_for: []
    verified: false
```

### HypothesisStore (hypotheses.yaml)

```yaml
version: "1.0"
hypotheses:
  - id: "hyp-a1b2c3d4"
    description: "Kernel CVE-2024-1086 for root privilege escalation"
    confidence: 0.80
    priority: 1  # 1 (highest) to 5 (lowest)
    status: "active"  # active | confirmed | rejected | superseded
    evidence_for:
      - "Kernel version 5.15.0 detected"
      - "SUID bit on /usr/bin/at"
    evidence_against: []
    related_technique_ids:
      - "ptt-technique-uuid"
    created_at: "2026-01-23T11:00:00"
    updated_at: "2026-01-23T11:30:00"
```

### QueryCache (query_cache.yaml)

```yaml
version: "1.0"
max_entries: 100
entries:
  - query_hash: "a1b2c3d4e5f6g7h8"
    query_text: "linux kernel privesc CVE-2024"
    tool: "qdrant-find"
    timestamp: "2026-01-23T11:30:00"
    results_summary: "Found 3 techniques: CVE-2024-1086, DirtyPipe, PwnKit"
    ttl_minutes: 60
    hit_count: 2
  - query_hash: "i9j0k1l2m3n4o5p6"
    query_text: "vsftpd 2.3.4 backdoor"
    tool: "google_web_search"
    timestamp: "2026-01-23T11:15:00"
    results_summary: "Metasploit module available, port 6200 backdoor"
    ttl_minutes: 30
    hit_count: 0
```

### AnalyzedFile (files/{sha256}.yaml)

```yaml
sha256: "a1b2c3d4e5f6789012345678abcdef12a1b2c3d4e5f6789012345678abcdef12"
remote_path: "/var/www/html/config.php"
local_cache_path: "/artifacts/10.129.5.135/session/files/a1b2c3..."
findings:
  - "Database credentials: dbuser/dbpass123"
  - "Debug mode enabled"
  - "Hardcoded API key detected"
analyzed_at: "2026-01-23T11:20:00"
skip_reread: true
```

### AttackLog Entry (attack_log.jsonl)

```json
{"timestamp": "2026-01-23T11:00:00", "action_type": "technique_start", "technique_id": "uuid", "technique_name": "SSH Bruteforce"}
{"timestamp": "2026-01-23T11:05:00", "action_type": "credential_found", "username": "admin", "source": "hydra"}
{"timestamp": "2026-01-23T11:10:00", "action_type": "shell_obtained", "session_id": "pwncat-1", "access_level": "user"}
{"timestamp": "2026-01-23T11:15:00", "action_type": "flag_captured", "flag_type": "user", "value": "a1b2..."}
```

## Enumerations

### AccessLevel

| Value | Description |
|-------|-------------|
| `none` | No access obtained |
| `user` | Standard user shell |
| `root` | Root/Administrator |
| `system` | SYSTEM-level (Windows) |

### CredentialType

| Value | Description |
|-------|-------------|
| `password` | Plaintext password |
| `hash` | Password hash (MD5, SHA, NTLM, etc.) |
| `ssh_key` | SSH private key |
| `token` | API token or bearer token |
| `cookie` | Session cookie |

### HypothesisStatus

| Value | Description |
|-------|-------------|
| `active` | Currently being investigated |
| `confirmed` | Hypothesis proved correct |
| `rejected` | Hypothesis disproved |
| `superseded` | Replaced by better hypothesis |

### ShellType

| Value | Description |
|-------|-------------|
| `reverse_shell` | Reverse connection to attacker |
| `bind_shell` | Listening shell on target |
| `webshell` | Web-based shell |
| `ssh` | SSH session |
| `pwncat` | Managed pwncat session |

## Memory Block Format

The `memory_block.md` file contains a pre-formatted context injection block (~500 tokens) for Dame's system prompt:

```markdown
## Current Session State (Auto-Updated)

**Target:** 10.129.5.135 | **Access:** user
**Flags:** user captured

**Active Shells:**
- reverse_shell as www-data (user)

**Active Hypotheses:**
1. [80%] Kernel CVE-2024-1086 → root
2. [50%] SUID binary /opt/backup

**Credentials Available:**
- admin:*** (verified, for ssh, mysql)
- backup:*** (unverified, for untested)

**Recent Queries (avoid repetition):**
- "linux kernel privesc" (15 min ago)
```

### Token Budget

| Section | Budget | Content |
|---------|--------|---------|
| State | 100 tokens | Target, access level, flags |
| Shells | 100 tokens | Up to 3 active shells |
| Hypotheses | 150 tokens | Top 3 by priority/confidence |
| Credentials | 100 tokens | Up to 5 credentials (masked) |
| Queries | 50 tokens | Last 3 queries with age |

## Query Cache TTLs

| Tool | Default TTL | Rationale |
|------|-------------|-----------|
| `qdrant-find` | 60 min | Skills DB content stable |
| `google_web_search` | 30 min | Web content changes |
| `web_fetch` | 30 min | Dynamic pages |

All entries are auto-pruned after 2 hours regardless of TTL.

## Security Considerations

### File Permissions

| File | Permissions | Reason |
|------|-------------|--------|
| Session directory | 0700 | Only owner access |
| credentials.yaml | 0600 | Contains secrets |
| All other files | 0600 | Consistent security |

### Credential Security Model

1. **Plaintext storage** - Credentials stored in plaintext
2. **File-level security** - 0600 permissions, container isolation
3. **Container boundary** - Primary security is container isolation
4. **No encryption at rest** - Trade-off for simplicity in contained environment

This is acceptable because:
- Dame runs in isolated containers
- Artifacts are ephemeral (engagement-scoped)
- Network access is controlled via VPN split-tunneling
- Host system handles real security boundaries

## API Reference

See `session_state.py` docstrings for full API. Key methods:

```python
# Lifecycle
mgr = SessionStateManager.from_target("10.129.5.135")
mgr.load_all()
mgr.save_all()

# Credentials
mgr.add_credential(Credential(...))
mgr.get_credentials_for_service("ssh")
mgr.mark_credential_verified(cred_id, "ssh")

# Hypotheses
mgr.add_hypothesis("Kernel CVE-2024-1086", confidence=0.8, priority=1)
mgr.update_hypothesis(hyp_id, confidence_delta=0.1, evidence_for="...")
mgr.get_active_hypotheses(limit=5)

# Query Cache
mgr.check_query_cache("linux privesc", "qdrant-find")
mgr.cache_query("linux privesc", "qdrant-find", "Found 3 techniques")

# Memory Block
block = mgr.generate_memory_block()  # Returns markdown string
```

## Integration Points

### Gemini CLI Hooks

Session state is managed via Gemini CLI hooks:

| Hook | Purpose |
|------|---------|
| `SessionStart` | Load state, inject memory block |
| `PreToolUse` | Query deduplication check |
| `PostToolUse` | Credential extraction from output |

### PTT Coordination

Session state and PTT are siblings in the target directory:

```
/artifacts/{target}/
├── context.yaml    # CAS (input)
├── ptt.yaml        # PTT (what to do)
└── session/        # Session State (how it's going)
```

When a technique succeeds:
1. PTT marks technique as `success`
2. Session state records shells, credentials
3. Memory block is regenerated
4. Next technique selection uses updated context

---

## Session Memory (Qdrant)

**Module:** `infrastructure/PrEP/session_memory.py`

Session Memory provides semantic search over session history, stored in Qdrant vector database.

### Collection Schema

Collection name: `dame_session_{target_hash}` (one per target)

```python
{
    "vectors": {
        "fast-all-minilm-l6-v2": {
            "size": 384,
            "distance": "Cosine"
        }
    },
    "payload_schema": {
        "event_type": "string",   # technique_attempt, error_resolution, discovery, etc.
        "context": "string",      # Full context (embedded for search)
        "timestamp": "datetime",
        "technique_id": "string", # PTT reference
        "outcome": "string",      # success, failed, blocked, partial, pending
        "resolution": "string",   # How it was resolved
        "tags": "string[]"
    }
}
```

### Event Types

| Type | Description |
|------|-------------|
| `technique_attempt` | Shell command execution |
| `error_resolution` | Error and its fix |
| `discovery` | Significant finding |
| `credential_found` | Credential extraction |
| `access_gained` | Shell or access obtained |
| `flag_captured` | Flag file read |

### Use Cases

**"I've seen this error before":**
```python
from session_memory import SessionMemory
mem = SessionMemory.for_target("10.129.5.135")
results = mem.search_errors("WAF blocking UNION SELECT")
```

**"What have I tried on this port?":**
```python
results = mem.search("SSH exploitation attempts")
```

**Cross-session learning:**
```python
from session_memory import search_all_sessions
results = search_all_sessions("privilege escalation SUID")
```

### Integration

Session Memory is indexed automatically via PostToolUse hook:
- Non-trivial shell commands are indexed
- Outcome is detected from output patterns
- Tags are extracted from command patterns
