# Dame Error Handling Decision Tree

**Purpose:** Guide adaptive exploitation when techniques fail

## Quick Reference

```
EXPLOIT FAILED
    │
    ├─→ Classify error type from output
    ├─→ Apply immediate recovery action
    ├─→ If 2nd failure: trigger research loop
    └─→ If 3rd failure: mark failed, move to next technique
```

## Error Classification

When a technique fails, classify the error by scanning the output for indicators:

### CONNECTION_FAILURE
**Indicators:** `connection refused`, `timeout`, `unreachable`, `no route`, `host down`, `network error`

**Recovery Actions (try in order):**
1. `retry_after_delay` - Wait 5-10 seconds, retry
2. `verify_target` - Confirm target IP/port still accessible
3. `try_alternate_port` - If service runs on multiple ports

**Research Query:** `{service} connection refused troubleshoot`

---

### VERSION_MISMATCH
**Indicators:** `not vulnerable`, `version`, `patch`, `target is not vulnerable`, `wrong version`

**Recovery Actions:**
1. `re_fingerprint` - Run deeper version detection
   ```
   nmap -sV --version-intensity 5 -p {port} {target}
   ```
2. `find_correct_exploit` - Search for exploit matching actual version
3. `try_generic_exploit` - Use version-agnostic technique if available

**Research Query:** `{service} {actual_version} exploit CVE`

---

### PAYLOAD_BLOCKED
**Indicators:** `blocked`, `detected`, `quarantine`, `av`, `edr`, `defender`, `antivirus`, `malicious`

**Recovery Actions:**
1. `encode_payload` - Apply encoding (base64, xor, shikata_ga_nai)
2. `try_fileless` - Use memory-only execution
3. `try_different_payload` - Switch payload type entirely
   - If using meterpreter → try plain reverse shell
   - If using staged → try stageless
   - If using exe → try powershell/script

**Research Query:** `{av_product} bypass 2025` or `{payload_type} evasion technique`

---

### NETWORK_BLOCKED
**Indicators:** `reverse shell`, `callback failed`, `no connection`, `listener`, `outbound filtered`

**Recovery Actions (try in order):**
1. `try_port_443` - Most likely to be allowed (HTTPS)
2. `try_port_80` - Second most likely (HTTP)
3. `try_port_53` - DNS often allowed
4. `try_bind_shell` - Target connects to you instead
5. `try_dns_tunnel` - Last resort, slow but often works

**Research Query:** `reverse shell alternatives firewall bypass`

---

### AUTH_FAILURE
**Indicators:** `invalid`, `password`, `credential`, `login failed`, `access denied`, `authentication failed`, `wrong password`

**Recovery Actions:**
1. `try_alternate_creds` - Try other discovered credentials
2. `try_next_wordlist` - Switch to different password list
3. `check_lockout` - Verify account isn't locked
4. `try_password_spray` - Low and slow approach

**Research Query:** `{service} default credentials` or `{application} password reset`

---

### EXPLOIT_CRASH
**Indicators:** `crash`, `segfault`, `unresponsive`, `died`, `exception`, `core dump`, `service stopped`

**Recovery Actions:**
1. `wait_recovery` - Wait 30-60 seconds for service restart
2. `verify_service` - Check if service is back up
3. `try_stable_variant` - Find more reliable exploit
4. `skip_service` - Mark service as fragile, move on

**Research Query:** `{exploit_name} stable version` or `{CVE} reliable exploit`

---

### PERMISSION_DENIED
**Indicators:** `permission`, `privilege`, `unauthorized`, `forbidden`, `not allowed`, `insufficient`

**Recovery Actions:**
1. `check_current_access` - Verify what access you have
2. `find_alternate_path` - Look for different entry point
3. `note_for_privesc` - Mark for privilege escalation phase

**Research Query:** `{service} permission bypass` or `{application} privilege escalation`

---

### UNKNOWN
**Indicators:** None of the above patterns matched

**Recovery Actions:**
1. `log_full_error` - Capture complete error output
2. `web_search_error` - Search the exact error message
3. `try_variant` - Try slight variation of technique

**Research Query:** `"{exact_error_message}"` (quoted for exact match)

---

## Decision Tree Flowchart

```
┌─────────────────────────────────────────────────────────────────┐
│                    TECHNIQUE EXECUTION FAILED                    │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: CLASSIFY ERROR                                         │
│  ─────────────────────────────────────────────────────────────  │
│  Scan error output for indicator keywords                       │
│  Map to error type: CONNECTION | VERSION | PAYLOAD | NETWORK |  │
│                     AUTH | CRASH | PERMISSION | UNKNOWN         │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: CHECK ATTEMPT COUNT                                    │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
              Attempt 1                 Attempt 2+
                    │                       │
                    ▼                       ▼
        ┌───────────────────┐   ┌─────────────────────────┐
        │ Apply Recovery    │   │ RESEARCH LOOP           │
        │ Action #1         │   │ ─────────────────────── │
        │                   │   │ 1. Build search query   │
        │ Retry technique   │   │ 2. Web search error     │
        └─────────┬─────────┘   │ 3. Search skills DB     │
                  │             │ 4. Apply findings       │
                  │             │ 5. Retry with fix       │
                  │             └───────────┬─────────────┘
                  │                         │
                  └────────────┬────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Attempt 3 Failed?   │
                    └─────────┬───────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                   NO                  YES
                    │                   │
                    ▼                   ▼
           Retry with next      ┌───────────────────┐
           recovery action      │ MARK FAILED       │
                               │ Move to next      │
                               │ technique/vector  │
                               └───────────────────┘
```

## Research Loop Protocol

Triggered on **2nd failure** of a technique:

### Step 1: Build Search Query
```
Base query: "{error_type} {service} {version}"
Append: "fix" or "workaround" or "bypass"
```

**Examples:**
- `connection refused ssh OpenSSH 8.9 fix`
- `payload blocked windows defender bypass 2025`
- `CVE-2021-44228 log4j exploit not working`

### Step 2: Execute Search
Use available tools:
1. **Web Search** - General error resolution
2. **Skills DB Query** - Find alternate techniques
3. **CVE Database** - Version-specific exploits

### Step 3: Analyze Results
Look for:
- Alternative commands/syntax
- Required prerequisites missed
- Known workarounds
- Updated exploit versions

### Step 4: Apply and Retry
- Modify technique based on findings
- Log what was changed
- Execute modified technique

---

## Iteration Thresholds

### Per-Technique Thresholds
| Attempt | Action |
|---------|--------|
| 1 | Apply recovery action #1, retry |
| 2 | Trigger research loop, apply findings, retry |
| 3 | Mark technique FAILED, move to next |

### Per-Vector Thresholds
| Condition | Action |
|-----------|--------|
| All techniques exhausted | Mark vector FAILED |
| 1+ technique succeeded | Mark vector SUCCESS |
| >50% techniques failed fast | Demote vector priority |

### Per-Service Thresholds
| Condition | Action |
|-----------|--------|
| All vectors exhausted | Mark service FAILED |
| Any vector succeeded | Mark service EXPLOITED |
| 5+ total technique failures | Consider skipping service |

### Per-Engagement Thresholds
| Condition | Action |
|-----------|--------|
| 10 total failures | Trigger deep re-enumeration |
| 15 total failures | Pivot to credential attacks |
| 20 total failures | Report status, request guidance |

---

## Deep Re-enumeration Protocol

Triggered after **10 total failures**:

1. **UDP Scan** (if not done)
   ```
   nmap -sU --top-ports 100 {target}
   ```

2. **Higher Port Ranges**
   ```
   nmap -p 10000-65535 {target}
   ```

3. **Service Version Refinement**
   ```
   nmap -sV --version-all -p {open_ports} {target}
   ```

4. **Alternate Vhosts** (for web)
   ```
   gobuster vhost -u http://{target} -w vhosts.txt
   ```

5. **SNMP Enumeration** (if UDP 161 open)
   ```
   snmpwalk -v2c -c public {target}
   ```

---

## Pivot Strategy

When all primary vectors fail, pivot to:

### 1. Credential-Focused Attacks
- Password spraying with discovered usernames
- Credential stuffing from OSINT
- Hash cracking if hashes obtained

### 2. Adjacent Targets
- Other hosts in same subnet (if in scope)
- Related services discovered during recon

### 3. Social Engineering
- Phishing if email addresses discovered
- Physical access vectors if applicable

### 4. Supply Chain
- Third-party integrations
- Vendor access portals

---

## Logging Requirements

Every error must be logged with:

```yaml
error_log:
  timestamp: "ISO-8601"
  technique_id: "uuid"
  attempt: 1
  error_type: "CONNECTION_FAILURE"
  error_message: "Connection refused"
  command_executed: "hydra -L users.txt ..."
  recovery_action: "retry_after_delay"
  research_performed: false
  research_query: null
  research_findings: null
  outcome: "retry_scheduled"
```

This enables:
- Pattern detection (same error across techniques)
- Learning from failures
- Improving future attempts

---

## Integration with PTT

The PTT module (`ptt.py`) handles:
- `_classify_error()` - Maps error message to type
- `_handle_failure()` - Applies recovery, logs error
- `RECOVERY_ACTIONS` - Maps error types to actions

Dame should:
1. Execute technique
2. On failure: call `ptt.update_technique(id, status="failed", error={...})`
3. PTT classifies and logs
4. Dame reads `error_history` for recovery guidance
5. Dame applies recovery or moves to next technique
