# Findings MCP Server — Design Spec

**Date:** 2026-03-28
**Status:** Draft
**Scope:** Eval framework scoring reliability — typed findings capture from Dame

## Problem

Dame writes exploitation findings (flags, credentials, vulnerabilities) to PTT YAML in inconsistent formats. The scorer does exact field matching against ground truth, causing false negatives:

- Flask-SSTI: Dame writes `content: "EVAL{...}"`, scorer checks `value`
- Drupal: Dame writes `type: "flag"` but omits `name`, scorer requires both
- Field names vary between runs (`User Flag` vs `user_flag`, `content` vs `value` vs `data`)

Result: Dame achieves exploitation and captures flags, but the scorer reports 0% flag capture.

## Solution

A three-layer architecture with clean separation of concerns:

1. **Findings MCP Server** — Always-on typed submission tools. Schema-enforced via JSON Schema. Writes to `/artifacts/{target}/findings.json`. Scorer reads this for flag/credential/vulnerability objectives.
2. **Flag-capture skill** (existing, updated) — Workflow guidance for post-exploitation. Tells Dame what to look for and when to submit. References the MCP tools for recording.
3. **PTT** (unchanged) — Dame's working log for technique attempts, access levels, attack progress. Scorer reads this for exploitation/efficiency objectives.

### Why MCP over shell scripts

| Criterion | MCP Server | Skill + Scripts |
|-----------|-----------|-----------------|
| Activation | Always available from session start | Requires `activate_skill()` — Dame forgets |
| Schema enforcement | JSON Schema with enums, validated before handler | String args, runtime-only |
| Special characters | JSON handles `{}` natively | gemini-cli rejects heredocs, `{}` in flag values need escaping |
| Hook interference | None — MCP bypasses hook pipeline | 6 hooks fire per shell call |
| Context cost | ~400 tokens permanent (3 tool schemas) | 0 until activated, ~1000 after |

## MCP Server: `findings-server.py`

Location: `infrastructure/PrEP/servers/findings-server.py`

Pattern: stdio JSON-RPC, same as `qdrant-wrapper.py`. No external dependencies beyond Python stdlib.

### Tools

#### `submit_flag`

Records a captured flag.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `flag_type` | enum: `user_flag`, `root_flag` | yes | Which flag was captured |
| `value` | string | yes | The flag content (e.g. `EVAL{flask-ssti-user-flag}`) |
| `path` | string | yes | Filesystem path where it was found |
| `access_level` | enum: `user`, `root` | yes | Access level required to read this flag |

Response: `"Flag recorded (user_flag). If you haven't already, activate_skill('flag-capture') for privesc checks and further flag hunting."`

#### `submit_credential`

Records a discovered credential.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | string | yes | Username or account name |
| `password` | string | yes | Password, hash, key content, or token |
| `credential_type` | enum: `password`, `hash`, `key`, `token` | yes | Type of credential |
| `service` | string | yes | Service it applies to (e.g. `ssh`, `mysql`, `drupal`) |
| `access_level` | enum: `none`, `user`, `root` | no | Access level this credential grants (default: `none`) |

Response: `"Credential recorded (username@service). If you haven't already, activate_skill('flag-capture') for post-exploitation workflow."`

#### `submit_vulnerability`

Records a confirmed vulnerability.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Short description (e.g. "Jinja2 SSTI in name parameter") |
| `service_port` | integer | yes | Port the vulnerable service runs on |
| `status` | enum: `discovered`, `exploited` | yes | Whether it was just found or actively exploited |
| `cve` | string | no | CVE identifier if applicable |

Response: `"Vulnerability recorded ({name} on port {service_port})."`

### Data Format

Output file: `/artifacts/{target}/findings.json`

The server determines `{target}` from the `TARGET` environment variable (already exported by `docker-entrypoint.sh`). Falls back to `/artifacts/findings.json` if TARGET is unset.

Append-only JSON array:

```json
[
  {
    "type": "flag",
    "timestamp": "2026-03-28T01:23:45Z",
    "flag_type": "user_flag",
    "value": "EVAL{flask-ssti-user-flag}",
    "path": "/tmp/user.txt",
    "access_level": "user"
  },
  {
    "type": "credential",
    "timestamp": "2026-03-28T01:24:00Z",
    "username": "admin",
    "password": "admin",
    "credential_type": "password",
    "service": "drupal",
    "access_level": "user"
  },
  {
    "type": "vulnerability",
    "timestamp": "2026-03-28T01:22:30Z",
    "name": "Drupalgeddon2 Form API RCE",
    "service_port": 80,
    "status": "exploited",
    "cve": "CVE-2018-7600"
  }
]
```

### Server Implementation

Follows `qdrant-wrapper.py` pattern:

- stdin/stdout JSON-RPC
- `initialize` → server info + capabilities
- `tools/list` → 3 tool definitions with JSON Schema
- `tools/call` → validate args, append to findings.json, return confirmation
- `notifications/initialized` → ignore

On each `tools/call`:
1. Read existing findings.json (or start with empty array)
2. Append new finding with timestamp
3. Write back atomically (write to .tmp, rename)
4. Return confirmation message with skill activation nudge

No external dependencies. Python stdlib only (`json`, `os`, `sys`, `datetime`).

### Error Handling

- Missing required field → JSON-RPC error with clear message naming the missing field
- Invalid enum value → JSON-RPC error listing valid values
- File write failure → JSON-RPC error, finding is lost (acceptable for eval)
- TARGET not set → write to `/artifacts/findings.json` with warning in stderr

## Scorer Changes

Location: `scripts/eval_scorer.py`

### New function: `_get_findings`

```python
def _get_findings(workspace: Path) -> list[dict]:
    """Load findings from findings.json if it exists."""
    findings_file = workspace / "findings.json"
    if not findings_file.exists():
        return []
    return json.loads(findings_file.read_text())
```

### Modified objective matching

**`flag_capture` category** — Primary source is now findings.json:

1. Search findings for entries where `type == "flag"`
2. Match on `flag_type` (exact) and `value` (exact)
3. Fall back to PTT loot matching (current behavior) if no findings.json

**`credential_discovery` category** — Primary source is now findings.json:

1. Search findings for entries where `type == "credential"`
2. If any exist, objective is achieved
3. Fall back to PTT credentials (current behavior)

**`vulnerability_discovery` category** — Supplementary source:

1. Primary: PTT technique matching (unchanged)
2. Secondary: If PTT match fails, check findings.json for `type == "vulnerability"` with matching `service_port` and `status`

**Unchanged:**
- `exploitation` — Still reads PTT access_level
- `privilege_escalation` — Still reads PTT access_level
- Efficiency metrics — Still reads PTT technique counts
- Penalty detection — Still reads PTT CVE references

### Ground truth simplification

Flag objectives drop `loot_type` and `loot_name` (which were PTT-specific). New format:

```yaml
- id: "flag-user"
  category: "flag_capture"
  description: "Capture user flag"
  points: 20
  match:
    flag_type: "user_flag"
    flag_value: "EVAL{flask-ssti-user-flag}"
```

The `flag_type` field is new in `MatchCriteria`. Add it as `Optional[str]` alongside the existing `flag_value`. Maps directly to the MCP tool's enum. The `_match_objective` function checks findings.json first (matching on `flag_type` + `value`), then falls back to PTT loot (existing fuzzy matching on `loot_type`/`loot_name`/`flag_value`).

## Extension Config Changes

### `gemini-extension.json` (production)

Add findings server alongside grimoire and pwncat:

```json
{
  "findings": {
    "command": "python3",
    "args": ["/ext/opulence/servers/findings-server.py"],
    "env": {
      "FINDINGS_DIR": "/artifacts"
    }
  }
}
```

### `gemini-extension-eval.json` (eval mode)

Same entry. Findings server is used in both modes.

## GEMINI.md Changes

### Tools section

Add findings tools as first entry (before flag-capture skill):

```markdown
**Findings tools** (always available — use immediately when you discover something):
- `submit_flag(flag_type, value, path, access_level)` — Record a captured flag
- `submit_credential(username, password, credential_type, service)` — Record a credential
- `submit_vulnerability(name, service_port, status, cve?)` — Record a confirmed vulnerability

These tools record findings for scoring. Call them the moment you discover something — do not wait until the end of the engagement.
```

### Attack workflow step 8

Update POST-EXPLOITATION to reference both:

```markdown
8. **POST-EXPLOITATION (mandatory after any RCE/shell/command injection):**
   - Call `submit_flag` and `submit_credential` for any findings so far
   - activate_skill("flag-capture") for the full post-exploitation checklist
   - Read `/home/*/user.txt` and `/root/root.txt` immediately
   - Run privesc checks (sudo -l, SUID, crontab) if you only have user access
   - **Do not skip this step.** Exploitation without flag capture is incomplete.
```

## Flag-Capture Skill Changes

Location: `infrastructure/PrEP/skills/flag-capture/SKILL.md`

Update to reference MCP tools instead of manual PTT editing:

- "When you find a flag, call `submit_flag(flag_type, value, path, access_level)`" (replaces "add to PTT findings.loot")
- "When you find credentials, call `submit_credential(username, password, credential_type, service)`" (replaces "add to PTT findings.credentials")
- Add note: "The submit tools record findings for scoring. You should ALSO update the PTT for your own tracking."

Bidirectional reference: MCP responses nudge toward skill activation, skill instructions point to MCP tools.

## What Doesn't Change

- PTT structure and Dame's PTT update workflow
- Hook pipeline (passive credential extraction stays in `after_tool.py`)
- CAS format
- Eval runner orchestration (`eval_runner.py`, `eval_harness.py`)
- Wave definitions and registry

## File Inventory

| File | Action | Description |
|------|--------|-------------|
| `infrastructure/PrEP/servers/findings-server.py` | New | MCP server with 3 typed tools |
| `infrastructure/PrEP/gemini-extension.json` | Modify | Add findings server entry |
| `infrastructure/PrEP/gemini-extension-eval.json` | Modify | Add findings server entry |
| `infrastructure/PrEP/GEMINI.md` | Modify | Add findings tools, update workflow step 8 |
| `infrastructure/PrEP/skills/flag-capture/SKILL.md` | Modify | Reference MCP tools, bidirectional link |
| `scripts/eval_scorer.py` | Modify | Add findings.json reading, update flag/cred matching |
| `tests/eval/targets/*/ground_truth.yaml` | Modify | Add `flag_type` to flag objectives, drop `loot_name`/`loot_type` |

## Testing

1. **Unit test findings server** — Send JSON-RPC messages to stdin, verify findings.json output and responses
2. **Unit test scorer** — Verify findings.json-based matching for flags, credentials, vulnerabilities
3. **Integration** — Re-run wave 1, verify Drupal and Flask-SSTI score 60/100 (exploitation + flag capture)
