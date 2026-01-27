---
name: code-vuln-analysis
description: Multi-agent source code vulnerability analysis. Recon-first approach with taint-informed focus. Use when Dame has access to a git repository and needs static code analysis during exploitation.
---

# Code Vulnerability Analysis

Multi-agent pipeline for static source code vulnerability analysis. Designed for exploitation phase when Dame has repository access.

---

## When to Use This Skill

Activate this skill when:
- You have filesystem access to application source code (e.g., `/var/www/html`, `/app`)
- A git repository has been cloned or is accessible
- The target service exposes source code (backup files, .git directory)
- Initial enumeration reveals custom application code worth analyzing

**Do NOT use for:**
- Binary analysis (use reversing tools instead)
- Network-only reconnaissance (no source access)
- Third-party/vendor code analysis (use SCA/CVE lookup)

---

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                          DAME (You)                             │
│    Orchestrates workflow, aggregates findings, controls budget  │
└─────────────────┬───────────────────────────────────────────────┘
                  │
    ┌─────────────┼─────────────┬─────────────────┐
    ▼             ▼             ▼                 ▼
┌───────┐   ┌───────────┐  ┌──────────┐    ┌────────────┐
│ RECON │ → │  TRIAGE   │→ │ ANALYSIS │ →  │ VALIDATION │
│ Agent │   │   Agent   │  │  Agent   │    │   Agent    │
└───────┘   └───────────┘  └──────────┘    └────────────┘
 5 turns      3 turns       12 turns         5 turns
```

**Total Budget: ~25 turns**

---

## Phase 1: Reconnaissance

**Agent:** `code-analysis/recon`
**Turn Budget:** 5 turns max
**Purpose:** Map codebase structure WITHOUT reading file contents deeply

### Invoke

```
delegate_to_agent(
  agent="code-analysis/recon",
  query="Map source code structure at {repo_path}. Languages detected: {languages}. Find dangerous sinks, entry points, and dependency graph."
)
```

### Expected Output

```yaml
manifest:
  files: [list of source files]
  languages: {php: 45, js: 12}

dependency_graph:
  includes:
    - from: admin.php
      imports: [config.php, db.php]

entry_points:
  web_routes: [{file, methods, auth_required}]
  cron_jobs: [{file, schedule}]

dangerous_sinks:
  code_execution: [{file, line, function, context}]
  sql: [{file, line, parameterized}]
  file_ops: [{file, line, function}]

user_inputs:
  - {file, line, variable, type}
```

### Checkpoint

Before proceeding to Triage, verify:
- [ ] At least one entry point identified
- [ ] Dangerous sinks list populated (or confirmed none found)
- [ ] File manifest includes expected language extensions

**If recon produces empty results:** The codebase may be obfuscated, compiled, or non-standard. Consider manual analysis or abort.

---

## Phase 2: Triage

**Agent:** `code-analysis/triage`
**Turn Budget:** 3 turns max
**Purpose:** Prioritize files by attack surface potential

### Invoke

```
delegate_to_agent(
  agent="code-analysis/triage",
  query="Prioritize analysis targets from recon output. Create chunks of 5-12k tokens grouped by data flow."
)
```

Pass the recon output as context.

### Expected Output

```yaml
priority_queue:
  critical:
    - {file, reason, attack_surface, confidence}
  high:
    - {file, reason, attack_surface, confidence}
  medium:
    - {file, reason, attack_surface, confidence}

analysis_chunks:
  - id: chunk_001
    files: [file1.php, file2.php]
    focus: "Trace user input to SQL sink"
    token_estimate: 6000

excluded:
  - {file, reason}
```

### Prioritization Formula

```
Score = (Sink_Severity × 3) + (Input_Proximity × 2) + (Auth_Bypass_Potential × 2)

Sink_Severity:
  code_execution: 10
  SQL: 8
  file_ops: 7
  deserialization: 7
  XSS: 5

Input_Proximity:
  direct_user_input: 10
  db_stored: 7
  config: 3

Auth_Bypass_Potential:
  no_auth: 10
  weak_auth: 5
  strong_auth: 1
```

### Checkpoint

Before proceeding to Analysis, verify:
- [ ] Priority queue has at least one entry
- [ ] Chunks are within 5-12k token budget
- [ ] Critical/high priority items explain WHY they're prioritized

**If no high-priority targets:** Either codebase is secure OR recon missed sinks. Try broader sink patterns or report "no obvious vulnerabilities."

---

## Phase 3: Analysis

**Agent:** `code-analysis/analysis`
**Turn Budget:** 12 turns total (process chunks until budget exhausted)
**Purpose:** Deep vulnerability analysis on prioritized chunks

### Invoke (per chunk)

```
delegate_to_agent(
  agent="code-analysis/analysis",
  query="Analyze chunk {chunk_id}: {focus}. Files: {files}. Look for: {attack_surface}"
)
```

Include security anti-patterns from `resources/sec-context/anti-patterns.md` in context.

### Processing Order

1. Process `critical` chunks first
2. Then `high` priority
3. Stop when:
   - All critical/high chunks processed, OR
   - Turn budget (12) exhausted, OR
   - High-confidence findings discovered

### Expected Output (per chunk)

```yaml
findings:
  - id: VULN-001
    severity: critical|high|medium|low
    type: code_injection|sqli|path_traversal|etc
    cwe: CWE-XX
    location:
      file: path/to/file.php
      line: 42-45
    description: |
      What is vulnerable and why
    evidence:
      code: |
        $dangerous = $userInput;
        dangerous_sink($dangerous);
      trace: |
        1. Input from $_GET['x']
        2. Passed to function()
        3. Reaches dangerous sink
    exploitability: |
      How to exploit this
    remediation: |
      How to fix it
    confidence: 0.0-1.0
```

### Checkpoint

After each chunk, evaluate:
- [ ] Findings include exact file:line references
- [ ] Each finding has source-to-sink trace
- [ ] Confidence is realistic (>0.7 for high severity)

**Aggregate findings across chunks before validation.**

---

## Phase 4: Validation

**Agent:** `code-analysis/validation`
**Turn Budget:** 5 turns max
**Purpose:** Confirm exploitability, reduce false positives

### Invoke

```
delegate_to_agent(
  agent="code-analysis/validation",
  query="Validate these findings. Check for missed sanitization, auth requirements, and exploitability."
)
```

Pass aggregated findings from Analysis phase.

### Expected Output

```yaml
validated_findings:
  - finding_id: VULN-001
    status: confirmed|false_positive|needs_more_info
    attack_path:
      - step: 1
        action: "POST to /admin with payload"
        location: admin.php:45
    authentication_required: none|user|admin
    proof_of_concept: |
      curl -X POST http://$TARGET/admin.php -d "param=payload"
    impact: |
      Remote Code Execution as web server user
    cvss_estimate: 8.8
    reason: |
      Why confirmed or rejected

false_positives:
  - finding_id: VULN-002
    reason: "Sanitization at line 23 prevents exploitation"
```

### Checkpoint

Final validation:
- [ ] Each confirmed finding has PoC command (use $TARGET, $LHOST, $LPORT)
- [ ] False positives explain WHY (sanitization, unreachable path, etc.)
- [ ] CVSS estimates provided for confirmed findings

---

## Final Output: Vulnerability Brief

After validation, compile results into this format:

```markdown
## Vulnerability Brief: {target} Source Analysis

### Executive Summary
[1-2 sentences: Most critical finding and recommended action]

### Confirmed Vulnerabilities

#### 1. {Vulnerability Type} - {CVSS Score}
- **Location:** `{file}:{line}`
- **Type:** {CWE-XX}
- **Auth Required:** {none|user|admin}
- **Exploit:**
  ```bash
  {proof_of_concept}
  ```
- **Impact:** {what attacker gains}

### Attack Order
1. [Highest confidence, lowest auth requirement first]
2. [Second priority]
3. [Fallback if above fail]

### Coverage Report
- Files analyzed: X/Y
- Chunks processed: X of Y priority items
- Turns used: X/25

### Caveats
- [Any limitations: skipped chunks, obfuscated code, etc.]
```

---

## Turn Budget Guidance

| Phase | Budget | When to Exceed | When to Reduce |
|-------|--------|----------------|----------------|
| Recon | 5 | Large codebase (>100 files) | Small app (<20 files) |
| Triage | 3 | Complex dependencies | Obvious sink patterns |
| Analysis | 12 | Multiple critical chunks | Single chunk covers all |
| Validation | 5 | Many findings to verify | Few findings |

### Adaptive Budget

**Small codebase (<20 files):**
- Reduce Recon to 2 turns
- Skip Triage, go direct to Analysis
- Increase Analysis to 15 turns

**Large codebase (>200 files):**
- Strict Triage (analyze only top 5 chunks)
- Focus on code_execution and SQL sinks only
- Accept partial coverage

---

## Variables

Use these placeholders in PoCs (Dame substitutes during execution):

| Variable | Meaning |
|----------|---------|
| `$TARGET` | Target IP/hostname |
| `$LHOST` | Attacker IP |
| `$LPORT` | Listener port |
| `$RPORT` | Service port |

---

## Error Recovery

### Recon Fails (No Files Found)
- Check path permissions
- Try broader glob patterns
- Verify code actually exists at path

### Triage Produces No Priorities
- Broaden sink patterns
- Check if code is obfuscated
- Report "no obvious attack surface"

### Analysis Timeout
- Reduce chunk count
- Increase chunk size (accept lower precision)
- Focus on highest priority only

### Validation Rejects All Findings
- Re-examine sanitization paths
- Consider auth-required exploits
- Report "potential vulnerabilities require privileged access"

---

## Integration Notes

This skill runs **inside Dame's exploitation context**. Output goes back to Dame for:
1. Updating attack strategy based on findings
2. Executing PoCs against confirmed vulnerabilities
3. Pivoting to related attack vectors

**Do NOT output to CAS or Faraday** - this is exploitation phase intelligence, not recon enrichment.
