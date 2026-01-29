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

## Artifact Persistence

### Why Artifacts?

Sub-agent YAML output flows through your context window, which is lossy. By writing each stage's output to disk, you get:
- **Persistent artifacts** for debugging and reproducibility
- **No context loss** between stages (next agent reads from disk)
- **Observable stage boundaries** (human or tooling can inspect intermediate outputs)

### Artifact Directory Structure

At pipeline start, create the artifact directory. The target name is available in your context.

```
./artifacts/{target}/code-analysis/
├── 01-recon-manifest.yaml         # Recon agent output
├── 02-triage-chunks.yaml          # Triage agent output
├── 03-analysis-findings.yaml      # Aggregated analysis findings (all chunks)
├── 03-analysis-chunk-{id}.yaml    # Per-chunk analysis findings
├── 04-validation-findings.yaml    # Validated findings
├── 04-validation-brief.md         # Final Vulnerability Brief
└── state.yaml                     # Pipeline state tracking
```

### Setup (FIRST ACTION when skill activates)

Before invoking any agent, create the artifact directory:

```bash
mkdir -p ./artifacts/{target}/code-analysis
```

Set a variable for the path and use it throughout the pipeline:

```
ARTIFACT_DIR=./artifacts/{target}/code-analysis
```

### Write Protocol (Dame's responsibility)

Sub-agents are READ-ONLY -- they cannot write files. After each `delegate_to_agent()` returns, YOU (Dame) must write the output to disk. The sequence for every phase is:

1. Invoke `delegate_to_agent()` with the artifact directory path in the query
2. Receive structured YAML output from the agent
3. **Write the output** to the corresponding artifact file using the `write_file` tool
4. Update `state.yaml` with phase completion
5. Proceed to the next phase (the next agent reads the previous artifact from disk)

### Read Protocol (Sub-agent responsibility)

Each sub-agent (except Recon, which is first) should read the previous stage's artifact from disk at the start of its work. This provides grounding independent of what Dame passes in the query string, preventing context loss.

---

## CRITICAL: Orchestration Discipline

### State Persistence Protocol

After EACH phase completes, you MUST persist state before proceeding:

```yaml
# Write to ./artifacts/{target}/code-analysis/state.yaml
current_phase: recon|triage|analysis|validation|complete
phases_completed:
  - phase: recon
    turn: 3
    output_summary: "12 files, 3 dangerous sinks identified"
  - phase: triage
    turn: 5
    output_summary: "2 critical chunks created"

artifact_dir: ./artifacts/{target}/code-analysis
artifacts_written:
  - 01-recon-manifest.yaml
  - 02-triage-chunks.yaml

findings_aggregated:
  - id: VULN-001
    phase_discovered: analysis
    status: pending_validation

files_analyzed: [list of files subagents have examined]
```

**Why:** Without state persistence, you will lose context and repeat work. The state file is your memory between phases. The artifact directory provides durable storage that survives context window limits.

### Cognitive Drift Prevention (MANDATORY)

Once a subagent returns structured YAML output, the following behaviors are **PROHIBITED**:

| ❌ PROHIBITED | Why |
|---------------|-----|
| Manually reading files the subagent analyzed | Wastes turns, subagent already extracted relevant code |
| Running grep/cat on paths in subagent output | Duplicates completed work |
| "Verifying" subagent findings by re-reading | Trust the pipeline; validation agent handles verification |
| Starting manual exploration (git log, find, ls) | This is drift - you're avoiding the next phase |
| Reading files "for context" after analysis phase | Context was already provided to subagent |

| ✅ REQUIRED | Why |
|-------------|-----|
| Proceed directly to next phase | Maintain pipeline momentum |
| Use subagent YAML output as-is for next phase input | Structured handoff preserves fidelity |
| Trust file:line references from subagent | Subagent read the actual code |
| Update state file before invoking next agent | Ensures no lost work |

**Self-Check:** If you find yourself about to run `cat`, `grep`, or read a file that appears in the previous phase's output, STOP. You are drifting. Proceed to the next phase instead.

### Exit Requirements (MANDATORY)

Code analysis is **INCOMPLETE** until ALL of these are true:

```
[ ] 1. All four phases attempted (or documented skip reason)
[ ] 2. Validation agent was invoked with aggregated findings
[ ] 3. Vulnerability Brief was generated (even if "no vulnerabilities found")
[ ] 4. State file updated to current_phase: complete
[ ] 5. Brief returned to calling context (Dame's exploitation workflow)
[ ] 6. All artifact files written to {ARTIFACT_DIR}:
       - 01-recon-manifest.yaml
       - 02-triage-chunks.yaml
       - 03-analysis-findings.yaml (+ per-chunk files)
       - 04-validation-findings.yaml
       - 04-validation-brief.md
       - state.yaml
```

**If you are about to say "analysis complete" without a Vulnerability Brief, you have failed the task.** Go back and complete the pipeline.

---

## Phase Transition Protocol

When a subagent completes, execute this sequence EXACTLY:

```
1. RECEIVE subagent YAML output
2. VALIDATE output has expected structure (manifest/priority_queue/findings)
3. WRITE output to artifact file (e.g., 01-recon-manifest.yaml)
4. UPDATE state.yaml with phase completion and artifact path
5. EXTRACT data needed for next phase
6. INVOKE next phase agent immediately (include artifact dir path in query)
7. DO NOT read files, run commands, or "explore" between steps 1-6
```

**Between-Phase Actions Whitelist:**
- Writing agent output to artifact file (e.g., `01-recon-manifest.yaml`) ✓
- Writing to `state.yaml` ✓
- Parsing YAML output ✓
- Formatting input for next agent ✓

**Between-Phase Actions Blacklist:**
- File reads (cat, Read tool) ✗
- Code searches (grep, Grep tool) ✗
- Directory listing (ls, find) ✗
- Version control (git log, git diff) ✗
- Any "let me check..." reasoning ✗

---

## Phase 1: Reconnaissance

**Agent:** `code-analysis-recon`
**Turn Budget:** 5 turns max
**Purpose:** Map codebase structure WITHOUT reading file contents deeply

### Invoke

```
delegate_to_agent(
  agent="code-analysis-recon",
  query="Map source code structure at {repo_path}. Languages detected: {languages}. Find dangerous sinks, entry points, and dependency graph. Artifact directory: {ARTIFACT_DIR}"
)
```

### After Recon Returns (Dame writes artifact)

When the recon agent returns its YAML manifest, immediately write it to disk:

```
write_file("{ARTIFACT_DIR}/01-recon-manifest.yaml", <recon agent YAML output>)
```

Then update `{ARTIFACT_DIR}/state.yaml` with phase completion before proceeding to Triage.

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

**Agent:** `code-analysis-triage`
**Turn Budget:** 3 turns max
**Purpose:** Prioritize files by attack surface potential

### Invoke

```
delegate_to_agent(
  agent="code-analysis-triage",
  query="Prioritize analysis targets from recon output. Create chunks of 5-12k tokens grouped by data flow. Artifact directory: {ARTIFACT_DIR} — read recon manifest from {ARTIFACT_DIR}/01-recon-manifest.yaml"
)
```

Pass the recon output as context in the query AND tell the agent to read from disk. The disk copy is the authoritative source if context is truncated.

### After Triage Returns (Dame writes artifact)

When the triage agent returns its YAML output, immediately write it to disk:

```
write_file("{ARTIFACT_DIR}/02-triage-chunks.yaml", <triage agent YAML output>)
```

Then update `{ARTIFACT_DIR}/state.yaml` with phase completion before proceeding to Analysis.

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

**Agent:** `code-analysis-analysis`
**Turn Budget:** 12 turns total (process chunks until budget exhausted)
**Purpose:** Deep vulnerability analysis on prioritized chunks

### Invoke (per chunk)

```
delegate_to_agent(
  agent="code-analysis-analysis",
  query="Analyze chunk {chunk_id}: {focus}. Files: {files}. Look for: {attack_surface}. Artifact directory: {ARTIFACT_DIR} — read triage chunks from {ARTIFACT_DIR}/02-triage-chunks.yaml"
)
```

Include security anti-patterns from `resources/sec-context/anti-patterns.md` in context.

### After Each Chunk Returns (Dame writes artifacts)

After the analysis agent returns findings for a chunk, write them to disk immediately:

```
write_file("{ARTIFACT_DIR}/03-analysis-chunk-{chunk_id}.yaml", <analysis agent YAML output for this chunk>)
```

After ALL chunks are processed, aggregate findings across all chunks into a single file:

```
write_file("{ARTIFACT_DIR}/03-analysis-findings.yaml", <aggregated findings from all chunks>)
```

The aggregated file should contain all `findings` entries from every chunk, combined into one YAML document. Update `{ARTIFACT_DIR}/state.yaml` after aggregation.

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

**Agent:** `code-analysis-validation`
**Turn Budget:** 5 turns max
**Purpose:** Confirm exploitability, reduce false positives

### Invoke

```
delegate_to_agent(
  agent="code-analysis-validation",
  query="Validate these findings. Check for missed sanitization, auth requirements, and exploitability. Artifact directory: {ARTIFACT_DIR} — read aggregated findings from {ARTIFACT_DIR}/03-analysis-findings.yaml"
)
```

Pass aggregated findings from Analysis phase in the query AND tell the agent to read from disk. The disk copy is the authoritative source if context is truncated.

### After Validation Returns (Dame writes artifacts)

When the validation agent returns, write TWO artifacts:

1. The validated findings YAML:
```
write_file("{ARTIFACT_DIR}/04-validation-findings.yaml", <validation agent YAML output>)
```

2. The Vulnerability Brief (markdown):
```
write_file("{ARTIFACT_DIR}/04-validation-brief.md", <Vulnerability Brief from validation output>)
```

If the validation agent includes both validated_findings YAML and a Vulnerability Brief in its response, split them into the two separate files. Then update `{ARTIFACT_DIR}/state.yaml` with `current_phase: complete`.

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

## Common Failure Modes (AVOID THESE)

### Failure Mode 1: Post-Subagent Drift

**Symptom:** After Analysis agent returns findings with exploit payloads, you run `git log`, `cat admin.php`, or start "exploring" the codebase manually.

**Why it happens:** Manual exploration feels productive but avoids the harder task of proceeding to Validation.

**Fix:** When you receive subagent output, your ONLY next action is invoking the next phase's agent. No manual file reads.

### Failure Mode 2: Missing Vulnerability Brief

**Symptom:** You report findings informally ("I found an RCE in admin.php") but never generate the structured Vulnerability Brief.

**Why it happens:** The brief feels redundant after detailed analysis, but it's the required deliverable.

**Fix:** The Vulnerability Brief is not optional. Generate it even for "no vulnerabilities found" results.

### Failure Mode 3: Re-Analyzing Analyzed Code

**Symptom:** Subagent analyzed `includes/bid_validator.php`, then you read the same file "to understand it better."

**Why it happens:** Distrust of subagent output, or habit of manual verification.

**Fix:** The subagent's code snippets and line references ARE the understanding. Use them directly.

### Failure Mode 4: Skipping Validation

**Symptom:** Analysis agent produces findings, you report them without invoking Validation agent.

**Why it happens:** Findings look complete, validation seems redundant.

**Fix:** Validation catches false positives and generates PoCs. ALWAYS invoke it.

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

## Security Mitigations (MAESTRO Framework)

This multi-agent system implements mitigations for agentic AI risks identified by the MAESTRO framework.

### Agent Constraints

Each agent operates under strict capability limits:

| Agent | Read | Write | Execute | Network |
|-------|------|-------|---------|---------|
| Recon | ✓ | ✗ | grep/rg only | ✗ |
| Triage | ✓ | ✗ | ✗ | ✗ |
| Analysis | ✓ | ✗ | ✗ | ✗ |
| Validation | ✓ | ✗ | ✗ | ✗ |

**Enforcement:**
- Recon agent: Can only use `Glob`, `Grep`, `Read` tools. No `Write`, `Edit`, or `Bash` (except search commands).
- Triage/Analysis/Validation: Read-only access. No tool execution beyond file reads.
- PoC commands are documented, never executed by these agents.

### Determinism

All agents MUST operate with deterministic settings:

```yaml
agent_config:
  temperature: 0
  top_p: 1
  seed: 42  # When available
```

**Why:** Non-deterministic outputs make vulnerability findings unreproducible. Same codebase should produce same findings across runs.

### Structured Output Format

All inter-agent communication uses YAML with strict schemas:

```yaml
# Every agent output MUST include:
_metadata:
  agent: recon|triage|analysis|validation
  timestamp: 2026-01-26T12:00:00Z
  turn: 3
  checksum: sha256:<hash_of_payload>

# Payload follows schema defined in each phase section
```

**Why:** Structured data prevents prompt injection between agents. Free-text outputs could contain adversarial content.

### Output Verification

Before passing agent output to next phase:

1. **Schema validation:** Output matches expected YAML structure
2. **Checksum verification:** `_metadata.checksum` matches sha256 of payload
3. **Bounds checking:** Token counts, file counts within expected ranges

```python
def verify_agent_output(output: dict, expected_schema: str) -> bool:
    # 1. Validate YAML structure
    if not validate_schema(output, expected_schema):
        return False

    # 2. Verify checksum (payload = output without _metadata)
    payload = {k: v for k, v in output.items() if k != '_metadata'}
    expected_hash = hashlib.sha256(yaml.dump(payload).encode()).hexdigest()
    if output['_metadata']['checksum'] != f"sha256:{expected_hash}":
        return False

    return True
```

### Sanitization Between Phases

When passing findings between agents:

1. **Strip code blocks:** Re-read original files rather than trusting quoted code
2. **Validate file references:** Confirm referenced files exist at claimed paths
3. **Bound numeric values:** CVSS, confidence scores must be in valid ranges

**Anti-Pattern:** Never pass `evidence.code` directly - always re-read from source.

### Chain of Custody

Each finding tracks its journey through the pipeline:

```yaml
finding:
  id: VULN-001
  provenance:
    - agent: recon
      turn: 2
      action: "identified dangerous sink"
    - agent: triage
      turn: 1
      action: "prioritized as critical"
    - agent: analysis
      turn: 4
      action: "confirmed taint path"
    - agent: validation
      turn: 2
      action: "verified exploitability"
```

**Why:** Audit trail for each finding enables debugging false positives and understanding agent reasoning.

---

## Integration Notes

This skill runs **inside Dame's exploitation context**. Output goes back to Dame for:
1. Updating attack strategy based on findings
2. Executing PoCs against confirmed vulnerabilities
3. Pivoting to related attack vectors

**Do NOT output to CAS or Faraday** - this is exploitation phase intelligence, not recon enrichment.
