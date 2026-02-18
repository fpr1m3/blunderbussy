# Testing TAT Improvement Design

**Date:** 2026-02-17
**Status:** Approved
**Goal:** Reduce testing turnaround time by decoupling validation from live HTB targets and VPN infrastructure.

## Problem

Testing Dame's behavior (skills, hooks, pipeline changes) currently requires:
- A live HTB target (Gavel, Expressway, etc.)
- VPN connected through gluetun
- Full stack running (Faraday, enrichment, HexStrike, Dame)
- A complete recon cycle before Dame can be tested

This makes the feedback loop for skill and hook changes unacceptably slow.

## Deliverables

### 1. Frozen CAS/PTT Fixture Library

Curated snapshots of real CAS/PTT/session data, versioned in git, used as canonical test inputs.

**Fixture set:**

| Name | Source | CAS Schema | Purpose |
|---|---|---|---|
| `gavel-full-session` | `artifacts/10.129.242.203/` | 1.2 | Full session state (attack_log, hypotheses, loop_state, credentials) |
| `expressway-completed` | `archive/.../10.129.1.128/` | 1.1 | Only completed engagement — creds, flags, loot |
| `conversor-rich` | `archive/.../10.129.4.182/` | 1.1 | 287-line CAS, richest attack surface detail |
| `high-surface` | `artifacts/10.129.7.111/` | 1.2 | 102 services, `attack_surface: high` — stress case |
| `empty-workspace` | `archive/.../10.129.3.123/` | 1.2 | 0 hosts/vulns — edge case |
| `stale-wrong-ip` | `artifacts/...stale-wrong-ip/` | 1.2 | Garbage input — error handling |

**Structure:**
```
tests/fixtures/sessions/
├── gavel-full-session/
│   ├── context.yaml
│   ├── ptt.yaml
│   └── session/
│       ├── state.yaml
│       ├── credentials.yaml
│       ├── hypotheses.yaml
│       ├── attack_log.jsonl
│       └── loop_state.json
├── expressway-completed/
│   ├── context.yaml
│   └── ptt.yaml
├── conversor-rich/
│   ├── context.yaml
│   └── ptt.yaml
├── high-surface/
│   ├── context.yaml
│   └── ptt.yaml
├── empty-workspace/
│   ├── context.yaml
│   └── ptt.yaml
└── stale-wrong-ip/
    ├── context.yaml
    └── ptt.yaml
```

**Sanitization:** Strip real HTB flag values from `expressway-completed/ptt.yaml` (replace with `REDACTED-FOR-FIXTURE`). IPs are ephemeral HTB allocations, safe to commit.

**Conftest helper:** A pytest fixture that copies a session fixture into `tmp_path` and sets `ARTIFACTS_PATH` + `TARGET` env vars, so hooks and pipeline code under test see a realistic artifact tree.

---

### 2. Hook Trace Replay

Record and replay tool call sequences through the hook pipeline without a live target.

**Components:**

#### 2a. Trace Extractor (`scripts/extract_hook_trace.py`)

Reads a gemini-cli session JSON and emits hook-pipe JSONL:

```jsonl
{"seq": 0, "tool_name": "run_shell_command", "tool_input": {"command": "nmap -sV ..."}, "tool_output": "Starting Nmap..."}
{"seq": 1, "tool_name": "read_file", "tool_input": {"path": "/artifacts/.../context.yaml"}, "tool_output": "cas_version: '1.2'..."}
```

**Source mapping:**
- `tool_name` <- `toolCall.name`
- `tool_input` <- `toolCall.args`
- `tool_output` <- `toolCall.result[0].functionResponse.response.output`

**Source data:** `analysis/dame-logs-20260130-191104/dame-session-main.json` — 165 tool calls from a real Dame session (143 shell, 9 delegate_to_agent, 7 write_file, 5 read_file, 1 activate_skill).

Run once, commit extracted trace as `tests/fixtures/traces/gavel-session-165.jsonl`.

#### 2b. Replay Harness (`tests/test_hook_replay.py`)

Iterates a trace JSONL and for each event:

1. Pipes `{tool_name, tool_input}` through `before_tool.py` -> asserts continue/block decision
2. Pipes `{tool_name, tool_input, tool_output}` through `after_tool.py` -> captures hook annotations
3. Feeds data through `loop_detector.py` -> verifies escalation levels

**Environment:** Each replay test gets `tmp_path` seeded from frozen fixtures (Deliverable 1). `ARTIFACTS_PATH` and `TARGET` env vars point there. Side effects (credential extraction, hypothesis updates, cache writes) land in temp dir and can be asserted on.

**Catches:** Hook regressions, loop detector threshold tuning, cache dedup correctness.

**Mocked:** Qdrant (session memory indexing) — existing mock pattern from `test_session_memory.py`.

---

### 3. Extension Linter (`tests/test_extension_lint.py`)

Static validation of the PrEP extension tree. No LLM calls, runs in existing pytest suite.

**Checks:**

#### 3a. Manifest integrity
- `gemini-extension.json` parses as valid JSON
- Every MCP server declared has a corresponding file in `servers/`
- Every tool referenced in hooks exists in the manifest's tool list

#### 3b. Skill structure
- Every directory in `skills/` contains a `SKILL.md`
- `SKILL.md` follows schema defined in `skills/SCHEMA.md` (required sections present)
- Sub-agent references resolve (e.g., `code-vuln-analysis` -> 4 agents in `agents/`)
- Script references resolve and scripts are executable

#### 3c. Agent references
- Every `.md` in `agents/` is non-empty with a title
- No orphaned agents (unreferenced by any skill or command)
- No dangling references (skills pointing to nonexistent agents)

#### 3d. Hook wiring
- Every hook script in `hooks/hooks.json` exists as `.py` in `hooks/`
- Every hook script is importable (catches broken imports like the `watcher` module issue)
- Hook event types match valid gemini-cli events (`BeforeTool`, `AfterTool`, `SessionStart`)

#### 3e. Command integrity
- Every `.toml` in `commands/` parses correctly
- Commands referencing tools or skills point to things that exist

#### Future Enhancement: Skill Description Evaluator

Use local embeddings (`sentence-transformers`, `all-MiniLM-L6-v2`) to validate skill descriptions are semantically retrievable for their intended scenarios:

```python
from sentence_transformers import SentenceTransformer, util

model = SentenceTransformer('all-MiniLM-L6-v2')  # local, free
# Embed each skill description + test queries
# Assert top-1 similarity matches expected skill
```

Zero API cost. Validates that skill descriptions will surface correctly when the model encounters a matching scenario. Based on the Embedding-Based Routing pattern documented at agentic-design.ai.

Supported by SkillsBench research (arxiv:2602.12670) showing focused skills outperform comprehensive reference documents, suggesting a complexity/size check could flag skills that have grown too large.

---

### 4. Local Mock Target

A compose profile with a deliberately vulnerable container for full pipeline end-to-end testing without VPN or HTB.

**Initial target: Apache 2.4.49 Path Traversal** (`vulhub/httpd:2.4.49`)

Rationale:
- Simplest exploit path (curl-based path traversal -> RCE)
- Exercises most pipeline stages: nmap finds HTTP -> enrichment flags CVE -> CAS populates `quick_wins` -> Dame exploits
- Existing CAS fixtures already have Apache targets for comparison

**Compose profile:**

```yaml
services:
  mock-target:
    image: docker.io/vulhub/httpd:2.4.49
    profiles: ["test"]
    container_name: mock-target
    networks:
      - test-net

  hexstrike-test:
    extends:
      service: hexstrike-recon
    profiles: ["test"]
    environment:
      - TARGET=mock-target
    networks:
      - test-net
    depends_on:
      - mock-target
```

**Usage:** `podman-compose --profile test up -d`

**Tests:** Full pipeline flow, enrichment CAS generation, Dame exploit execution, hook behavior on real tool calls, PTT reaching `completed` status.

**Does not test:** Complex multi-step exploitation, VPN/split-tunnel networking, skills needing rich attack surfaces.

**Future expansion:**
- Add Tomcat default creds target for credential extraction + pwncat shell handling
- CI integration: GitHub Actions workflow — stand up test profile, run pipeline, assert PTT `completed`, tear down. No secrets, no VPN, self-contained.

---

## Summary

| # | Deliverable | LLM Cost | Infra Needed | Catches |
|---|---|---|---|---|
| 1 | Frozen CAS/PTT Fixtures | None | None | Skill testing inputs, schema regression |
| 2 | Hook Trace Replay | None | None | Hook regressions, loop detector tuning |
| 3 | Extension Linter | None | None | Broken references, missing files, structural drift |
| 4 | Local Mock Target | Gemini API (Dame) | One vulhub container | Full pipeline end-to-end |
| Future | Skill Description Evaluator | None (local embeddings) | `sentence-transformers` | Skill retrievability, description quality |

## Research References

- SkillsBench (arxiv:2602.12670) — first systematic benchmark for agent skills
- DeepEval `ToolCorrectnessMetric` — deterministic tool selection scoring
- Ragas `ToolCallF1` — order-independent tool call evaluation
- PydanticAI `TestModel` — zero-cost deterministic tool exercising
- Google ADK evaluation — trajectory matching (EXACT/IN_ORDER/ANY_ORDER)
- Embedding-Based Routing pattern — local similarity testing for skill descriptions
- pytest-recording / vcrpy — record/replay for LLM API calls
