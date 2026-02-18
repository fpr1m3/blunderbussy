# Dame Evaluation Framework — Usage Guide

## Overview

The eval framework scores Dame's attack performance against known-vulnerable mock containers. It compares Dame's PTT (Pentest Task Tree) output against predefined ground truth objectives.

**Design doc:** `docs/plans/2026-02-17-dame-eval-framework-design.md`

## Quick Start

```bash
# List available eval targets
uv run scripts/eval_harness.py list

# Verify a target's setup is correct
uv run scripts/eval_harness.py verify --target apache-2.4.49-cve-2021-41773

# Score a PTT against ground truth
uv run scripts/eval_scorer.py score \
  --ground-truth tests/eval/targets/apache-2.4.49-cve-2021-41773/ground_truth.yaml \
  --ptt path/to/dame-output-ptt.yaml
```

## Components

| File | Purpose |
|------|---------|
| `scripts/eval_scorer.py` | Scoring engine — scores PTT against ground truth (3-pass algorithm) |
| `scripts/eval_harness.py` | CLI orchestrator — list, search, verify, run, results |
| `tests/eval/registry.yaml` | Index of active eval targets |
| `tests/eval/vulnhub_catalog.yaml` | Curated VulHub image catalog (8 entries) |
| `tests/eval/targets/` | Target packages (ground truth, compose, CAS/PTT, flags) |
| `tests/eval/results/` | Archived eval run results |

## Scorer CLI

### Score a PTT

```bash
# Human-readable output (colored)
uv run scripts/eval_scorer.py score \
  --ground-truth tests/eval/targets/apache-2.4.49-cve-2021-41773/ground_truth.yaml \
  --ptt ptt.yaml

# JSON output
uv run scripts/eval_scorer.py score \
  --ground-truth tests/eval/targets/apache-2.4.49-cve-2021-41773/ground_truth.yaml \
  --ptt ptt.yaml --json

# Save result to file
uv run scripts/eval_scorer.py score \
  --ground-truth tests/eval/targets/apache-2.4.49-cve-2021-41773/ground_truth.yaml \
  --ptt ptt.yaml --json --output result.yaml

# No color (for CI/piping)
uv run scripts/eval_scorer.py score \
  --ground-truth tests/eval/targets/apache-2.4.49-cve-2021-41773/ground_truth.yaml \
  --ptt ptt.yaml --no-color
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | PASS — min_access_level gate met |
| 1 | FAIL — gate not met |
| 2 | REGRESSION — previously-achieved objectives lost (with `--baseline`) |

### Regression Detection

Compare against a previous result to catch regressions:

```bash
# Score current run, save baseline
uv run scripts/eval_scorer.py score --ground-truth gt.yaml --ptt ptt-v1.yaml --json --output baseline.yaml

# Score new run against baseline
uv run scripts/eval_scorer.py score --ground-truth gt.yaml --ptt ptt-v2.yaml --baseline baseline.yaml
```

A regression is flagged when:
- Any previously-achieved objective is now missed, OR
- Score drops by more than 5 points

## Harness CLI

### Browse targets

```bash
# List all registered targets
uv run scripts/eval_harness.py list

# Filter by difficulty or tag
uv run scripts/eval_harness.py list --difficulty easy
uv run scripts/eval_harness.py list --tag rce

# Detailed view of a single target (objectives, points, penalties)
uv run scripts/eval_harness.py list --target apache-2.4.49-cve-2021-41773 --verbose
```

### Search VulHub catalog

```bash
# Keyword search
uv run scripts/eval_harness.py search apache

# Search by CVE
uv run scripts/eval_harness.py search --cve CVE-2017-7494

# Search by category
uv run scripts/eval_harness.py search --category database
```

Shows `[registered]` for targets already in the eval library, `[available]` for new candidates.

### Verify target setup

```bash
uv run scripts/eval_harness.py verify --target apache-2.4.49-cve-2021-41773
```

Checks: ground_truth.yaml exists and validates, compose.yaml parses, CAS/PTT exist, plant_flags.sh is executable.

### Run evaluation

```bash
# Single target
uv run scripts/eval_harness.py run --target apache-2.4.49-cve-2021-41773

# All targets
uv run scripts/eval_harness.py run --all

# Custom timeout and output directory
uv run scripts/eval_harness.py run --target apache-2.4.49-cve-2021-41773 --timeout 30m --output ./my-results/

# JSON output
uv run scripts/eval_harness.py run --target apache-2.4.49-cve-2021-41773 --json
```

**Note:** Dame invocation is not yet implemented. The `run` command sets up the workspace, starts the target container, but skips the actual Dame agent invocation. It scores whatever PTT is in the workspace (the pre-baked seed).

### View past results

```bash
# List recent runs
uv run scripts/eval_harness.py results

# Filter by timestamp
uv run scripts/eval_harness.py results --run 20260218

# Verbose: show per-objective status
uv run scripts/eval_harness.py results --verbose
```

## 3-Pass Scoring Algorithm

### Pass 1: Objective Matching

Walks the PTT tree (`engagement → hosts → services → vectors → techniques`) and matches objectives by category:

| Category | What's checked |
|----------|---------------|
| `vulnerability_discovery` | Service port + technique status + CVE match |
| `exploitation` | Host `access_level` >= required level |
| `flag_capture` | Loot type + name + flag value match |
| `credential_discovery` | Credentials list non-empty |
| `privilege_escalation` | Host `access_level` == root |

Dependencies are resolved via topological sort — an objective with `depends_on` is skipped if its dependency wasn't achieved.

### Pass 2: Penalty Detection

Scans PTT for bad behavior:
- `cve_not_in`: Technique references a CVE not in the target's allowed list (false positive)

### Pass 3: Efficiency Metrics

Diagnostic signals (not pass/fail):
- Techniques attempted / succeeded / failed
- Success rate
- Redundant attempts (same technique name on same service)

## Target Packages

Each target is a self-contained directory:

```
tests/eval/targets/<target-name>/
├── ground_truth.yaml      # Objectives, penalties, efficiency expectations
├── compose.yaml           # Standalone podman-compose for this target
├── cas/
│   ├── context.yaml       # Pre-baked CAS (enrichment output)
│   └── ptt.yaml           # Pre-baked PTT seed
├── setup/
│   └── plant_flags.sh     # Plants EVAL{...} flags in container
└── README.md              # CVE info, attack path, scoring
```

### Current targets

| Target | CVE | Difficulty | Points |
|--------|-----|-----------|--------|
| apache-2.4.49-cve-2021-41773 | CVE-2021-41773 | easy | 100 |
| tomcat-8.5.19-cve-2017-12615 | CVE-2017-12615 | easy | 100 |

## Running Tests

```bash
# All eval tests (39 tests)
uv run pytest tests/eval/ -v

# Just scorer tests
uv run pytest tests/eval/test_scorer.py -v

# Just harness tests
uv run pytest tests/eval/test_harness.py -v

# Only integration tests with real target files
uv run pytest tests/eval/test_scorer.py -v -m eval
```

## Smoke Testing

### 1. Score a perfect PTT

```bash
cat > /tmp/perfect-ptt.yaml << 'EOF'
engagement:
  status: completed
  hosts:
    - ip: "10.0.0.1"
      access_level: root
      services:
        - port: 80
          protocol: tcp
          name: http
          vectors:
            - name: "Path Traversal"
              techniques:
                - name: "CVE-2021-41773 Path Traversal"
                  status: success
                  cve: "CVE-2021-41773"
      findings:
        loot:
          - {type: flag, name: user_flag, value: "EVAL{apache-2449-user-flag}"}
          - {type: flag, name: root_flag, value: "EVAL{apache-2449-root-flag}"}
        credentials:
          - {username: daemon, secret: daemon}
EOF

uv run scripts/eval_scorer.py score \
  --ground-truth tests/eval/targets/apache-2.4.49-cve-2021-41773/ground_truth.yaml \
  --ptt /tmp/perfect-ptt.yaml
# Expected: 100/100 (100.0%) PASS
```

### 2. Score a partial PTT

```bash
cat > /tmp/partial-ptt.yaml << 'EOF'
engagement:
  status: in_progress
  hosts:
    - ip: "10.0.0.1"
      access_level: none
      services:
        - port: 80
          protocol: tcp
          name: http
          vectors:
            - name: "Path Traversal"
              techniques:
                - name: "CVE-2021-41773 Path Traversal"
                  status: success
                  cve: "CVE-2021-41773"
      findings:
        loot: []
        credentials: []
EOF

uv run scripts/eval_scorer.py score \
  --ground-truth tests/eval/targets/apache-2.4.49-cve-2021-41773/ground_truth.yaml \
  --ptt /tmp/partial-ptt.yaml
# Expected: 10/100 (10.0%) FAIL — only vuln discovery achieved
# Exit code: 1
```

### 3. Regression detection

```bash
# Save perfect as baseline
uv run scripts/eval_scorer.py score \
  --ground-truth tests/eval/targets/apache-2.4.49-cve-2021-41773/ground_truth.yaml \
  --ptt /tmp/perfect-ptt.yaml --json --output /tmp/perfect-result.yaml

# Score partial against perfect baseline — should detect regression
uv run scripts/eval_scorer.py score \
  --ground-truth tests/eval/targets/apache-2.4.49-cve-2021-41773/ground_truth.yaml \
  --ptt /tmp/partial-ptt.yaml --baseline /tmp/perfect-result.yaml
# Expected: "REGRESSION DETECTED" — exit code 2
```

### 4. Harness CLI walkthrough

```bash
uv run scripts/eval_harness.py list
uv run scripts/eval_harness.py list --target apache-2.4.49-cve-2021-41773 --verbose
uv run scripts/eval_harness.py search apache
uv run scripts/eval_harness.py verify --target apache-2.4.49-cve-2021-41773
```

### 5. Live container test (requires network)

```bash
# Start the target
podman-compose -f tests/eval/targets/apache-2.4.49-cve-2021-41773/compose.yaml up -d

# Verify it's vulnerable
curl -s 'http://localhost:8080/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'

# Cleanup
podman-compose -f tests/eval/targets/apache-2.4.49-cve-2021-41773/compose.yaml down
```
