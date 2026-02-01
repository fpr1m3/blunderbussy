# Code Vulnerability Analysis - Utility Scripts

This directory contains utility scripts used by the code-vuln-analysis skill for static source code analysis.

## Scripts Overview

### `entrypoints.py`

**Purpose:** Detect application entry points (web routes, CLI scripts, cron jobs) to map attack surface during reconnaissance.

**Supported Patterns:**

- **Python/Flask:** `@app.route()`, `@bp.route()` decorators
- **Python/Django:** `urlpatterns`, `path()`, `re_path()`
- **Python/FastAPI:** `@app.get()`, `@app.post()`, etc.
- **Node.js/Express:** `app.get()`, `app.post()`, `router.use()`
- **PHP:** Direct file access, `$_SERVER['REQUEST_URI']` routing, Laravel routes
- **CLI Scripts:** `#!/usr/bin/env` shebangs, `if __name__ == "__main__"`
- **Cron Jobs:** `# cron:` comment annotations

**Usage:**

```python
from entrypoints import detect_entrypoints, format_output

files = glob.glob("**/*.py", recursive=True)
entry_points = detect_entrypoints(files)

# Get structured output matching SKILL.md format
output = format_output(entry_points)
# Returns:
# {
#   'web_routes': [{file, route, methods, auth_required, line, framework}],
#   'api_endpoints': [{file, route, methods, auth_required, line, framework}],
#   'cli_scripts': [{file, command, metadata}],
#   'cron_jobs': [{file, schedule, line}]
# }
```

**Features:**

- Authentication decorator detection (e.g., `@login_required`, `@jwt_required`)
- HTTP method extraction
- Line number tracking for precise references
- Framework identification
- Handles multiple quote styles and formatting variations

**Tests:** `test_entrypoints.py`

---

### `dependencies.py`

**Purpose:** Parse source files to extract import/include statements and build dependency graphs showing file relationships.

**Supported Languages:**

- **PHP:** `include`, `include_once`, `require`, `require_once`
- **Python:** `import`, `from ... import` (including relative imports)
- **JavaScript/TypeScript:** `import`, `require()`

**Usage:**

```bash
# Generate YAML dependency graph
./dependencies.py /var/www/html/*.php --root /var/www/html

# Show reverse dependencies (what imports what)
./dependencies.py *.php --root . --reverse

# Detect circular dependencies
./dependencies.py *.php --root . --cycles
```

**Programmatic Usage:**

```python
from dependencies import build_dependency_graph, to_yaml, get_reverse_dependencies

# Build graph
files = ["index.php", "admin.php", "config.php"]
graph = build_dependency_graph(files, project_root="/var/www")

# Export to YAML (matches SKILL.md lines 70-76)
yaml_output = to_yaml(graph)

# Analyze reverse dependencies
reverse = get_reverse_dependencies(graph)
```

**Tests:** `test_dependencies.py`, `test_manual.py`, `test_integration.py`

---

### `exclusions.py`

**Purpose:** Filter out files that aren't worth analyzing during the recon phase, reducing token usage by 60-90%.

**Categories Excluded:**

- **Static assets:** CSS, images, fonts, media files
- **Vendor directories:** `vendor/`, `node_modules/`, `bower_components/`
- **Build artifacts:** `dist/`, `*.min.js`, `*.bundle.js`, source maps
- **Test files:** `*_test.py`, `*.spec.js`, `tests/` directories
- **Config/metadata:** `package.json`, `.gitignore`, `README.md`

**Usage:**

```python
from exclusions import should_exclude, filter_files, get_exclusion_summary

# Check single file
result = should_exclude("vendor/symfony/http-kernel/HttpKernel.php")
print(result.excluded)       # False (included for analysis)
print(result.recommendation) # "SCA: Check CVE databases for symfony/http-kernel"

# Batch filter
files = ["app.php", "test.css", "vendor/lib.php"]
included, exclusions = filter_files(files)

# Get statistics
summary = get_exclusion_summary(all_files)
print(f"Reduction: {summary['efficiency_gain']}")
```

**SCA Flagging:** Vendor files are included but flagged for Software Composition Analysis (CVE database lookup) rather than manual static analysis.

**Tests:** `test_exclusions.py`

---

### `prioritize.py`

**Purpose:** Implements the triage scoring formula from SKILL.md to prioritize files for deep analysis.

**Scoring Formula:**

```
Score = (Sink_Severity x 3) + (Input_Proximity x 2) + (Auth_Bypass_Potential x 2)

Maximum Score: 70
```

**Usage:**

```python
from prioritize import score_finding, rank_findings, SinkType, InputProximity, AuthLevel

# Score a single finding
score = score_finding(
    sink=SinkType.CODE_EXECUTION,
    proximity=InputProximity.DIRECT,
    auth=AuthLevel.NONE
)

# Rank multiple findings
ranked = rank_findings(findings)
```

**Severity Scores:**

| Sink Type | Score |
|-----------|-------|
| Code Execution | 10 |
| SQL | 8 |
| File Operations | 7 |
| Deserialization | 7 |
| SSRF | 6 |
| XSS | 5 |
| Other | 2-3 |

**Priority Buckets:**

- **Critical:** Score >= 50 (71% of max)
- **High:** Score >= 35 (50% of max)
- **Medium:** Score >= 20 (29% of max)
- **Low:** Score < 20

---

### `tokens.py`

**Purpose:** Accurate token counting using tiktoken with fallback to character-based estimation for chunk size budgeting.

**Usage:**

```python
from tokens import count_tokens, estimate_file_tokens, TokenBudget

# Count tokens in text
tokens = count_tokens(source_code)

# Estimate tokens for a file
file_tokens = estimate_file_tokens("path/to/file.py")

# Track budget across turns/phases
budget = TokenBudget(turn_limit=12000, phase_limit=50000)
if budget.can_fit(chunk_tokens):
    budget.consume(chunk_tokens)
print(budget.summary())
```

**Budget Constraints (from SKILL.md):**

| Phase | Turn Budget | Phase Budget |
|-------|-------------|--------------|
| Recon | 5-12k/turn | ~25k total |
| Triage | 5-12k/turn | ~15k total |
| Analysis | 5-12k/turn | ~60k total |
| Validation | 5-12k/turn | ~25k total |

**Tests:** `test_tokens.py`, `test_tokens_simple.py`

---

### `chunker.py`

**Purpose:** Split analysis targets into token-bounded chunks (5-12k tokens) for efficient LLM processing.

**Usage:**

```python
from chunker import create_chunks, chunks_to_yaml

# Create analysis chunks
chunks = create_chunks(file_infos, recon_data, token_limit=10000)

# Export to YAML
yaml_output = chunks_to_yaml(chunks)
```

**Features:**

- Token estimation via tiktoken (cl100k_base encoding)
- Dependency-aware grouping (keeps related files together)
- Topological sorting for dependency ordering
- Taint-path grouping: sink file + all files in potential data flow

**Tests:** `test_chunker.py`

---

### `taint.py`

**Purpose:** Backward taint analysis from dangerous sinks to user input sources. Used by the Validation Agent (Phase 4) to confirm exploitability.

**Usage:**

```python
from taint import backward_taint, find_transforms, validate_path_exploitability
from prioritize import CodeLocation

# Define sink location
sink = CodeLocation(
    file="/var/www/admin.php",
    line=42,
    context='mysql_query("SELECT * WHERE id = $id");'
)

# Trace backward to sources
paths = backward_taint(sink, files)

# Check for sanitization
for path in paths:
    is_exploitable, blockers = validate_path_exploitability(path, "sql", "php")
    if not is_exploitable:
        print(f"False positive: blocked by {blockers}")
```

**Sanitization Database:** Maintains comprehensive database of sanitization functions by language:

- **PHP:** `mysqli_real_escape_string`, `intval`, `htmlspecialchars`, `escapeshellarg`
- **Python:** `shlex.quote`, `html.escape`, parameterized queries
- **JavaScript:** `encodeURIComponent`, `DOMPurify.sanitize`

**Tests:** `test_taint.py`, `example_taint_usage.py`

---

### `attack_path.py`

**Purpose:** Generate executable attack paths and PoC code from validated findings.

**Usage:**

```python
from attack_path import generate_attack_path, generate_poc

# Generate attack path from validated finding
path = generate_attack_path(finding, taint_path)

# Generate proof of concept
poc = generate_poc(path, finding.sink_type)
```

**Features:**

- Step-by-step attack sequences
- Authentication requirement calculation
- Executable PoC commands with placeholders

**Tests:** `test_attack_path.py`

---

### `verification.py`

**Purpose:** Security layer for agent outputs - checksum verification and phase sanitization to prevent prompt injection.

**Usage:**

```python
from verification import verify_agent_output, sanitize_findings, VerificationConfig

# Configure verification (checksums optional)
config = VerificationConfig(verify_checksums=True)

# Verify agent output
if verify_agent_output(output, config):
    # Sanitize before passing to next phase
    clean_findings = sanitize_findings(output['findings'], source_files)
```

**Tests:** `test_verification.py`

---

## Integration with SKILL.md

These utilities support the 4-phase analysis pipeline:

### Phase 1: Reconnaissance (Recon Agent)

```python
from exclusions import filter_files
from dependencies import build_dependency_graph, to_yaml
from entrypoints import detect_entrypoints, format_output

# Filter files first
included, exclusions = filter_files(all_source_files)

# Build dependency graph
graph = build_dependency_graph(included, project_root)
dep_yaml = to_yaml(graph)

# Map entry points
entry_points = detect_entrypoints(included)
output = format_output(entry_points)
```

### Phase 2: Triage (Triage Agent)

```python
from prioritize import rank_findings, categorize_priority
from chunker import create_chunks

# Score and prioritize findings
ranked = rank_findings(findings)
priority_queue = {
    'critical': [f for f in ranked if categorize_priority(f.score) == 'critical'],
    'high': [f for f in ranked if categorize_priority(f.score) == 'high'],
}

# Create analysis chunks
chunks = create_chunks(priority_queue['critical'], max_tokens=10000)
```

### Phase 3: Analysis (Analysis Agent)

Receives prioritized chunks for deep vulnerability analysis.

### Phase 4: Validation (Validation Agent)

```python
from taint import backward_taint, analyze_paths
from attack_path import generate_attack_path, generate_poc

# Verify finding with taint analysis
paths = backward_taint(sink_location, files)
analysis = analyze_paths(paths, vuln_type, language)

if analysis['verdict'] == 'exploitable':
    # Generate attack path and PoC
    attack = generate_attack_path(finding, paths[0])
    poc = generate_poc(attack, finding.sink_type)
```

---

## Design Principles

1. **Zero LLM Invocations:** All utilities are deterministic pattern matching - no AI calls required
2. **Precision Over Recall:** Better to miss edge cases than produce false positives
3. **Fast Fail:** Skip unparseable files rather than crash
4. **Framework Agnostic:** Support multiple languages/frameworks
5. **Token Efficiency:** Reduce analysis context to fit within LLM windows

---

## Testing

Run all tests:

```bash
cd scripts/

# Run all tests (no pytest needed)
python3 test_manual.py
python3 test_integration.py
python3 test_entrypoints.py
python3 test_chunker.py
python3 test_exclusions.py
python3 test_tokens_simple.py
python3 test_taint.py
python3 test_attack_path.py
python3 test_verification.py

# Demo scripts
python3 demo_entrypoints.py
python3 demo_pipeline.py
python3 example_taint_usage.py

# Module demo modes
python -m prioritize
```

---

## Performance Characteristics

- **File Exclusion:** < 0.1ms per file (no I/O)
- **Entry Point Detection:** O(n x m) where n=files, m=avg_lines_per_file
- **Dependency Graph:** ~50 files/second
- **Prioritization:** O(n log n) for sorting findings
- **Chunking:** O(n) for file iteration
- **Token Counting:** ~50K tokens/sec with tiktoken

**Typical Performance:**

- 100 files @ 500 lines each: ~2-3 seconds
- 1000 files: ~30-40 seconds
- Scales linearly with codebase size

---

## Limitations

1. **No Semantic Analysis:** Pattern matching only, no AST parsing
2. **Framework-Specific:** New frameworks require explicit support
3. **No Dynamic Routing:** Cannot detect runtime-generated routes
4. **Language Support:** Currently Python, PHP, JavaScript, TypeScript
5. **Auth Detection Heuristic:** May miss non-standard auth decorators
6. **Static Analysis Only:** Cannot detect runtime-only sanitization

---

## Adding New Frameworks

To add support for a new web framework:

1. Add pattern to `FRAMEWORK_PATTERNS` in `entrypoints.py`
2. Implement `detect_<framework>_routes()` function
3. Add test case to `test_entrypoints.py`
4. Update this README

Example:

```python
def detect_rails_routes(file_path: str, content: str) -> List[EntryPoint]:
    """Detect Ruby on Rails routes."""
    route_pattern = re.compile(
        r"(get|post|put|delete)\s+['\"]([^'\"]+)['\"]",
        re.MULTILINE
    )
    # ... implementation
```

---

## Future Enhancements

- [ ] AST-based parsing for better precision (tree-sitter)
- [ ] Support for Rust (Axum, Actix)
- [ ] Support for Go (Gin, Echo, Chi)
- [ ] Support for Java (Spring Boot)
- [ ] GraphQL schema parsing
- [ ] OpenAPI/Swagger endpoint extraction
- [ ] Middleware/auth chain analysis
- [ ] Custom sanitizer definitions via config file
