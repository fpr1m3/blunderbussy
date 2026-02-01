# Backward Taint Analysis Utility

## Overview

The taint analysis utility (`taint.py`) provides backward data flow analysis from dangerous sinks to user input sources. This is used by the **Validation Agent (Phase 4)** to confirm exploitability and reduce false positives.

## Purpose

Static analysis often produces false positives when sanitization functions are present but not detected. This utility:

1. **Traces data flow backward** from sink to all possible sources
2. **Identifies sanitization** functions that prevent exploitation
3. **Handles multiple paths** (if ANY path is exploitable, vulnerability is real)
4. **Reduces manual validation** by automating false positive detection

## Core Components

### Data Structures

#### `TaintNode`

Represents a single node in the taint graph.

```python
@dataclass
class TaintNode:
    location: CodeLocation      # Where this variable appears
    variable: str               # Variable name (e.g., "$user_input")
    operation: str              # assignment, function_call, return, etc.
    transform: Optional[str]    # Sanitization function if any
    confidence: float           # 0.0-1.0 confidence score
```

**Example:**
```python
node = TaintNode(
    location=CodeLocation(file="admin.php", line=42),
    variable="$safe_id",
    operation="assignment",
    transform="intval",  # This is a sanitizer
    confidence=0.9
)
```

#### `TaintPath`

Represents a complete source→sink data flow path.

```python
@dataclass
class TaintPath:
    nodes: List[TaintNode]              # From sink (index 0) to source (last)
    confidence: float                   # Minimum of all node confidences
    is_exploitable: bool                # True if no blocking transforms
    blocking_transforms: List[str]      # Sanitizers that prevent exploitation
```

**Example:**
```python
path = TaintPath(nodes=[
    sink_node,      # mysql_query($id)
    middle_node,    # $id = intval($unsafe)
    source_node,    # $unsafe = $_GET['id']
])

# String representation: $_GET:5 → $unsafe:7 [intval] → $id:10
```

### Main Functions

#### `backward_taint(sink_location, files, max_depth=10) -> List[TaintPath]`

Performs backward taint analysis from a dangerous sink.

**Parameters:**
- `sink_location: CodeLocation` - Location of the dangerous sink
- `files: Dict[str, FileInfo]` - File information dict from recon
- `max_depth: int` - Maximum path length (prevents infinite loops)
- `max_paths: int` - Maximum paths to return (default: 20)

**Returns:**
- `List[TaintPath]` - All discovered source→sink paths

**Algorithm:**
1. Start at sink location with BFS queue
2. For each node, find assignments to that variable (backward)
3. Check if variable is user input (terminal condition)
4. Follow imports to trace cross-file data flows
5. Track sanitization functions encountered
6. Return all complete paths found

**Example:**
```python
from taint import backward_taint
from prioritize import CodeLocation

sink = CodeLocation(
    file="/var/www/admin.php",
    line=42,
    context='mysql_query("SELECT * WHERE id = $id");'
)

paths = backward_taint(sink, files)
print(f"Found {len(paths)} data flow paths")
```

#### `find_transforms(path: TaintPath) -> List[str]`

Extracts all transformation functions from a path.

**Returns:**
- `List[str]` - Names of all transform functions (e.g., `["intval", "trim"]`)

**Example:**
```python
transforms = find_transforms(path)
if "htmlspecialchars" in transforms:
    print("XSS prevented by HTML encoding")
```

#### `validate_path_exploitability(path, vuln_type, language) -> Tuple[bool, List[str]]`

Checks if a path is exploitable given its transformations.

**Parameters:**
- `path: TaintPath` - Path to validate
- `vuln_type: str` - Vulnerability type (`"sql"`, `"xss"`, `"code_execution"`, etc.)
- `language: str` - Programming language (`"php"`, `"python"`, `"javascript"`)

**Returns:**
- `(is_exploitable, blocking_sanitizers)` - Tuple of bool and list of blocking functions

**Example:**
```python
is_vuln, blockers = validate_path_exploitability(path, "sql", "php")

if not is_vuln:
    print(f"False positive: blocked by {blockers}")
```

#### `analyze_paths(paths, vuln_type, language) -> Dict`

Aggregates analysis of multiple paths.

**Returns:**
```python
{
    "total_paths": 3,
    "exploitable_count": 1,
    "blocked_count": 2,
    "exploitable_paths": [path1],
    "blocked_paths": [path2, path3],
    "verdict": "exploitable",  # or "false_positive"
    "confidence": 0.85
}
```

**Logic:**
- If ANY path is exploitable → `verdict: "exploitable"`
- If ALL paths blocked → `verdict: "false_positive"`

## Sanitization Database

The utility maintains a comprehensive database of sanitization functions by language and vulnerability type.

### PHP Sanitizers

| Vulnerability | Sanitizers |
|--------------|-----------|
| SQL Injection | `mysqli_real_escape_string`, `intval`, `floatval`, `PDO::quote`, `filter_var` |
| Code Execution | `escapeshellarg`, `escapeshellcmd`, `preg_quote` |
| XSS | `htmlspecialchars`, `htmlentities`, `strip_tags`, `esc_html` |
| Path Traversal | `basename`, `realpath`, `dirname` |

### Python Sanitizers

| Vulnerability | Sanitizers |
|--------------|-----------|
| SQL Injection | `execute` (with params), `quote`, `int()`, `float()` |
| Code Execution | `shlex.quote`, `pipes.quote`, `re.escape` |
| XSS | `html.escape`, `bleach.clean`, `markupsafe.escape` |
| Path Traversal | `os.path.basename`, `os.path.realpath`, `pathlib.Path.resolve` |

### JavaScript Sanitizers

| Vulnerability | Sanitizers |
|--------------|-----------|
| SQL Injection | `escape`, `escapeId`, `parseInt`, `parseFloat` |
| XSS | `encodeURI`, `encodeURIComponent`, `DOMPurify.sanitize`, `textContent` |
| Path Traversal | `path.basename`, `path.normalize` |

## Usage in Validation Phase

The Validation Agent uses this utility to verify findings from the Analysis phase:

```python
from taint import backward_taint, analyze_paths
from prioritize import CodeLocation

# Step 1: Get finding from Analysis phase
finding = analysis_results['findings'][0]
sink_location = finding['location']
vuln_type = finding['type']  # e.g., "sql"

# Step 2: Perform backward taint analysis
paths = backward_taint(sink_location, files)

# Step 3: Check exploitability
language = detect_language(sink_location.file)
analysis = analyze_paths(paths, vuln_type, language)

# Step 4: Make validation decision
if analysis['verdict'] == 'exploitable':
    print("✓ CONFIRMED: Real vulnerability")
    print(f"  Confidence: {analysis['confidence']:.0%}")
    print(f"  Exploitable paths: {analysis['exploitable_count']}")
else:
    print("✗ FALSE POSITIVE: Sanitization prevents exploit")
    blocked = analysis['blocked_paths'][0]
    print(f"  Blocked by: {blocked.blocking_transforms}")
```

## Validation Workflow

```
┌──────────────────────────────────────────────────────────┐
│  Analysis Phase Reports Finding                          │
│  "SQL injection at admin.php:42"                         │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│  Validation Agent: Run backward_taint()                  │
│  Trace from mysql_query() back to all input sources     │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│  Find 2 paths:                                           │
│  Path 1: $_GET['id'] → intval() → $safe_id → sink       │
│  Path 2: $_POST['id'] → $unsafe_id → sink               │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│  validate_path_exploitability() for each path            │
│  Path 1: BLOCKED (intval sanitizes SQL)                 │
│  Path 2: EXPLOITABLE (no sanitization)                  │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│  analyze_paths() aggregates results                      │
│  Verdict: EXPLOITABLE (at least one path is vulnerable) │
│  Confidence: 0.85                                        │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│  Report to Dame:                                         │
│  ✓ CONFIRMED SQL Injection via $_POST['id']             │
│  Note: $_GET['id'] path is properly sanitized           │
└──────────────────────────────────────────────────────────┘
```

## Limitations

1. **Static Analysis**: Cannot detect runtime-only sanitization
2. **Simple Pattern Matching**: May miss complex sanitization logic
3. **Cross-File Tracking**: Limited to import boundaries (no deep call graph)
4. **Context Sensitivity**: Doesn't fully track object state or conditions

## Future Enhancements

- [ ] Add support for more languages (Ruby, Java, Go)
- [ ] Implement call graph analysis for better cross-function tracking
- [ ] Add custom sanitizer definitions via config file
- [ ] Support conditional sanitization (if/else branches)
- [ ] Integrate with AST parsers for better accuracy

## Testing

Run tests with:
```bash
python3 scripts/test_taint.py
```

Run examples:
```bash
python3 scripts/example_taint_usage.py
```

## References

- **SKILL.md** - Overall pipeline architecture
- **prioritize.py** - Scoring and data structures
- **chunker.py** - File dependency graph utilities
- **Phase 4: Validation** (SKILL.md lines 238-283) - Usage context
