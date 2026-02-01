#!/usr/bin/env python3
"""
Backward Taint Analysis Utility for Vulnerability Validation
=============================================================

Performs backward taint analysis from sink to sources, tracking data
transformations and sanitization functions along the way.

This is used by the Validation Agent (Phase 4) to:
1. Trace from sink location back to all possible user input sources
2. Identify sanitization/encoding functions that might prevent exploitation
3. Determine if a reported vulnerability is a false positive

Key features:
- Language-aware pattern matching (PHP, Python, JavaScript)
- Tracks variable renames and assignments
- Identifies sanitization/encoding functions
- Returns multiple paths if data can reach sink via different routes

Usage:
    from taint import backward_taint, find_transforms

    paths = backward_taint(sink_location, files)
    for path in paths:
        sanitizers = find_transforms(path)
        if sanitizers:
            print(f"False positive: sanitized by {sanitizers}")
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import deque
from pathlib import Path
import re

try:
    from .prioritize import CodeLocation
    from .chunker import FileInfo
except ImportError:
    from prioritize import CodeLocation
    from chunker import FileInfo


@dataclass
class TaintNode:
    """
    A node in the taint graph representing a variable at a specific location.

    Attributes:
        location: Where this variable appears in code
        variable: Variable name (e.g., "$user_input", "params['id']")
        operation: What happens at this node (assignment, function_call, return, etc.)
        transform: Function/operation applied (e.g., "htmlspecialchars", "int()")
        confidence: Confidence that taint flows through this node (0.0-1.0)
    """
    location: CodeLocation
    variable: str
    operation: str = "assignment"  # assignment, function_call, return, param
    transform: Optional[str] = None  # Transformation function if any
    confidence: float = 1.0

    def __hash__(self):
        return hash((self.location.file, self.location.line, self.variable))

    def __eq__(self, other):
        if not isinstance(other, TaintNode):
            return False
        return (self.location.file == other.location.file and
                self.location.line == other.location.line and
                self.variable == other.variable)


@dataclass
class TaintPath:
    """
    A complete path from source to sink in the taint graph.

    Attributes:
        nodes: List of TaintNodes from sink (index 0) to source (last index)
        confidence: Overall path confidence (minimum of all node confidences)
        is_exploitable: Whether this path represents a real vulnerability
        blocking_transforms: Sanitization functions that prevent exploitation
    """
    nodes: List[TaintNode] = field(default_factory=list)
    confidence: float = 1.0
    is_exploitable: bool = True
    blocking_transforms: List[str] = field(default_factory=list)

    @property
    def source(self) -> Optional[TaintNode]:
        """The ultimate source (user input) node."""
        return self.nodes[-1] if self.nodes else None

    @property
    def sink(self) -> Optional[TaintNode]:
        """The dangerous sink node."""
        return self.nodes[0] if self.nodes else None

    def __str__(self) -> str:
        """Human-readable path representation."""
        if not self.nodes:
            return "Empty path"

        parts = []
        for i, node in enumerate(reversed(self.nodes)):
            arrow = " → " if i > 0 else ""
            transform_str = f" [{node.transform}]" if node.transform else ""
            parts.append(f"{arrow}{node.variable}:{node.location.line}{transform_str}")

        return "".join(parts)


# Sanitization/encoding functions that prevent exploitation
# Format: {language: {vuln_type: [sanitizer_functions]}}
SANITIZERS: Dict[str, Dict[str, List[str]]] = {
    "php": {
        "sql": [
            "mysqli_real_escape_string", "mysql_real_escape_string",
            "pg_escape_string", "sqlite_escape_string",
            "PDO::quote", "addslashes", "intval", "floatval",
            "preg_replace", "filter_var"
        ],
        "code_execution": [
            "escapeshellarg", "escapeshellcmd", "preg_quote"
        ],
        "xss": [
            "htmlspecialchars", "htmlentities", "strip_tags",
            "filter_var", "esc_html", "esc_attr", "esc_url"
        ],
        "path_traversal": [
            "basename", "realpath", "dirname", "pathinfo"
        ],
        "generic": [
            "filter_input", "filter_var", "preg_match", "in_array"
        ]
    },
    "python": {
        "sql": [
            "execute", "executemany",  # When used with params
            "quote", "escape", "literal", "int", "float", "str"
        ],
        "code_execution": [
            "shlex.quote", "pipes.quote", "re.escape"
        ],
        "xss": [
            "html.escape", "cgi.escape", "xml.sax.saxutils.escape",
            "jinja2.escape", "markupsafe.escape", "bleach.clean"
        ],
        "path_traversal": [
            "os.path.basename", "os.path.realpath", "os.path.normpath",
            "pathlib.Path.resolve"
        ],
        "generic": [
            "re.match", "re.search", "isinstance", "type"
        ]
    },
    "javascript": {
        "sql": [
            "escape", "escapeId", "format",  # mysql module
            "parameterize", "sanitize", "parseInt", "parseFloat"
        ],
        "code_execution": [
            "JSON.parse",  # Safer than eval
        ],
        "xss": [
            "encodeURI", "encodeURIComponent", "escape",
            "DOMPurify.sanitize", "xss", "validator.escape",
            "textContent"  # Property access, not innerHTML
        ],
        "path_traversal": [
            "path.basename", "path.normalize", "path.resolve"
        ],
        "generic": [
            "validator.isEmail", "validator.isURL", "validator.isInt",
            "Number", "String", "Boolean"
        ]
    }
}

# User input source patterns by language
USER_INPUT_PATTERNS: Dict[str, List[str]] = {
    "php": [
        r'\$_GET\[', r'\$_POST\[', r'\$_REQUEST\[', r'\$_COOKIE\[',
        r'\$_SERVER\[', r'\$_FILES\[', r'\$_ENV\[',
        r'file_get_contents\(["\']php://input',
        r'json_decode\(\s*file_get_contents',
    ],
    "python": [
        r'request\.args\.get', r'request\.form\.get', r'request\.json',
        r'request\.data', r'request\.files', r'request\.cookies',
        r'request\.environ', r'request\.query_string',
        r'input\(', r'sys\.stdin', r'os\.environ\[',
    ],
    "javascript": [
        r'req\.query\.', r'req\.body\.', r'req\.params\.', r'req\.cookies\.',
        r'req\.headers\.', r'process\.env\.', r'process\.argv',
        r'window\.location', r'document\.URL', r'document\.location',
        r'location\.search', r'location\.hash',
    ]
}


def detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    ext = Path(file_path).suffix.lower()
    ext_map = {
        '.php': 'php',
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'javascript',  # TypeScript similar patterns
        '.jsx': 'javascript',
        '.tsx': 'javascript',
    }
    return ext_map.get(ext, 'unknown')


def is_user_input(variable: str, context: str, language: str) -> bool:
    """
    Check if a variable represents user input.

    Args:
        variable: Variable name to check
        context: Surrounding code context
        language: Programming language

    Returns:
        True if variable appears to be user-controlled input
    """
    if language not in USER_INPUT_PATTERNS:
        return False

    for pattern in USER_INPUT_PATTERNS[language]:
        if re.search(pattern, context, re.IGNORECASE):
            return True

    return False


def extract_variable_name(expression: str, language: str) -> Optional[str]:
    """
    Extract the primary variable from an expression.

    Examples:
        "$user->name" -> "$user"
        "params['id']" -> "params"
        "req.body.username" -> "req"
    """
    if not expression:
        return None

    # Remove whitespace
    expression = expression.strip()

    if language == "php":
        # PHP: $variable, $obj->prop, $arr['key']
        match = re.match(r'(\$\w+)', expression)
        return match.group(1) if match else None

    elif language == "python":
        # Python: variable, obj.attr, dict['key']
        match = re.match(r'([a-zA-Z_]\w*)', expression)
        return match.group(1) if match else None

    elif language == "javascript":
        # JavaScript: variable, obj.prop, arr[0]
        match = re.match(r'([a-zA-Z_$]\w*)', expression)
        return match.group(1) if match else None

    return None


def find_assignments_in_file(
    file_info: FileInfo,
    target_variable: str,
    before_line: int,
    language: str
) -> List[Tuple[int, str, str]]:
    """
    Find all assignments to target_variable in file before a given line.

    Returns:
        List of (line_number, source_variable, code_context) tuples
    """
    assignments = []

    # Read file content
    try:
        with open(file_info.path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError):
        return []

    # Build patterns based on language
    if language == "php":
        # $target = $source;
        # $target = some_function($source);
        pattern = rf'{re.escape(target_variable)}\s*=\s*(.+?)[;,]'
    elif language == "python":
        # target = source
        # target = some_function(source)
        var_name = target_variable.lstrip('$')
        pattern = rf'{re.escape(var_name)}\s*=\s*(.+?)(?:\n|#|$)'
    elif language == "javascript":
        # target = source
        # let target = source
        var_name = target_variable.lstrip('$')
        pattern = rf'(?:var|let|const)?\s*{re.escape(var_name)}\s*=\s*(.+?)(?:;|\n|$)'
    else:
        return []

    # Search backwards from target line
    for line_num in range(min(before_line - 1, len(lines)), 0, -1):
        line = lines[line_num - 1]
        match = re.search(pattern, line)

        if match:
            source_expr = match.group(1).strip()
            source_var = extract_variable_name(source_expr, language)

            if source_var:
                assignments.append((line_num, source_var, line.strip()))

    return assignments


def find_function_param_sources(
    file_info: FileInfo,
    param_name: str,
    language: str
) -> List[Tuple[str, int, str]]:
    """
    Find where a function parameter is called from (across file boundaries).

    Returns:
        List of (caller_file, line, variable_passed) tuples
    """
    # This is a simplified version - full implementation would need
    # function call graph analysis
    sources = []

    # Check imported_by files for function calls
    for caller_file in file_info.imported_by:
        try:
            with open(caller_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Look for function calls (simplified pattern)
            for i, line in enumerate(lines, 1):
                # This is very basic - real implementation needs
                # function name resolution
                if param_name.replace('$', '') in line:
                    sources.append((caller_file, i, line.strip()))
        except (FileNotFoundError, PermissionError):
            continue

    return sources


def identify_transform(code_context: str, language: str) -> Optional[str]:
    """
    Identify if code applies a transformation/sanitization function.

    Args:
        code_context: Line of code to analyze
        language: Programming language

    Returns:
        Name of transformation function if found, None otherwise
    """
    if language not in SANITIZERS:
        return None

    # Check all sanitizer categories
    for category, functions in SANITIZERS[language].items():
        for func in functions:
            # Simple function call detection
            if func in code_context:
                return func

    # Check for type casts
    type_cast_patterns = {
        "php": [r'\(int\)', r'\(float\)', r'\(bool\)', r'\(string\)'],
        "python": [r'\bint\(', r'\bfloat\(', r'\bbool\(', r'\bstr\('],
        "javascript": [r'\bNumber\(', r'\bString\(', r'\bBoolean\(', r'\bparseInt\(', r'\bparseFloat\(']
    }

    if language in type_cast_patterns:
        for pattern in type_cast_patterns[language]:
            if re.search(pattern, code_context):
                match = re.search(pattern, code_context)
                return match.group(0).strip('(') if match else None

    return None


def backward_taint(
    sink_location: CodeLocation,
    files: Dict[str, FileInfo],
    max_depth: int = 10,
    max_paths: int = 20
) -> List[TaintPath]:
    """
    Perform backward taint analysis from sink to all possible sources.

    This is the main entry point for validation. It traces data flow backward
    from a dangerous sink to find all user input sources that could reach it.

    Args:
        sink_location: Location of the dangerous sink
        files: Dict mapping file paths to FileInfo objects
        max_depth: Maximum path length to prevent infinite loops
        max_paths: Maximum number of paths to return

    Returns:
        List of TaintPath objects representing all possible source→sink flows
    """
    if sink_location.file not in files:
        return []

    language = detect_language(sink_location.file)
    if language == 'unknown':
        return []

    # Initialize with sink node
    sink_node = TaintNode(
        location=sink_location,
        variable=sink_location.context.split('(')[0].strip() if sink_location.context else "unknown",
        operation="sink",
        confidence=1.0
    )

    # BFS to find all paths
    paths: List[TaintPath] = []
    queue: deque = deque([(sink_node, [sink_node], 0)])
    visited: Set[Tuple[str, int, str]] = set()

    while queue and len(paths) < max_paths:
        current_node, path, depth = queue.popleft()

        if depth >= max_depth:
            continue

        # Avoid cycles
        node_key = (current_node.location.file, current_node.location.line, current_node.variable)
        if node_key in visited:
            continue
        visited.add(node_key)

        # Check if this is a user input source
        file_info = files.get(current_node.location.file)
        if file_info:
            try:
                with open(file_info.path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                if 0 < current_node.location.line <= len(lines):
                    line_context = lines[current_node.location.line - 1]

                    if is_user_input(current_node.variable, line_context, language):
                        # Found a complete path!
                        taint_path = TaintPath(
                            nodes=list(path),
                            confidence=min(n.confidence for n in path)
                        )
                        paths.append(taint_path)
                        continue
            except (FileNotFoundError, PermissionError):
                pass

        # Find assignments to current variable in the same file
        if file_info:
            assignments = find_assignments_in_file(
                file_info,
                current_node.variable,
                current_node.location.line,
                language
            )

            for line_num, source_var, code in assignments:
                transform = identify_transform(code, language)

                new_node = TaintNode(
                    location=CodeLocation(
                        file=current_node.location.file,
                        line=line_num,
                        context=code
                    ),
                    variable=source_var,
                    operation="assignment",
                    transform=transform,
                    confidence=0.9 if not transform else 0.7
                )

                new_path = path + [new_node]
                queue.append((new_node, new_path, depth + 1))

        # Check for inter-file flows via imports
        if file_info:
            for imported_file in file_info.imports:
                if imported_file in files:
                    # Look for function returns or global assignments
                    # Simplified: assume variable might come from imported file
                    imported_info = files[imported_file]

                    new_node = TaintNode(
                        location=CodeLocation(
                            file=imported_file,
                            line=1,  # Would need better line tracking
                            context="import boundary"
                        ),
                        variable=current_node.variable,
                        operation="import",
                        confidence=0.6  # Lower confidence for cross-file
                    )

                    new_path = path + [new_node]
                    queue.append((new_node, new_path, depth + 1))

    return paths


def find_transforms(path: TaintPath) -> List[str]:
    """
    Extract all transformation/sanitization functions from a taint path.

    Args:
        path: TaintPath to analyze

    Returns:
        List of transformation function names found in the path
    """
    transforms = []

    for node in path.nodes:
        if node.transform:
            transforms.append(node.transform)

    return transforms


def is_sanitizer(transform: str, vuln_type: str, language: str) -> bool:
    """
    Check if a transformation function is a valid sanitizer for the vulnerability type.

    Args:
        transform: Function name (e.g., "htmlspecialchars")
        vuln_type: Vulnerability type (e.g., "xss", "sql", "code_execution")
        language: Programming language

    Returns:
        True if transform function sanitizes the vulnerability type
    """
    if language not in SANITIZERS:
        return False

    # Check specific category
    if vuln_type in SANITIZERS[language]:
        if transform in SANITIZERS[language][vuln_type]:
            return True

    # Check generic sanitizers
    if "generic" in SANITIZERS[language]:
        if transform in SANITIZERS[language]["generic"]:
            return True

    return False


def validate_path_exploitability(
    path: TaintPath,
    vuln_type: str,
    language: str
) -> Tuple[bool, List[str]]:
    """
    Validate if a taint path is exploitable given its transformations.

    Args:
        path: TaintPath to validate
        vuln_type: Type of vulnerability (sql, xss, code_execution, etc.)
        language: Programming language

    Returns:
        Tuple of (is_exploitable, blocking_sanitizers)
    """
    transforms = find_transforms(path)
    blocking = []

    for transform in transforms:
        if is_sanitizer(transform, vuln_type, language):
            blocking.append(transform)

    is_exploitable = len(blocking) == 0

    return is_exploitable, blocking


def analyze_paths(
    paths: List[TaintPath],
    vuln_type: str,
    language: str
) -> Dict[str, any]:
    """
    Analyze a set of taint paths to determine overall exploitability.

    Args:
        paths: List of TaintPath objects to analyze
        vuln_type: Type of vulnerability
        language: Programming language

    Returns:
        Dict with analysis results including exploitable/blocked path counts
    """
    exploitable_paths = []
    blocked_paths = []

    for path in paths:
        is_exploitable, blockers = validate_path_exploitability(path, vuln_type, language)

        if is_exploitable:
            path.is_exploitable = True
            exploitable_paths.append(path)
        else:
            path.is_exploitable = False
            path.blocking_transforms = blockers
            blocked_paths.append(path)

    return {
        "total_paths": len(paths),
        "exploitable_count": len(exploitable_paths),
        "blocked_count": len(blocked_paths),
        "exploitable_paths": exploitable_paths,
        "blocked_paths": blocked_paths,
        "verdict": "exploitable" if len(exploitable_paths) > 0 else "false_positive",
        "confidence": max(p.confidence for p in paths) if paths else 0.0
    }


if __name__ == "__main__":
    # Demo usage
    print("Taint Analysis Utility")
    print("=" * 50)
    print("\nThis module provides backward taint analysis for vulnerability validation.")
    print("\nKey functions:")
    print("  - backward_taint(sink, files) -> List[TaintPath]")
    print("  - find_transforms(path) -> List[str]")
    print("  - validate_path_exploitability(path, vuln_type, lang) -> (bool, List[str])")
    print("\nExample:")
    print("  paths = backward_taint(sink_location, file_dict)")
    print("  analysis = analyze_paths(paths, 'sql', 'php')")
    print("  if analysis['verdict'] == 'exploitable':")
    print("      print('Confirmed vulnerability!')")
