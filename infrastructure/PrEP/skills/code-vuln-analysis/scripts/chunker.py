#!/usr/bin/env python3
"""
Code Chunking Utility for Vulnerability Analysis
=================================================

Groups source files by data flow relationships for optimal LLM analysis.
Creates analysis chunks of 5-12k tokens that preserve complete taint paths.

Key features:
- Token-aware chunking using tiktoken (cl100k_base encoding)
- Topological sorting for dependency ordering (Kahn's algorithm)
- Taint-path grouping: sink file + all files in potential data flow
- YAML output matching triage.md schema (lines 114-192)

Usage:
    from chunker import create_chunks, chunks_to_yaml

    chunks = create_chunks(file_infos, recon_data, token_limit=10000)
    yaml_output = chunks_to_yaml(chunks)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple
from collections import deque
from pathlib import Path
import yaml

try:
    from .tokens import count_tokens, estimate_file_tokens
except ImportError:
    from tokens import count_tokens, estimate_file_tokens

try:
    from .prioritize import (
        SinkType,
        InputProximity,
        AuthLevel,
        TriageFinding,
        CodeLocation,
        score_finding,
        categorize_priority,
        SINK_SEVERITY
    )
except ImportError:
    from prioritize import (
        SinkType,
        InputProximity,
        AuthLevel,
        TriageFinding,
        CodeLocation,
        score_finding,
        categorize_priority,
        SINK_SEVERITY
    )


# Chunk size constraints from research (CODE_ANALYSIS_AGENT_DESIGN.md)
MIN_CHUNK_TOKENS = 5000
MAX_CHUNK_TOKENS = 12000
OPTIMAL_CHUNK_TOKENS = 10000


@dataclass
class FileInfo:
    """Information about a source file for chunking."""
    path: str
    token_count: int = 0
    char_count: int = 0
    imports: List[str] = field(default_factory=list)      # Files this file imports
    imported_by: List[str] = field(default_factory=list)  # Files that import this file
    sinks: List[TriageFinding] = field(default_factory=list)
    user_inputs: List[Dict[str, Any]] = field(default_factory=list)
    language: str = ""

    @property
    def has_dangerous_sink(self) -> bool:
        """Check if file contains any dangerous sinks."""
        return len(self.sinks) > 0

    @property
    def has_user_input(self) -> bool:
        """Check if file contains user input sources."""
        return len(self.user_inputs) > 0

    @property
    def max_sink_severity(self) -> int:
        """Return the highest severity sink in this file."""
        if not self.sinks:
            return 0
        return max(SINK_SEVERITY.get(s.sink_type, 0) for s in self.sinks)


@dataclass
class AnalysisChunk:
    """A group of related files for LLM analysis."""
    id: str
    priority: str  # "critical", "high", "medium", "low"
    files: List[str] = field(default_factory=list)
    focus: str = ""  # Specific analysis instruction
    attack_surface: str = ""  # Primary vulnerability type
    hypothesis: str = ""  # Exploitation hypothesis to test
    token_estimate: int = 0
    rationale: str = ""  # Why these files are grouped

    # Internal tracking
    primary_sink: Optional[TriageFinding] = None

    def add_file(self, file_path: str, tokens: int) -> None:
        """Add a file to this chunk."""
        if file_path not in self.files:
            self.files.append(file_path)
            self.token_estimate += tokens


# Token counting functions moved to tokens.py module
# Import them above: from tokens import count_tokens, estimate_file_tokens


def topological_sort(
    files: Dict[str, FileInfo],
    dependency_graph: Dict[str, List[str]]
) -> List[str]:
    """
    Sort files topologically so dependencies come before dependents.

    Uses Kahn's algorithm with cycle handling. Files in cycles are
    grouped together and sorted by sink severity.

    Args:
        files: Dict mapping file paths to FileInfo objects
        dependency_graph: Dict mapping file paths to list of files they import

    Returns:
        List of file paths in topological order
    """
    # Build in-degree map
    in_degree: Dict[str, int] = {path: 0 for path in files}

    for path, imports in dependency_graph.items():
        for imp in imports:
            if imp in in_degree:
                in_degree[imp] += 0  # Ensure key exists
            # Count reverse edges (how many files depend on each file)

    # Count actual in-degrees (files that import this file)
    for path, file_info in files.items():
        for importer in file_info.imported_by:
            if importer in in_degree:
                in_degree[path] = in_degree.get(path, 0) + 1

    # Kahn's algorithm
    queue: deque = deque()
    for path, degree in in_degree.items():
        if degree == 0:
            queue.append(path)

    result: List[str] = []
    visited: Set[str] = set()

    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        result.append(current)

        # Decrease in-degree of dependents
        if current in files:
            for dependent in files[current].imported_by:
                if dependent in in_degree:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0 and dependent not in visited:
                        queue.append(dependent)

    # Handle cycles: add remaining files sorted by sink severity
    remaining = [p for p in files if p not in visited]
    if remaining:
        # Sort by max sink severity (highest first) to prioritize dangerous files
        remaining.sort(
            key=lambda p: files[p].max_sink_severity if p in files else 0,
            reverse=True
        )
        result.extend(remaining)

    return result


def find_taint_path(
    sink_file: str,
    files: Dict[str, FileInfo],
    dependency_graph: Dict[str, List[str]],
    max_depth: int = 5
) -> Set[str]:
    """
    Find all files that could influence data reaching a sink.

    Performs backward traversal from sink to find potential sources.

    Args:
        sink_file: File containing the dangerous sink
        files: Dict mapping file paths to FileInfo objects
        dependency_graph: Import relationships
        max_depth: Maximum traversal depth to prevent explosion

    Returns:
        Set of file paths in the potential taint path
    """
    taint_path: Set[str] = {sink_file}
    queue: deque = deque([(sink_file, 0)])
    visited: Set[str] = {sink_file}

    while queue:
        current, depth = queue.popleft()

        if depth >= max_depth:
            continue

        if current not in files:
            continue

        # Backward trace: find files that this file imports
        # (data flows from imports into current file)
        for imported in files[current].imports:
            if imported not in visited:
                visited.add(imported)
                taint_path.add(imported)
                queue.append((imported, depth + 1))

        # Also check files that import us (for config-like patterns)
        # where data might flow in from a parent controller
        if depth < 2:  # Only go up one level
            for importer in files[current].imported_by:
                if importer not in visited and importer in files:
                    # Only include if importer has user input
                    if files[importer].has_user_input:
                        visited.add(importer)
                        taint_path.add(importer)
                        queue.append((importer, depth + 1))

    return taint_path


def create_taint_chunk(
    sink: TriageFinding,
    files: Dict[str, FileInfo],
    dependency_graph: Dict[str, List[str]],
    token_limit: int = OPTIMAL_CHUNK_TOKENS
) -> AnalysisChunk:
    """
    Create a chunk containing all files in potential taint path to a sink.

    Groups the sink file with all files that could influence data reaching it,
    respecting token limits by prioritizing direct dependencies.

    Args:
        sink: The dangerous sink finding
        files: Dict mapping file paths to FileInfo objects
        dependency_graph: Import relationships
        token_limit: Maximum tokens per chunk

    Returns:
        AnalysisChunk ready for analysis
    """
    sink_file = sink.location.file

    # Find all files in taint path
    taint_path = find_taint_path(sink_file, files, dependency_graph)

    # Create chunk
    chunk = AnalysisChunk(
        id=f"chunk_{sink.id}",
        priority=categorize_priority(sink.score),
        attack_surface=sink.sink_type.value,
        primary_sink=sink
    )

    # Always include sink file first
    if sink_file in files:
        chunk.add_file(sink_file, files[sink_file].token_count)

    # Add other files in taint path, sorted by relevance
    remaining_files = [f for f in taint_path if f != sink_file and f in files]

    # Sort by: 1) has user input (sources), 2) direct import of sink, 3) token count
    def file_priority(path: str) -> Tuple[int, int, int]:
        f = files[path]
        is_source = 1 if f.has_user_input else 0
        is_direct = 1 if path in files.get(sink_file, FileInfo(path="")).imports else 0
        return (-is_source, -is_direct, f.token_count)

    remaining_files.sort(key=file_priority)

    # Add files until token limit
    for path in remaining_files:
        if chunk.token_estimate + files[path].token_count <= token_limit:
            chunk.add_file(path, files[path].token_count)
        elif chunk.token_estimate < MIN_CHUNK_TOKENS:
            # Force add if below minimum
            chunk.add_file(path, files[path].token_count)

    # Generate focus and hypothesis
    chunk.focus = _generate_focus(sink, files, chunk.files)
    chunk.hypothesis = _generate_hypothesis(sink)
    chunk.rationale = _generate_rationale(sink, chunk.files, files)

    return chunk


def _generate_focus(
    sink: TriageFinding,
    files: Dict[str, FileInfo],
    chunk_files: List[str]
) -> str:
    """Generate specific analysis instruction for a chunk."""
    sink_type = sink.sink_type.value.replace("_", " ")
    sink_func = sink.sink_function
    sink_loc = f"{sink.location.file}:{sink.location.line}"

    # Find input sources in chunk
    sources = []
    for path in chunk_files:
        if path in files and files[path].has_user_input:
            for inp in files[path].user_inputs[:2]:  # Max 2 sources
                sources.append(f"{path}: {inp.get('source', 'unknown')}")

    source_str = ", ".join(sources) if sources else "database/config values"

    return (
        f"Trace data flow from {source_str} to {sink_func}() at {sink_loc}. "
        f"Verify if user input can reach this {sink_type} sink without adequate sanitization. "
        f"Check for validation, encoding, or parameterization between source and sink."
    )


def _generate_hypothesis(sink: TriageFinding) -> str:
    """Generate exploitation hypothesis for a chunk."""
    sink_type = sink.sink_type

    hypotheses = {
        SinkType.CODE_EXECUTION: "User-controlled data reaches code evaluation without sanitization, allowing arbitrary code execution",
        SinkType.SQL: "User input is concatenated into SQL query without parameterization, enabling SQL injection",
        SinkType.FILE_OPS: "User-controlled path is used in file operation without proper validation, allowing path traversal",
        SinkType.DESERIALIZATION: "Untrusted data is deserialized without validation, potentially allowing object injection or RCE",
        SinkType.XSS: "User input is rendered in HTML response without proper encoding, enabling cross-site scripting",
        SinkType.SSRF: "User-controlled URL is fetched server-side without validation, enabling server-side request forgery",
        SinkType.LDAP: "User input is used in LDAP query without escaping, enabling LDAP injection",
        SinkType.XPATH: "User input is used in XPath query without sanitization, enabling XPath injection",
        SinkType.TEMPLATE: "User-controlled data is used in template rendering, enabling server-side template injection",
        SinkType.REDIRECT: "User-controlled URL is used in redirect without validation, enabling open redirect",
    }

    return hypotheses.get(sink_type, f"User input reaches {sink_type.value} sink without adequate validation")


def _generate_rationale(
    sink: TriageFinding,
    chunk_files: List[str],
    files: Dict[str, FileInfo]
) -> str:
    """Generate rationale for why files are grouped together."""
    sink_file = sink.location.file
    other_files = [f for f in chunk_files if f != sink_file]

    if not other_files:
        return f"{sink_file} contains {sink.sink_function}() sink; analyzing in isolation"

    # Categorize other files
    imports = [f for f in other_files if f in files.get(sink_file, FileInfo(path="")).imports]
    sources = [f for f in other_files if f in files and files[f].has_user_input]

    parts = []
    parts.append(f"{sink_file} contains {sink.sink_function}() sink")

    if imports:
        parts.append(f"{', '.join(imports)} provide dependencies")
    if sources:
        parts.append(f"{', '.join(sources)} contain user input sources")

    return "; ".join(parts)


def create_chunks(
    files: Dict[str, FileInfo],
    recon_data: Dict[str, Any],
    token_limit: int = OPTIMAL_CHUNK_TOKENS
) -> List[AnalysisChunk]:
    """
    Create analysis chunks from recon data.

    Main entry point for chunking. Groups files by data flow relationships,
    prioritizing dangerous sinks.

    Args:
        files: Dict mapping file paths to FileInfo objects
        recon_data: Output from recon agent containing sinks, inputs, dependencies
        token_limit: Maximum tokens per chunk

    Returns:
        List of AnalysisChunk objects sorted by priority
    """
    # Build dependency graph from recon data
    dependency_graph: Dict[str, List[str]] = {}
    if "dependency_graph" in recon_data:
        for entry in recon_data["dependency_graph"].get("includes", []):
            from_file = entry.get("from", "")
            imports = entry.get("imports", [])
            dependency_graph[from_file] = imports

            # Update FileInfo
            if from_file in files:
                files[from_file].imports = imports

            # Track reverse relationships
            for imp in imports:
                if imp in files:
                    if from_file not in files[imp].imported_by:
                        files[imp].imported_by.append(from_file)

    # Collect all sinks and rank them
    all_sinks: List[TriageFinding] = []
    for file_info in files.values():
        all_sinks.extend(file_info.sinks)

    # Sort sinks by score (highest first)
    all_sinks.sort(key=lambda s: s.score, reverse=True)

    # Create chunks for each sink, avoiding duplicate files
    chunks: List[AnalysisChunk] = []
    processed_files: Set[str] = set()

    for sink in all_sinks:
        sink_file = sink.location.file

        # Skip if primary sink file already processed
        if sink_file in processed_files:
            continue

        chunk = create_taint_chunk(sink, files, dependency_graph, token_limit)

        # Only add chunk if it has files not yet processed
        new_files = [f for f in chunk.files if f not in processed_files]
        if new_files:
            chunks.append(chunk)
            processed_files.update(chunk.files)

    # Sort chunks by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    chunks.sort(key=lambda c: (priority_order.get(c.priority, 4), -c.token_estimate))

    # Assign sequential IDs
    for i, chunk in enumerate(chunks):
        chunk.id = f"chunk_{i+1:03d}"

    return chunks


def chunks_to_yaml(chunks: List[AnalysisChunk]) -> str:
    """
    Convert chunks to YAML format matching triage.md schema.

    Args:
        chunks: List of AnalysisChunk objects

    Returns:
        YAML string matching lines 114-192 of triage.md
    """
    output = {
        "analysis_chunks": [],
        "metadata": {
            "chunks_created": len(chunks),
            "total_estimated_tokens": sum(c.token_estimate for c in chunks),
            "estimated_analysis_turns": sum(3 for c in chunks)  # ~3 turns per chunk
        }
    }

    for chunk in chunks:
        chunk_dict = {
            "id": chunk.id,
            "priority": chunk.priority,
            "files": chunk.files,
            "focus": chunk.focus,
            "attack_surface": chunk.attack_surface,
            "hypothesis": chunk.hypothesis,
            "token_estimate": chunk.token_estimate,
            "rationale": chunk.rationale
        }
        output["analysis_chunks"].append(chunk_dict)

    return yaml.dump(output, default_flow_style=False, sort_keys=False, allow_unicode=True)


def build_file_infos_from_recon(recon_data: Dict[str, Any]) -> Dict[str, FileInfo]:
    """
    Build FileInfo objects from recon agent output.

    Args:
        recon_data: Output from recon agent

    Returns:
        Dict mapping file paths to FileInfo objects
    """
    files: Dict[str, FileInfo] = {}

    # Get file list from manifest
    manifest = recon_data.get("manifest", {})
    file_list = manifest.get("files", [])
    languages = manifest.get("languages", {})

    # Infer language from file extension
    def get_language(path: str) -> str:
        ext = Path(path).suffix.lower()
        ext_map = {
            ".php": "php", ".phtml": "php",
            ".py": "python", ".pyw": "python",
            ".js": "javascript", ".jsx": "javascript",
            ".ts": "typescript", ".tsx": "typescript",
            ".rb": "ruby", ".java": "java", ".go": "go"
        }
        return ext_map.get(ext, "")

    # Create FileInfo for each file
    for path in file_list:
        files[path] = FileInfo(
            path=path,
            language=get_language(path)
        )

    # Process dangerous sinks
    dangerous_sinks = recon_data.get("dangerous_sinks", {})
    for sink_type, sink_list in dangerous_sinks.items():
        for sink_data in sink_list:
            file_path = sink_data.get("file", "")
            if file_path not in files:
                files[file_path] = FileInfo(path=file_path, language=get_language(file_path))

            # Map sink type string to enum
            try:
                sink_enum = SinkType(sink_type)
            except ValueError:
                sink_enum = SinkType.OTHER

            # Create TriageFinding
            finding = TriageFinding(
                id=f"{sink_type}_{file_path}_{sink_data.get('line', 0)}",
                location=CodeLocation(
                    file=file_path,
                    line=sink_data.get("line", 0),
                    function=sink_data.get("function", ""),
                    context=sink_data.get("context", "")
                ),
                sink_type=sink_enum,
                sink_function=sink_data.get("function", "unknown"),
                input_proximity=InputProximity.DB_STORED,  # Conservative default
                auth_level=AuthLevel.NONE,  # Will be refined by triage
            )

            # Calculate initial score
            finding.score = score_finding(
                finding.sink_type,
                finding.input_proximity,
                finding.auth_level
            )

            files[file_path].sinks.append(finding)

    # Process user inputs
    user_inputs = recon_data.get("user_inputs", [])
    for input_data in user_inputs:
        file_path = input_data.get("file", "")
        if file_path not in files:
            files[file_path] = FileInfo(path=file_path, language=get_language(file_path))

        files[file_path].user_inputs.append({
            "line": input_data.get("line", 0),
            "source": input_data.get("source", ""),
            "variable": input_data.get("variable", "")
        })

    # Process dependencies
    dependency_graph = recon_data.get("dependency_graph", {})
    for entry in dependency_graph.get("includes", []):
        from_file = entry.get("from", "")
        imports = entry.get("imports", [])

        if from_file in files:
            files[from_file].imports = imports

        for imp in imports:
            if imp in files:
                if from_file not in files[imp].imported_by:
                    files[imp].imported_by.append(from_file)

    return files


if __name__ == "__main__":
    # Demo with sample recon data
    sample_recon = {
        "manifest": {
            "files": ["admin.php", "login.php", "includes/db.php", "includes/auth.php", "config.php"],
            "languages": {"php": 5}
        },
        "dependency_graph": {
            "includes": [
                {"from": "admin.php", "imports": ["config.php", "includes/db.php", "includes/auth.php"]},
                {"from": "login.php", "imports": ["config.php", "includes/db.php", "includes/auth.php"]}
            ]
        },
        "dangerous_sinks": {
            "sql": [
                {"file": "includes/db.php", "line": 23, "function": "query()", "parameterized": False}
            ],
            "code_execution": [
                {"file": "includes/auth.php", "line": 45, "function": "assert()"}
            ]
        },
        "user_inputs": [
            {"file": "login.php", "line": 15, "source": "$_POST", "variable": "username"},
            {"file": "admin.php", "line": 34, "source": "$_POST", "variable": "config_data"}
        ]
    }

    print("Chunker Demo")
    print("=" * 50)

    # Build file infos
    files = build_file_infos_from_recon(sample_recon)

    # Estimate tokens (mock values since we don't have actual files)
    for path, info in files.items():
        info.token_count = 2000  # Mock: 2k tokens each

    # Create chunks
    chunks = create_chunks(files, sample_recon)

    # Output
    print(f"\nCreated {len(chunks)} chunks:\n")
    print(chunks_to_yaml(chunks))
