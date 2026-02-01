#!/usr/bin/env python3
"""
End-to-End Pipeline Demonstration
==================================

Shows how dependencies.py integrates with the full code-vuln-analysis pipeline:
  Recon → Triage → Analysis → Validation

This demonstrates the complete workflow from dependency graph building through
to chunked analysis ready for the LLM analysis agent.
"""

import tempfile
import yaml
from pathlib import Path
from typing import Dict, List

from dependencies import build_dependency_graph, to_yaml as deps_to_yaml
from prioritize import (
    TriageFinding,
    CodeLocation,
    SinkType,
    InputProximity,
    AuthLevel,
    rank_findings,
    categorize_priority
)
from chunker import FileInfo, create_chunks, chunks_to_yaml


def create_vulnerable_php_app(tmpdir: str) -> List[str]:
    """Create a realistic vulnerable PHP application for testing."""
    files = {
        "index.php": """<?php
require_once 'config.php';
include 'db.php';

// Entry point - no auth required
$page = $_GET['page'];  // User input
include "pages/$page.php";  // Vulnerable!
?>""",
        "admin.php": """<?php
require 'auth.php';
include 'db.php';

// Admin panel
$cmd = $_POST['cmd'];
system($cmd);  // RCE vulnerability!
?>""",
        "auth.php": """<?php
include 'db.php';

function check_auth() {
    // Weak auth check
    if (!isset($_SESSION['user'])) {
        return false;
    }
    return true;
}
?>""",
        "db.php": """<?php
require_once 'config.php';

$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS);

function get_user($id) {
    global $conn;
    $query = "SELECT * FROM users WHERE id = $id";  // SQLi vulnerable!
    return mysqli_query($conn, $query);
}
?>""",
        "config.php": """<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'password');
?>"""
    }

    file_paths = []
    for filename, content in files.items():
        filepath = Path(tmpdir) / filename
        filepath.write_text(content)
        file_paths.append(str(filepath))

    return file_paths


def phase1_recon(file_paths: List[str], project_root: str) -> Dict:
    """
    PHASE 1: RECONNAISSANCE

    Uses dependencies.py to build dependency graph.
    In real scenario, recon agent would also detect sinks and entry points.
    """
    print("=" * 70)
    print("PHASE 1: RECONNAISSANCE")
    print("=" * 70)

    # Build dependency graph
    print("\nBuilding dependency graph...")
    graph = build_dependency_graph(file_paths, project_root)

    for file, deps in sorted(graph.items()):
        print(f"  {file} → {deps}")

    # Convert to YAML (matching SKILL.md lines 70-76)
    dep_yaml = deps_to_yaml(graph)
    print("\nDependency graph YAML:")
    print(dep_yaml)

    # Simulate complete recon output (in real scenario, would include sinks)
    recon_output = yaml.safe_load(dep_yaml)

    # Add simulated dangerous sinks
    recon_output["dangerous_sinks"] = {
        "code_execution": [
            {"file": "admin.php", "line": 8, "function": "system", "context": "system($cmd)"}
        ],
        "sql": [
            {"file": "db.php", "line": 11, "function": "mysqli_query", "parameterized": False}
        ],
        "file_ops": [
            {"file": "index.php", "line": 6, "function": "include", "context": "include pages/$page.php"}
        ]
    }

    recon_output["user_inputs"] = [
        {"file": "index.php", "line": 5, "variable": "$_GET['page']", "type": "direct"},
        {"file": "admin.php", "line": 7, "variable": "$_POST['cmd']", "type": "direct"}
    ]

    return recon_output


def phase2_triage(recon_data: Dict) -> Dict:
    """
    PHASE 2: TRIAGE

    Uses prioritize.py to score findings and chunker.py to create analysis chunks.
    Chunker.py consumes the dependency graph from phase 1 (lines 436-451).
    """
    print("\n" + "=" * 70)
    print("PHASE 2: TRIAGE")
    print("=" * 70)

    # Create findings from recon sinks
    findings = [
        TriageFinding(
            id="VULN-001",
            location=CodeLocation(file="admin.php", line=8, function="system"),
            sink_type=SinkType.CODE_EXECUTION,
            sink_function="system",
            input_proximity=InputProximity.DIRECT,
            input_source="$_POST['cmd']",
            auth_level=AuthLevel.WEAK,
            description="RCE via system() call with POST input",
            confidence=0.9
        ),
        TriageFinding(
            id="VULN-002",
            location=CodeLocation(file="db.php", line=11, function="mysqli_query"),
            sink_type=SinkType.SQL,
            sink_function="mysqli_query",
            input_proximity=InputProximity.DIRECT,
            input_source="$id parameter",
            auth_level=AuthLevel.USER,
            description="SQL injection in user lookup",
            confidence=0.85
        ),
        TriageFinding(
            id="VULN-003",
            location=CodeLocation(file="index.php", line=6, function="include"),
            sink_type=SinkType.FILE_OPS,
            sink_function="include",
            input_proximity=InputProximity.DIRECT,
            input_source="$_GET['page']",
            auth_level=AuthLevel.NONE,
            description="Local file inclusion via GET parameter",
            confidence=0.95
        )
    ]

    # Score and rank findings
    print("\nScoring findings...")
    ranked = rank_findings(findings)

    priority_queue = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }

    for finding in ranked:
        priority = categorize_priority(finding.score)
        priority_queue[priority].append(finding)
        print(f"  {finding.id}: {finding.sink_type.value} - Score: {finding.score:.1f}/70 [{priority.upper()}]")

    # Create file info objects for chunker
    files = {}
    for file in ["index.php", "admin.php", "auth.php", "db.php", "config.php"]:
        files[file] = FileInfo(
            path=file,
            token_count=500,  # Simulated
            sinks=[f for f in findings if f.location.file == file]
        )

    # Create chunks using dependency graph
    print("\nCreating analysis chunks...")
    chunks = create_chunks(files, recon_data, token_limit=10000)

    print(f"  Created {len(chunks)} chunks:")
    for chunk in chunks:
        print(f"    {chunk.id}: {chunk.priority} - {len(chunk.files)} files, ~{chunk.token_estimate} tokens")
        print(f"      Files: {', '.join(chunk.files)}")
        print(f"      Focus: {chunk.focus}")

    # Export to YAML
    triage_yaml = chunks_to_yaml(chunks)

    return {
        "priority_queue": priority_queue,
        "chunks": chunks,
        "yaml_output": triage_yaml
    }


def main():
    """Run the complete pipeline demonstration."""
    print("\n" + "=" * 70)
    print("CODE VULNERABILITY ANALYSIS PIPELINE DEMONSTRATION")
    print("=" * 70)
    print("\nThis demonstrates how dependencies.py integrates with the full pipeline:")
    print("  1. Recon: Build dependency graph")
    print("  2. Triage: Score findings and create chunks using dependency info")
    print("  3. Analysis: (simulated - would be LLM agent)")
    print("  4. Validation: (simulated - would be LLM agent)")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup
        print(f"\nCreating vulnerable PHP app in: {tmpdir}")
        file_paths = create_vulnerable_php_app(tmpdir)
        print(f"Created {len(file_paths)} files")

        # Phase 1: Recon
        recon_data = phase1_recon(file_paths, tmpdir)

        # Verify dependency graph is in correct format for chunker
        print("\n✓ Dependency graph format matches chunker.py expectations (lines 386-391)")
        assert "dependency_graph" in recon_data
        assert "includes" in recon_data["dependency_graph"]

        # Phase 2: Triage
        triage_data = phase2_triage(recon_data)

        # Show final output
        print("\n" + "=" * 70)
        print("TRIAGE OUTPUT (Ready for Analysis Agent)")
        print("=" * 70)
        print("\nChunks YAML:")
        print(triage_data["yaml_output"])

        print("\n" + "=" * 70)
        print("PIPELINE COMPLETE")
        print("=" * 70)
        print("\nKey Integration Points:")
        print("  ✓ dependencies.py generates YAML matching SKILL.md (lines 70-76)")
        print("  ✓ chunker.py consumes dependency_graph (lines 386-391)")
        print("  ✓ Chunks preserve taint paths using dependency information")
        print("  ✓ Output ready for LLM analysis agent")
        print("\nNext steps (would be done by LLM agents):")
        print("  3. Analysis: Process each chunk for deep vulnerability analysis")
        print("  4. Validation: Confirm exploitability and generate PoCs")


if __name__ == "__main__":
    main()
