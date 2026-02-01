#!/usr/bin/env python3
"""
Example: Using Backward Taint Analysis for Vulnerability Validation
====================================================================

This example demonstrates how the Validation Agent (Phase 4) would use
the taint analysis utility to validate findings from the Analysis phase.

Scenario: Validating a reported SQL injection vulnerability in a PHP web app.
"""

import sys
from pathlib import Path

# Add scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from taint import (
    backward_taint,
    analyze_paths,
    TaintNode,
    TaintPath,
)
from prioritize import CodeLocation, SinkType, TriageFinding
from chunker import FileInfo


def create_example_files():
    """Create example file structures for demonstration."""
    # Example PHP application with potential SQL injection
    files = {}

    # File 1: admin.php (contains the dangerous sink)
    admin_php = FileInfo(
        path="/var/www/html/admin.php",
        token_count=500,
        imports=["config.php", "db.php"],
        language="php",
    )
    files["/var/www/html/admin.php"] = admin_php

    # File 2: db.php (database connection)
    db_php = FileInfo(
        path="/var/www/html/db.php",
        token_count=300,
        imports=["config.php"],
        imported_by=["/var/www/html/admin.php"],
        language="php",
    )
    files["/var/www/html/db.php"] = db_php

    # File 3: config.php (configuration)
    config_php = FileInfo(
        path="/var/www/html/config.php",
        token_count=100,
        imported_by=["/var/www/html/admin.php", "/var/www/html/db.php"],
        language="php",
    )
    files["/var/www/html/config.php"] = config_php

    return files


def example_1_vulnerable_sqli():
    """
    Example 1: Unprotected SQL Injection

    The vulnerability:
        $user_id = $_GET['id'];
        $query = "SELECT * FROM users WHERE id = $user_id";
        mysql_query($query);

    Expected result: EXPLOITABLE (no sanitization)
    """
    print("\n" + "=" * 70)
    print("Example 1: Unprotected SQL Injection")
    print("=" * 70)

    files = create_example_files()

    # The Analysis agent found this dangerous sink
    sink_location = CodeLocation(
        file="/var/www/html/admin.php",
        line=42,
        context='mysql_query("SELECT * FROM users WHERE id = $user_id");',
        function="mysql_query"
    )

    print(f"\nSink Location: {sink_location.file}:{sink_location.line}")
    print(f"Sink Function: {sink_location.function}")
    print(f"Context: {sink_location.context}")

    # Perform backward taint analysis
    print("\n[*] Running backward taint analysis...")
    paths = backward_taint(sink_location, files, max_depth=5)

    print(f"[+] Found {len(paths)} potential data flow path(s)")

    # Analyze exploitability
    analysis = analyze_paths(paths, vuln_type="sql", language="php")

    print(f"\n{'='*70}")
    print("VALIDATION RESULT")
    print(f"{'='*70}")
    print(f"Total paths: {analysis['total_paths']}")
    print(f"Exploitable paths: {analysis['exploitable_count']}")
    print(f"Blocked paths: {analysis['blocked_count']}")
    print(f"Verdict: {analysis['verdict'].upper()}")
    print(f"Confidence: {analysis['confidence']:.2%}")

    if analysis['verdict'] == 'exploitable':
        print("\n[!] CONFIRMED VULNERABILITY")
        print("Recommendation: This is a real SQL injection vulnerability")
    else:
        print("\n[+] FALSE POSITIVE")
        print("Recommendation: Sanitization prevents exploitation")


def example_2_sanitized_sqli():
    """
    Example 2: Sanitized SQL Query

    The code:
        $user_id = $_GET['id'];
        $safe_id = intval($user_id);
        $query = "SELECT * FROM users WHERE id = $safe_id";
        mysql_query($query);

    Expected result: FALSE POSITIVE (intval sanitizes input)
    """
    print("\n" + "=" * 70)
    print("Example 2: Sanitized SQL Query")
    print("=" * 70)

    files = create_example_files()

    sink_location = CodeLocation(
        file="/var/www/html/admin.php",
        line=45,
        context='mysql_query("SELECT * FROM users WHERE id = $safe_id");',
        function="mysql_query"
    )

    print(f"\nSink Location: {sink_location.file}:{sink_location.line}")
    print(f"Context: {sink_location.context}")

    # Create a manual path to demonstrate transform detection
    # (In real usage, backward_taint would discover this)
    print("\n[*] Constructing taint path with sanitization...")

    sink_node = TaintNode(
        location=sink_location,
        variable="$safe_id",
        operation="sink"
    )

    sanitize_node = TaintNode(
        location=CodeLocation(
            file="/var/www/html/admin.php",
            line=43,
            context="$safe_id = intval($user_id);"
        ),
        variable="$user_id",
        operation="assignment",
        transform="intval"  # THIS BLOCKS THE EXPLOIT
    )

    source_node = TaintNode(
        location=CodeLocation(
            file="/var/www/html/admin.php",
            line=42,
            context='$user_id = $_GET["id"];'
        ),
        variable="$_GET",
        operation="source"
    )

    path = TaintPath(nodes=[sink_node, sanitize_node, source_node])
    paths = [path]

    print(f"[+] Taint path: {path}")

    # Analyze exploitability
    analysis = analyze_paths(paths, vuln_type="sql", language="php")

    print(f"\n{'='*70}")
    print("VALIDATION RESULT")
    print(f"{'='*70}")
    print(f"Verdict: {analysis['verdict'].upper()}")

    if analysis['blocked_count'] > 0:
        blocked_path = analysis['blocked_paths'][0]
        print(f"Blocking transforms: {blocked_path.blocking_transforms}")
        print("\n[+] FALSE POSITIVE DETECTED")
        print(f"Reason: Input is sanitized by {blocked_path.blocking_transforms[0]}")
        print("Recommendation: Downgrade severity or remove from report")


def example_3_xss_blocked():
    """
    Example 3: XSS Blocked by htmlspecialchars

    The code:
        $name = $_POST['name'];
        echo htmlspecialchars($name);

    Expected result: FALSE POSITIVE (htmlspecialchars prevents XSS)
    """
    print("\n" + "=" * 70)
    print("Example 3: XSS Blocked by htmlspecialchars")
    print("=" * 70)

    files = create_example_files()

    sink_location = CodeLocation(
        file="/var/www/html/profile.php",
        line=28,
        context='echo htmlspecialchars($name);',
        function="echo"
    )

    print(f"\nSink Location: {sink_location.file}:{sink_location.line}")
    print(f"Context: {sink_location.context}")

    # Manual path construction
    sink_node = TaintNode(
        location=sink_location,
        variable="$name",
        operation="sink"
    )

    sanitize_node = TaintNode(
        location=CodeLocation(
            file="/var/www/html/profile.php",
            line=28,
            context='echo htmlspecialchars($name);'
        ),
        variable="$name",
        operation="function_call",
        transform="htmlspecialchars"
    )

    source_node = TaintNode(
        location=CodeLocation(
            file="/var/www/html/profile.php",
            line=25,
            context='$name = $_POST["name"];'
        ),
        variable="$_POST",
        operation="source"
    )

    path = TaintPath(nodes=[sink_node, sanitize_node, source_node])

    print(f"[+] Taint path: {path}")

    # Analyze exploitability
    analysis = analyze_paths([path], vuln_type="xss", language="php")

    print(f"\n{'='*70}")
    print("VALIDATION RESULT")
    print(f"{'='*70}")
    print(f"Verdict: {analysis['verdict'].upper()}")

    if analysis['blocked_count'] > 0:
        blocked = analysis['blocked_paths'][0]
        print(f"Blocking transforms: {blocked.blocking_transforms}")
        print("\n[+] FALSE POSITIVE DETECTED")
        print("Reason: Output is HTML-encoded before display")


def example_4_multiple_paths_mixed():
    """
    Example 4: Multiple Paths with Mixed Results

    Scenario: A variable can be reached via two paths:
    - Path 1: $_GET['id'] → intval() → $safe_id → sink (BLOCKED)
    - Path 2: $_POST['id'] → $unsafe_id → sink (EXPLOITABLE)

    Expected result: EXPLOITABLE (at least one path is exploitable)
    """
    print("\n" + "=" * 70)
    print("Example 4: Multiple Paths - Mixed Results")
    print("=" * 70)

    files = create_example_files()

    sink_location = CodeLocation(
        file="/var/www/html/search.php",
        line=50,
        context='mysql_query("SELECT * FROM items WHERE id = $id");',
        function="mysql_query"
    )

    print(f"\nSink Location: {sink_location.file}:{sink_location.line}")

    # Path 1: Sanitized via intval() - FALSE POSITIVE
    path1_nodes = [
        TaintNode(
            location=sink_location,
            variable="$id",
            operation="sink"
        ),
        TaintNode(
            location=CodeLocation(file=sink_location.file, line=45),
            variable="$safe_id",
            transform="intval"
        ),
        TaintNode(
            location=CodeLocation(file=sink_location.file, line=42),
            variable="$_GET",
            operation="source"
        ),
    ]
    path1 = TaintPath(nodes=path1_nodes)

    # Path 2: Direct from POST - EXPLOITABLE
    path2_nodes = [
        TaintNode(
            location=sink_location,
            variable="$id",
            operation="sink"
        ),
        TaintNode(
            location=CodeLocation(file=sink_location.file, line=47),
            variable="$unsafe_id",
            operation="assignment"
        ),
        TaintNode(
            location=CodeLocation(file=sink_location.file, line=44),
            variable="$_POST",
            operation="source"
        ),
    ]
    path2 = TaintPath(nodes=path2_nodes)

    paths = [path1, path2]

    print(f"\n[*] Found {len(paths)} data flow paths")
    print(f"\nPath 1: {path1}")
    print(f"Path 2: {path2}")

    # Analyze exploitability
    analysis = analyze_paths(paths, vuln_type="sql", language="php")

    print(f"\n{'='*70}")
    print("VALIDATION RESULT")
    print(f"{'='*70}")
    print(f"Total paths: {analysis['total_paths']}")
    print(f"Exploitable paths: {analysis['exploitable_count']}")
    print(f"Blocked paths: {analysis['blocked_count']}")
    print(f"Verdict: {analysis['verdict'].upper()}")

    print("\n[!] CONFIRMED VULNERABILITY")
    print("Reason: While one path is sanitized, another path bypasses sanitization")
    print("Recommendation: ALL input paths must be sanitized, not just some")
    print("\nExploitable via: $_POST['id'] parameter (Path 2)")


def main():
    """Run all examples."""
    print("\n" + "#" * 70)
    print("# Backward Taint Analysis Utility - Usage Examples")
    print("#" * 70)

    example_1_vulnerable_sqli()
    example_2_sanitized_sqli()
    example_3_xss_blocked()
    example_4_multiple_paths_mixed()

    print("\n" + "#" * 70)
    print("# Summary")
    print("#" * 70)
    print("""
The taint analysis utility helps the Validation Agent (Phase 4) to:

1. Trace data flow from sink back to sources
2. Identify sanitization functions that might block exploitation
3. Reduce false positives by detecting proper input validation
4. Handle multiple input paths (confirming if ANY path is exploitable)

This saves manual analysis time and improves accuracy of vulnerability reports.
""")


if __name__ == "__main__":
    main()
