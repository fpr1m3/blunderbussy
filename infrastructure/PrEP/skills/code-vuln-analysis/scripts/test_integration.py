#!/usr/bin/env python3
"""
Integration test between dependencies.py and chunker.py
========================================================

Verifies that dependency graph output from dependencies.py can be
consumed by chunker.py as expected (lines 436-451).
"""

import tempfile
import yaml
from pathlib import Path

from dependencies import build_dependency_graph, to_yaml


def test_yaml_format_matches_chunker_expectations():
    """
    Test that our YAML output matches what chunker.py expects.

    From chunker.py lines 436-451:
        for entry in recon_data["dependency_graph"].get("includes", []):
            from_file = entry.get("from", "")
            imports = entry.get("imports", [])
    """
    print("Testing YAML format compatibility with chunker.py...")

    # Create test dependency graph
    graph = {
        "admin.php": ["config.php", "db.php"],
        "index.php": ["admin.php", "config.php"],
    }

    # Export to YAML
    yaml_output = to_yaml(graph)
    print(f"\nGenerated YAML:\n{yaml_output}")

    # Parse it back (simulating what chunker.py does)
    recon_data = yaml.safe_load(yaml_output)

    # Verify structure matches chunker.py expectations
    assert "dependency_graph" in recon_data, "Missing 'dependency_graph' key"
    assert "includes" in recon_data["dependency_graph"], "Missing 'includes' key"

    includes = recon_data["dependency_graph"]["includes"]
    assert isinstance(includes, list), "'includes' should be a list"

    # Verify each entry has expected keys
    for entry in includes:
        assert "from" in entry, "Entry missing 'from' key"
        assert "imports" in entry, "Entry missing 'imports' key"

        from_file = entry.get("from", "")
        imports = entry.get("imports", [])

        assert isinstance(from_file, str), "'from' should be a string"
        assert isinstance(imports, list), "'imports' should be a list"

        print(f"  ✓ Entry: {from_file} -> {imports}")

    print("\n✓ YAML format matches chunker.py expectations")


def test_realistic_integration():
    """
    Test full integration: create files, build graph, verify chunker can use it.
    """
    print("\n" + "=" * 60)
    print("Testing realistic integration scenario...")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create realistic PHP app structure
        files = {
            "index.php": """<?php
require_once 'config.php';
include 'db.php';
include 'admin.php';
?>""",
            "admin.php": """<?php
require 'auth.php';
?>""",
            "auth.php": """<?php
include 'db.php';
?>""",
            "db.php": """<?php
require_once 'config.php';
?>""",
            "config.php": """<?php
define('DB_HOST', 'localhost');
?>"""
        }

        # Write files
        file_paths = []
        for filename, content in files.items():
            filepath = Path(tmpdir) / filename
            filepath.write_text(content)
            file_paths.append(str(filepath))

        # Build dependency graph
        graph = build_dependency_graph(file_paths, tmpdir)
        print(f"\nBuilt graph for {len(graph)} files:")
        for file, deps in sorted(graph.items()):
            print(f"  {file} -> {deps}")

        # Export to YAML
        yaml_output = to_yaml(graph)

        # Simulate what chunker.py does (lines 436-451)
        recon_data = yaml.safe_load(yaml_output)
        dependency_graph = {}

        for entry in recon_data["dependency_graph"].get("includes", []):
            from_file = entry.get("from", "")
            imports = entry.get("imports", [])
            dependency_graph[from_file] = imports

        print(f"\nChunker-style dependency graph:")
        for file, deps in sorted(dependency_graph.items()):
            print(f"  {file} -> {deps}")

        # Verify critical relationships
        assert "index.php" in dependency_graph
        assert "admin.php" in dependency_graph["index.php"]
        assert "config.php" in dependency_graph["index.php"]

        print("\n✓ Integration test passed - chunker.py can consume our output")


def test_empty_graph():
    """Test that empty graph is handled correctly."""
    print("\n" + "=" * 60)
    print("Testing empty graph handling...")
    print("=" * 60)

    graph = {}
    yaml_output = to_yaml(graph)
    recon_data = yaml.safe_load(yaml_output)

    assert "dependency_graph" in recon_data
    assert recon_data["dependency_graph"]["includes"] == []

    # Simulate chunker.py processing
    dependency_graph = {}
    for entry in recon_data["dependency_graph"].get("includes", []):
        from_file = entry.get("from", "")
        imports = entry.get("imports", [])
        dependency_graph[from_file] = imports

    assert dependency_graph == {}
    print("✓ Empty graph handled correctly")


def test_schema_compliance():
    """
    Verify output matches SKILL.md schema (lines 70-76).

    Expected format:
        dependency_graph:
          includes:
            - from: admin.php
              imports: [config.php, db.php]
    """
    print("\n" + "=" * 60)
    print("Testing SKILL.md schema compliance...")
    print("=" * 60)

    # Build a simple graph
    graph = {
        "admin.php": ["config.php", "db.php"],
    }

    yaml_output = to_yaml(graph)
    print(f"\nGenerated YAML:\n{yaml_output}")

    # Verify format matches SKILL.md spec
    lines = yaml_output.split('\n')
    assert any("dependency_graph:" in line for line in lines), "Missing 'dependency_graph:'"
    assert any("includes:" in line for line in lines), "Missing 'includes:'"
    assert any("from: admin.php" in line for line in lines), "Missing 'from:' field"
    assert any("imports:" in line for line in lines), "Missing 'imports:' field"

    # Verify it matches the expected structure
    recon_data = yaml.safe_load(yaml_output)
    includes = recon_data["dependency_graph"]["includes"]

    admin_entry = includes[0]
    assert admin_entry["from"] == "admin.php"
    assert set(admin_entry["imports"]) == {"config.php", "db.php"}

    print("✓ Output matches SKILL.md schema specification")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Integration Tests: dependencies.py <-> chunker.py")
    print("=" * 60)

    try:
        test_yaml_format_matches_chunker_expectations()
        test_realistic_integration()
        test_empty_graph()
        test_schema_compliance()

        print("\n" + "=" * 60)
        print("All integration tests passed! ✓")
        print("=" * 60)
        print("\nThe dependency graph builder is ready for use by:")
        print("  1. Recon agent (generates YAML)")
        print("  2. Chunker (consumes YAML via lines 436-451)")
        print("  3. Triage agent (uses graph for file grouping)")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
