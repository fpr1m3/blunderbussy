#!/usr/bin/env python3
"""
Manual testing script for dependencies.py
"""

import tempfile
import os
from pathlib import Path
from dependencies import (
    parse_imports,
    build_dependency_graph,
    to_yaml,
    detect_language,
    get_reverse_dependencies,
    find_dependency_cycles,
)


def test_language_detection():
    print("Testing language detection...")
    assert detect_language("test.php") == "php"
    assert detect_language("test.py") == "python"
    assert detect_language("test.js") == "javascript"
    assert detect_language("test.ts") == "typescript"
    assert detect_language("test.txt") is None
    print("✓ Language detection passed")


def test_php_parsing():
    print("\nTesting PHP import parsing...")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
        f.write("""<?php
require_once 'config.php';
include 'db.php';
include_once("auth.php");
require "utils.php";
?>""")
        f.flush()

        imports = parse_imports(f.name, "php")
        os.unlink(f.name)

        assert "config.php" in imports
        assert "db.php" in imports
        assert "auth.php" in imports
        assert "utils.php" in imports
        print(f"  Found imports: {imports}")
        print("✓ PHP parsing passed")


def test_python_parsing():
    print("\nTesting Python import parsing...")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("""import os
import sys
from django.http import HttpResponse
from utils import helper
from . import config
""")
        f.flush()

        imports = parse_imports(f.name, "python")
        os.unlink(f.name)

        assert "os.py" in imports
        assert "sys.py" in imports
        assert "django/http.py" in imports
        assert "utils.py" in imports
        assert "." in imports
        print(f"  Found imports: {imports}")
        print("✓ Python parsing passed")


def test_js_parsing():
    print("\nTesting JavaScript import parsing...")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write("""import React from 'react';
import utils from './utils';
const express = require('express');
const router = require('./routes');
""")
        f.flush()

        imports = parse_imports(f.name, "javascript")
        os.unlink(f.name)

        assert "react" in imports
        assert "./utils" in imports
        assert "express" in imports
        assert "./routes" in imports
        print(f"  Found imports: {imports}")
        print("✓ JavaScript parsing passed")


def test_dependency_graph():
    print("\nTesting dependency graph building...")
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        index = Path(tmpdir) / "index.php"
        admin = Path(tmpdir) / "admin.php"
        config = Path(tmpdir) / "config.php"

        config.write_text("<?php ?>")
        admin.write_text("<?php include 'config.php'; ?>")
        index.write_text("<?php require 'admin.php'; include 'config.php'; ?>")

        files = [str(index), str(admin), str(config)]
        graph = build_dependency_graph(files, tmpdir)

        print(f"  Graph: {graph}")
        assert "index.php" in graph
        assert "admin.php" in graph["index.php"]
        assert "config.php" in graph["index.php"]
        assert "config.php" in graph["admin.php"]
        print("✓ Dependency graph building passed")


def test_yaml_output():
    print("\nTesting YAML output...")
    graph = {
        "index.php": ["config.php", "db.php"],
        "admin.php": ["config.php"],
    }

    yaml_output = to_yaml(graph)
    print(f"  YAML output:\n{yaml_output}")

    assert "dependency_graph:" in yaml_output
    assert "includes:" in yaml_output
    assert "from: index.php" in yaml_output
    assert "imports:" in yaml_output
    print("✓ YAML output passed")


def test_reverse_dependencies():
    print("\nTesting reverse dependencies...")
    graph = {
        "index.php": ["config.php", "db.php"],
        "admin.php": ["config.php"],
    }

    reverse = get_reverse_dependencies(graph)
    print(f"  Reverse dependencies: {reverse}")

    assert "config.php" in reverse
    assert set(reverse["config.php"]) == {"index.php", "admin.php"}
    assert reverse["db.php"] == ["index.php"]
    print("✓ Reverse dependencies passed")


def test_cycle_detection():
    print("\nTesting cycle detection...")

    # Graph with cycle
    graph_with_cycle = {
        "a.php": ["b.php"],
        "b.php": ["c.php"],
        "c.php": ["a.php"],
    }

    cycles = find_dependency_cycles(graph_with_cycle)
    print(f"  Cycles found: {cycles}")
    assert len(cycles) > 0
    print("✓ Cycle detection (with cycle) passed")

    # Graph without cycle
    graph_no_cycle = {
        "a.php": ["b.php"],
        "b.php": ["c.php"],
    }

    cycles = find_dependency_cycles(graph_no_cycle)
    print(f"  Cycles found: {cycles}")
    assert len(cycles) == 0
    print("✓ Cycle detection (no cycle) passed")


def test_realistic_scenario():
    print("\nTesting realistic PHP web app scenario...")
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create realistic structure
        index = Path(tmpdir) / "index.php"
        admin = Path(tmpdir) / "admin.php"
        config = Path(tmpdir) / "config.php"
        db = Path(tmpdir) / "db.php"
        auth = Path(tmpdir) / "auth.php"

        config.write_text("<?php define('DB_HOST', 'localhost'); ?>")
        db.write_text("<?php require_once 'config.php'; ?>")
        auth.write_text("<?php include 'db.php'; ?>")
        admin.write_text("<?php require 'auth.php'; ?>")
        index.write_text("""<?php
require_once 'config.php';
include 'db.php';
include 'admin.php';
?>""")

        files = [str(f) for f in [index, admin, config, db, auth]]
        graph = build_dependency_graph(files, tmpdir)

        print(f"  Graph structure:")
        for file, deps in sorted(graph.items()):
            print(f"    {file} -> {deps}")

        # Verify expected relationships
        assert "index.php" in graph
        assert "config.php" in graph["index.php"]

        # Get reverse dependencies
        reverse = get_reverse_dependencies(graph)
        config_importers = reverse.get("config.php", [])
        print(f"  Files that import config.php: {config_importers}")

        # Export to YAML
        yaml_output = to_yaml(graph)
        assert "dependency_graph" in yaml_output

        print("✓ Realistic scenario passed")


if __name__ == "__main__":
    print("=" * 60)
    print("Running manual tests for dependencies.py")
    print("=" * 60)

    try:
        test_language_detection()
        test_php_parsing()
        test_python_parsing()
        test_js_parsing()
        test_dependency_graph()
        test_yaml_output()
        test_reverse_dependencies()
        test_cycle_detection()
        test_realistic_scenario()

        print("\n" + "=" * 60)
        print("All tests passed! ✓")
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
