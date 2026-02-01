#!/usr/bin/env python3
"""
Test suite for dependencies.py
==============================

Tests dependency graph building across PHP, Python, and JavaScript/TypeScript.
"""

import pytest
import tempfile
import os
from pathlib import Path
import yaml

from dependencies import (
    parse_imports,
    build_dependency_graph,
    to_yaml,
    detect_language,
    resolve_path,
    get_reverse_dependencies,
    find_dependency_cycles,
)


class TestLanguageDetection:
    """Test language detection from file extensions."""

    def test_php_extensions(self):
        assert detect_language("file.php") == "php"
        assert detect_language("file.phtml") == "php"
        assert detect_language("file.php5") == "php"

    def test_python_extensions(self):
        assert detect_language("file.py") == "python"
        assert detect_language("file.pyw") == "python"

    def test_javascript_extensions(self):
        assert detect_language("file.js") == "javascript"
        assert detect_language("file.jsx") == "javascript"
        assert detect_language("file.mjs") == "javascript"

    def test_typescript_extensions(self):
        assert detect_language("file.ts") == "typescript"
        assert detect_language("file.tsx") == "typescript"

    def test_unknown_extension(self):
        assert detect_language("file.txt") is None
        assert detect_language("file.exe") is None


class TestPHPImports:
    """Test PHP import/include parsing."""

    def test_include(self, tmp_path):
        file = tmp_path / "test.php"
        file.write_text("""<?php
include 'config.php';
include("database.php");
include 'lib/utils.php';
?>""")
        imports = parse_imports(str(file), "php")
        assert "config.php" in imports
        assert "database.php" in imports
        assert "lib/utils.php" in imports

    def test_include_once(self, tmp_path):
        file = tmp_path / "test.php"
        file.write_text("""<?php
include_once 'header.php';
include_once("footer.php");
?>""")
        imports = parse_imports(str(file), "php")
        assert "header.php" in imports
        assert "footer.php" in imports

    def test_require(self, tmp_path):
        file = tmp_path / "test.php"
        file.write_text("""<?php
require 'config.php';
require("init.php");
?>""")
        imports = parse_imports(str(file), "php")
        assert "config.php" in imports
        assert "init.php" in imports

    def test_require_once(self, tmp_path):
        file = tmp_path / "test.php"
        file.write_text("""<?php
require_once 'vendor/autoload.php';
require_once("../common/functions.php");
?>""")
        imports = parse_imports(str(file), "php")
        assert "vendor/autoload.php" in imports
        assert "../common/functions.php" in imports

    def test_mixed_quotes(self, tmp_path):
        file = tmp_path / "test.php"
        file.write_text("""<?php
include "double.php";
include 'single.php';
include('parens.php');
include("both.php");
?>""")
        imports = parse_imports(str(file), "php")
        assert len(imports) == 4
        assert "double.php" in imports
        assert "single.php" in imports


class TestPythonImports:
    """Test Python import parsing."""

    def test_simple_import(self, tmp_path):
        file = tmp_path / "test.py"
        file.write_text("""import os
import sys
import requests
""")
        imports = parse_imports(str(file), "python")
        assert "os.py" in imports
        assert "sys.py" in imports
        assert "requests.py" in imports

    def test_from_import(self, tmp_path):
        file = tmp_path / "test.py"
        file.write_text("""from django.http import HttpResponse
from utils import helpers
from lib.database import connect
""")
        imports = parse_imports(str(file), "python")
        assert "django/http.py" in imports
        assert "utils.py" in imports
        assert "lib/database.py" in imports

    def test_relative_import(self, tmp_path):
        file = tmp_path / "test.py"
        file.write_text("""from . import utils
from .. import config
from .helpers import func
""")
        imports = parse_imports(str(file), "python")
        assert "." in imports
        assert ".." in imports
        assert ".helpers" in imports

    def test_multiline_import(self, tmp_path):
        file = tmp_path / "test.py"
        file.write_text("""import json
import yaml

from pathlib import Path
from typing import List, Dict
""")
        imports = parse_imports(str(file), "python")
        assert "json.py" in imports
        assert "yaml.py" in imports
        assert "pathlib.py" in imports
        assert "typing.py" in imports


class TestJavaScriptImports:
    """Test JavaScript/TypeScript import parsing."""

    def test_es6_import(self, tmp_path):
        file = tmp_path / "test.js"
        file.write_text("""import React from 'react';
import { useState } from 'react';
import utils from './utils';
import * as helpers from './helpers';
""")
        imports = parse_imports(str(file), "javascript")
        assert "react" in imports
        assert "./utils" in imports
        assert "./helpers" in imports

    def test_require(self, tmp_path):
        file = tmp_path / "test.js"
        file.write_text("""const express = require('express');
const router = require('./routes');
const config = require('../config/database');
""")
        imports = parse_imports(str(file), "javascript")
        assert "express" in imports
        assert "./routes" in imports
        assert "../config/database" in imports

    def test_mixed_imports(self, tmp_path):
        file = tmp_path / "test.js"
        file.write_text("""import axios from 'axios';
const db = require('./db');
import { Router } from 'express';
""")
        imports = parse_imports(str(file), "javascript")
        assert "axios" in imports
        assert "./db" in imports
        assert "express" in imports

    def test_typescript_imports(self, tmp_path):
        file = tmp_path / "test.ts"
        file.write_text("""import { Component } from '@angular/core';
import { UserService } from './services/user.service';
import type { User } from './types';
""")
        imports = parse_imports(str(file), "typescript")
        assert "@angular/core" in imports
        assert "./services/user.service" in imports
        assert "./types" in imports


class TestPathResolution:
    """Test relative and absolute path resolution."""

    def test_php_relative_path(self, tmp_path):
        # Create file structure
        main_file = tmp_path / "index.php"
        config_file = tmp_path / "config.php"
        config_file.write_text("<?php ?>")

        main_file.write_text("<?php include 'config.php'; ?>")

        result = resolve_path(
            str(main_file),
            "config.php",
            str(tmp_path),
            "php"
        )
        assert result == "config.php"

    def test_php_subdirectory(self, tmp_path):
        main_file = tmp_path / "index.php"
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        util_file = lib_dir / "utils.php"
        util_file.write_text("<?php ?>")

        result = resolve_path(
            str(main_file),
            "lib/utils.php",
            str(tmp_path),
            "php"
        )
        assert result == "lib/utils.php"

    def test_python_relative_import(self, tmp_path):
        subdir = tmp_path / "src"
        subdir.mkdir()
        main_file = subdir / "main.py"
        util_file = subdir / "utils.py"
        util_file.write_text("# utils")

        result = resolve_path(
            str(main_file),
            "./utils",
            str(tmp_path),
            "python"
        )
        assert result == "src/utils.py"

    def test_js_relative_import(self, tmp_path):
        main_file = tmp_path / "index.js"
        util_file = tmp_path / "utils.js"
        util_file.write_text("// utils")

        result = resolve_path(
            str(main_file),
            "./utils",
            str(tmp_path),
            "javascript"
        )
        assert result == "utils.js"

    def test_unresolvable_path(self, tmp_path):
        main_file = tmp_path / "index.php"
        result = resolve_path(
            str(main_file),
            "nonexistent.php",
            str(tmp_path),
            "php"
        )
        assert result is None


class TestDependencyGraph:
    """Test full dependency graph building."""

    def test_simple_php_graph(self, tmp_path):
        # Create PHP project structure
        index = tmp_path / "index.php"
        config = tmp_path / "config.php"
        db = tmp_path / "db.php"

        config.write_text("<?php ?>")
        db.write_text("<?php ?>")
        index.write_text("""<?php
require_once 'config.php';
require_once 'db.php';
?>""")

        files = [str(index), str(config), str(db)]
        graph = build_dependency_graph(files, str(tmp_path))

        assert "index.php" in graph
        assert "config.php" in graph["index.php"]
        assert "db.php" in graph["index.php"]

    def test_nested_php_dependencies(self, tmp_path):
        # Create nested structure
        index = tmp_path / "index.php"
        admin = tmp_path / "admin.php"
        config = tmp_path / "config.php"

        config.write_text("<?php ?>")
        admin.write_text("<?php include 'config.php'; ?>")
        index.write_text("<?php include 'admin.php'; ?>")

        files = [str(index), str(admin), str(config)]
        graph = build_dependency_graph(files, str(tmp_path))

        assert "index.php" in graph
        assert "admin.php" in graph["index.php"]
        assert "config.php" in graph["admin.php"]

    def test_python_project(self, tmp_path):
        # Create Python project structure
        main = tmp_path / "main.py"
        utils = tmp_path / "utils.py"
        config = tmp_path / "config.py"

        config.write_text("# config")
        utils.write_text("from . import config")
        main.write_text("import utils")

        files = [str(main), str(utils), str(config)]
        graph = build_dependency_graph(files, str(tmp_path))

        assert "main.py" in graph
        # Python imports get converted to file paths
        assert any("utils" in imp for imp in graph["main.py"])

    def test_mixed_language_project(self, tmp_path):
        # PHP and JS in same project
        index_php = tmp_path / "index.php"
        app_js = tmp_path / "app.js"
        utils_js = tmp_path / "utils.js"

        utils_js.write_text("// utils")
        app_js.write_text("import utils from './utils';")
        index_php.write_text("<?php ?>")

        files = [str(index_php), str(app_js), str(utils_js)]
        graph = build_dependency_graph(files, str(tmp_path))

        assert "app.js" in graph
        assert "utils.js" in graph["app.js"]


class TestYAMLOutput:
    """Test YAML export format."""

    def test_yaml_format(self):
        graph = {
            "admin.php": ["config.php", "db.php"],
            "index.php": ["admin.php"],
        }

        yaml_output = to_yaml(graph)
        parsed = yaml.safe_load(yaml_output)

        assert "dependency_graph" in parsed
        assert "includes" in parsed["dependency_graph"]
        includes = parsed["dependency_graph"]["includes"]

        # Find the admin.php entry
        admin_entry = next(e for e in includes if e["from"] == "admin.php")
        assert set(admin_entry["imports"]) == {"config.php", "db.php"}

        # Find the index.php entry
        index_entry = next(e for e in includes if e["from"] == "index.php")
        assert index_entry["imports"] == ["admin.php"]

    def test_empty_graph(self):
        graph = {}
        yaml_output = to_yaml(graph)
        parsed = yaml.safe_load(yaml_output)

        assert "dependency_graph" in parsed
        assert parsed["dependency_graph"]["includes"] == []


class TestReverseDependencies:
    """Test reverse dependency mapping."""

    def test_simple_reverse(self):
        graph = {
            "index.php": ["config.php", "db.php"],
            "admin.php": ["config.php"],
        }

        reverse = get_reverse_dependencies(graph)

        assert "config.php" in reverse
        assert set(reverse["config.php"]) == {"index.php", "admin.php"}
        assert reverse["db.php"] == ["index.php"]

    def test_empty_reverse(self):
        graph = {}
        reverse = get_reverse_dependencies(graph)
        assert reverse == {}


class TestCycleDetection:
    """Test circular dependency detection."""

    def test_simple_cycle(self):
        graph = {
            "a.php": ["b.php"],
            "b.php": ["c.php"],
            "c.php": ["a.php"],
        }

        cycles = find_dependency_cycles(graph)
        assert len(cycles) > 0
        # Should find the cycle a -> b -> c -> a
        assert any("a.php" in cycle and "b.php" in cycle and "c.php" in cycle
                   for cycle in cycles)

    def test_no_cycle(self):
        graph = {
            "a.php": ["b.php"],
            "b.php": ["c.php"],
            "c.php": [],
        }

        cycles = find_dependency_cycles(graph)
        assert len(cycles) == 0

    def test_self_reference(self):
        graph = {
            "a.php": ["a.php"],  # Self-referencing
        }

        cycles = find_dependency_cycles(graph)
        assert len(cycles) > 0


class TestIntegrationScenario:
    """End-to-end integration tests simulating real codebases."""

    def test_vulnerable_php_app(self, tmp_path):
        """Simulate a typical vulnerable PHP web app structure."""
        # Create realistic PHP app structure
        index = tmp_path / "index.php"
        admin = tmp_path / "admin.php"
        config = tmp_path / "config.php"
        db = tmp_path / "db.php"
        auth = tmp_path / "auth.php"

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
        graph = build_dependency_graph(files, str(tmp_path))

        # Verify graph structure
        assert "index.php" in graph
        assert "config.php" in graph["index.php"]
        assert "db.php" in graph["index.php"]

        # Test reverse dependencies
        reverse = get_reverse_dependencies(graph)
        config_importers = set(reverse.get("config.php", []))
        assert "index.php" in config_importers

        # Export to YAML
        yaml_output = to_yaml(graph)
        assert "dependency_graph" in yaml_output
        assert "includes" in yaml_output

    def test_python_flask_app(self, tmp_path):
        """Simulate a Flask application structure."""
        app = tmp_path / "app.py"
        models = tmp_path / "models.py"
        views = tmp_path / "views.py"
        utils = tmp_path / "utils.py"

        utils.write_text("# Utility functions")
        models.write_text("from . import utils")
        views.write_text("from . import models")
        app.write_text("""import views
import models
import utils
""")

        files = [str(f) for f in [app, models, views, utils]]
        graph = build_dependency_graph(files, str(tmp_path))

        # Should have captured the imports
        assert "app.py" in graph
        assert len(graph["app.py"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
