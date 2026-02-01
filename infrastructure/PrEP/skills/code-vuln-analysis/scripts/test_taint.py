#!/usr/bin/env python3
"""
Test suite for backward taint analysis utility.

Run with: uv run pytest scripts/test_taint.py -v
"""

import pytest
from pathlib import Path
from typing import Dict

from taint import (
    TaintNode,
    TaintPath,
    backward_taint,
    find_transforms,
    is_sanitizer,
    validate_path_exploitability,
    analyze_paths,
    detect_language,
    is_user_input,
    extract_variable_name,
    identify_transform,
)
from prioritize import CodeLocation, SinkType
from chunker import FileInfo


class TestLanguageDetection:
    """Test language detection from file extensions."""

    def test_php_detection(self):
        assert detect_language("/var/www/admin.php") == "php"
        assert detect_language("test.PHP") == "php"

    def test_python_detection(self):
        assert detect_language("/app/views.py") == "python"

    def test_javascript_detection(self):
        assert detect_language("app.js") == "javascript"
        assert detect_language("component.jsx") == "javascript"
        assert detect_language("api.ts") == "javascript"
        assert detect_language("view.tsx") == "javascript"

    def test_unknown_extension(self):
        assert detect_language("readme.txt") == "unknown"


class TestUserInputDetection:
    """Test user input source pattern matching."""

    def test_php_get_input(self):
        context = "$user_id = $_GET['id'];"
        assert is_user_input("$user_id", context, "php")

    def test_php_post_input(self):
        context = "$data = $_POST['data'];"
        assert is_user_input("$data", context, "php")

    def test_python_request_args(self):
        context = "user_id = request.args.get('id')"
        assert is_user_input("user_id", context, "python")

    def test_python_request_json(self):
        context = "data = request.json"
        assert is_user_input("data", context, "python")

    def test_javascript_req_query(self):
        context = "const userId = req.query.id"
        assert is_user_input("userId", context, "javascript")

    def test_javascript_req_body(self):
        context = "const data = req.body.data"
        assert is_user_input("data", context, "javascript")

    def test_not_user_input(self):
        context = "$config_value = 'hardcoded';"
        assert not is_user_input("$config_value", context, "php")


class TestVariableExtraction:
    """Test variable name extraction from expressions."""

    def test_php_simple_variable(self):
        assert extract_variable_name("$user", "php") == "$user"

    def test_php_object_property(self):
        assert extract_variable_name("$user->name", "php") == "$user"

    def test_php_array_access(self):
        assert extract_variable_name("$data['key']", "php") == "$data"

    def test_python_simple_variable(self):
        assert extract_variable_name("user", "python") == "user"

    def test_python_object_attribute(self):
        assert extract_variable_name("user.name", "python") == "user"

    def test_javascript_simple_variable(self):
        assert extract_variable_name("user", "javascript") == "user"

    def test_javascript_object_property(self):
        assert extract_variable_name("req.body", "javascript") == "req"


class TestTransformIdentification:
    """Test sanitization function detection."""

    def test_php_htmlspecialchars(self):
        code = "echo htmlspecialchars($user_input);"
        assert identify_transform(code, "php") == "htmlspecialchars"

    def test_php_int_cast(self):
        code = "$id = (int)$_GET['id'];"
        assert identify_transform(code, "php") == "(int)"

    def test_python_html_escape(self):
        code = "output = html.escape(user_input)"
        assert identify_transform(code, "python") == "html.escape"

    def test_python_int_cast(self):
        code = "user_id = int(request.args.get('id'))"
        assert identify_transform(code, "python") == "int("

    def test_javascript_encode_uri(self):
        code = "const url = encodeURIComponent(userInput);"
        assert identify_transform(code, "javascript") == "encodeURIComponent"

    def test_no_transform(self):
        code = "$unsafe = $user_input;"
        assert identify_transform(code, "php") is None


class TestSanitizerValidation:
    """Test sanitizer function validation."""

    def test_php_xss_sanitizer(self):
        assert is_sanitizer("htmlspecialchars", "xss", "php")

    def test_php_sql_sanitizer(self):
        assert is_sanitizer("mysqli_real_escape_string", "sql", "php")

    def test_php_code_execution_sanitizer(self):
        assert is_sanitizer("escapeshellarg", "code_execution", "php")

    def test_python_xss_sanitizer(self):
        assert is_sanitizer("html.escape", "xss", "python")

    def test_javascript_xss_sanitizer(self):
        assert is_sanitizer("encodeURIComponent", "xss", "javascript")

    def test_not_a_sanitizer(self):
        assert not is_sanitizer("strlen", "sql", "php")

    def test_wrong_vuln_type(self):
        # htmlspecialchars doesn't sanitize SQL
        assert not is_sanitizer("htmlspecialchars", "sql", "php")


class TestTaintNode:
    """Test TaintNode dataclass."""

    def test_node_creation(self):
        location = CodeLocation(file="test.php", line=42, context="$x = $y;")
        node = TaintNode(
            location=location,
            variable="$x",
            operation="assignment"
        )

        assert node.variable == "$x"
        assert node.location.line == 42
        assert node.operation == "assignment"
        assert node.transform is None
        assert node.confidence == 1.0

    def test_node_with_transform(self):
        location = CodeLocation(file="test.php", line=42)
        node = TaintNode(
            location=location,
            variable="$x",
            transform="htmlspecialchars"
        )

        assert node.transform == "htmlspecialchars"

    def test_node_equality(self):
        loc1 = CodeLocation(file="test.php", line=42)
        node1 = TaintNode(location=loc1, variable="$x")

        loc2 = CodeLocation(file="test.php", line=42)
        node2 = TaintNode(location=loc2, variable="$x")

        assert node1 == node2

    def test_node_hash(self):
        loc = CodeLocation(file="test.php", line=42)
        node1 = TaintNode(location=loc, variable="$x")
        node2 = TaintNode(location=loc, variable="$x")

        assert hash(node1) == hash(node2)


class TestTaintPath:
    """Test TaintPath dataclass."""

    def test_empty_path(self):
        path = TaintPath()
        assert path.source is None
        assert path.sink is None
        assert str(path) == "Empty path"

    def test_path_with_nodes(self):
        sink_loc = CodeLocation(file="test.php", line=10)
        sink_node = TaintNode(location=sink_loc, variable="$dangerous")

        source_loc = CodeLocation(file="test.php", line=5)
        source_node = TaintNode(location=source_loc, variable="$_GET")

        path = TaintPath(nodes=[sink_node, source_node])

        assert path.sink == sink_node
        assert path.source == source_node

    def test_path_string_representation(self):
        sink_loc = CodeLocation(file="test.php", line=10)
        sink_node = TaintNode(location=sink_loc, variable="$dangerous")

        middle_loc = CodeLocation(file="test.php", line=7)
        middle_node = TaintNode(
            location=middle_loc,
            variable="$sanitized",
            transform="htmlspecialchars"
        )

        source_loc = CodeLocation(file="test.php", line=5)
        source_node = TaintNode(location=source_loc, variable="$_GET")

        path = TaintPath(nodes=[sink_node, middle_node, source_node])
        path_str = str(path)

        # Should show source → sink with transforms
        assert "$_GET" in path_str
        assert "$dangerous" in path_str
        assert "htmlspecialchars" in path_str


class TestFindTransforms:
    """Test transformation extraction from paths."""

    def test_no_transforms(self):
        loc1 = CodeLocation(file="test.php", line=5)
        node1 = TaintNode(location=loc1, variable="$_GET")

        loc2 = CodeLocation(file="test.php", line=10)
        node2 = TaintNode(location=loc2, variable="$dangerous")

        path = TaintPath(nodes=[node2, node1])
        transforms = find_transforms(path)

        assert len(transforms) == 0

    def test_single_transform(self):
        loc1 = CodeLocation(file="test.php", line=5)
        node1 = TaintNode(location=loc1, variable="$_GET")

        loc2 = CodeLocation(file="test.php", line=7)
        node2 = TaintNode(
            location=loc2,
            variable="$sanitized",
            transform="htmlspecialchars"
        )

        loc3 = CodeLocation(file="test.php", line=10)
        node3 = TaintNode(location=loc3, variable="$output")

        path = TaintPath(nodes=[node3, node2, node1])
        transforms = find_transforms(path)

        assert len(transforms) == 1
        assert "htmlspecialchars" in transforms

    def test_multiple_transforms(self):
        nodes = [
            TaintNode(
                location=CodeLocation(file="test.php", line=10),
                variable="$final"
            ),
            TaintNode(
                location=CodeLocation(file="test.php", line=8),
                variable="$int_val",
                transform="intval"
            ),
            TaintNode(
                location=CodeLocation(file="test.php", line=6),
                variable="$trimmed",
                transform="trim"
            ),
            TaintNode(
                location=CodeLocation(file="test.php", line=5),
                variable="$_GET"
            ),
        ]

        path = TaintPath(nodes=nodes)
        transforms = find_transforms(path)

        assert len(transforms) == 2
        assert "intval" in transforms
        assert "trim" in transforms


class TestPathExploitability:
    """Test path exploitability validation."""

    def test_exploitable_path_no_sanitization(self):
        nodes = [
            TaintNode(
                location=CodeLocation(file="test.php", line=10),
                variable="$dangerous"
            ),
            TaintNode(
                location=CodeLocation(file="test.php", line=5),
                variable="$_GET"
            ),
        ]

        path = TaintPath(nodes=nodes)
        is_exploitable, blockers = validate_path_exploitability(path, "sql", "php")

        assert is_exploitable
        assert len(blockers) == 0

    def test_blocked_path_with_sanitization(self):
        nodes = [
            TaintNode(
                location=CodeLocation(file="test.php", line=10),
                variable="$query"
            ),
            TaintNode(
                location=CodeLocation(file="test.php", line=7),
                variable="$safe_id",
                transform="intval"
            ),
            TaintNode(
                location=CodeLocation(file="test.php", line=5),
                variable="$_GET"
            ),
        ]

        path = TaintPath(nodes=nodes)
        is_exploitable, blockers = validate_path_exploitability(path, "sql", "php")

        assert not is_exploitable
        assert "intval" in blockers

    def test_xss_blocked_by_htmlspecialchars(self):
        nodes = [
            TaintNode(
                location=CodeLocation(file="test.php", line=10),
                variable="$output"
            ),
            TaintNode(
                location=CodeLocation(file="test.php", line=7),
                variable="$safe_html",
                transform="htmlspecialchars"
            ),
            TaintNode(
                location=CodeLocation(file="test.php", line=5),
                variable="$_POST"
            ),
        ]

        path = TaintPath(nodes=nodes)
        is_exploitable, blockers = validate_path_exploitability(path, "xss", "php")

        assert not is_exploitable
        assert "htmlspecialchars" in blockers


class TestAnalyzePaths:
    """Test path analysis aggregation."""

    def test_all_paths_exploitable(self):
        path1 = TaintPath(nodes=[
            TaintNode(location=CodeLocation(file="test.php", line=10), variable="$a"),
            TaintNode(location=CodeLocation(file="test.php", line=5), variable="$_GET"),
        ])

        path2 = TaintPath(nodes=[
            TaintNode(location=CodeLocation(file="test.php", line=10), variable="$a"),
            TaintNode(location=CodeLocation(file="test.php", line=3), variable="$_POST"),
        ])

        analysis = analyze_paths([path1, path2], "sql", "php")

        assert analysis["total_paths"] == 2
        assert analysis["exploitable_count"] == 2
        assert analysis["blocked_count"] == 0
        assert analysis["verdict"] == "exploitable"

    def test_all_paths_blocked(self):
        path1 = TaintPath(nodes=[
            TaintNode(location=CodeLocation(file="test.php", line=10), variable="$query"),
            TaintNode(
                location=CodeLocation(file="test.php", line=7),
                variable="$safe",
                transform="intval"
            ),
            TaintNode(location=CodeLocation(file="test.php", line=5), variable="$_GET"),
        ])

        analysis = analyze_paths([path1], "sql", "php")

        assert analysis["total_paths"] == 1
        assert analysis["exploitable_count"] == 0
        assert analysis["blocked_count"] == 1
        assert analysis["verdict"] == "false_positive"

    def test_mixed_paths(self):
        exploitable_path = TaintPath(nodes=[
            TaintNode(location=CodeLocation(file="test.php", line=10), variable="$a"),
            TaintNode(location=CodeLocation(file="test.php", line=5), variable="$_GET"),
        ])

        blocked_path = TaintPath(nodes=[
            TaintNode(location=CodeLocation(file="test.php", line=10), variable="$a"),
            TaintNode(
                location=CodeLocation(file="test.php", line=7),
                variable="$safe",
                transform="intval"
            ),
            TaintNode(location=CodeLocation(file="test.php", line=3), variable="$_POST"),
        ])

        analysis = analyze_paths([exploitable_path, blocked_path], "sql", "php")

        # If ANY path is exploitable, verdict should be exploitable
        assert analysis["total_paths"] == 2
        assert analysis["exploitable_count"] == 1
        assert analysis["blocked_count"] == 1
        assert analysis["verdict"] == "exploitable"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
