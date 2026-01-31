"""Tests for file_size_gate — BeforeTool hook for context overflow prevention."""

import sys
from pathlib import Path

import pytest

# Add hooks to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "infrastructure" / "PrEP" / "hooks"))

from file_size_gate import (
    check_file,
    count_lines,
    extract_paths_from_input,
    has_force_override,
    MAX_LINES,
    MAX_KB,
)


# =============================================================================
# count_lines
# =============================================================================


class TestCountLines:
    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        assert count_lines(str(f)) == 0

    def test_small_file(self, tmp_path):
        f = tmp_path / "small.txt"
        f.write_text("line1\nline2\nline3\n")
        assert count_lines(str(f)) == 3

    def test_nonexistent_file(self):
        assert count_lines("/nonexistent/file/path.txt") == 0


# =============================================================================
# check_file
# =============================================================================


class TestCheckFile:
    def test_small_file_passes(self, tmp_path):
        f = tmp_path / "small.txt"
        f.write_text("hello world\n" * 10)
        ok, reason = check_file(str(f))
        assert ok is True
        assert reason == ""

    def test_large_file_blocked(self, tmp_path):
        f = tmp_path / "big.txt"
        # Write enough lines to exceed threshold
        content = "\n".join(f"line {i}" for i in range(MAX_LINES + 100))
        f.write_text(content)
        ok, reason = check_file(str(f))
        assert ok is False
        assert "lines" in reason
        assert "head" in reason  # Should suggest head/grep

    def test_nonexistent_file_passes(self):
        """Nonexistent files should pass through — let the tool report the error."""
        ok, reason = check_file("/nonexistent/path.txt")
        assert ok is True

    def test_large_byte_size_blocked(self, tmp_path):
        f = tmp_path / "blob.bin"
        # Create a file larger than MAX_KB
        f.write_bytes(b"x" * (MAX_KB * 1024 + 1))
        ok, reason = check_file(str(f))
        assert ok is False


# =============================================================================
# extract_paths_from_input
# =============================================================================


class TestExtractPathsFromInput:
    def test_read_file(self):
        paths = extract_paths_from_input("read_file", {"path": "/tmp/test.txt"})
        assert paths == ["/tmp/test.txt"]

    def test_read_many_files(self):
        paths = extract_paths_from_input(
            "read_many_files", {"paths": ["/a.txt", "/b.txt"]}
        )
        assert paths == ["/a.txt", "/b.txt"]

    def test_shell_cat(self):
        paths = extract_paths_from_input(
            "Shell", {"command": "cat /etc/passwd"}
        )
        assert paths == ["/etc/passwd"]

    def test_shell_cat_with_sudo(self):
        paths = extract_paths_from_input(
            "bash", {"command": "sudo cat /etc/shadow"}
        )
        assert paths == ["/etc/shadow"]

    def test_unrelated_tool(self):
        paths = extract_paths_from_input("google_web_search", {"query": "test"})
        assert paths == []

    def test_empty_input(self):
        paths = extract_paths_from_input("read_file", {})
        assert paths == []


# =============================================================================
# has_force_override
# =============================================================================


class TestHasForceOverride:
    def test_force_true_boolean(self):
        assert has_force_override({"force": True}) is True

    def test_force_true_string(self):
        assert has_force_override({"force": "true"}) is True

    def test_force_false(self):
        assert has_force_override({"force": False}) is False

    def test_no_force(self):
        assert has_force_override({"path": "/tmp/test.txt"}) is False

    def test_force_in_serialized(self):
        assert has_force_override({"command": "read force=true /big.txt"}) is True
