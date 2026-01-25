"""Tests for infrastructure/PrEP/hooks/shellcheck_validator.py"""

import json
import pytest
import subprocess
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add hooks to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "infrastructure" / "PrEP" / "hooks"))

from shellcheck_validator import (
    format_error,
    run_shellcheck,
    main,
    SHELL_TOOLS,
    MAX_ERRORS,
)


class TestFormatError:
    """Tests for format_error() function."""

    def test_formats_basic_error(self):
        """Should format error with code, message, line."""
        error = {
            "code": 2086,
            "message": "Double quote to prevent globbing",
            "line": 5,
            "column": 10,
        }
        result = format_error(error)
        assert "SC2086" in result
        assert "line 5" in result
        assert "col 10" in result
        assert "Double quote" in result

    def test_includes_wiki_link(self):
        """Should include shellcheck wiki link."""
        error = {"code": 2086, "message": "test", "line": 1}
        result = format_error(error)
        assert "https://www.shellcheck.net/wiki/SC2086" in result

    def test_handles_missing_column(self):
        """Should handle missing column gracefully."""
        error = {"code": 2086, "message": "test", "line": 1}
        result = format_error(error)
        assert "line 1" in result
        assert "col" not in result

    def test_handles_missing_fields(self):
        """Should handle missing fields gracefully."""
        error = {}
        result = format_error(error)
        assert "Unknown error" in result


class TestRunShellcheck:
    """Tests for run_shellcheck() function."""

    def test_empty_command_returns_valid(self):
        """Empty command should be considered valid."""
        is_valid, msg = run_shellcheck("")
        assert is_valid is True
        assert msg == ""

    def test_whitespace_command_returns_valid(self):
        """Whitespace-only command should be considered valid."""
        is_valid, msg = run_shellcheck("   \n\t  ")
        assert is_valid is True

    @patch('shellcheck_validator.subprocess.run')
    def test_valid_command_returns_true(self, mock_run):
        """Valid command should return (True, '')."""
        mock_run.return_value = MagicMock(returncode=0)

        is_valid, msg = run_shellcheck("echo 'hello'")
        assert is_valid is True
        assert msg == ""

    @patch('shellcheck_validator.subprocess.run')
    def test_invalid_command_returns_false(self, mock_run):
        """Invalid command should return (False, message)."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps([{
                "code": 2086,
                "message": "Double quote to prevent globbing",
                "line": 2,  # After shebang
                "column": 1,
            }])
        )

        is_valid, msg = run_shellcheck("echo $unquoted")
        assert is_valid is False
        assert "SC2086" in msg

    @patch('shellcheck_validator.subprocess.run')
    def test_adjusts_line_numbers_for_shebang(self, mock_run):
        """Should adjust line numbers to account for added shebang."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps([{
                "code": 2086,
                "message": "test",
                "line": 3,  # Line 3 in temp file = line 2 in original
            }])
        )

        is_valid, msg = run_shellcheck("echo $foo")
        # Line should be adjusted down by 1
        assert "line 2" in msg

    @patch('shellcheck_validator.subprocess.run')
    def test_limits_errors_to_max(self, mock_run):
        """Should limit displayed errors to MAX_ERRORS."""
        errors = [{"code": i, "message": f"Error {i}", "line": i} for i in range(10)]
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps(errors)
        )

        is_valid, msg = run_shellcheck("bad command")
        assert f"and {10 - MAX_ERRORS} more error" in msg

    @patch('shellcheck_validator.subprocess.run')
    def test_shellcheck_not_installed(self, mock_run):
        """Should return valid with message when shellcheck not found."""
        mock_run.side_effect = FileNotFoundError("shellcheck not found")

        is_valid, msg = run_shellcheck("echo 'test'")
        assert is_valid is True
        assert "shellcheck not installed" in msg

    @patch('shellcheck_validator.subprocess.run')
    def test_shellcheck_timeout(self, mock_run):
        """Should return valid with message on timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="shellcheck", timeout=5)

        is_valid, msg = run_shellcheck("echo 'test'")
        assert is_valid is True
        assert "timeout" in msg.lower()

    @patch('shellcheck_validator.subprocess.run')
    def test_handles_invalid_json_output(self, mock_run):
        """Should handle non-JSON shellcheck output gracefully."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="not valid json"
        )

        is_valid, msg = run_shellcheck("echo 'test'")
        # Should allow through if can't parse
        assert is_valid is True

    @patch('shellcheck_validator.subprocess.run')
    def test_handles_empty_errors_array(self, mock_run):
        """Should handle empty errors array."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="[]"
        )

        is_valid, msg = run_shellcheck("echo 'test'")
        assert is_valid is True


class TestShellTools:
    """Tests for SHELL_TOOLS mapping."""

    def test_run_shell_command_mapped(self):
        """run_shell_command should be mapped."""
        assert "run_shell_command" in SHELL_TOOLS
        assert SHELL_TOOLS["run_shell_command"] == "command"

    def test_shell_mapped(self):
        """Shell should be mapped."""
        assert "Shell" in SHELL_TOOLS
        assert SHELL_TOOLS["Shell"] == "command"

    def test_bash_mapped(self):
        """bash should be mapped."""
        assert "bash" in SHELL_TOOLS
        assert SHELL_TOOLS["bash"] == "command"

    def test_execute_command_mapped(self):
        """execute_command should be mapped."""
        assert "execute_command" in SHELL_TOOLS


class TestMain:
    """Tests for main() function."""

    @patch('shellcheck_validator.run_shellcheck')
    def test_non_shell_tool_continues(self, mock_shellcheck, monkeypatch, capsys):
        """Non-shell tools should get continue=true."""
        stdin = StringIO(json.dumps({
            "tool_name": "read_file",
            "tool_input": {"path": "/etc/passwd"}
        }))
        monkeypatch.setattr('sys.stdin', stdin)

        main()

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["continue"] is True
        mock_shellcheck.assert_not_called()

    @patch('shellcheck_validator.run_shellcheck')
    def test_shell_tool_with_valid_command(self, mock_shellcheck, monkeypatch, capsys):
        """Valid shell command should get continue=true."""
        mock_shellcheck.return_value = (True, "")
        stdin = StringIO(json.dumps({
            "tool_name": "bash",
            "tool_input": {"command": "echo 'hello'"}
        }))
        monkeypatch.setattr('sys.stdin', stdin)

        main()

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["continue"] is True

    @patch('shellcheck_validator.run_shellcheck')
    def test_shell_tool_with_invalid_command(self, mock_shellcheck, monkeypatch, capsys):
        """Invalid shell command should get decision=block."""
        mock_shellcheck.return_value = (False, "SC2086: Double quote")
        stdin = StringIO(json.dumps({
            "tool_name": "bash",
            "tool_input": {"command": "echo $unquoted"}
        }))
        monkeypatch.setattr('sys.stdin', stdin)

        main()

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["decision"] == "block"
        assert "SC2086" in result["reason"]

    @patch('shellcheck_validator.run_shellcheck')
    def test_shell_tool_with_warning(self, mock_shellcheck, monkeypatch, capsys):
        """Valid command with warning should continue with reason."""
        mock_shellcheck.return_value = (True, "shellcheck not installed")
        stdin = StringIO(json.dumps({
            "tool_name": "bash",
            "tool_input": {"command": "echo 'test'"}
        }))
        monkeypatch.setattr('sys.stdin', stdin)

        main()

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["continue"] is True
        assert result["reason"] == "shellcheck not installed"

    def test_malformed_json_continues(self, monkeypatch, capsys):
        """Malformed JSON input should allow through."""
        stdin = StringIO("not valid json")
        monkeypatch.setattr('sys.stdin', stdin)

        main()

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["continue"] is True

    @patch('shellcheck_validator.run_shellcheck')
    def test_empty_command_continues(self, mock_shellcheck, monkeypatch, capsys):
        """Empty command should continue without calling shellcheck."""
        stdin = StringIO(json.dumps({
            "tool_name": "bash",
            "tool_input": {"command": ""}
        }))
        monkeypatch.setattr('sys.stdin', stdin)

        main()

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["continue"] is True

    @patch('shellcheck_validator.run_shellcheck')
    def test_run_shell_command_tool(self, mock_shellcheck, monkeypatch, capsys):
        """run_shell_command tool should be checked."""
        mock_shellcheck.return_value = (True, "")
        stdin = StringIO(json.dumps({
            "tool_name": "run_shell_command",
            "tool_input": {"command": "ls -la"}
        }))
        monkeypatch.setattr('sys.stdin', stdin)

        main()

        mock_shellcheck.assert_called_once()

    @patch('shellcheck_validator.run_shellcheck')
    def test_execute_command_tool(self, mock_shellcheck, monkeypatch, capsys):
        """execute_command tool should be checked."""
        mock_shellcheck.return_value = (True, "")
        stdin = StringIO(json.dumps({
            "tool_name": "execute_command",
            "tool_input": {"command": "pwd"}
        }))
        monkeypatch.setattr('sys.stdin', stdin)

        main()

        mock_shellcheck.assert_called_once()
