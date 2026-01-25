"""Tests for infrastructure/PrEP/protocol/responses.py"""

import pytest
import yaml
from datetime import datetime

from protocol.responses import format_success, format_error, format_response
from protocol.errors import (
    ErrorType,
    SessionNotFoundError,
    InvalidInputError,
    MCPError,
)


class TestFormatSuccess:
    """Tests for format_success() function."""

    def test_returns_valid_yaml(self):
        """Output should be valid YAML."""
        result = format_success({"output": "test"}, "pwncat")
        parsed = yaml.safe_load(result)
        assert isinstance(parsed, dict)

    def test_success_is_true(self):
        """Response should have success=True."""
        result = format_success({"output": "test"}, "pwncat")
        parsed = yaml.safe_load(result)
        assert parsed["success"] is True

    def test_includes_tool_name(self):
        """Response should include tool name."""
        result = format_success({"output": "test"}, "msf")
        parsed = yaml.safe_load(result)
        assert parsed["tool"] == "msf"

    def test_includes_result(self):
        """Response should include the result data."""
        data = {"uid": "0(root)", "gid": "0(root)"}
        result = format_success(data, "pwncat")
        parsed = yaml.safe_load(result)
        assert parsed["result"] == data

    def test_includes_timestamp(self):
        """Response should include ISO timestamp."""
        result = format_success({}, "pwncat")
        parsed = yaml.safe_load(result)
        assert "timestamp" in parsed
        # Should be parseable as ISO format
        datetime.fromisoformat(parsed["timestamp"].replace("Z", "+00:00"))

    def test_includes_context_when_provided(self):
        """Response should include context if provided."""
        ctx = {"target": "10.10.10.5", "session_id": "pwncat-1"}
        result = format_success({}, "pwncat", context=ctx)
        parsed = yaml.safe_load(result)
        assert parsed["context"] == ctx

    def test_no_context_when_not_provided(self):
        """Response should not have context key if not provided."""
        result = format_success({}, "pwncat")
        parsed = yaml.safe_load(result)
        assert "context" not in parsed

    def test_handles_string_result(self):
        """Should handle string results."""
        result = format_success("command output here", "pwncat")
        parsed = yaml.safe_load(result)
        assert parsed["result"] == "command output here"

    def test_handles_list_result(self):
        """Should handle list results."""
        data = ["session-1", "session-2"]
        result = format_success(data, "pwncat")
        parsed = yaml.safe_load(result)
        assert parsed["result"] == data

    def test_handles_multiline_strings(self):
        """YAML should handle multiline strings cleanly."""
        data = {"output": "line1\nline2\nline3"}
        result = format_success(data, "pwncat")
        parsed = yaml.safe_load(result)
        assert "line1\nline2\nline3" in parsed["result"]["output"]


class TestFormatError:
    """Tests for format_error() function."""

    def test_returns_valid_yaml(self):
        """Output should be valid YAML."""
        err = ValueError("test error")
        result = format_error(err, "pwncat")
        parsed = yaml.safe_load(result)
        assert isinstance(parsed, dict)

    def test_success_is_false(self):
        """Response should have success=False."""
        err = ValueError("test error")
        result = format_error(err, "pwncat")
        parsed = yaml.safe_load(result)
        assert parsed["success"] is False

    def test_includes_error_type(self):
        """Response should include classified error_type."""
        err = SessionNotFoundError("Not found")
        result = format_error(err, "pwncat")
        parsed = yaml.safe_load(result)
        assert parsed["error_type"] == "session_not_found"

    def test_includes_message(self):
        """Response should include error message."""
        err = ValueError("Invalid port: -1")
        result = format_error(err, "pwncat")
        parsed = yaml.safe_load(result)
        assert parsed["message"] == "Invalid port: -1"

    def test_includes_recoverable_flag(self):
        """Response should include recoverable boolean."""
        err = SessionNotFoundError("Not found")
        result = format_error(err, "pwncat")
        parsed = yaml.safe_load(result)
        assert "recoverable" in parsed
        assert isinstance(parsed["recoverable"], bool)

    def test_includes_suggested_actions(self):
        """Response should include suggested recovery actions."""
        err = SessionNotFoundError("Not found")
        result = format_error(err, "pwncat")
        parsed = yaml.safe_load(result)
        assert "suggested_actions" in parsed
        assert isinstance(parsed["suggested_actions"], list)

    def test_includes_context_with_tool(self):
        """Context should include the tool name."""
        err = ValueError("test")
        result = format_error(err, "msf")
        parsed = yaml.safe_load(result)
        assert parsed["context"]["tool"] == "msf"

    def test_merges_mcp_error_context(self):
        """Should merge context from MCPError subclasses."""
        err = SessionNotFoundError(
            "Not found",
            context={"available_sessions": ["pwncat-1"]}
        )
        result = format_error(err, "pwncat", context={"target": "10.10.10.5"})
        parsed = yaml.safe_load(result)
        assert parsed["context"]["available_sessions"] == ["pwncat-1"]
        assert parsed["context"]["target"] == "10.10.10.5"

    def test_includes_timestamp(self):
        """Response should include ISO timestamp."""
        err = ValueError("test")
        result = format_error(err, "pwncat")
        parsed = yaml.safe_load(result)
        assert "timestamp" in parsed

    def test_filters_attempted_actions(self):
        """Should exclude already-attempted actions from suggestions."""
        err = SessionNotFoundError("Not found")
        result = format_error(
            err, "pwncat",
            attempted_actions=["list_active_sessions"]
        )
        parsed = yaml.safe_load(result)
        assert "list_active_sessions" not in parsed["suggested_actions"]


class TestFormatResponse:
    """Tests for format_response() unified function."""

    def test_routes_to_success_when_true(self):
        """Should call format_success when success=True."""
        result = format_response(True, {"data": "test"}, "pwncat")
        parsed = yaml.safe_load(result)
        assert parsed["success"] is True
        assert parsed["result"] == {"data": "test"}

    def test_routes_to_error_when_false(self):
        """Should call format_error when success=False."""
        err = ValueError("failed")
        result = format_response(False, err, "pwncat")
        parsed = yaml.safe_load(result)
        assert parsed["success"] is False
        assert "error_type" in parsed

    def test_passes_context_to_success(self):
        """Should pass context to format_success."""
        ctx = {"session_id": "test-1"}
        result = format_response(True, {}, "pwncat", context=ctx)
        parsed = yaml.safe_load(result)
        assert parsed["context"] == ctx

    def test_passes_context_to_error(self):
        """Should pass context to format_error."""
        ctx = {"target": "10.10.10.5"}
        err = ValueError("test")
        result = format_response(False, err, "pwncat", context=ctx)
        parsed = yaml.safe_load(result)
        assert parsed["context"]["target"] == "10.10.10.5"

    def test_passes_attempted_actions_to_error(self):
        """Should pass attempted_actions to format_error."""
        err = SessionNotFoundError("Not found")
        result = format_response(
            False, err, "pwncat",
            attempted_actions=["reconnect_to_target"]
        )
        parsed = yaml.safe_load(result)
        assert "reconnect_to_target" not in parsed["suggested_actions"]
