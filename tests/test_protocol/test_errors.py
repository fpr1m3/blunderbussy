"""Tests for infrastructure/PrEP/protocol/errors.py"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "infrastructure" / "PrEP"))

import builtins
import pytest

from protocol.errors import (
    ErrorType,
    RECOVERABLE_ERRORS,
    EXCEPTION_MAP,
    MCPError,
    SessionNotFoundError,
    SessionDeadError,
    BridgeUnavailableError,
    ResourceBusyError,
    TimeoutError,
    InvalidInputError,
    classify_exception,
)


class TestErrorType:
    """Tests for ErrorType enum."""

    def test_base_error_types_exist(self):
        """All base error types should be defined."""
        base_types = [
            "CONNECTION_FAILURE",
            "VERSION_MISMATCH",
            "PAYLOAD_BLOCKED",
            "NETWORK_BLOCKED",
            "AUTH_FAILURE",
            "EXPLOIT_CRASH",
            "PERMISSION_DENIED",
            "UNKNOWN",
        ]
        for error_type in base_types:
            assert hasattr(ErrorType, error_type)

    def test_extended_error_types_exist(self):
        """All extended (MCP-specific) error types should be defined."""
        extended_types = [
            "SESSION_NOT_FOUND",
            "SESSION_DEAD",
            "INVALID_INPUT",
            "TIMEOUT",
            "BRIDGE_UNAVAILABLE",
            "RESOURCE_BUSY",
        ]
        for error_type in extended_types:
            assert hasattr(ErrorType, error_type)

    def test_error_type_values_are_strings(self):
        """ErrorType values should be snake_case strings."""
        for error_type in ErrorType:
            assert isinstance(error_type.value, str)
            assert error_type.value == error_type.value.lower()


class TestRecoverableErrors:
    """Tests for RECOVERABLE_ERRORS mapping."""

    def test_all_error_types_mapped(self):
        """Every ErrorType should have a recoverability mapping."""
        for error_type in ErrorType:
            assert error_type in RECOVERABLE_ERRORS, f"{error_type} not in RECOVERABLE_ERRORS"

    def test_exploit_crash_not_recoverable(self):
        """EXPLOIT_CRASH should be the only non-recoverable error."""
        assert RECOVERABLE_ERRORS[ErrorType.EXPLOIT_CRASH] is False

    def test_most_errors_are_recoverable(self):
        """Most errors should be recoverable."""
        recoverable_count = sum(1 for v in RECOVERABLE_ERRORS.values() if v)
        total = len(RECOVERABLE_ERRORS)
        assert recoverable_count >= total - 1  # At most 1 non-recoverable


class TestMCPError:
    """Tests for MCPError base class and subclasses."""

    def test_mcp_error_has_message(self):
        """MCPError should store message."""
        err = MCPError("test message")
        assert err.message == "test message"
        assert str(err) == "test message"

    def test_mcp_error_has_context(self):
        """MCPError should store context dict."""
        ctx = {"target": "10.10.10.5", "port": 445}
        err = MCPError("test", context=ctx)
        assert err.context == ctx

    def test_mcp_error_default_context(self):
        """MCPError context should default to empty dict."""
        err = MCPError("test")
        assert err.context == {}

    def test_mcp_error_default_type(self):
        """MCPError base class should have UNKNOWN type."""
        err = MCPError("test")
        assert err.error_type == ErrorType.UNKNOWN


class TestMCPErrorSubclasses:
    """Tests for specific MCPError subclasses."""

    def test_session_not_found_error(self):
        """SessionNotFoundError should have correct error_type."""
        err = SessionNotFoundError("Session 'pwncat-3' not found")
        assert err.error_type == ErrorType.SESSION_NOT_FOUND

    def test_session_dead_error(self):
        """SessionDeadError should have correct error_type."""
        err = SessionDeadError("Session unresponsive")
        assert err.error_type == ErrorType.SESSION_DEAD

    def test_bridge_unavailable_error(self):
        """BridgeUnavailableError should have correct error_type."""
        err = BridgeUnavailableError("MSF RPC down")
        assert err.error_type == ErrorType.BRIDGE_UNAVAILABLE

    def test_resource_busy_error(self):
        """ResourceBusyError should have correct error_type."""
        err = ResourceBusyError("Session locked")
        assert err.error_type == ErrorType.RESOURCE_BUSY

    def test_timeout_error(self):
        """TimeoutError should have correct error_type."""
        err = TimeoutError("Operation timed out")
        assert err.error_type == ErrorType.TIMEOUT

    def test_invalid_input_error(self):
        """InvalidInputError should have correct error_type."""
        err = InvalidInputError("Invalid port number")
        assert err.error_type == ErrorType.INVALID_INPUT

    def test_subclass_inherits_context(self):
        """Subclasses should inherit context functionality."""
        ctx = {"available_sessions": ["pwncat-1", "pwncat-2"]}
        err = SessionNotFoundError("Not found", context=ctx)
        assert err.context == ctx


class TestClassifyException:
    """Tests for classify_exception() function."""

    def test_classify_mcp_error_subclass(self):
        """Should return error_type from MCPError subclasses."""
        err = SessionNotFoundError("test")
        assert classify_exception(err) == ErrorType.SESSION_NOT_FOUND

    def test_classify_connection_error(self):
        """Should classify ConnectionError as CONNECTION_FAILURE."""
        err = ConnectionError("Connection refused")
        assert classify_exception(err) == ErrorType.CONNECTION_FAILURE

    def test_classify_connection_refused_error(self):
        """Should classify ConnectionRefusedError as CONNECTION_FAILURE."""
        err = ConnectionRefusedError("Refused")
        assert classify_exception(err) == ErrorType.CONNECTION_FAILURE

    def test_classify_builtin_timeout_error(self):
        """Should classify builtins.TimeoutError as TIMEOUT."""
        err = builtins.TimeoutError("Timed out")
        assert classify_exception(err) == ErrorType.TIMEOUT

    def test_classify_permission_error(self):
        """Should classify PermissionError as PERMISSION_DENIED."""
        err = PermissionError("Access denied")
        assert classify_exception(err) == ErrorType.PERMISSION_DENIED

    def test_classify_value_error(self):
        """Should classify ValueError as INVALID_INPUT."""
        err = ValueError("Invalid value")
        assert classify_exception(err) == ErrorType.INVALID_INPUT

    def test_classify_type_error(self):
        """Should classify TypeError as INVALID_INPUT."""
        err = TypeError("Wrong type")
        assert classify_exception(err) == ErrorType.INVALID_INPUT

    def test_classify_unknown_exception(self):
        """Should return UNKNOWN for unmapped exceptions."""
        class CustomError(Exception):
            pass
        err = CustomError("custom")
        assert classify_exception(err) == ErrorType.UNKNOWN

    def test_classify_subclass_of_mapped_type(self):
        """Should handle subclasses of mapped exception types."""
        # ConnectionResetError is a subclass of ConnectionError
        err = ConnectionResetError("Reset")
        assert classify_exception(err) == ErrorType.CONNECTION_FAILURE


class TestExceptionMap:
    """Tests for EXCEPTION_MAP coverage."""

    def test_common_exceptions_mapped(self):
        """Common Python exceptions should be mapped."""
        expected = [
            ConnectionError,
            ConnectionRefusedError,
            ConnectionResetError,
            builtins.TimeoutError,
            PermissionError,
            ValueError,
            TypeError,
        ]
        for exc_type in expected:
            assert exc_type in EXCEPTION_MAP, f"{exc_type} not in EXCEPTION_MAP"
