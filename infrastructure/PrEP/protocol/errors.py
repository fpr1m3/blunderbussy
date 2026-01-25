"""Extended error types for MCP tool responses.

This module provides a standardized error taxonomy for MCP servers,
extending the PTT domain model with server-specific error types.

Design Decision: This module defines its own ErrorType enum rather than
importing from ptt.py. This avoids coupling the protocol layer to the
domain model and allows independent evolution.
"""

import builtins
from enum import Enum
from typing import Optional


class ErrorType(str, Enum):
    """
    Error taxonomy for MCP tool responses.

    Base types align with PTT domain model for consistency.
    Extended types cover server-specific failure modes.
    """
    # === Base types (aligned with PTT domain) ===
    CONNECTION_FAILURE = "connection_failure"
    VERSION_MISMATCH = "version_mismatch"
    PAYLOAD_BLOCKED = "payload_blocked"
    NETWORK_BLOCKED = "network_blocked"
    AUTH_FAILURE = "auth_failure"
    EXPLOIT_CRASH = "exploit_crash"
    PERMISSION_DENIED = "permission_denied"
    UNKNOWN = "unknown"

    # === Extended types (MCP server-specific) ===
    SESSION_NOT_FOUND = "session_not_found"
    SESSION_DEAD = "session_dead"
    INVALID_INPUT = "invalid_input"
    TIMEOUT = "timeout"
    BRIDGE_UNAVAILABLE = "bridge_unavailable"
    RESOURCE_BUSY = "resource_busy"


# Recoverability by error type - most errors are recoverable
RECOVERABLE_ERRORS: dict[ErrorType, bool] = {
    ErrorType.CONNECTION_FAILURE: True,
    ErrorType.VERSION_MISMATCH: True,
    ErrorType.PAYLOAD_BLOCKED: True,
    ErrorType.NETWORK_BLOCKED: True,
    ErrorType.AUTH_FAILURE: True,
    ErrorType.EXPLOIT_CRASH: False,  # Target may be crashed/unstable
    ErrorType.PERMISSION_DENIED: True,
    ErrorType.UNKNOWN: True,
    ErrorType.SESSION_NOT_FOUND: True,
    ErrorType.SESSION_DEAD: True,
    ErrorType.INVALID_INPUT: True,
    ErrorType.TIMEOUT: True,
    ErrorType.BRIDGE_UNAVAILABLE: True,
    ErrorType.RESOURCE_BUSY: True,
}


class MCPError(Exception):
    """Base exception for MCP protocol errors.

    Subclass this for specific error types. The error_type class attribute
    is used by classify_exception() to map exceptions to ErrorType values.

    Example:
        class SessionNotFoundError(MCPError):
            error_type = ErrorType.SESSION_NOT_FOUND

        raise SessionNotFoundError(
            "Session 'pwncat-3' not found",
            context={"available_sessions": ["pwncat-1", "pwncat-2"]}
        )
    """

    error_type: ErrorType = ErrorType.UNKNOWN

    def __init__(self, message: str, context: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.context = context or {}


class SessionNotFoundError(MCPError):
    """Requested C2 session does not exist."""
    error_type = ErrorType.SESSION_NOT_FOUND


class SessionDeadError(MCPError):
    """Session exists but is unresponsive."""
    error_type = ErrorType.SESSION_DEAD


class BridgeUnavailableError(MCPError):
    """Intermediary service (MSF RPC, bridge, etc.) is down."""
    error_type = ErrorType.BRIDGE_UNAVAILABLE


class ResourceBusyError(MCPError):
    """Resource is locked by another operation."""
    error_type = ErrorType.RESOURCE_BUSY


class TimeoutError(MCPError):
    """Operation timed out."""
    error_type = ErrorType.TIMEOUT


class InvalidInputError(MCPError):
    """Invalid input provided to tool."""
    error_type = ErrorType.INVALID_INPUT


# Exception mapping for automatic error type detection
# Maps Python exception types to ErrorType values
EXCEPTION_MAP: dict[type, ErrorType] = {
    # Python built-ins
    ConnectionError: ErrorType.CONNECTION_FAILURE,
    ConnectionRefusedError: ErrorType.CONNECTION_FAILURE,
    ConnectionResetError: ErrorType.CONNECTION_FAILURE,
    ConnectionAbortedError: ErrorType.CONNECTION_FAILURE,
    builtins.TimeoutError: ErrorType.TIMEOUT,
    PermissionError: ErrorType.PERMISSION_DENIED,
    ValueError: ErrorType.INVALID_INPUT,
    TypeError: ErrorType.INVALID_INPUT,
    FileNotFoundError: ErrorType.PERMISSION_DENIED,  # Usually access issue
    OSError: ErrorType.CONNECTION_FAILURE,
}

# Try to add httpx exceptions if available
try:
    import httpx
    EXCEPTION_MAP[httpx.ConnectError] = ErrorType.CONNECTION_FAILURE
    EXCEPTION_MAP[httpx.ConnectTimeout] = ErrorType.TIMEOUT
    EXCEPTION_MAP[httpx.ReadTimeout] = ErrorType.TIMEOUT
    EXCEPTION_MAP[httpx.WriteTimeout] = ErrorType.TIMEOUT
    EXCEPTION_MAP[httpx.TimeoutException] = ErrorType.TIMEOUT
    EXCEPTION_MAP[httpx.HTTPStatusError] = ErrorType.BRIDGE_UNAVAILABLE
except ImportError:
    pass


def classify_exception(exc: Exception) -> ErrorType:
    """Map an exception to its ErrorType.

    Checks in order:
    1. If exception has error_type attribute (MCPError subclasses)
    2. If exception type is in EXCEPTION_MAP
    3. Falls back to UNKNOWN

    Args:
        exc: The exception to classify

    Returns:
        ErrorType enum value
    """
    # Check if it's an MCPError subclass with explicit type
    if hasattr(exc, 'error_type'):
        return exc.error_type

    # Check the mapping table (exact type match first)
    exc_type = type(exc)
    if exc_type in EXCEPTION_MAP:
        return EXCEPTION_MAP[exc_type]

    # Check for subclass matches
    for mapped_type, error_type in EXCEPTION_MAP.items():
        if isinstance(exc, mapped_type):
            return error_type

    return ErrorType.UNKNOWN
