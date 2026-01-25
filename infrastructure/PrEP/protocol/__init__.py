"""MCP Protocol layer for standardized tool responses.

This module provides a unified interface for formatting MCP tool responses
with structured error types, recovery suggestions, and YAML output.

Design Decision (2026-01-25):
    Alternative B - dedicated protocol/ directory for MCP response formatting.
    Rationale: Provides control over responses from MCP servers we don't want
    to fork and extend. We can process their data before it's returned to the model.

Usage:
    from infrastructure.PrEP.protocol import (
        format_success,
        format_error,
        SessionNotFoundError,
        ErrorType,
    )

    TOOL_NAME = "pwncat"

    async def handle_tool_call(name: str, arguments: dict) -> str:
        context = {"target": arguments.get("target")}

        try:
            result = await do_something(arguments)
            return format_success(result, TOOL_NAME, context)
        except Exception as e:
            return format_error(e, TOOL_NAME, context)

Response Format (YAML):
    # Success
    success: true
    tool: pwncat
    result:
      output: "command output here"
    timestamp: '2026-01-25T18:30:00+00:00'
    context:
      target: 10.10.10.5
      session_id: pwncat-1

    # Error
    success: false
    error_type: session_not_found
    message: Session 'pwncat-3' not found
    recoverable: true
    suggested_actions:
      - list_active_sessions
      - reconnect_to_target
    context:
      target: 10.10.10.5
      tool: pwncat
    timestamp: '2026-01-25T18:30:00+00:00'
"""

from .errors import (
    # Enum
    ErrorType,
    # Base exception
    MCPError,
    # Specific exceptions
    SessionNotFoundError,
    SessionDeadError,
    BridgeUnavailableError,
    ResourceBusyError,
    TimeoutError,
    InvalidInputError,
    # Utilities
    classify_exception,
    RECOVERABLE_ERRORS,
)

from .actions import (
    get_suggested_actions,
    RECOVERY_ACTIONS,
    TOOL_ACTIONS,
)

from .responses import (
    format_response,
    format_error,
    format_success,
)

__all__ = [
    # Error types
    "ErrorType",
    "MCPError",
    "SessionNotFoundError",
    "SessionDeadError",
    "BridgeUnavailableError",
    "ResourceBusyError",
    "TimeoutError",
    "InvalidInputError",
    # Classification
    "classify_exception",
    "RECOVERABLE_ERRORS",
    # Actions
    "get_suggested_actions",
    "RECOVERY_ACTIONS",
    "TOOL_ACTIONS",
    # Formatting
    "format_response",
    "format_error",
    "format_success",
]
