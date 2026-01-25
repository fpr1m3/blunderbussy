"""YAML response formatting for MCP tools.

This module provides standardized response formatting that outputs YAML
instead of JSON. YAML is preferred for LLM consumption because:
- Fewer escape characters
- Cleaner nesting representation
- Better handling of multiline strings
- More human-readable for debugging

All MCP tool responses should use these formatters for consistency.
"""

import yaml
from datetime import datetime, timezone
from typing import Any

from .errors import (
    ErrorType,
    RECOVERABLE_ERRORS,
    classify_exception,
)
from .actions import get_suggested_actions


def format_success(
    result: Any,
    tool: str,
    context: dict | None = None,
) -> str:
    """
    Format a successful tool response as YAML.

    Args:
        result: The tool's output (dict, list, string, etc.)
        tool: Tool name for context
        context: Additional context (target, session_id, etc.)

    Returns:
        YAML-formatted response string

    Example output:
        success: true
        tool: pwncat
        result:
          output: |
            uid=0(root) gid=0(root)
        timestamp: '2026-01-25T18:30:00+00:00'
        context:
          target: 10.10.10.5
          session_id: pwncat-1
    """
    response = {
        "success": True,
        "tool": tool,
        "result": result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if context:
        response["context"] = context

    return yaml.dump(
        response,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def format_error(
    exception: Exception,
    tool: str,
    context: dict | None = None,
    attempted_actions: list[str] | None = None,
) -> str:
    """
    Format an error response as YAML with recovery suggestions.

    Automatically classifies the exception, determines recoverability,
    and provides relevant recovery suggestions based on error type and tool.

    Args:
        exception: The caught exception
        tool: Tool name for context and action lookup
        context: Additional context (target, session_id, etc.)
        attempted_actions: Recovery actions already tried (excluded from suggestions)

    Returns:
        YAML-formatted error response string

    Example output:
        success: false
        error_type: session_not_found
        message: Session 'pwncat-3' not found
        recoverable: true
        suggested_actions:
          - list_active_sessions
          - reconnect_to_target
          - pwncat_sessions_list
        context:
          target: 10.10.10.5
          session_id: pwncat-3
          available_sessions:
            - pwncat-1
            - pwncat-2
          tool: pwncat
        timestamp: '2026-01-25T18:30:00+00:00'
    """
    context = context or {}
    error_type = classify_exception(exception)

    # Build context - merge in any extra info from MCPError subclasses
    full_context = {**context}
    if hasattr(exception, 'context') and exception.context:
        full_context.update(exception.context)
    full_context["tool"] = tool

    response = {
        "success": False,
        "error_type": error_type.value,
        "message": str(exception),
        "recoverable": RECOVERABLE_ERRORS.get(error_type, True),
        "suggested_actions": get_suggested_actions(
            error_type,
            tool=tool,
            attempted=attempted_actions,
        ),
        "context": full_context,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return yaml.dump(
        response,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def format_response(
    success: bool,
    result_or_exception: Any,
    tool: str,
    context: dict | None = None,
    attempted_actions: list[str] | None = None,
) -> str:
    """
    Unified response formatter - routes to success or error format.

    Convenience function that dispatches to format_success or format_error
    based on the success flag.

    Args:
        success: Whether the operation succeeded
        result_or_exception: Either the result (if success) or exception (if failure)
        tool: Tool name
        context: Additional context
        attempted_actions: For errors, actions already tried

    Returns:
        YAML-formatted response string

    Example:
        try:
            result = await do_something()
            return format_response(True, result, "pwncat", context)
        except Exception as e:
            return format_response(False, e, "pwncat", context)
    """
    if success:
        return format_success(result_or_exception, tool, context)
    else:
        return format_error(
            result_or_exception,
            tool,
            context,
            attempted_actions,
        )
