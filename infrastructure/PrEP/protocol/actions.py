"""Recovery action mappings for error types.

This module provides suggested recovery actions for each error type,
both base actions and tool-specific extensions.

The LLM uses these suggestions to determine next steps after a failure.
"""

from .errors import ErrorType


# Base recovery actions per error type
# These are general actions that apply regardless of which tool failed
RECOVERY_ACTIONS: dict[ErrorType, list[str]] = {
    # === Base types ===
    ErrorType.CONNECTION_FAILURE: [
        "retry_after_delay",
        "try_alternate_port",
        "verify_target_alive",
    ],
    ErrorType.VERSION_MISMATCH: [
        "re_fingerprint",
        "find_correct_exploit",
        "try_generic_exploit",
    ],
    ErrorType.PAYLOAD_BLOCKED: [
        "encode_payload",
        "try_fileless",
        "try_different_payload",
    ],
    ErrorType.NETWORK_BLOCKED: [
        "try_port_443",
        "try_port_80",
        "try_bind_shell",
        "try_dns_tunnel",
    ],
    ErrorType.AUTH_FAILURE: [
        "try_next_credential",
        "check_lockout_policy",
        "try_alternate_auth_method",
    ],
    ErrorType.EXPLOIT_CRASH: [
        "wait_for_recovery",
        "try_stable_variant",
        "skip_and_continue",
    ],
    ErrorType.PERMISSION_DENIED: [
        "try_privesc",
        "find_alternate_path",
        "enumerate_permissions",
    ],
    ErrorType.UNKNOWN: [
        "log_for_analysis",
        "retry_with_verbose",
    ],

    # === Extended types ===
    ErrorType.SESSION_NOT_FOUND: [
        "list_active_sessions",
        "reconnect_to_target",
        "verify_implant_alive",
    ],
    ErrorType.SESSION_DEAD: [
        "kill_dead_session",
        "reconnect_to_target",
        "check_target_rebooted",
    ],
    ErrorType.INVALID_INPUT: [
        "check_argument_format",
        "review_tool_schema",
    ],
    ErrorType.TIMEOUT: [
        "retry_with_longer_timeout",
        "check_network_latency",
        "try_async_operation",
    ],
    ErrorType.BRIDGE_UNAVAILABLE: [
        "restart_bridge_service",
        "check_bridge_logs",
        "verify_bridge_config",
    ],
    ErrorType.RESOURCE_BUSY: [
        "wait_and_retry",
        "cancel_blocking_operation",
        "use_different_session",
    ],
}


# Tool-specific action extensions
# Key: (ErrorType, tool_name) -> additional actions
# These are appended to base actions for tool-specific context
TOOL_ACTIONS: dict[tuple[ErrorType, str], list[str]] = {
    # === Pwncat-specific ===
    (ErrorType.SESSION_NOT_FOUND, "pwncat"): [
        "pwncat_sessions_list",
        "check_listener_status",
    ],
    (ErrorType.CONNECTION_FAILURE, "pwncat"): [
        "verify_callback_ip_reachable",
        "check_firewall_rules",
    ],
    (ErrorType.TIMEOUT, "pwncat"): [
        "check_pwncat_process",
        "increase_command_timeout",
    ],

    # === MSF-specific ===
    (ErrorType.PAYLOAD_BLOCKED, "msf"): [
        "use_meterpreter_https",
        "try_stageless_payload",
        "use_custom_template",
    ],
    (ErrorType.SESSION_NOT_FOUND, "msf"): [
        "msf_sessions_list",
        "check_handler_running",
    ],
    (ErrorType.BRIDGE_UNAVAILABLE, "msf"): [
        "restart_msfrpcd",
        "check_msf_bridge_container",
        "verify_msf_rpc_credentials",
    ],
    (ErrorType.CONNECTION_FAILURE, "msf"): [
        "check_msf_bridge_health",
        "verify_msfrpcd_running",
    ],
    (ErrorType.TIMEOUT, "msf"): [
        "check_module_progress",
        "increase_http_timeout",
    ],

    # === Sliver-specific ===
    (ErrorType.SESSION_NOT_FOUND, "sliver"): [
        "sliver_sessions_list",
        "sliver_beacons_list",
    ],
    (ErrorType.CONNECTION_FAILURE, "sliver"): [
        "check_implant_checkin",
        "verify_mtls_cert",
        "check_sliver_server_status",
    ],
    (ErrorType.SESSION_DEAD, "sliver"): [
        "check_beacon_interval",
        "wait_for_next_checkin",
    ],
    (ErrorType.TIMEOUT, "sliver"): [
        "check_beacon_jitter",
        "force_beacon_checkin",
    ],
}


def get_suggested_actions(
    error_type: ErrorType,
    tool: str | None = None,
    attempted: list[str] | None = None,
) -> list[str]:
    """
    Get recovery actions for an error, filtered by context.

    Combines base actions with tool-specific actions, then filters out
    any actions that have already been attempted.

    Args:
        error_type: The classified error type
        tool: Tool name (pwncat, msf, sliver) for tool-specific actions
        attempted: Actions already tried (will be excluded from results)

    Returns:
        List of suggested recovery actions, base actions first, then tool-specific

    Example:
        >>> get_suggested_actions(ErrorType.SESSION_NOT_FOUND, tool="msf")
        ['list_active_sessions', 'reconnect_to_target', 'verify_implant_alive',
         'msf_sessions_list', 'check_handler_running']
    """
    attempted = attempted or []

    # Start with base actions for this error type
    actions = list(RECOVERY_ACTIONS.get(error_type, []))

    # Add tool-specific actions if tool is specified
    if tool:
        tool_key = (error_type, tool.lower())
        tool_specific = TOOL_ACTIONS.get(tool_key, [])
        actions.extend(tool_specific)

    # Filter out already-attempted actions
    actions = [a for a in actions if a not in attempted]

    return actions
