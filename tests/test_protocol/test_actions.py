"""Tests for infrastructure/PrEP/protocol/actions.py"""

import pytest

from protocol.actions import (
    RECOVERY_ACTIONS,
    TOOL_ACTIONS,
    get_suggested_actions,
)
from protocol.errors import ErrorType


class TestRecoveryActions:
    """Tests for RECOVERY_ACTIONS mapping."""

    def test_all_error_types_have_actions(self):
        """Every ErrorType should have recovery actions defined."""
        for error_type in ErrorType:
            assert error_type in RECOVERY_ACTIONS, f"{error_type} missing from RECOVERY_ACTIONS"

    def test_actions_are_lists(self):
        """All action values should be lists."""
        for error_type, actions in RECOVERY_ACTIONS.items():
            assert isinstance(actions, list), f"{error_type} actions should be a list"

    def test_actions_are_non_empty(self):
        """Each error type should have at least one action."""
        for error_type, actions in RECOVERY_ACTIONS.items():
            assert len(actions) > 0, f"{error_type} should have at least one action"

    def test_connection_failure_actions(self):
        """CONNECTION_FAILURE should have relevant recovery actions."""
        actions = RECOVERY_ACTIONS[ErrorType.CONNECTION_FAILURE]
        assert "retry_after_delay" in actions
        assert "verify_target_alive" in actions

    def test_session_not_found_actions(self):
        """SESSION_NOT_FOUND should have session-related actions."""
        actions = RECOVERY_ACTIONS[ErrorType.SESSION_NOT_FOUND]
        assert "list_active_sessions" in actions
        assert "reconnect_to_target" in actions

    def test_payload_blocked_actions(self):
        """PAYLOAD_BLOCKED should have evasion-related actions."""
        actions = RECOVERY_ACTIONS[ErrorType.PAYLOAD_BLOCKED]
        assert "encode_payload" in actions or "try_different_payload" in actions


class TestToolActions:
    """Tests for TOOL_ACTIONS mapping."""

    def test_pwncat_specific_actions_exist(self):
        """Should have pwncat-specific action extensions."""
        pwncat_keys = [k for k in TOOL_ACTIONS.keys() if k[1] == "pwncat"]
        assert len(pwncat_keys) > 0

    def test_msf_specific_actions_exist(self):
        """Should have msf-specific action extensions."""
        msf_keys = [k for k in TOOL_ACTIONS.keys() if k[1] == "msf"]
        assert len(msf_keys) > 0

    def test_sliver_specific_actions_exist(self):
        """Should have sliver-specific action extensions."""
        sliver_keys = [k for k in TOOL_ACTIONS.keys() if k[1] == "sliver"]
        assert len(sliver_keys) > 0

    def test_tool_actions_are_lists(self):
        """All tool action values should be lists."""
        for key, actions in TOOL_ACTIONS.items():
            assert isinstance(actions, list), f"{key} actions should be a list"

    def test_pwncat_session_not_found_actions(self):
        """Pwncat should have specific actions for SESSION_NOT_FOUND."""
        key = (ErrorType.SESSION_NOT_FOUND, "pwncat")
        assert key in TOOL_ACTIONS
        actions = TOOL_ACTIONS[key]
        assert "pwncat_sessions_list" in actions

    def test_msf_session_not_found_actions(self):
        """MSF should have specific actions for SESSION_NOT_FOUND."""
        key = (ErrorType.SESSION_NOT_FOUND, "msf")
        assert key in TOOL_ACTIONS
        actions = TOOL_ACTIONS[key]
        assert "msf_sessions_list" in actions

    def test_sliver_session_not_found_actions(self):
        """Sliver should have specific actions for SESSION_NOT_FOUND."""
        key = (ErrorType.SESSION_NOT_FOUND, "sliver")
        assert key in TOOL_ACTIONS
        actions = TOOL_ACTIONS[key]
        assert "sliver_sessions_list" in actions


class TestGetSuggestedActions:
    """Tests for get_suggested_actions() function."""

    def test_returns_list(self):
        """Should return a list of actions."""
        actions = get_suggested_actions(ErrorType.CONNECTION_FAILURE)
        assert isinstance(actions, list)

    def test_returns_base_actions(self):
        """Should return base actions for error type."""
        actions = get_suggested_actions(ErrorType.SESSION_NOT_FOUND)
        assert "list_active_sessions" in actions

    def test_adds_tool_specific_actions(self):
        """Should add tool-specific actions when tool specified."""
        actions = get_suggested_actions(ErrorType.SESSION_NOT_FOUND, tool="pwncat")
        assert "list_active_sessions" in actions  # base
        assert "pwncat_sessions_list" in actions  # tool-specific

    def test_tool_actions_come_after_base(self):
        """Tool-specific actions should be appended after base actions."""
        actions = get_suggested_actions(ErrorType.SESSION_NOT_FOUND, tool="msf")
        base_idx = actions.index("list_active_sessions")
        tool_idx = actions.index("msf_sessions_list")
        assert tool_idx > base_idx

    def test_filters_attempted_actions(self):
        """Should exclude already-attempted actions."""
        actions = get_suggested_actions(
            ErrorType.SESSION_NOT_FOUND,
            attempted=["list_active_sessions"]
        )
        assert "list_active_sessions" not in actions

    def test_filters_multiple_attempted(self):
        """Should filter multiple attempted actions."""
        attempted = ["list_active_sessions", "reconnect_to_target"]
        actions = get_suggested_actions(
            ErrorType.SESSION_NOT_FOUND,
            attempted=attempted
        )
        for action in attempted:
            assert action not in actions

    def test_tool_actions_also_filtered(self):
        """Should filter tool-specific attempted actions too."""
        actions = get_suggested_actions(
            ErrorType.SESSION_NOT_FOUND,
            tool="pwncat",
            attempted=["pwncat_sessions_list"]
        )
        assert "pwncat_sessions_list" not in actions

    def test_case_insensitive_tool_match(self):
        """Tool matching should be case-insensitive."""
        actions_lower = get_suggested_actions(ErrorType.SESSION_NOT_FOUND, tool="pwncat")
        actions_upper = get_suggested_actions(ErrorType.SESSION_NOT_FOUND, tool="PWNCAT")
        assert actions_lower == actions_upper

    def test_unknown_tool_returns_base_only(self):
        """Unknown tool should just return base actions."""
        actions = get_suggested_actions(ErrorType.SESSION_NOT_FOUND, tool="unknown_tool")
        base_actions = get_suggested_actions(ErrorType.SESSION_NOT_FOUND)
        assert actions == base_actions

    def test_none_attempted_handled(self):
        """Should handle attempted=None gracefully."""
        actions = get_suggested_actions(ErrorType.CONNECTION_FAILURE, attempted=None)
        assert len(actions) > 0

    def test_empty_attempted_handled(self):
        """Should handle empty attempted list."""
        actions = get_suggested_actions(ErrorType.CONNECTION_FAILURE, attempted=[])
        assert len(actions) > 0

    def test_returns_copy_not_reference(self):
        """Should return a copy, not modify original mapping."""
        actions1 = get_suggested_actions(ErrorType.CONNECTION_FAILURE)
        actions1.append("custom_action")
        actions2 = get_suggested_actions(ErrorType.CONNECTION_FAILURE)
        assert "custom_action" not in actions2
