"""Tests for the pipeline completion gate in after_tool.py."""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

# Stub heavy dependencies that after_tool.py imports transitively.
# The pipeline gate code doesn't use any of them.
_pydantic = types.ModuleType("pydantic")
_pydantic.BaseModel = MagicMock()
_pydantic.Field = MagicMock()
_pydantic.field_validator = MagicMock()
sys.modules.setdefault("pydantic", _pydantic)

# session_state needs specific names that after_tool imports at module level
_ss = types.ModuleType("session_state")
_ss.SessionStateManager = MagicMock()
_ss.extract_credentials_from_output = MagicMock(return_value=[])
_ss.ConfidenceDelta = MagicMock(
    TECHNIQUE_SUCCESS=0.15, TECHNIQUE_FAIL=-0.10, BLOCKED_THRESHOLD=-0.30
)
sys.modules.setdefault("session_state", _ss)

# session_memory needs Outcome/EventType/SessionMemory (used in type hints at module level)
_sm = types.ModuleType("session_memory")
_sm.SessionMemory = MagicMock()
_sm.EventType = MagicMock()
_sm.Outcome = MagicMock()
# Outcome needs enum-like attributes for comparisons in detect_outcome()
_sm.Outcome.SUCCESS = "success"
_sm.Outcome.FAILED = "failed"
_sm.Outcome.BLOCKED = "blocked"
_sm.Outcome.PARTIAL = "partial"
sys.modules.setdefault("session_memory", _sm)

# Add hooks directory to path so we can import the module
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

from after_tool import (  # noqa: E402
    PIPELINE_STAGE_GATES,
    _PIPELINE_HARD_STOP,
    handle_pipeline_completion_gate,
)


class TestPipelineStageGates:
    """Verify the PIPELINE_STAGE_GATES constant is well-formed."""

    def test_has_all_four_stages(self):
        assert len(PIPELINE_STAGE_GATES) == 4

    def test_stages_numbered_1_through_4(self):
        stages = sorted(g["stage"] for g in PIPELINE_STAGE_GATES.values())
        assert stages == [1, 2, 3, 4]

    def test_each_entry_has_required_keys(self):
        for name, gate in PIPELINE_STAGE_GATES.items():
            assert "stage" in gate, f"{name} missing 'stage'"
            assert "artifact" in gate, f"{name} missing 'artifact'"
            assert "next_action" in gate, f"{name} missing 'next_action'"

    def test_validation_stage_is_pipeline_complete(self):
        assert PIPELINE_STAGE_GATES["code-analysis-validation"]["next_action"] == "PIPELINE COMPLETE"


class TestHandlePipelineCompletionGate:
    """Verify handle_pipeline_completion_gate dispatches correctly."""

    def test_non_pipeline_tool_returns_none(self):
        result = handle_pipeline_completion_gate("Shell", {"command": "ls"})
        assert result is None

    def test_delegate_to_agent_unknown_agent_returns_none(self):
        result = handle_pipeline_completion_gate(
            "delegate_to_agent", {"agent_name": "some-other-agent"}
        )
        assert result is None

    def test_recon_agent_returns_stage_directive(self):
        result = handle_pipeline_completion_gate(
            "delegate_to_agent", {"agent_name": "code-analysis-recon"}
        )
        assert result is not None
        assert "STAGE 1/4" in result
        assert "code-analysis-recon" in result
        assert "code-analysis-triage" in result
        assert "PROHIBITED" in result

    def test_triage_agent_returns_stage_directive(self):
        result = handle_pipeline_completion_gate(
            "delegate_to_agent", {"agent_name": "code-analysis-triage"}
        )
        assert result is not None
        assert "STAGE 2/4" in result
        assert "code-analysis-analysis" in result

    def test_analysis_agent_returns_stage_directive(self):
        result = handle_pipeline_completion_gate(
            "delegate_to_agent", {"agent_name": "code-analysis-analysis"}
        )
        assert result is not None
        assert "STAGE 3/4" in result
        assert "code-analysis-validation" in result

    def test_validation_agent_returns_hard_stop(self):
        result = handle_pipeline_completion_gate(
            "delegate_to_agent", {"agent_name": "code-analysis-validation"}
        )
        assert result is not None
        assert result == _PIPELINE_HARD_STOP
        assert "PIPELINE COMPLETE" in result
        assert "PROHIBITED" in result
        assert "04-validation-findings.yaml" in result
        assert "04-validation-brief.md" in result

    def test_non_delegate_tool_with_agent_name_input_returns_none(self):
        """Ensure only delegate_to_agent triggers the gate, not other tools
        that happen to have agent_name in their input."""
        result = handle_pipeline_completion_gate(
            "bash", {"agent_name": "code-analysis-recon", "command": "echo hi"}
        )
        assert result is None

    def test_missing_agent_name_returns_none(self):
        result = handle_pipeline_completion_gate(
            "delegate_to_agent", {"query": "analyze this"}
        )
        assert result is None

    def test_empty_agent_name_returns_none(self):
        result = handle_pipeline_completion_gate(
            "delegate_to_agent", {"agent_name": ""}
        )
        assert result is None

    def test_all_non_final_stages_contain_prohibited_line(self):
        """Every stage directive should tell Dame not to read source files."""
        for agent_name in ["code-analysis-recon", "code-analysis-triage", "code-analysis-analysis"]:
            result = handle_pipeline_completion_gate(
                "delegate_to_agent", {"agent_name": agent_name}
            )
            assert "PROHIBITED" in result, f"{agent_name} directive missing PROHIBITED line"
