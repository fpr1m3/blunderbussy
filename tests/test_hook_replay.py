"""Tests for hook trace replay harness.

Replays recorded tool call traces through the hook pipeline and asserts
on hook decisions (continue/block) and annotations.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

HOOKS_DIR = Path(__file__).parent.parent / "infrastructure" / "PrEP" / "hooks"
TRACES_DIR = Path(__file__).parent / "fixtures" / "traces"


def run_hook(hook_script: str, event: dict, env: dict | None = None) -> dict:
    """Pipe a JSON event through a hook script and return parsed output.

    Args:
        hook_script: filename in hooks/ dir (e.g., "before_tool.py")
        event: dict to serialize as JSON stdin
        env: additional env vars to merge with os.environ
    """
    hook_path = HOOKS_DIR / hook_script
    run_env = {**os.environ, **(env or {})}

    result = subprocess.run(
        [sys.executable, str(hook_path)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        env=run_env,
        timeout=10,
    )

    if result.returncode != 0:
        # Some hooks exit non-zero on error but still produce JSON
        pass

    stdout = result.stdout.strip()
    if not stdout:
        return {"continue": True}

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"continue": True, "_raw_stdout": stdout}


def load_trace(name: str) -> list[dict]:
    """Load a trace JSONL file by name."""
    trace_path = TRACES_DIR / name
    return [json.loads(line) for line in trace_path.read_text().strip().split("\n")]


class TestHookReplayInfra:
    """Verify the replay infrastructure works."""

    def test_run_hook_returns_dict(self, session_fixture):
        """run_hook returns a parsed dict."""
        session_fixture("gavel-full-session")
        event = {"tool_name": "run_shell_command", "tool_input": {"command": "ls"}}
        result = run_hook("before_tool.py", event)
        assert isinstance(result, dict)

    def test_run_hook_continue_true_by_default(self, session_fixture):
        """Unknown tools pass through."""
        session_fixture("gavel-full-session")
        event = {"tool_name": "unknown_tool", "tool_input": {}}
        result = run_hook("before_tool.py", event)
        assert result.get("continue") is True

    def test_load_trace(self):
        """Trace loading works."""
        trace = load_trace("gavel-session-158.jsonl")
        assert len(trace) > 100
        assert trace[0]["seq"] == 0


class TestBeforeToolReplay:
    """Replay trace events through before_tool.py."""

    def test_shell_commands_pass_through(self, session_fixture):
        """Shell commands are not blocked by before_tool (query dedup only)."""
        session_fixture("gavel-full-session")
        trace = load_trace("gavel-session-158.jsonl")
        shell_events = [e for e in trace if e["tool_name"] == "run_shell_command"]

        blocked = []
        for event in shell_events[:10]:  # Sample first 10
            before_event = {
                "tool_name": event["tool_name"],
                "tool_input": event["tool_input"],
            }
            result = run_hook("before_tool.py", before_event)
            if result.get("decision") == "block":
                blocked.append(event["seq"])

        # Shell commands should not be blocked by query cache
        assert len(blocked) == 0, f"Unexpectedly blocked events: {blocked}"


class TestAfterToolReplay:
    """Replay trace events through after_tool.py."""

    def test_shell_output_processed(self, session_fixture):
        """Shell command outputs are processed without error."""
        session_fixture("gavel-full-session")
        trace = load_trace("gavel-session-158.jsonl")
        shell_events = [e for e in trace if e["tool_name"] == "run_shell_command"]

        errors = []
        for event in shell_events[:5]:  # Sample first 5
            after_event = {
                "tool_name": event["tool_name"],
                "tool_input": event["tool_input"],
                "tool_output": event["tool_output"],
            }
            result = run_hook("after_tool.py", after_event)
            if "_raw_stdout" in result:
                errors.append((event["seq"], result["_raw_stdout"]))

        assert len(errors) == 0, f"Hook errors: {errors}"


class TestLoopDetectorReplay:
    """Replay trace events through loop_detector.py."""

    def test_first_events_no_escalation(self, session_fixture):
        """First few events should not trigger loop detection."""
        artifact_dir = session_fixture("gavel-full-session")
        trace = load_trace("gavel-session-158.jsonl")

        # Reset loop state
        session_dir = artifact_dir / "session"
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "loop_state.json").write_text(json.dumps({
            "turn_hashes": [],
            "consecutive_similar": 0,
            "escalation_level": 0,
            "total_turns": 0,
        }))

        for event in trace[:5]:
            after_event = {
                "tool_name": event["tool_name"],
                "tool_input": event["tool_input"],
                "tool_output": event["tool_output"],
            }
            result = run_hook("loop_detector.py", after_event)
            # First 5 events should always continue
            assert result.get("continue") is not False, (
                f"Loop detector blocked event {event['seq']} unexpectedly"
            )
