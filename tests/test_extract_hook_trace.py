"""Tests for the hook trace extractor script."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "extract_hook_trace.py"

# Minimal session JSON matching dame-session-main.json schema
MINIMAL_SESSION = {
    "sessionId": "test-session-id",
    "startTime": "2026-01-31T00:00:00Z",
    "messages": [
        {
            "id": "msg-1",
            "type": "user",
            "content": "test prompt",
        },
        {
            "id": "msg-2",
            "type": "gemini",
            "content": "",
            "toolCalls": [
                {
                    "id": "tc-1",
                    "name": "run_shell_command",
                    "args": {"command": "nmap -sV 10.0.0.1"},
                    "result": [
                        {
                            "functionResponse": {
                                "name": "run_shell_command",
                                "response": {"output": "Starting Nmap..."},
                            }
                        }
                    ],
                    "status": "success",
                },
                {
                    "id": "tc-2",
                    "name": "read_file",
                    "args": {"path": "/artifacts/context.yaml"},
                    "result": [
                        {
                            "functionResponse": {
                                "name": "read_file",
                                "response": {"output": "cas_version: 1.2"},
                            }
                        }
                    ],
                    "status": "success",
                },
            ],
        },
        {
            "id": "msg-3",
            "type": "gemini",
            "content": "Analysis complete.",
            "toolCalls": [
                {
                    "id": "tc-3",
                    "name": "write_file",
                    "args": {"path": "/tmp/result.txt", "content": "done"},
                    "result": [
                        {
                            "functionResponse": {
                                "name": "write_file",
                                "response": {"output": "File written"},
                            }
                        }
                    ],
                    "status": "success",
                },
            ],
        },
    ],
}


class TestExtractHookTrace:
    def test_extracts_all_tool_calls(self, tmp_path):
        """Extracts correct number of tool call events."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(MINIMAL_SESSION))
        output_file = tmp_path / "trace.jsonl"

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(session_file), str(output_file)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_event_schema(self, tmp_path):
        """Each event has seq, tool_name, tool_input, tool_output."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(MINIMAL_SESSION))
        output_file = tmp_path / "trace.jsonl"

        subprocess.run(
            [sys.executable, str(SCRIPT), str(session_file), str(output_file)],
            capture_output=True,
            text=True,
        )

        lines = output_file.read_text().strip().split("\n")
        for i, line in enumerate(lines):
            event = json.loads(line)
            assert event["seq"] == i
            assert "tool_name" in event
            assert "tool_input" in event
            assert "tool_output" in event

    def test_preserves_tool_names(self, tmp_path):
        """Tool names match source data."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(MINIMAL_SESSION))
        output_file = tmp_path / "trace.jsonl"

        subprocess.run(
            [sys.executable, str(SCRIPT), str(session_file), str(output_file)],
            capture_output=True,
            text=True,
        )

        events = [json.loads(l) for l in output_file.read_text().strip().split("\n")]
        names = [e["tool_name"] for e in events]
        assert names == ["run_shell_command", "read_file", "write_file"]

    def test_skips_failed_tool_calls(self, tmp_path):
        """Failed tool calls are excluded from trace."""
        session = {
            "sessionId": "test",
            "messages": [
                {
                    "id": "msg-1",
                    "type": "gemini",
                    "toolCalls": [
                        {
                            "id": "tc-ok",
                            "name": "run_shell_command",
                            "args": {"command": "ls"},
                            "result": [
                                {
                                    "functionResponse": {
                                        "name": "run_shell_command",
                                        "response": {"output": "file.txt"},
                                    }
                                }
                            ],
                            "status": "success",
                        },
                        {
                            "id": "tc-fail",
                            "name": "run_shell_command",
                            "args": {"command": "rm /etc"},
                            "result": [],
                            "status": "error",
                        },
                    ],
                }
            ],
        }
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session))
        output_file = tmp_path / "trace.jsonl"

        subprocess.run(
            [sys.executable, str(SCRIPT), str(session_file), str(output_file)],
            capture_output=True,
            text=True,
        )

        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_handles_missing_result_gracefully(self, tmp_path):
        """Tool calls with empty/missing result get empty tool_output."""
        session = {
            "sessionId": "test",
            "messages": [
                {
                    "id": "msg-1",
                    "type": "gemini",
                    "toolCalls": [
                        {
                            "id": "tc-1",
                            "name": "activate_skill",
                            "args": {"skill_name": "initial-access"},
                            "result": [],
                            "status": "success",
                        },
                    ],
                }
            ],
        }
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session))
        output_file = tmp_path / "trace.jsonl"

        subprocess.run(
            [sys.executable, str(SCRIPT), str(session_file), str(output_file)],
            capture_output=True,
            text=True,
        )

        events = [json.loads(l) for l in output_file.read_text().strip().split("\n")]
        assert len(events) == 1
        assert events[0]["tool_output"] == ""

    def test_stdout_summary(self, tmp_path):
        """Script prints summary to stdout."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(MINIMAL_SESSION))
        output_file = tmp_path / "trace.jsonl"

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(session_file), str(output_file)],
            capture_output=True,
            text=True,
        )
        assert "3" in result.stdout  # 3 events extracted
