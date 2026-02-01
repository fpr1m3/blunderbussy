#!/usr/bin/env python3
"""
File Size Gate — BeforeTool Hook
==================================
Blocks reads of large files that would overflow the agent's context window.
Fires on: read_file, cat, read_many_files

Prevention is better than truncation: the existing truncate_output in
after_tool.py caps at MAX_OUTPUT_CHARS=8000, but only AFTER the file is
already read and injected into context. This hook blocks the read before
it happens, keeping tokens under control.

Configurable via:
  DAME_MAX_FILE_LINES (default: 500)
  DAME_MAX_FILE_KB (default: 20)

Override: include force=true in tool_input to bypass the gate.

Usage by Gemini CLI:
    python3 /ext/opulence/hooks/file_size_gate.py

Input (stdin): JSON with tool_name, tool_input (BeforeToolInput interface)
Output (stdout): JSON response using Gemini CLI HookOutput format:
    - continue: true to proceed
    - decision: "block" with reason to halt
"""

import sys
import json
import os
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
MAX_LINES = int(os.environ.get("DAME_MAX_FILE_LINES", "500"))
MAX_KB = int(os.environ.get("DAME_MAX_FILE_KB", "20"))

# Tools that perform file reads
FILE_READ_TOOLS = {"read_file", "read_many_files"}

# Pattern to extract file path from `cat <path>` (with optional sudo)
SHELL_CAT_PATTERN = r"^\s*(?:sudo\s+)?cat\s+(\S+)"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log_gate(msg: str):
    """Log to stderr (stdout is reserved for JSON responses)."""
    print(f"[FILE_GATE] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Target resolution (shared pattern with sibling hooks)
# ---------------------------------------------------------------------------
def get_target_from_env() -> str:
    """Get current target from environment or CAS path."""
    target = os.environ.get("TARGET")
    if target:
        return target

    cas_path = os.environ.get("CAS_PATH")
    if cas_path:
        parts = Path(cas_path).parts
        for i, part in enumerate(parts):
            if part == "artifacts" and i + 1 < len(parts):
                return parts[i + 1]

    # Try .current_target file written by /attack command
    current_target_file = Path(
        os.environ.get("ARTIFACTS_PATH", "/artifacts")
    ) / ".current_target"
    if current_target_file.exists():
        try:
            target = current_target_file.read_text().strip()
            if target:
                return target
        except OSError:
            pass

    artifacts_dir = Path(os.environ.get("ARTIFACTS_PATH", "/artifacts"))
    if artifacts_dir.exists():
        session_dirs = [
            d for d in artifacts_dir.iterdir()
            if d.is_dir() and (d / "session").exists()
        ]
        if session_dirs:
            session_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
            return session_dirs[0].name

    return ""


# ---------------------------------------------------------------------------
# File inspection helpers
# ---------------------------------------------------------------------------
def count_lines(path: str) -> int:
    """Count lines in a file. Returns 0 if the file cannot be read."""
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except (OSError, IOError):
        return 0


def check_file(path: str) -> tuple:
    """
    Check whether a single file exceeds the size thresholds.

    Returns:
        (ok, reason) — ok is True when the file is within limits,
        False with a human-readable reason when it should be blocked.
    """
    try:
        stat = os.stat(path)
    except (OSError, IOError):
        # File doesn't exist or isn't accessible — let the tool itself
        # report the error; don't block here.
        return True, ""

    size_kb = stat.st_size / 1024
    lines = count_lines(path)

    if lines > MAX_LINES or size_kb > MAX_KB:
        reason = (
            f"File {path} is {lines} lines ({size_kb:.0f}KB). "
            f"Use head -n 50, tail -n 50, or grep to sample first. "
            f"To override: read_file with force=true"
        )
        return False, reason

    return True, ""


# ---------------------------------------------------------------------------
# Path extraction from tool input
# ---------------------------------------------------------------------------
def extract_paths_from_input(tool_name: str, tool_input: dict) -> list:
    """
    Extract file path(s) from the tool invocation.

    Handles:
      - read_file        → tool_input["path"]
      - read_many_files  → tool_input["paths"]
      - Shell / bash     → parse `cat <path>` from tool_input["command"]

    Returns a list of path strings (may be empty).
    """
    paths = []

    if tool_name == "read_file":
        p = tool_input.get("path", "")
        if p:
            paths.append(p)

    elif tool_name == "read_many_files":
        raw = tool_input.get("paths", [])
        if isinstance(raw, list):
            paths.extend(p for p in raw if isinstance(p, str) and p)
        elif isinstance(raw, str) and raw:
            paths.append(raw)

    elif tool_name in ("Shell", "bash"):
        command = tool_input.get("command", "")
        m = re.match(SHELL_CAT_PATTERN, command)
        if m:
            paths.append(m.group(1))

    return paths


# ---------------------------------------------------------------------------
# Force-override detection
# ---------------------------------------------------------------------------
def has_force_override(tool_input: dict) -> bool:
    """
    Check if the caller explicitly requested a forced read.

    Accepts either:
      - tool_input["force"] = true / "true"
      - the literal string "force=true" or "force: true" anywhere in the
        serialised input (covers free-text arguments).
    """
    # Explicit boolean / string field
    force_val = tool_input.get("force")
    if force_val is True or str(force_val).lower() == "true":
        return True

    # Fallback: scan the raw JSON representation
    raw = json.dumps(tool_input).lower()
    if "force=true" in raw or "force: true" in raw:
        return True

    return False


# ---------------------------------------------------------------------------
# Main entry-point
# ---------------------------------------------------------------------------
def main():
    """Process BeforeTool event."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Malformed input — don't block.
        print(json.dumps({"continue": True}))
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # ---- Fast path: only inspect file-read tools and shell cat commands ----
    is_file_read_tool = tool_name in FILE_READ_TOOLS
    is_shell_cat = (
        tool_name in ("Shell", "bash")
        and re.match(SHELL_CAT_PATTERN, tool_input.get("command", ""))
    )

    if not is_file_read_tool and not is_shell_cat:
        print(json.dumps({"continue": True}))
        return

    # ---- Check for force override ----
    if has_force_override(tool_input):
        log_gate("Force override detected — allowing read")
        print(json.dumps({"continue": True}))
        return

    # ---- Extract paths and check each one ----
    paths = extract_paths_from_input(tool_name, tool_input)

    if not paths:
        # Couldn't determine the path — let it through.
        print(json.dumps({"continue": True}))
        return

    blocked_reasons = []
    for path in paths:
        ok, reason = check_file(path)
        if not ok:
            log_gate(f"BLOCKED: {reason}")
            blocked_reasons.append(reason)

    if blocked_reasons:
        combined_reason = " | ".join(blocked_reasons)
        print(json.dumps({
            "decision": "block",
            "reason": combined_reason,
        }))
        return

    # All files within limits.
    log_gate(f"PASS: {len(paths)} file(s) within limits")
    print(json.dumps({"continue": True}))


if __name__ == "__main__":
    main()
