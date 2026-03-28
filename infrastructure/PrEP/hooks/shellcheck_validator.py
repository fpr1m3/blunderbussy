#!/usr/bin/env python3
"""
BeforeTool Hook - Shellcheck Validator
======================================
Gemini CLI hook that validates shell commands with shellcheck before execution.

Triggered before: run_shell_command, Shell, bash, execute_command tools
Action: Run shellcheck and block commands with syntax errors

Input (stdin): JSON with tool_name, tool_input (BeforeToolInput interface)
Output (stdout): JSON response using Gemini CLI HookOutput format:
    - continue: true to proceed
    - decision: "block" with reason to reject
"""

import sys
import json
import subprocess
import re
from pathlib import Path


# Tools that execute shell commands
SHELL_TOOLS = {
    "run_shell_command": "command",
    "Shell": "command",
    "bash": "command",
    "execute_command": "command",
}

MAX_ERRORS = 5
SHELLCHECK_TIMEOUT = 3  # seconds (keep well under gemini-cli's 5s hook timeout)

# =============================================================================
# Dangerous Command Patterns (Context Explosion Prevention)
# =============================================================================
# These patterns can produce unbounded output that overwhelms context windows.
# The AfterTool hook truncates at 8K chars, but that doesn't help if the CLI
# itself passes 50K+ chars to the conversation first.

DANGEROUS_PATTERNS = [
    # Git commands that search all history - can return megabytes of minified JS
    (
        r"git\s+(grep|log|show|diff).*\$\(git\s+rev-list\s+--all\)",
        "git_rev_list_all",
        "Git command searches ALL revisions. Use --max-count or limit to specific branches:\n"
        "  Instead of: git grep 'pattern' $(git rev-list --all)\n"
        "  Try: git grep 'pattern' HEAD~50..HEAD\n"
        "  Or: git log --oneline -n 50 | head"
    ),
    (
        r"git\s+rev-list\s+--all(?!\s*\|)",
        "git_rev_list_raw",
        "Unbounded git rev-list. Add --max-count or pipe to head:\n"
        "  git rev-list --all --max-count=50\n"
        "  git rev-list --all | head -50"
    ),
    # Recursive find without depth limits
    (
        r"find\s+/\s+(?!.*-maxdepth)",
        "find_root_unbounded",
        "Unbounded find from /. Add -maxdepth:\n"
        "  find / -maxdepth 3 -name '*.conf'"
    ),
    # Strings on large binaries without filtering
    (
        r"strings\s+\S+(?!\s*\|)",
        "strings_unfiltered",
        "strings without filtering can produce huge output. Pipe to grep:\n"
        "  strings binary | grep -i password"
    ),
    # Cat on files that might be large
    (
        r"cat\s+.*\.(sql|csv|json|xml|log)(?!\s*\|)",
        "cat_large_file",
        "This file type may be large. Use head/tail or grep:\n"
        "  head -100 file.log\n"
        "  grep 'pattern' file.json | head -50"
    ),
    # Git log without limits
    (
        r"git\s+log(?!\s+(-n|--max-count|--oneline.*\|.*head))",
        "git_log_unbounded",
        "git log without limits. Add -n or --max-count:\n"
        "  git log --oneline -n 20"
    ),
]


def check_dangerous_patterns(command: str) -> tuple[bool, str, str]:
    """
    Check if command matches dangerous patterns that can explode context.

    Returns:
        (is_dangerous, pattern_name, suggestion)
    """
    for pattern, name, suggestion in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True, name, suggestion

    return False, "", ""


def format_error(error: dict) -> str:
    """Format a single shellcheck error for display."""
    code = error.get("code", "")
    message = error.get("message", "Unknown error")
    line = error.get("line", "?")
    column = error.get("column", "")

    location = f"line {line}"
    if column:
        location += f", col {column}"

    wiki_link = f"https://www.shellcheck.net/wiki/SC{code}"

    return f"SC{code} ({location}): {message}\n  See: {wiki_link}"


def run_shellcheck(command: str) -> tuple[bool, str]:
    """
    Run shellcheck on a command.

    Imports subprocess/tempfile lazily to avoid cold-start overhead when
    the dangerous-pattern check already blocks the command.

    Returns:
        (is_valid, message) - True if valid or shellcheck unavailable
    """
    if not command or not command.strip():
        return True, ""

    import tempfile

    # Write command to temp file with shebang
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".sh",
        delete=False
    ) as f:
        f.write("#!/bin/bash\n")
        f.write(command)
        temp_path = Path(f.name)

    try:
        result = subprocess.run(
            [
                "shellcheck",
                "--format=json",
                "--severity=error",
                "--shell=bash",
                str(temp_path)
            ],
            capture_output=True,
            text=True,
            timeout=SHELLCHECK_TIMEOUT
        )

        # Exit 0 = clean, Exit 1 = issues found
        if result.returncode == 0:
            return True, ""

        # Parse JSON output
        try:
            errors = json.loads(result.stdout)
        except json.JSONDecodeError:
            # Couldn't parse output, allow through
            return True, ""

        if not errors:
            return True, ""

        # Format errors (limit to MAX_ERRORS)
        formatted = []
        for error in errors[:MAX_ERRORS]:
            # Adjust line numbers (subtract 1 for shebang we added)
            if error.get("line", 0) > 1:
                error["line"] = error.get("line", 1) - 1
            if error.get("endLine", 0) > 1:
                error["endLine"] = error.get("endLine", 1) - 1
            formatted.append(format_error(error))

        remaining = len(errors) - MAX_ERRORS
        if remaining > 0:
            formatted.append(f"...and {remaining} more error(s)")

        return False, "\n\n".join(formatted)

    except FileNotFoundError:
        # shellcheck not installed - allow with warning
        return True, "shellcheck not installed"

    except subprocess.TimeoutExpired:
        # Timeout - allow through
        return True, "shellcheck timeout"

    except Exception as e:
        # Other errors - allow through
        return True, f"shellcheck error: {e}"

    finally:
        # Cleanup temp file
        try:
            temp_path.unlink()
        except Exception:
            pass


def main():
    """Process BeforeTool event."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"continue": True}))
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Only check shell tools
    if tool_name not in SHELL_TOOLS:
        print(json.dumps({"continue": True}))
        return

    # Get the command parameter for this tool
    command_param = SHELL_TOOLS[tool_name]
    command = tool_input.get(command_param, "")

    if not command:
        print(json.dumps({"continue": True}))
        return

    # ==========================================================================
    # Check for dangerous patterns FIRST (context explosion prevention)
    # This catches commands that can produce unbounded output
    # ==========================================================================
    is_dangerous, pattern_name, suggestion = check_dangerous_patterns(command)
    if is_dangerous:
        print(json.dumps({
            "decision": "block",
            "reason": f"⚠️ CONTEXT EXPLOSION RISK: {pattern_name}\n\n{suggestion}\n\nThis command pattern can produce megabytes of output, overwhelming the context window.",
            "systemMessage": f"Command blocked: {pattern_name} pattern detected"
        }))
        return

    # Run shellcheck
    is_valid, message = run_shellcheck(command)

    if is_valid:
        if message:
            # Valid but with warning (e.g., shellcheck not installed)
            print(json.dumps({
                "continue": True,
                "reason": message
            }))
        else:
            print(json.dumps({"continue": True}))
    else:
        # Shellcheck found errors - block
        print(json.dumps({
            "decision": "block",
            "reason": f"Shellcheck found syntax errors:\n\n{message}",
            "systemMessage": "Command blocked by shellcheck validator"
        }))


if __name__ == "__main__":
    main()
