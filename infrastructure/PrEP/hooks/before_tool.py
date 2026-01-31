#!/usr/bin/env python3
"""
BeforeTool Hook - Query Deduplication
======================================
Gemini CLI hook that checks for duplicate queries before execution.

Triggered before: qdrant-find, google_web_search, web_fetch tools
Action: Check cache and optionally skip if recent duplicate exists

Usage by Gemini CLI:
    python3 /ext/opulence/hooks/before_tool.py

Input (stdin): JSON with tool_name, tool_input (BeforeToolInput interface)
Output (stdout): JSON response using Gemini CLI HookOutput format:
    - continue: true to proceed
    - decision: "block" with reason to skip
"""

import sys
import json
import os
from pathlib import Path

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from session_state import SessionStateManager

# Import command splitting utility
try:
    from command_utils import extract_commands
    HAS_COMMAND_UTILS = True
except ImportError:
    HAS_COMMAND_UTILS = False


def log_debug(msg: str):
    """Log to stderr (stdout is reserved for JSON responses)."""
    print(f"[CACHE] {msg}", file=sys.stderr)


# Tools that support query deduplication
QUERY_TOOLS = {
    "qdrant-find": "query",       # Qdrant skills DB
    "google_web_search": "query", # Google search
    "web_fetch": "url",           # Web fetch (use URL as key)
}


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


# =============================================================================
# Cookie Staleness Check
# =============================================================================

COOKIE_STALE_MINUTES = 30  # PHP default session.gc_maxlifetime = 1440s ≈ 24 min


def log_cookie(msg: str):
    """Log cookie staleness checks to stderr."""
    print(f"[COOKIE] {msg}", file=sys.stderr)


def check_cookie_staleness(command: str, target: str) -> str | None:
    """
    Check if cookies are stale when curl uses -b flag.

    Warns the agent if cookies are older than COOKIE_STALE_MINUTES,
    since expired session cookies cause silent failures (empty responses
    that waste turns without clear error messages).

    Args:
        command: The shell command being executed
        target: Current target identifier

    Returns:
        Warning string if cookies are stale, None otherwise.
    """
    import re
    from datetime import datetime, timedelta

    # Only check curl commands with -b (cookie) flag
    if not re.search(r'\bcurl\b', command.lower()):
        return None
    if not re.search(r'\s-b\s|\s--cookie\s', command):
        return None

    try:
        base_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
        mgr = SessionStateManager.from_target(target, base_path=base_path)

        if not mgr.state or not mgr.state.last_auth_timestamp:
            return None

        last_auth = datetime.fromisoformat(mgr.state.last_auth_timestamp)
        age = datetime.utcnow() - last_auth
        age_minutes = int(age.total_seconds() / 60)

        if age_minutes > COOKIE_STALE_MINUTES:
            log_cookie(f"Cookies are {age_minutes} minutes old (threshold: {COOKIE_STALE_MINUTES}m)")
            return (
                f"⚠️ Session cookies are {age_minutes} minutes old (last auth: {age_minutes}m ago). "
                f"PHP sessions typically expire after 24 minutes. "
                f"Consider re-authenticating before making this request."
            )
    except Exception:
        pass

    return None


def main():
    """Process BeforeTool event."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"continue": True}))
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Get target
    target = get_target_from_env()

    # ======================================================================
    # Cookie Staleness Check (fires on shell tools with curl -b)
    # ======================================================================
    if tool_name in {"Shell", "bash", "pwncat__command", "execute_command"}:
        command = tool_input.get("command", tool_input.get("cmd", ""))
        if command and target:
            # Use command splitter if available
            commands_to_check = [command]
            if HAS_COMMAND_UTILS:
                commands_to_check = extract_commands(command)

            for cmd in commands_to_check:
                cookie_warning = check_cookie_staleness(cmd, target)
                if cookie_warning:
                    # Warn but don't block — agent might need the stale request for comparison
                    print(json.dumps({
                        "continue": True,
                        "hookSpecificOutput": {
                            "hookEventName": "BeforeTool",
                            "additionalContext": cookie_warning
                        }
                    }))
                    return

    # ======================================================================
    # Query Deduplication (existing functionality)
    # ======================================================================
    if tool_name not in QUERY_TOOLS:
        print(json.dumps({"continue": True}))
        return

    # Get the query parameter name for this tool
    query_param = QUERY_TOOLS[tool_name]
    query = tool_input.get(query_param, "")

    if not query:
        print(json.dumps({"continue": True}))
        return

    if not target:
        print(json.dumps({"continue": True}))
        return

    # Check cache
    try:
        base_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
        mgr = SessionStateManager.from_target(target, base_path=base_path)

        log_debug(f"Checking cache for {tool_name}: '{query[:50]}{'...' if len(query) > 50 else ''}'")
        cached = mgr.check_query_cache(query, tool_name)

        if cached:
            log_debug(f"HIT - Query cached {cached.hit_count}x, summary: {cached.results_summary[:80]}...")
            # Found cached result - block with cached result info
            age_minutes = int(
                (
                    __import__("datetime").datetime.utcnow() -
                    __import__("datetime").datetime.fromisoformat(cached.timestamp)
                ).total_seconds() / 60
            )

            print(json.dumps({
                "decision": "block",
                "reason": f"Query executed {age_minutes} minutes ago. Previous result: {cached.results_summary}",
                "hookSpecificOutput": {
                    "hookEventName": "BeforeTool",
                    "cached_result": {
                        "query": cached.query_text,
                        "tool": cached.tool,
                        "summary": cached.results_summary,
                        "hit_count": cached.hit_count
                    }
                }
            }))
            return

        # No cache hit - continue
        log_debug(f"MISS - Query not in cache, proceeding")
        print(json.dumps({"continue": True}))

    except Exception as e:
        # Don't block on errors - continue with warning in reason
        print(json.dumps({
            "continue": True,
            "reason": f"Cache check failed: {str(e)}"
        }))


if __name__ == "__main__":
    main()
