#!/usr/bin/env python3
"""
PreToolUse Hook - Query Deduplication
======================================
Gemini CLI hook that checks for duplicate queries before execution.

Triggered before: qdrant-find, google_web_search, web_fetch tools
Action: Check cache and optionally skip if recent duplicate exists

Usage by Gemini CLI:
    python3 /ext/opulence/hooks/pre_tool_use.py

Input (stdin): JSON with tool_name, tool_input
Output (stdout): JSON response with action (continue/skip)
"""

import sys
import json
import os
from pathlib import Path

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from session_state import SessionStateManager


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


def main():
    """Process PreToolUse event."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"action": "continue"}))
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Only check query tools
    if tool_name not in QUERY_TOOLS:
        print(json.dumps({"action": "continue"}))
        return

    # Get the query parameter name for this tool
    query_param = QUERY_TOOLS[tool_name]
    query = tool_input.get(query_param, "")

    if not query:
        print(json.dumps({"action": "continue"}))
        return

    # Get target
    target = get_target_from_env()
    if not target:
        print(json.dumps({"action": "continue"}))
        return

    # Check cache
    try:
        base_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
        mgr = SessionStateManager.from_target(target, base_path=base_path)

        cached = mgr.check_query_cache(query, tool_name)

        if cached:
            # Found cached result - suggest skipping
            age_minutes = int(
                (
                    __import__("datetime").datetime.utcnow() -
                    __import__("datetime").datetime.fromisoformat(cached.timestamp)
                ).total_seconds() / 60
            )

            print(json.dumps({
                "action": "skip",
                "reason": f"Query executed {age_minutes} minutes ago",
                "cached_result": {
                    "query": cached.query_text,
                    "tool": cached.tool,
                    "summary": cached.results_summary,
                    "hit_count": cached.hit_count
                },
                "suggestion": f"Previous result: {cached.results_summary}"
            }))
            return

        # No cache hit - continue
        print(json.dumps({"action": "continue"}))

    except Exception as e:
        # Don't block on errors
        print(json.dumps({
            "action": "continue",
            "warning": f"Cache check failed: {str(e)}"
        }))


if __name__ == "__main__":
    main()
