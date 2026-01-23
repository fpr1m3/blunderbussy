#!/usr/bin/env python3
"""
SessionStart Hook - Memory Block Injection
============================================
Gemini CLI hook that loads session state and injects memory block into context.

Triggered: At session start
Action: Load existing session state, generate memory block for context injection

Usage by Gemini CLI:
    python3 /ext/opulence/hooks/session_start.py

Input (stdin): JSON with session info (target, cas_path, etc.)
Output (stdout): JSON response with context injection
"""

import sys
import json
import os
from pathlib import Path

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from session_state import SessionStateManager


def get_target_from_input(input_data: dict) -> str:
    """Extract target from input data."""
    # Direct target specification
    if input_data.get("target"):
        return input_data["target"]

    # Extract from CAS path
    cas_path = input_data.get("cas_path") or os.environ.get("CAS_PATH")
    if cas_path:
        parts = Path(cas_path).parts
        for i, part in enumerate(parts):
            if part == "artifacts" and i + 1 < len(parts):
                return parts[i + 1]

    # Try environment
    return os.environ.get("TARGET", "")


def main():
    """Process SessionStart event."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        input_data = {}

    target = get_target_from_input(input_data)

    if not target:
        # No target, return minimal response
        print(json.dumps({
            "action": "continue",
            "context_injection": None,
            "message": "No target specified, session state not loaded"
        }))
        return

    try:
        base_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
        mgr = SessionStateManager.from_target(target, base_path=base_path)

        # Generate memory block for context injection
        memory_block = mgr.generate_memory_block()

        # Log session start
        mgr.log_action("session_start", {
            "session_id": mgr.state.session_id,
            "target": target,
            "access_level": mgr.state.current_access_level.value,
            "flags_captured": list(mgr.state.flags_captured.keys()),
            "shell_count": len(mgr.get_active_shells()),
            "credential_count": len(mgr.get_all_credentials()),
            "hypothesis_count": len(mgr.get_active_hypotheses())
        })

        mgr.save_all()

        # Return context injection
        response = {
            "action": "continue",
            "context_injection": memory_block,
            "session_info": {
                "session_id": mgr.state.session_id,
                "target": target,
                "access_level": mgr.state.current_access_level.value,
                "flags_captured": list(mgr.state.flags_captured.keys()),
                "shell_count": len(mgr.get_active_shells()),
                "credential_count": len(mgr.get_all_credentials()),
                "hypothesis_count": len(mgr.get_active_hypotheses())
            }
        }

        print(json.dumps(response))

    except Exception as e:
        # Return error but don't block session
        print(json.dumps({
            "action": "continue",
            "context_injection": None,
            "error": f"Failed to load session state: {str(e)}"
        }))


if __name__ == "__main__":
    main()
