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
import shutil

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from session_state import SessionStateManager


def log_debug(msg: str):
    """Log to stderr (stdout is reserved for JSON responses)."""
    print(f"[MEMORY] {msg}", file=sys.stderr)


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


# =============================================================================
# Tool Preflight Check
# =============================================================================

REQUIRED_TOOLS = [
    "nmap", "gobuster", "hydra", "sqlmap", "curl", "ssh",
    "sshpass", "smbclient", "crackmapexec", "pwncat",
    "feroxbuster", "ffuf", "nikto", "enum4linux", "smbmap",
    "nbtscan", "dnsrecon", "socat", "nc",
]


def log_preflight(msg: str):
    """Log preflight check to stderr."""
    print(f"[PREFLIGHT] {msg}", file=sys.stderr)


def preflight_check() -> dict:
    """
    Check tool availability via shutil.which.

    Returns dict with 'available' and 'missing' lists.
    Missing tools get a warning injected into the system message
    so the agent knows to use alternatives.
    """
    available = []
    missing = []

    for tool in REQUIRED_TOOLS:
        if shutil.which(tool):
            available.append(tool)
        else:
            missing.append(tool)

    if missing:
        log_preflight(f"Missing tools: {', '.join(missing)}")
    log_preflight(f"Available: {len(available)}/{len(REQUIRED_TOOLS)} tools")

    return {"available": available, "missing": missing}


def main():
    """Process SessionStart event."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        input_data = {}

    target = get_target_from_input(input_data)

    if not target:
        # No target, return minimal response using Gemini CLI HookOutput format
        print(json.dumps({
            "continue": True,
            "reason": "No target specified, session state not loaded"
        }))
        return

    try:
        base_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
        mgr = SessionStateManager.from_target(target, base_path=base_path)
        log_debug(f"Loading session for target: {target}")

        # Generate memory block for context injection
        memory_block = mgr.generate_memory_block()

        # Tool preflight check
        preflight = preflight_check()
        if preflight["missing"]:
            memory_block += "\n\n**⚠️ Missing Tools:**\n"
            for tool in preflight["missing"]:
                # Provide fallback suggestions for common tools
                fallbacks = {
                    "sshpass": "use ssh-copy-id or manual password entry",
                    "pwncat": "use nc/socat for reverse shells",
                    "crackmapexec": "use smbclient + rpcclient individually",
                    "feroxbuster": "use gobuster or ffuf instead",
                    "enum4linux": "use smbclient + rpcclient + ldapsearch",
                }
                fallback = fallbacks.get(tool, "not available — find alternative")
                memory_block += f"- {tool}: {fallback}\n"

        # Estimate token count (~4 chars per token is a rough heuristic)
        char_count = len(memory_block)
        estimated_tokens = char_count // 4
        log_debug(f"Memory block generated: {char_count} chars (~{estimated_tokens} tokens)")

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

        # Return context injection using Gemini CLI HookOutput format
        response = {
            "continue": True,
            "systemMessage": memory_block,
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "preflight": preflight,
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
        }

        print(json.dumps(response))

    except Exception as e:
        # Return error but don't block session
        print(json.dumps({
            "continue": True,
            "reason": f"Failed to load session state: {str(e)}"
        }))


if __name__ == "__main__":
    main()
