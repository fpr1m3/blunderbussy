#!/usr/bin/env python3
"""
Loop Detector & Circuit Breaker -- AfterTool Hook
==================================================
Detects thought loops via MinHash similarity and zero-tool-execution patterns.
Three-tier escalation: warn -> reset -> kill.

Problem this solves:
    In a pentest session, turns 104-166 (~62 turns) contained near-identical
    thought patterns cycling through SQLi, XSS, CSRF, and admin access.
    Turn 104 alone: 62,912 thought tokens with zero commands executed.
    Total session thought tokens: 848,557 against only 18,951 output tokens.
    A 44:1 thought-to-action ratio is catastrophic.

Signals:
    1. Thought similarity > 0.85 for 3+ consecutive turns
    2. Zero tool executions in 5+ turns
    3. Technique previously marked FAILED in PTT

Escalation:
    Level 1 (soft):  Inject "LOOP WARNING" context          (3 consecutive)
    Level 2 (hard):  Force context reset + pivot prompt      (7 consecutive)
    Level 3 (kill):  Terminate session, save state           (15 consecutive)

State: /artifacts/{target}/session/loop_state.json

Usage by Gemini CLI:
    python3 /ext/opulence/hooks/loop_detector.py

Input (stdin): JSON with tool_name, tool_input, tool_output (AfterToolInput)
Output (stdout): JSON response using Gemini CLI HookOutput format:
    - continue: true to proceed
    - continue: true + hookSpecificOutput.additionalContext for warning injection
    - continue: false + reason for session kill
"""

import sys
import json
import os
import re
import hashlib
from pathlib import Path


# =============================================================================
# Constants
# =============================================================================

WINDOW_SIZE = 10        # Rolling window of recent turns
SHINGLE_SIZE = 3        # n-gram size for MinHash
NUM_HASHES = 64         # Number of hash functions for MinHash
SIMILARITY_THRESHOLD = 0.85

LEVEL_1_TURNS = 3       # Consecutive similar turns for warning
LEVEL_2_TURNS = 7       # For context reset + PTT blocklist
LEVEL_3_TURNS = 15      # For session kill

# State file path template
STATE_FILE_TEMPLATE = "/artifacts/{target}/session/loop_state.json"

# Tools that count as "real work" -- zero-tool turns are the strongest signal
EXECUTION_TOOLS = {
    "Shell", "bash", "pwncat__command", "execute_command",
    "delegate_to_agent", "activate_skill",
}


# =============================================================================
# Logging (stderr only -- stdout is reserved for JSON hook protocol)
# =============================================================================

def log_loop(msg: str):
    """Log loop detection events to stderr."""
    print(f"[LOOP_DETECT] {msg}", file=sys.stderr)


# =============================================================================
# MinHash Similarity (cheap near-duplicate detection, no API call)
# =============================================================================

def shingle(text: str, n: int = SHINGLE_SIZE) -> set:
    """
    Generate n-gram shingles from text.

    Normalizes whitespace and lowercases before shingling to increase
    similarity detection across cosmetically different but semantically
    identical thought patterns.

    Args:
        text: Input text to shingle.
        n: Size of each n-gram shingle.

    Returns:
        Set of n-gram string shingles.
    """
    # Normalize: lowercase, collapse whitespace, strip punctuation noise
    text = re.sub(r'\s+', ' ', text.lower().strip())
    text = re.sub(r'[^\w\s]', '', text)

    tokens = text.split()
    if len(tokens) < n:
        return {text} if text else set()

    return {' '.join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def minhash(shingles: set, num_hashes: int = NUM_HASHES) -> list:
    """
    Compute MinHash signature from a set of shingles.

    Uses a family of hash functions h_i(x) = hash(str(i) + x) to produce
    a compact fingerprint suitable for Jaccard similarity estimation.

    Args:
        shingles: Set of text shingles.
        num_hashes: Number of hash functions (signature length).

    Returns:
        List of min hash values (the MinHash signature).
    """
    if not shingles:
        return [0] * num_hashes

    signature = []
    for i in range(num_hashes):
        min_val = float('inf')
        seed = str(i).encode()
        for s in shingles:
            h = int(hashlib.md5(seed + s.encode(), usedforsecurity=False).hexdigest(), 16)
            if h < min_val:
                min_val = h
        signature.append(min_val)

    return signature


def jaccard_similarity(mh1: list, mh2: list) -> float:
    """
    Estimate Jaccard similarity from two MinHash signatures.

    Args:
        mh1: First MinHash signature.
        mh2: Second MinHash signature.

    Returns:
        Estimated Jaccard similarity in [0.0, 1.0].
    """
    if not mh1 or not mh2 or len(mh1) != len(mh2):
        return 0.0

    matches = sum(1 for a, b in zip(mh1, mh2) if a == b)
    return matches / len(mh1)


# =============================================================================
# State Persistence
# =============================================================================

def _state_path(target: str) -> Path:
    """Resolve state file path for a target."""
    return Path(STATE_FILE_TEMPLATE.format(target=target))


def load_state(target: str) -> dict:
    """
    Load loop detector state from disk.

    Returns a default state dict if the file does not exist or is corrupt.

    Args:
        target: Target identifier (IP or hostname).

    Returns:
        State dictionary.
    """
    path = _state_path(target)
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log_loop(f"Corrupt state file, resetting: {e}")

    return {
        "turn_hashes": [],
        "consecutive_similar": 0,
        "escalation_level": 0,
        "total_turns": 0,
    }


def save_state(target: str, state: dict) -> None:
    """
    Persist loop detector state to disk.

    Creates parent directories if they do not exist.

    Args:
        target: Target identifier.
        state: State dictionary to persist.
    """
    path = _state_path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "w") as f:
            json.dump(state, f, indent=2)
    except OSError as e:
        log_loop(f"Failed to save state: {e}")


# =============================================================================
# PTT Integration (read failed/exhausted techniques)
# =============================================================================

def load_ptt_failed_techniques(target: str) -> list:
    """
    Read ptt.yaml and extract techniques marked FAILED or with exhausted vectors.

    Returns human-readable strings describing each failed technique and why,
    suitable for injection into the agent's context as a hard constraint.

    Args:
        target: Target identifier.

    Returns:
        List of strings describing failed techniques.
    """
    ptt_path = Path(f"/artifacts/{target}/ptt.yaml")
    if not ptt_path.exists():
        return []

    try:
        import yaml
    except ImportError:
        log_loop("PyYAML not available, skipping PTT read")
        return []

    try:
        with open(ptt_path) as f:
            ptt = yaml.safe_load(f)
    except Exception as e:
        log_loop(f"Failed to read PTT: {e}")
        return []

    failed = []
    engagement = ptt.get("engagement", {})
    for host in engagement.get("hosts", []):
        host_ip = host.get("ip", "unknown")
        for service in host.get("services", []):
            svc_name = service.get("service", "unknown")
            svc_port = service.get("port", "?")
            for vector in service.get("vectors", []):
                for technique in vector.get("techniques", []):
                    status = technique.get("status", "")
                    if status in ("failed", "skipped"):
                        name = technique.get("name", "unnamed")
                        # Extract last error for context
                        errors = technique.get("error_history", [])
                        reason = ""
                        if errors:
                            last_err = errors[-1]
                            reason = f" ({last_err.get('error_type', '')}: {last_err.get('error_message', '')})"
                        failed.append(
                            f"- {name} on {svc_name}:{svc_port} @ {host_ip}{reason}"
                        )

    return failed


def load_ptt_untried_surfaces(target: str) -> list:
    """
    Read ptt.yaml and extract techniques still in PENDING status.

    Returns human-readable strings describing untried attack surfaces,
    suitable for injection as pivot suggestions.

    Args:
        target: Target identifier.

    Returns:
        List of strings describing untried techniques.
    """
    ptt_path = Path(f"/artifacts/{target}/ptt.yaml")
    if not ptt_path.exists():
        return []

    try:
        import yaml
    except ImportError:
        return []

    try:
        with open(ptt_path) as f:
            ptt = yaml.safe_load(f)
    except Exception:
        return []

    untried = []
    engagement = ptt.get("engagement", {})
    for host in engagement.get("hosts", []):
        host_ip = host.get("ip", "unknown")
        for service in host.get("services", []):
            svc_name = service.get("service", "unknown")
            svc_port = service.get("port", "?")
            for vector in service.get("vectors", []):
                vec_category = vector.get("category", "")
                for technique in vector.get("techniques", []):
                    if technique.get("status", "") == "pending":
                        name = technique.get("name", "unnamed")
                        priority_tag = ""
                        if vec_category == "quick_win":
                            priority_tag = " (HIGH PRIORITY)"
                        elif vec_category == "known_vuln":
                            priority_tag = " (MEDIUM PRIORITY)"
                        untried.append(
                            f"- {name} on {svc_name}:{svc_port} @ {host_ip}{priority_tag}"
                        )

    return untried


# =============================================================================
# Warning / Reset / Kill Message Builders
# =============================================================================

def build_loop_warning(level: int, failed_techniques: list,
                       untried_surfaces: list, consecutive: int) -> str:
    """
    Build the context injection message for the agent.

    Args:
        level: Escalation level (1, 2, or 3).
        failed_techniques: List of failed technique descriptions from PTT.
        untried_surfaces: List of untried technique descriptions from PTT.
        consecutive: Number of consecutive similar turns detected.

    Returns:
        Formatted warning string for additionalContext injection.
    """
    if level == 1:
        # Soft warning -- nudge the agent
        msg = (
            f"[LOOP WARNING -- {consecutive} consecutive similar turns detected]\n"
            f"You appear to be repeating the same analysis without executing commands.\n"
            f"REQUIRED: Execute ONE concrete tool action this turn.\n"
            f"If your current approach is not working, pivot to a different technique."
        )

        if untried_surfaces:
            msg += "\n\nUntried attack surfaces:\n"
            msg += "\n".join(untried_surfaces[:5])

        return msg

    elif level == 2:
        # Hard reset -- inject PTT blocklist and force pivot
        msg = (
            f"[LOOP DETECTED -- CONTEXT RESET ({consecutive} consecutive similar turns)]\n"
        )

        if failed_techniques:
            msg += (
                "The following techniques have been tried and FAILED. "
                "Do NOT revisit:\n"
            )
            msg += "\n".join(failed_techniques[:10])
            msg += "\n\n"

        if untried_surfaces:
            msg += "Untried attack surfaces:\n"
            msg += "\n".join(untried_surfaces[:10])
            msg += "\n\n"

        msg += (
            "Execute ONE new technique from the untried list and report results.\n"
            "PROHIBITED: Revisiting any technique listed above as FAILED.\n"
            "PROHIBITED: Multi-paragraph analysis without tool execution."
        )

        return msg

    else:
        # Level 3 -- this message goes into the reason field for the kill
        return (
            f"LOOP DETECTED LEVEL 3 -- session terminated after "
            f"{consecutive} consecutive similar turns with no progress. "
            f"Session state saved for human review."
        )


# =============================================================================
# Target Resolution (same pattern as sibling hooks)
# =============================================================================

def get_target_from_env() -> str:
    """Get current target from environment or CAS path."""
    # Try environment variable first
    target = os.environ.get("TARGET")
    if target:
        return target

    # Try to extract from CAS path
    cas_path = os.environ.get("CAS_PATH")
    if cas_path:
        parts = Path(cas_path).parts
        for i, part in enumerate(parts):
            if part == "artifacts" and i + 1 < len(parts):
                return parts[i + 1]

    # Fallback: scan for recent session directories
    artifacts_dir = Path(os.environ.get("ARTIFACTS_PATH", "/artifacts"))
    if artifacts_dir.exists():
        session_dirs = [
            d for d in artifacts_dir.iterdir()
            if d.is_dir() and (d / "session").exists()
        ]
        if session_dirs:
            # Return most recently modified
            session_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
            return session_dirs[0].name

    return ""


# =============================================================================
# Core Detection Logic
# =============================================================================

def detect_loop(state: dict, thought_text: str, tool_count: int) -> tuple:
    """
    Run loop detection against rolling window of turn fingerprints.

    Updates state in place and returns the escalation action to take.

    Args:
        state: Mutable state dictionary (updated in place).
        thought_text: The agent's thought/output text for this turn.
        tool_count: Number of tool executions in this turn (0 = thinking only).

    Returns:
        (escalation_level, consecutive_count) where escalation_level is:
            0 = no loop detected
            1 = soft warning
            2 = hard reset
            3 = session kill
    """
    state["total_turns"] = state.get("total_turns", 0) + 1

    # Compute MinHash for this turn's thought text
    shingles = shingle(thought_text)
    mh = minhash(shingles)

    # Build turn record
    turn_record = {
        "minhash": mh,
        "tool_count": tool_count,
        "turn_id": state["total_turns"],
    }

    # Append to rolling window
    turn_hashes = state.get("turn_hashes", [])
    turn_hashes.append(turn_record)

    # Trim to window size
    if len(turn_hashes) > WINDOW_SIZE:
        turn_hashes = turn_hashes[-WINDOW_SIZE:]
    state["turn_hashes"] = turn_hashes

    # Need at least 2 turns to compare
    if len(turn_hashes) < 2:
        state["consecutive_similar"] = 0
        state["escalation_level"] = 0
        return 0, 0

    # Check pairwise similarity with previous turn
    prev_mh = turn_hashes[-2]["minhash"]
    similarity = jaccard_similarity(prev_mh, mh)

    is_similar = similarity >= SIMILARITY_THRESHOLD
    is_zero_tool = tool_count == 0

    log_loop(
        f"Turn {state['total_turns']}: similarity={similarity:.3f}, "
        f"tool_count={tool_count}, "
        f"threshold={'EXCEEDED' if is_similar else 'ok'}"
    )

    # Update consecutive counter
    # A turn counts as "looping" if it is similar to the previous AND has zero tools
    if is_similar and is_zero_tool:
        state["consecutive_similar"] = state.get("consecutive_similar", 0) + 1
    elif is_similar:
        # Similar but with tool execution -- partial credit, increment slower
        state["consecutive_similar"] = max(
            0, state.get("consecutive_similar", 0) - 1
        )
    else:
        # Dissimilar turn -- reset counter
        state["consecutive_similar"] = 0

    consecutive = state["consecutive_similar"]

    # Determine escalation level
    if consecutive >= LEVEL_3_TURNS:
        level = 3
    elif consecutive >= LEVEL_2_TURNS:
        level = 2
    elif consecutive >= LEVEL_1_TURNS:
        level = 1
    else:
        level = 0

    state["escalation_level"] = level

    if level > 0:
        log_loop(
            f"Escalation LEVEL {level}: {consecutive} consecutive similar turns "
            f"(thresholds: L1={LEVEL_1_TURNS}, L2={LEVEL_2_TURNS}, L3={LEVEL_3_TURNS})"
        )

    return level, consecutive


# =============================================================================
# Hook Entrypoint
# =============================================================================

def main():
    """
    Process AfterTool event for loop detection.

    Reads hook input from stdin, runs loop detection against the rolling
    window, and writes the appropriate hook response to stdout.
    """
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Malformed input -- pass through
        print(json.dumps({"continue": True}))
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    tool_output = input_data.get("tool_output", "")

    # Get target
    target = get_target_from_env()
    if not target:
        log_loop("No target found, skipping loop detection")
        print(json.dumps({"continue": True}))
        return

    # Load state
    state = load_state(target)

    # Determine tool execution count for this turn
    # If we are in the AfterTool hook, at least one tool was called.
    # But we differentiate between "real work" tools and passive tools.
    tool_count = 1 if tool_name in EXECUTION_TOOLS else 0

    # Use tool_output as the "thought text" for fingerprinting.
    # In Gemini CLI, tool_output contains the agent's response/reasoning.
    # For shell tools, tool_output is command output (less useful for loop
    # detection), but for delegate_to_agent and others it captures thought.
    # We also incorporate tool_input for broader fingerprinting.
    thought_text = ""
    if isinstance(tool_output, str):
        thought_text += tool_output
    if isinstance(tool_input, dict):
        # Include relevant input fields for fingerprinting
        for key in ("command", "query", "prompt", "agent_name"):
            val = tool_input.get(key, "")
            if val:
                thought_text += f" {val}"
    elif isinstance(tool_input, str):
        thought_text += f" {tool_input}"

    if not thought_text.strip():
        # No text to fingerprint -- pass through
        log_loop("No thought text to fingerprint, skipping")
        print(json.dumps({"continue": True}))
        save_state(target, state)
        return

    # Run detection
    level, consecutive = detect_loop(state, thought_text, tool_count)

    # Save updated state
    save_state(target, state)

    # Build response based on escalation level
    if level == 0:
        # No loop -- pass through
        print(json.dumps({"continue": True}))
        return

    if level == 3:
        # Kill session
        failed = load_ptt_failed_techniques(target)
        untried = load_ptt_untried_surfaces(target)
        reason = build_loop_warning(3, failed, untried, consecutive)
        log_loop(f"SESSION KILL: {reason}")

        # Save final state before kill
        state["kill_reason"] = reason
        save_state(target, state)

        print(json.dumps({
            "continue": False,
            "reason": reason,
        }))
        return

    # Level 1 or 2 -- inject warning/reset context
    failed = load_ptt_failed_techniques(target) if level >= 2 else []
    untried = load_ptt_untried_surfaces(target)
    warning = build_loop_warning(level, failed, untried, consecutive)

    log_loop(f"Injecting level {level} warning ({consecutive} consecutive)")

    print(json.dumps({
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": "AfterTool",
            "additionalContext": warning,
        },
    }))


if __name__ == "__main__":
    main()
