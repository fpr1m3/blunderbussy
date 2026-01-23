#!/usr/bin/env python3
"""
PostToolUse Hook - Credential Extraction, Query Caching, Session Memory & Hypothesis Ranking
=============================================================================================
Gemini CLI hook that:
1. Extracts credentials from shell command output
2. Caches query results for deduplication
3. Indexes events to Qdrant session memory for semantic search
4. Updates hypothesis confidence based on technique outcomes (Phase 5)

Triggered after: pwncat__command, Shell, bash, qdrant-find, google_web_search, web_fetch
Action: Extract credentials, cache queries, index to session memory, update hypothesis confidence

Usage by Gemini CLI:
    python3 /ext/opulence/hooks/post_tool_use.py

Input (stdin): JSON with tool_name, tool_input, tool_output
Output (stdout): JSON response (pass-through, possibly with annotations)
"""

import sys
import json
import os
import re
from pathlib import Path

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from session_state import (
    SessionStateManager,
    extract_credentials_from_output,
    ConfidenceDelta,
)

# Import session memory (optional - may not have dependencies)
try:
    from session_memory import SessionMemory, EventType, Outcome
    HAS_SESSION_MEMORY = True
except ImportError:
    HAS_SESSION_MEMORY = False


# Tools that may contain credential output
CREDENTIAL_TOOLS = {
    "pwncat__command",
    "Shell",
    "bash",
    "execute_command",
}

# Tools that support query caching
QUERY_TOOLS = {
    "qdrant-find": {"query_param": "query", "ttl": 60},
    "google_web_search": {"query_param": "query", "ttl": 30},
    "web_fetch": {"query_param": "url", "ttl": 30},
}


def get_target_from_env() -> str:
    """Get current target from environment or CAS path."""
    # Try environment variable first
    target = os.environ.get("TARGET")
    if target:
        return target

    # Try to extract from CAS path
    cas_path = os.environ.get("CAS_PATH")
    if cas_path:
        # /artifacts/10.129.5.135/context.yaml -> 10.129.5.135
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


def summarize_output(output: str, max_length: int = 200) -> str:
    """Create a brief summary of tool output for caching."""
    if not output:
        return "No results"

    # Clean and truncate
    summary = output.strip()

    # For structured outputs, try to extract key info
    if "techniques" in summary.lower() or "skill" in summary.lower():
        # Count matches
        lines = summary.split('\n')
        match_count = sum(1 for line in lines if line.strip().startswith('-') or line.strip().startswith('*'))
        if match_count > 0:
            first_matches = [l.strip() for l in lines if l.strip().startswith('-') or l.strip().startswith('*')][:3]
            return f"Found {match_count} results: " + "; ".join(first_matches)[:max_length]

    # Default: truncate with ellipsis
    if len(summary) > max_length:
        return summary[:max_length - 3] + "..."
    return summary


def handle_credential_extraction(tool_name: str, tool_output: str, target: str) -> dict:
    """Extract credentials from shell output."""
    credentials = extract_credentials_from_output(
        tool_output,
        source=f"{tool_name} command output"
    )

    if not credentials:
        return {"action": "continue"}

    try:
        base_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
        mgr = SessionStateManager.from_target(target, base_path=base_path)

        added_count = 0
        for cred in credentials:
            mgr.add_credential(cred)
            added_count += 1

        mgr.log_action("credential_extracted", {
            "tool": tool_name,
            "count": added_count,
            "usernames": [c.username for c in credentials]
        })

        mgr.save_all()

        return {
            "action": "continue",
            "annotations": [{
                "type": "credential_found",
                "message": f"Extracted {added_count} credential(s) from {tool_name} output",
                "credentials": [
                    {"username": c.username, "type": c.secret_type.value}
                    for c in credentials
                ]
            }]
        }

    except Exception as e:
        return {"action": "continue", "error": str(e)}


def handle_query_caching(tool_name: str, tool_input: dict, tool_output: str, target: str) -> dict:
    """Cache query results for deduplication."""
    tool_config = QUERY_TOOLS.get(tool_name)
    if not tool_config:
        return {"action": "continue"}

    query_param = tool_config["query_param"]
    query = tool_input.get(query_param, "")

    if not query:
        return {"action": "continue"}

    try:
        base_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
        mgr = SessionStateManager.from_target(target, base_path=base_path)

        # Create summary of results
        summary = summarize_output(tool_output)

        # Cache the query
        mgr.cache_query(
            query=query,
            tool=tool_name,
            results_summary=summary,
            ttl_minutes=tool_config["ttl"]
        )

        mgr.log_action("query_cached", {
            "tool": tool_name,
            "query": query[:100],
            "summary_length": len(summary)
        })

        mgr.save_all()

        return {
            "action": "continue",
            "annotations": [{
                "type": "query_cached",
                "message": f"Cached {tool_name} query for {tool_config['ttl']} minutes"
            }]
        }

    except Exception as e:
        return {"action": "continue", "error": str(e)}


# =============================================================================
# Session Memory Indexing
# =============================================================================

# Error patterns that indicate failures worth indexing
ERROR_PATTERNS = [
    (r"permission denied", "permission_error"),
    (r"access denied", "access_error"),
    (r"connection refused", "connection_error"),
    (r"timeout|timed out", "timeout_error"),
    (r"not found|no such file", "not_found_error"),
    (r"authentication failed|invalid password", "auth_error"),
    (r"blocked|filtered|firewall", "blocked_error"),
    (r"exploit completed|shell opened|session \d+ opened", "exploit_success"),
    (r"flag\{|HTB\{|user\.txt|root\.txt", "flag_found"),
]


def detect_outcome(output: str) -> tuple[Outcome, str]:
    """Detect outcome from shell output."""
    output_lower = output.lower()

    for pattern, error_type in ERROR_PATTERNS:
        if re.search(pattern, output_lower):
            if error_type in ("exploit_success", "flag_found"):
                return Outcome.SUCCESS, error_type
            elif error_type == "blocked_error":
                return Outcome.BLOCKED, error_type
            else:
                return Outcome.FAILED, error_type

    # Default: assume partial/pending if no clear signal
    return Outcome.PARTIAL, "no_clear_outcome"


def handle_session_memory_indexing(
    tool_name: str,
    tool_input: dict,
    tool_output: str,
    target: str
) -> dict:
    """Index shell commands and their outcomes to session memory."""
    if not HAS_SESSION_MEMORY:
        return {"action": "continue"}

    # Only index shell tools
    if tool_name not in CREDENTIAL_TOOLS:
        return {"action": "continue"}

    # Extract command from input
    command = tool_input.get("command", tool_input.get("cmd", ""))
    if not command:
        return {"action": "continue"}

    # Skip trivial commands
    trivial_patterns = [
        r"^(ls|pwd|cd|echo|cat|head|tail|whoami|id|uname)\b",
        r"^(env|export|alias|source)\b",
    ]
    for pattern in trivial_patterns:
        if re.match(pattern, command.strip()):
            return {"action": "continue"}

    try:
        mem = SessionMemory.for_target(target)

        # Detect outcome
        outcome, outcome_type = detect_outcome(tool_output)

        # Build context for embedding
        context = f"Command: {command}\n"
        if len(tool_output) < 500:
            context += f"Output: {tool_output}"
        else:
            context += f"Output (truncated): {tool_output[:500]}..."

        # Determine event type
        if outcome_type == "flag_found":
            event_type = EventType.FLAG_CAPTURED
        elif outcome == Outcome.SUCCESS and "shell" in tool_output.lower():
            event_type = EventType.ACCESS_GAINED
        elif outcome == Outcome.FAILED or outcome == Outcome.BLOCKED:
            event_type = EventType.ERROR_RESOLUTION if "resolution" in tool_output.lower() else EventType.TECHNIQUE_ATTEMPT
        else:
            event_type = EventType.TECHNIQUE_ATTEMPT

        # Extract technique hints from command
        tags = []
        technique_patterns = [
            (r"\bnmap\b", "nmap", "recon"),
            (r"\bgobuster\b|\bffuf\b|\bdirsearch\b", "web_fuzzing", "recon"),
            (r"\bsqlmap\b|\bunion.*select\b", "sqli", "injection"),
            (r"\bhydra\b|\bmedusa\b|\bncrack\b", "brute_force", "auth"),
            (r"\bmetasploit\b|\bmsfconsole\b|\bexploit/", "metasploit", "exploit"),
            (r"\bssh\b", "ssh", "remote_access"),
            (r"\bnetcat\b|\bnc\b|\bsocat\b", "reverse_shell", "post_exploit"),
            (r"\bprivesc\b|\blinpeas\b|\bwinpeas\b", "privesc", "post_exploit"),
            (r"\bsudo\b|\bsuid\b", "privilege", "privesc"),
            (r"\bcurl\b|\bwget\b", "http_request", "web"),
        ]

        for pattern, tag, category in technique_patterns:
            if re.search(pattern, command.lower()):
                tags.extend([tag, category])

        # Add outcome type as tag
        tags.append(outcome_type)

        # Index to session memory
        success = mem.index_event(
            event_type=event_type,
            context=context,
            outcome=outcome,
            tags=list(set(tags)),  # Dedupe
        )

        if success:
            return {
                "action": "continue",
                "annotations": [{
                    "type": "session_memory_indexed",
                    "message": f"Indexed {event_type.value} to session memory",
                    "outcome": outcome.value,
                }]
            }

    except Exception as e:
        # Don't fail the hook if session memory fails
        pass

    return {"action": "continue"}


# =============================================================================
# Hypothesis Confidence Updates (Phase 5)
# =============================================================================

# Patterns that indicate technique success (warrant confidence boost)
SUCCESS_PATTERNS = [
    (r"exploit completed", "exploit_success"),
    (r"shell opened|session \d+ opened", "shell_obtained"),
    (r"authenticated|logged in|login success", "auth_success"),
    (r"flag\{|HTB\{", "flag_captured"),
    (r"root@|#\s*$", "root_shell"),
    (r"meterpreter\s*>", "meterpreter_session"),
    (r"www-data@|user@", "user_shell"),
]

# Patterns that indicate technique failure (warrant confidence reduction)
FAILURE_PATTERNS = [
    (r"exploit failed|exploit aborted", "exploit_failed"),
    (r"authentication failed|invalid password|access denied", "auth_failed"),
    (r"permission denied", "permission_denied"),
    (r"connection refused|connection closed", "connection_failed"),
    (r"timeout|timed out", "timeout"),
    (r"not vulnerable|not exploitable", "not_vulnerable"),
    (r"payload failed|payload error", "payload_failed"),
]

# Patterns that indicate blocking (warrant setting to blocked threshold)
BLOCKING_PATTERNS = [
    (r"blocked by firewall|filtered|waf detected", "firewall_blocked"),
    (r"rate limited|too many requests", "rate_limited"),
    (r"ids detected|ips blocked", "ids_blocked"),
]


def detect_hypothesis_outcome(output: str) -> tuple[str, str, float]:
    """
    Detect outcome from shell output for hypothesis updates.

    Returns:
        (outcome_type, evidence, confidence_delta)
        outcome_type: 'success', 'failure', 'blocked', or 'none'
        evidence: Description of what was detected
        confidence_delta: Suggested confidence change
    """
    output_lower = output.lower()

    # Check for success patterns first
    for pattern, outcome_name in SUCCESS_PATTERNS:
        if re.search(pattern, output_lower):
            return "success", f"Detected: {outcome_name}", ConfidenceDelta.TECHNIQUE_SUCCESS

    # Check for blocking patterns (more specific than general failure)
    for pattern, outcome_name in BLOCKING_PATTERNS:
        if re.search(pattern, output_lower):
            return "blocked", f"Blocked by: {outcome_name}", ConfidenceDelta.BLOCKED_THRESHOLD

    # Check for failure patterns
    for pattern, outcome_name in FAILURE_PATTERNS:
        if re.search(pattern, output_lower):
            return "failure", f"Failed: {outcome_name}", ConfidenceDelta.TECHNIQUE_FAIL

    return "none", "", 0.0


def handle_hypothesis_updates(
    tool_name: str,
    tool_input: dict,
    tool_output: str,
    target: str
) -> dict:
    """
    Update hypothesis confidence based on shell command outcomes.

    Automatically adjusts confidence for hypotheses linked to techniques
    based on success/failure patterns in the output.
    """
    # Only process shell tools
    if tool_name not in CREDENTIAL_TOOLS:
        return {"action": "continue"}

    # Extract command from input
    command = tool_input.get("command", tool_input.get("cmd", ""))
    if not command:
        return {"action": "continue"}

    # Skip trivial commands
    trivial_patterns = [
        r"^(ls|pwd|cd|echo|cat|head|tail|whoami|id|uname)\b",
        r"^(env|export|alias|source|history)\b",
    ]
    for pattern in trivial_patterns:
        if re.match(pattern, command.strip()):
            return {"action": "continue"}

    # Detect outcome
    outcome_type, evidence, delta = detect_hypothesis_outcome(tool_output)

    if outcome_type == "none":
        return {"action": "continue"}

    try:
        base_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
        mgr = SessionStateManager.from_target(target, base_path=base_path)

        # Get all active hypotheses
        active_hyps = mgr.get_active_hypotheses(limit=10)

        if not active_hyps:
            return {"action": "continue"}

        updated_count = 0
        updated_hyps = []

        # Update hypotheses that match command patterns
        # This is a heuristic - we look for command patterns that relate to hypothesis descriptions
        for hyp in active_hyps:
            should_update = False
            hyp_desc_lower = hyp.description.lower()

            # Check if command relates to hypothesis (simple keyword matching)
            command_lower = command.lower()

            # Common technique-to-hypothesis keyword mappings
            mappings = [
                (r"\bsqlmap\b|\bsql.*injection\b|\bunion.*select\b", ["sql", "injection", "sqli", "database"]),
                (r"\bhydra\b|\bmedusa\b|\bncrack\b|\bbrute", ["brute", "password", "login", "auth", "crack"]),
                (r"\bmetasploit\b|\bmsfconsole\b|\bexploit/", ["exploit", "cve-", "vulnerability", "remote"]),
                (r"\bkernel\b|\bprivesc\b|\blinpeas\b|\bsuid\b", ["kernel", "privilege", "escalation", "root", "suid"]),
                (r"\bssh\b", ["ssh", "remote", "shell"]),
                (r"\bweb.*shell\b|\bphp.*reverse\b|\bupload", ["webshell", "upload", "rce", "php"]),
                (r"\blfi\b|\brfi\b|\binclude\b", ["lfi", "rfi", "include", "traversal"]),
                (r"\bsmb\b|\bsamba\b|\beternalblue\b", ["smb", "samba", "windows", "share"]),
            ]

            for cmd_pattern, hyp_keywords in mappings:
                if re.search(cmd_pattern, command_lower):
                    if any(kw in hyp_desc_lower for kw in hyp_keywords):
                        should_update = True
                        break

            if should_update:
                if outcome_type == "blocked":
                    # Set to blocked threshold
                    mgr.block_hypothesis(hyp.id, evidence)
                else:
                    # Apply delta
                    is_contradiction = outcome_type == "failure"
                    mgr.update_hypothesis_confidence(
                        hyp.id,
                        delta=delta,
                        reason=f"{evidence} (from: {command[:50]}...)" if len(command) > 50 else f"{evidence} (from: {command})",
                        is_contradiction=is_contradiction
                    )

                updated_count += 1
                updated_hyps.append({
                    "id": hyp.id,
                    "outcome": outcome_type,
                    "delta": delta if outcome_type != "blocked" else "blocked"
                })

        if updated_count > 0:
            # Log the update
            mgr.log_action("hypothesis_confidence_updated", {
                "tool": tool_name,
                "command": command[:100],
                "outcome_type": outcome_type,
                "updated_hypotheses": updated_hyps
            })

            mgr.save_all()

            return {
                "action": "continue",
                "annotations": [{
                    "type": "hypothesis_updated",
                    "message": f"Updated {updated_count} hypothesis confidence ({outcome_type})",
                    "hypotheses": updated_hyps
                }]
            }

    except Exception as e:
        # Don't fail the hook if hypothesis update fails
        pass

    return {"action": "continue"}


def main():
    """Process PostToolUse event."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"action": "continue"}))
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    tool_output = input_data.get("tool_output", "")

    # Get target
    target = get_target_from_env()
    if not target:
        print(json.dumps({"action": "continue"}))
        return

    # Skip if no output
    if not tool_output or not isinstance(tool_output, str):
        print(json.dumps({"action": "continue"}))
        return

    result = {"action": "continue"}
    annotations = []

    # Handle query caching for search tools
    if tool_name in QUERY_TOOLS:
        cache_result = handle_query_caching(tool_name, tool_input, tool_output, target)
        if "annotations" in cache_result:
            annotations.extend(cache_result["annotations"])

    # Handle credential extraction for shell tools
    if tool_name in CREDENTIAL_TOOLS:
        cred_result = handle_credential_extraction(tool_name, tool_output, target)
        if "annotations" in cred_result:
            annotations.extend(cred_result["annotations"])

    # Handle session memory indexing for shell tools
    if tool_name in CREDENTIAL_TOOLS:
        mem_result = handle_session_memory_indexing(tool_name, tool_input, tool_output, target)
        if "annotations" in mem_result:
            annotations.extend(mem_result["annotations"])

    # Handle hypothesis confidence updates for shell tools (Phase 5)
    if tool_name in CREDENTIAL_TOOLS:
        hyp_result = handle_hypothesis_updates(tool_name, tool_input, tool_output, target)
        if "annotations" in hyp_result:
            annotations.extend(hyp_result["annotations"])

    # Build final response
    if annotations:
        result["annotations"] = annotations

    print(json.dumps(result))


if __name__ == "__main__":
    main()
