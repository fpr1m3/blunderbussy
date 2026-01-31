#!/usr/bin/env python3
"""
AfterTool Hook - Pipeline Gate, Web Stripping, Credential Extraction, Query Caching, Session Memory & Hypothesis Ranking
==========================================================================================================================
Gemini CLI hook that:
1. Gates code-vuln-analysis pipeline stages (prevents goal amnesia after delegate_to_agent)
2. Strips web content (JS/CSS/SVG) from web tool output to prevent context pollution
3. Extracts credentials from shell command output
4. Caches query results for deduplication
5. Indexes events to Qdrant session memory for semantic search
6. Updates hypothesis confidence based on technique outcomes (Phase 5)

Triggered after: delegate_to_agent, pwncat__command, Shell, bash, qdrant-find, google_web_search, web_fetch, curl, wget, httpx
Action: Gate pipeline stages, strip web content, extract credentials, cache queries, index to session memory, update hypothesis confidence

Usage by Gemini CLI:
    python3 /ext/opulence/hooks/after_tool.py

Input (stdin): JSON with tool_name, tool_input, tool_output (AfterToolInput interface)
Output (stdout): JSON response using Gemini CLI HookOutput format:
    - continue: true to proceed
    - hookSpecificOutput.additionalContext for context injection
"""

import sys
import json
import os
import re
from pathlib import Path

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# =============================================================================
# Output Truncation Configuration
# =============================================================================
MAX_OUTPUT_CHARS = int(os.environ.get("DAME_MAX_OUTPUT", "8000"))

from session_state import (
    SessionStateManager,
    extract_credentials_from_output,
    ConfidenceDelta,
)


def log_creds(msg: str):
    """Log credential extraction to stderr."""
    print(f"[CREDS] {msg}", file=sys.stderr)


def log_hypothesis(msg: str):
    """Log hypothesis updates to stderr."""
    print(f"[HYPOTHESIS] {msg}", file=sys.stderr)


def log_cache(msg: str):
    """Log cache operations to stderr."""
    print(f"[CACHE] {msg}", file=sys.stderr)


def log_pipeline_gate(msg: str):
    """Log pipeline stage gate events to stderr."""
    print(f"[PIPELINE_GATE] {msg}", file=sys.stderr)


def log_web_strip(msg: str):
    """Log web content stripping to stderr."""
    print(f"[WEB_STRIP] {msg}", file=sys.stderr)


def log_truncate(msg: str):
    """Log output truncation to stderr."""
    print(f"[TRUNCATE] {msg}", file=sys.stderr)


# =============================================================================
# Output Truncation (Context Overflow Prevention)
# =============================================================================

# Patterns for known bloat that should be stripped before truncation
BLOAT_PATTERNS = [
    # Minified JavaScript - long lines with common JS patterns and minimal whitespace
    (r'(?:^|\n)[^\n]{500,}(?:function|var |let |const |=>|\{|\}|;)[^\n]*(?:\n|$)', 'minified_js'),
    # Base64 data URIs (images, fonts, etc.)
    (r'data:[a-zA-Z0-9/+]+;base64,[A-Za-z0-9+/=]{100,}', 'base64_data_uri'),
    # Long base64-like strings (alphanumeric, 100+ chars with no spaces)
    (r'(?<![a-zA-Z0-9])[A-Za-z0-9+/=]{200,}(?![a-zA-Z0-9])', 'base64_blob'),
    # Hex dumps (common in binary output)
    (r'(?:^|\n)(?:[0-9a-fA-F]{2}\s*){32,}(?:\n|$)', 'hex_dump'),
    # Long lines with no spaces (likely binary/minified content)
    (r'(?:^|\n)[^\s\n]{300,}(?:\n|$)', 'long_no_space'),
    # Repeated patterns (e.g., "AAAA..." padding)
    (r'(.)\1{50,}', 'repeated_chars'),
    # Source maps
    (r'//# sourceMappingURL=data:[^\n]+', 'source_map'),
    # Inline SVG data
    (r'<svg[^>]*>(?:[^<]|<(?!/svg>))*</svg>', 'inline_svg'),
]


def truncate_output(output: str, max_chars: int = None) -> tuple[str, bool]:
    """
    Truncate tool output to prevent context overflow.

    Strips known bloat patterns (minified JS, base64, hex dumps) before truncating.

    Args:
        output: Raw tool output string
        max_chars: Maximum allowed characters (default from MAX_OUTPUT_CHARS)

    Returns:
        (truncated_output, was_truncated) tuple
    """
    if max_chars is None:
        max_chars = MAX_OUTPUT_CHARS

    if not output or len(output) <= max_chars:
        return output, False

    original_len = len(output)
    cleaned = output
    patterns_stripped = []

    # Strip known bloat patterns
    for pattern, pattern_name in BLOAT_PATTERNS:
        try:
            matches = list(re.finditer(pattern, cleaned, re.MULTILINE | re.IGNORECASE))
            if matches:
                # Replace with placeholder showing what was stripped
                for match in reversed(matches):  # Reverse to preserve indices
                    stripped_len = len(match.group())
                    if stripped_len > 100:  # Only strip if substantial
                        placeholder = f"[STRIPPED: {pattern_name} ({stripped_len} chars)]"
                        cleaned = cleaned[:match.start()] + placeholder + cleaned[match.end():]
                        patterns_stripped.append(pattern_name)
        except re.error:
            # Skip problematic patterns
            continue

    # Check if stripping was enough
    if len(cleaned) <= max_chars:
        if patterns_stripped:
            log_truncate(f"Stripped bloat patterns: {set(patterns_stripped)}, {original_len} -> {len(cleaned)} chars")
        return cleaned, len(cleaned) < original_len

    # Still over limit - truncate with suffix
    truncate_suffix = f"\n\n[TRUNCATED: {original_len} chars -> {max_chars} chars]"
    truncated = cleaned[:max_chars - len(truncate_suffix)] + truncate_suffix

    log_truncate(f"Output truncated: {original_len} -> {max_chars} chars (stripped: {set(patterns_stripped) if patterns_stripped else 'none'})")

    return truncated, True


# =============================================================================
# Pipeline Completion Gate (Code Vulnerability Analysis)
# =============================================================================

PIPELINE_STAGE_GATES = {
    "code-analysis-recon": {
        "stage": 1,
        "artifact": "01-recon-manifest.yaml",
        "next_action": (
            "Write recon output to {ARTIFACT_DIR}/01-recon-manifest.yaml, "
            "update state.yaml, then invoke code-analysis-triage. "
            "Do NOT read source files."
        ),
    },
    "code-analysis-triage": {
        "stage": 2,
        "artifact": "02-triage-chunks.yaml",
        "next_action": (
            "Write triage output to {ARTIFACT_DIR}/02-triage-chunks.yaml, "
            "update state.yaml, then invoke code-analysis-analysis for each chunk. "
            "Do NOT read source files."
        ),
    },
    "code-analysis-analysis": {
        "stage": 3,
        "artifact": "03-analysis-chunk-*.yaml",
        "next_action": (
            "Write analysis output to {ARTIFACT_DIR}/03-analysis-chunk-{id}.yaml. "
            "If all chunks processed, aggregate to 03-analysis-findings.yaml, "
            "update state.yaml, then invoke code-analysis-validation. "
            "Do NOT read source files."
        ),
    },
    "code-analysis-validation": {
        "stage": 4,
        "artifact": "04-validation-findings.yaml",
        "next_action": "PIPELINE COMPLETE",
    },
}

_PIPELINE_HARD_STOP = """
=== CODE VULNERABILITY ANALYSIS PIPELINE COMPLETE ===

All 4 phases finished. You MUST now:
1. Write 04-validation-findings.yaml (YAML portion of output)
2. Write 04-validation-brief.md (Vulnerability Brief portion)
3. Update state.yaml with current_phase: complete
4. Return the Vulnerability Brief to your exploitation workflow

PROHIBITED: Reading source files, running grep/cat, exploring the codebase.
The pipeline is done. Proceed to exploitation using the PoCs from the brief.
""".strip()


def handle_pipeline_completion_gate(tool_name: str, tool_input: dict) -> str | None:
    """
    Inject stage-specific directives when a pipeline agent finishes.

    Returns a directive string for additionalContext, or None if not a pipeline tool.
    """
    if tool_name != "delegate_to_agent":
        return None

    agent_name = tool_input.get("agent_name", "")
    gate = PIPELINE_STAGE_GATES.get(agent_name)
    if gate is None:
        return None

    stage = gate["stage"]
    next_action = gate["next_action"]

    if next_action == "PIPELINE COMPLETE":
        log_pipeline_gate(f"Stage {stage}/4 ({agent_name}) COMPLETE — injecting hard stop")
        return _PIPELINE_HARD_STOP

    log_pipeline_gate(f"Stage {stage}/4 ({agent_name}) done — injecting next-action directive")
    return (
        f"[PIPELINE STAGE {stage}/4 COMPLETE: {agent_name}]\n"
        f"Next: {next_action}\n"
        f"PROHIBITED: Reading source files, running grep/cat, exploring the codebase."
    )


# =============================================================================
# Pipeline Failure Recovery (Sub-Agent Timeout/Error Handling)
# =============================================================================

PIPELINE_FAILURE_RECOVERY = {
    "code-analysis-recon": {
        "recovery": (
            "Recon agent failed. Likely cause: too many files in source directory. "
            "Manual fallback: run 'find {SRC_DIR} -name \"*.php\" -o -name \"*.py\" | head -30' "
            "and list files manually."
        ),
    },
    "code-analysis-triage": {
        "recovery": (
            "Triage agent failed. Likely cause: recon manifest too large for sub-agent context. "
            "Recovery options:\n"
            "1. Reduce the file list in 01-recon-manifest.yaml to top-20 files by relevance\n"
            "2. Run triage manually: categorize files into chunks of 5-8 files each\n"
            "3. Skip triage and analyze the top-3 most suspicious files directly"
        ),
    },
    "code-analysis-analysis": {
        "recovery": (
            "Analysis agent failed on chunk '{chunk_id}'. Likely cause: chunk too large "
            "for sub-agent context window. Recovery options:\n"
            "1. Split this chunk into 2 smaller chunks (halve the file list)\n"
            "2. Analyze the highest-priority file from this chunk manually using grep-before-read\n"
            "3. Skip this chunk and proceed to the next one\n"
            "DO NOT retry with the same input — the sub-agent will fail again."
        ),
    },
    "code-analysis-validation": {
        "recovery": (
            "Validation agent failed. Recovery:\n"
            "1. Review 03-analysis-findings.yaml directly for PoC candidates\n"
            "2. Select the highest-confidence finding and write a manual PoC\n"
            "3. Skip validation and proceed to exploitation with best available finding"
        ),
    },
}

# High-priority sinks that warrant escalation when lost to pipeline failure
HIGH_PRIORITY_SINKS = [
    "yaml_parse_file", "yaml_parse", "yaml.load", "yaml.unsafe_load",
    "unserialize", "pickle.loads", "marshal.loads", "readObject",
    "Runtime.getRuntime().exec", "ProcessBuilder",
    "eval", "exec", "system", "passthru", "shell_exec",
    "preg_replace",  # with /e modifier
]


def handle_pipeline_failure_gate(tool_name: str, tool_input: dict, tool_output: str) -> str | None:
    """
    Inject structured recovery guidance when a pipeline sub-agent fails.

    Detects failure from error patterns in tool_output from delegate_to_agent.
    Cross-references triage output for high-priority sinks in the failed chunk.

    Returns a recovery directive string, or None if not a pipeline failure.
    """
    if tool_name != "delegate_to_agent":
        return None

    agent_name = tool_input.get("agent_name", "")
    recovery_config = PIPELINE_FAILURE_RECOVERY.get(agent_name)
    if recovery_config is None:
        return None

    # Detect failure indicators
    output_str = str(tool_output).lower() if tool_output else ""
    failure_indicators = [
        "400", "invalid_argument", "timeout", "error", "failed",
        "internal error", "rate limit", "resource exhausted",
    ]

    is_failure = (
        not tool_output
        or len(str(tool_output).strip()) < 50  # Suspiciously short output
        or any(indicator in output_str for indicator in failure_indicators)
    )

    if not is_failure:
        return None

    log_pipeline_gate(f"FAILURE detected for {agent_name}: output={str(tool_output)[:100]}")

    # Build recovery message
    chunk_id = tool_input.get("query", "").split("chunk")[-1].strip() if "chunk" in tool_input.get("query", "") else "unknown"
    recovery_text = recovery_config["recovery"].format(
        SRC_DIR="/artifacts/*/source",
        chunk_id=chunk_id,
    )

    # Check for high-priority sink escalation
    escalation = _check_sink_escalation(agent_name)

    directive = (
        f"[PIPELINE STAGE FAILED: {agent_name}]\n"
        f"{recovery_text}\n"
    )

    if escalation:
        directive += f"\n{escalation}"

    return directive


def _check_sink_escalation(agent_name: str) -> str | None:
    """
    Cross-reference triage output for high-priority sinks in a failed chunk.

    Reads 02-triage-chunks.yaml to find dangerous sinks that were in the
    failed chunk, warranting manual analysis escalation.
    """
    import yaml

    # Find triage output
    artifacts_dir = Path(os.environ.get("ARTIFACTS_PATH", "/artifacts"))
    if not artifacts_dir.exists():
        return None

    # Search for triage chunks file
    triage_files = list(artifacts_dir.glob("*/code-analysis/02-triage-chunks.yaml"))
    if not triage_files:
        return None

    try:
        with open(triage_files[0], 'r') as f:
            triage_data = yaml.safe_load(f) or {}

        # Look for high-priority sinks across chunks
        escalations = []
        for chunk in triage_data.get("chunks", []):
            sinks = chunk.get("sinks", [])
            files = chunk.get("files", [])

            for sink in sinks:
                sink_name = sink if isinstance(sink, str) else sink.get("name", "")
                if any(hp_sink in sink_name for hp_sink in HIGH_PRIORITY_SINKS):
                    file_context = ", ".join(files[:3]) if files else "unknown files"
                    escalations.append(
                        f"\u26a0\ufe0f HIGH-PRIORITY: {sink_name} found in [{file_context}]. "
                        f"This is a dangerous sink that often leads to RCE. "
                        f"MANDATORY: Analyze this file manually using grep-before-read. "
                        f"Check if the file path passed to {sink_name} is user-controllable."
                    )

        if escalations:
            return "\n".join(escalations)

    except Exception:
        pass

    return None


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

# =============================================================================
# Brute-Force Tool Result Parsers (Structured Verdict Injection)
# =============================================================================

CREDENTIAL_TOOL_PARSERS = {
    "hydra": {
        "success_pattern": r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
        "summary_pattern": r"(\d+) valid password[s]? found",
        "no_result": r"0 valid passwords found|no valid passwords found",
        "trigger_pattern": r"\bhydra\b",
    },
    "medusa": {
        "success_pattern": r"ACCOUNT FOUND:.*Host:\s*(\S+).*User:\s*(\S+).*Password:\s*(\S+)",
        "summary_pattern": r"(\d+) of \d+ target",
        "no_result": r"0 of \d+ target",
        "trigger_pattern": r"\bmedusa\b",
    },
    "ncrack": {
        "success_pattern": r"Discovered credentials.*\s+(\S+)\s+(\S+)\s+(\S+)",
        "summary_pattern": r"Discovered credentials",
        "no_result": r"No credentials found|Ncrack done: 0 credentials found",
        "trigger_pattern": r"\bncrack\b",
    },
}


def parse_credential_tool_output(command: str, output: str) -> str | None:
    """
    Parse brute-force tool output and inject structured verdict.

    Unlike extract_credentials_from_output which only captures successful finds,
    this function also surfaces NEGATIVE results explicitly — "nothing found" is
    as important as "something found" to prevent the agent from re-running the tool.

    Returns a structured verdict string, or None if not a brute-force tool.
    """
    command_lower = command.lower()

    for tool_name, patterns in CREDENTIAL_TOOL_PARSERS.items():
        if not re.search(patterns["trigger_pattern"], command_lower):
            continue

        # Check for successful credentials
        successes = re.findall(patterns["success_pattern"], output, re.IGNORECASE)

        if successes:
            cred_lines = []
            for match in successes[:10]:  # Cap at 10
                cred_lines.append(f"  - {match}")
            return (
                f"[{tool_name.upper()} RESULT SUMMARY]\n"
                f"Status: {len(successes)} VALID CREDENTIAL(S) FOUND\n"
                f"Credentials:\n" + "\n".join(cred_lines) +
                f"\n\u2192 Store these credentials and test against other services."
            )

        # Check for explicit no-result
        if re.search(patterns["no_result"], output, re.IGNORECASE):
            # Try to extract what was tested
            return (
                f"[{tool_name.upper()} RESULT SUMMARY]\n"
                f"Status: NO VALID CREDENTIALS FOUND\n"
                f"\u2192 Brute-force is EXHAUSTED for these parameters. Move to next technique."
            )

        # Tool was used but output is ambiguous
        return (
            f"[{tool_name.upper()} RESULT SUMMARY]\n"
            f"Status: INCONCLUSIVE \u2014 check output manually\n"
            f"\u2192 Review the raw output above for partial results."
        )

    return None


# =============================================================================
# Redirect / Vhost Alias Detection
# =============================================================================

def detect_redirect_alias(output: str, known_hosts: list[str]) -> str | None:
    """
    Detect when a curl/wget response redirects to a known host, indicating
    the queried hostname is just an alias, not a separate target.

    Args:
        output: Tool output (curl -I headers, wget output, etc.)
        known_hosts: List of known hostnames from CAS

    Returns:
        Warning string if redirect alias detected, None otherwise.
    """
    if not known_hosts:
        return None

    # Match Location header in various formats
    redirect_patterns = [
        r'[Ll]ocation:\s*(https?://([^/\s]+))',
        r'[Rr]edirect(?:ed)?\s+to\s+(https?://([^/\s]+))',
        r'-> (https?://([^/\s]+))',
    ]

    for pattern in redirect_patterns:
        match = re.search(pattern, output)
        if match:
            redirect_url = match.group(1)
            redirect_host = match.group(2)
            if redirect_host in known_hosts:
                return (
                    f"[VHOST ALIAS DETECTED] This host redirects to {redirect_host} "
                    f"({redirect_url}) \u2014 NOT a separate target. "
                    f"Do not enumerate this hostname further."
                )

    return None


# Tools that support query caching
QUERY_TOOLS = {
    "qdrant-find": {"query_param": "query", "ttl": 60},
    "google_web_search": {"query_param": "query", "ttl": 30},
    "web_fetch": {"query_param": "url", "ttl": 30},
}

# Tools that return web content (need stripping to avoid context pollution)
WEB_TOOLS = {"web_fetch", "curl", "wget", "httpx"}

# Tools whose output should be truncated (file reads can also blow up context)
TRUNCATE_TOOLS = {"read_file", "cat", "read_many_files"}


def strip_web_content(output: str) -> str:
    """
    Strip JavaScript, CSS, and other web content that pollutes agent context.

    Removes:
    - <script>...</script> blocks
    - <style>...</style> blocks
    - Inline event handlers (onclick, onload, etc.)
    - Base64 data URIs (data:image/png;base64,...)
    - SVG content blocks
    - Remaining HTML tags (keeps text content)

    Args:
        output: Raw tool output (potentially HTML/web content)

    Returns:
        Cleaned text with web artifacts removed
    """
    if not output:
        return output

    original_len = len(output)

    # Strip <script>...</script> blocks (including multiline)
    output = re.sub(r'<script[^>]*>.*?</script>', '', output, flags=re.DOTALL | re.IGNORECASE)

    # Strip <style>...</style> blocks (including multiline)
    output = re.sub(r'<style[^>]*>.*?</style>', '', output, flags=re.DOTALL | re.IGNORECASE)

    # Strip <svg>...</svg> blocks (including multiline)
    output = re.sub(r'<svg[^>]*>.*?</svg>', '', output, flags=re.DOTALL | re.IGNORECASE)

    # Strip inline event handlers (onclick, onload, onerror, onmouseover, etc.)
    output = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', output, flags=re.IGNORECASE)
    output = re.sub(r'\s+on\w+\s*=\s*[^\s>]+', '', output, flags=re.IGNORECASE)

    # Strip base64 data URIs (data:image/png;base64,... data:application/..., etc.)
    output = re.sub(r'data:[a-zA-Z0-9+/]+;base64,[A-Za-z0-9+/=]+', '[BASE64_DATA_REMOVED]', output)

    # Strip noscript blocks
    output = re.sub(r'<noscript[^>]*>.*?</noscript>', '', output, flags=re.DOTALL | re.IGNORECASE)

    # Strip HTML comments
    output = re.sub(r'<!--.*?-->', '', output, flags=re.DOTALL)

    # Strip remaining HTML tags but keep text content
    output = re.sub(r'<[^>]+>', ' ', output)

    # Collapse multiple whitespace/newlines into single space
    output = re.sub(r'\s+', ' ', output)

    # Trim
    output = output.strip()

    stripped_len = len(output)
    if original_len > stripped_len:
        reduction = original_len - stripped_len
        log_web_strip(f"Stripped {reduction} chars ({100 * reduction // original_len}% reduction)")

    return output


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
        log_creds(f"No credentials found in {tool_name} output ({len(tool_output)} chars)")
        return {"action": "continue"}

    log_creds(f"Extracted {len(credentials)} credential(s) from {tool_name}")

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

        log_cache(f"Cached {tool_name} query (TTL={tool_config['ttl']}m): '{query[:40]}...'")

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
        log_hypothesis(f"No outcome detected in command output")
        return {"action": "continue"}

    log_hypothesis(f"Detected outcome: {outcome_type} ({evidence})")

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
            log_hypothesis(f"Updated {updated_count} hypothesis(es): {[h['id'] for h in updated_hyps]}")

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

    return {"continue": True}


def main():
    """Process AfterTool event."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"continue": True}))
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    tool_output = input_data.get("tool_output", "")

    # ======================================================================
    # Pipeline Completion Gate (fires on delegate_to_agent regardless of
    # tool_output content — the gate only needs tool_input.agent_name)
    # ======================================================================
    result = {"continue": True}
    annotations = []

    pipeline_directive = handle_pipeline_completion_gate(tool_name, tool_input)
    if pipeline_directive:
        annotations.append(pipeline_directive)

    # Pipeline Failure Gate (fires on delegate_to_agent with error output)
    failure_directive = handle_pipeline_failure_gate(tool_name, tool_input, tool_output)
    if failure_directive:
        annotations.append(failure_directive)

    # Get target
    target = get_target_from_env()
    if not target:
        # Even without a target, emit pipeline gate if we have one
        if annotations:
            result["hookSpecificOutput"] = {
                "hookEventName": "AfterTool",
                "additionalContext": "\n".join(annotations),
            }
        print(json.dumps(result))
        return

    # Skip if no output (but pipeline gate above already handled)
    if not tool_output or not isinstance(tool_output, str):
        if annotations:
            result["hookSpecificOutput"] = {
                "hookEventName": "AfterTool",
                "additionalContext": "\n".join(annotations),
            }
        print(json.dumps(result))
        return

    # ==========================================================================
    # Output Truncation (MUST happen FIRST - before ANY other processing)
    # Prevents context overflow that caused 688K token blow-up
    # ==========================================================================
    tool_output, was_truncated = truncate_output(tool_output)

    # ==========================================================================
    # Web Content Stripping (happens after truncation)
    # Prevents JavaScript/CSS blobs from polluting agent context
    # ==========================================================================
    if tool_name in WEB_TOOLS or "curl" in str(tool_input.get("command", "")):
        tool_output = strip_web_content(tool_output)

    # Also strip web content from file reads if content looks like HTML
    if tool_name in TRUNCATE_TOOLS and ("<html" in tool_output.lower() or "<script" in tool_output.lower()):
        tool_output = strip_web_content(tool_output)

    # Credential tool verdict injection (brute-force tools)
    if tool_name in CREDENTIAL_TOOLS:
        command = tool_input.get("command", tool_input.get("cmd", ""))
        if command:
            verdict = parse_credential_tool_output(command, tool_output)
            if verdict:
                annotations.append(verdict)

            # Redirect/vhost alias detection (on curl/wget output)
            if re.search(r'\bcurl\b|\bwget\b', command.lower()):
                try:
                    base_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
                    mgr = SessionStateManager.from_target(target, base_path=base_path)
                    known_hosts = mgr.load_known_hosts_from_cas()
                    alias_warning = detect_redirect_alias(tool_output, known_hosts)
                    if alias_warning:
                        annotations.append(alias_warning)
                except Exception:
                    pass

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

    # Build final response using Gemini CLI HookOutput format
    if annotations:
        result["hookSpecificOutput"] = {
            "hookEventName": "AfterTool",
            "additionalContext": "\n".join(annotations)
        }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
