#!/usr/bin/env python3
"""
Command Utilities — Shared Hook Helpers
==========================================
Provides command splitting and normalization for safety checking hooks.

The key function extract_commands() splits shell lines on &&, ||, ;
and strips sudo/timeout prefixes so safety rules can match individual
commands rather than raw chained strings.

Problem this solves:
    The git_log_unbounded hook blocked "cd ... && git log --oneline -n 20"
    because its regex didn't account for command chaining operators (&&, ||, ;).
    Rather than making each safety regex handle all chaining operators, this
    module normalizes chained commands before matching.

Usage:
    from command_utils import extract_commands

    commands = extract_commands("cd /tmp && sudo git log --oneline -n 20")
    # Returns: ["cd /tmp", "git log --oneline -n 20"]
"""

import re
from typing import List


# Prefixes to strip from individual commands before safety checks.
# Order matters: we strip outermost wrappers first.
# Each entry is (regex_pattern, description) — the regex must match from the
# start of the string and its .group(0) is what gets removed.
_PREFIX_PATTERNS: List[re.Pattern] = [
    # sudo with optional flags: sudo, sudo -u user, sudo -E, sudo --preserve-env, etc.
    # The alternation handles -u/--user with their required argument before
    # generic single-letter flags so that -u isn't consumed without its arg.
    re.compile(r'^sudo\s+(?:(?:-u\s+\S+|--user[=\s]+\S+|-[A-Za-z]+|--\S+)\s+)*'),
    # timeout with optional flags: timeout 30, timeout --signal=KILL 60
    re.compile(r'^timeout\s+(?:--?\S+\s+)*\d+[smhd]?\s+'),
    # nice with optional priority: nice -n 10, nice --adjustment=5
    re.compile(r'^nice\s+(?:-n\s+\d+\s+|--adjustment[=\s]+\d+\s+)?'),
    # env with variable assignments: env FOO=bar command
    re.compile(r'^env\s+(?:\S+=\S+\s+)+'),
    # stdbuf (common with nmap, etc.): stdbuf -oL, stdbuf -i0 -o0 -e0
    re.compile(r'^stdbuf\s+(?:-[ioe][A-Za-z0-9]*\s+)+'),
]


def strip_prefixes(command: str) -> str:
    """Strip sudo, timeout, nice, env, and similar wrapper prefixes from a command.

    Iteratively removes known wrapper prefixes so that the underlying command
    is exposed for safety rule matching. Runs multiple passes because prefixes
    can stack (e.g., ``sudo timeout 30 nice -n 10 nmap ...``).

    Args:
        command: A single shell command (should not contain chaining operators).

    Returns:
        Command with wrapper prefixes removed, whitespace trimmed.

    Examples:
        >>> strip_prefixes("sudo timeout 30 nmap -sV 10.0.0.1")
        'nmap -sV 10.0.0.1'
        >>> strip_prefixes("sudo -u www-data cat /etc/passwd")
        'cat /etc/passwd'
        >>> strip_prefixes("nice -n 10 sudo timeout 60s nmap -sS 10.0.0.0/24")
        'nmap -sS 10.0.0.0/24'
        >>> strip_prefixes("env LANG=C sudo ls /root")
        'ls /root'
        >>> strip_prefixes("  sudo   ls  ")
        'ls'
        >>> strip_prefixes("")
        ''
    """
    result = command.strip()
    if not result:
        return ""

    # Collapse internal whitespace runs so patterns match cleanly
    result = re.sub(r'\s+', ' ', result)

    changed = True
    max_passes = 10  # safety limit to avoid infinite loop
    passes = 0
    while changed and passes < max_passes:
        changed = False
        passes += 1
        for pattern in _PREFIX_PATTERNS:
            m = pattern.match(result)
            if m:
                result = result[m.end():].lstrip()
                changed = True
                break  # restart from the first pattern

    return result


def _split_on_operators(raw: str) -> List[str]:
    """Split a shell string on &&, ||, and ; while respecting quoted regions.

    This is the core tokeniser. It walks the string character by character,
    tracking single-quote, double-quote, and escape contexts so that
    operators inside quotes are *not* treated as separators.

    Pipe (|) is intentionally NOT a separator — piped commands form a
    single logical operation. Subshells ($(), backticks) are also left
    intact as part of the parent command.

    Args:
        raw: Raw shell string, possibly containing chained commands.

    Returns:
        List of raw command segments (not yet stripped of prefixes).
    """
    segments: List[str] = []
    current: List[str] = []
    i = 0
    n = len(raw)

    in_single_quote = False
    in_double_quote = False

    while i < n:
        ch = raw[i]

        # --- quote tracking ---
        if ch == '\\' and not in_single_quote:
            # Escaped character — consume it and the next char verbatim
            current.append(ch)
            if i + 1 < n:
                i += 1
                current.append(raw[i])
            i += 1
            continue

        if ch == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            current.append(ch)
            i += 1
            continue

        if ch == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            current.append(ch)
            i += 1
            continue

        # Inside any quotes — everything is literal
        if in_single_quote or in_double_quote:
            current.append(ch)
            i += 1
            continue

        # --- operator detection (only outside quotes) ---

        # && operator
        if ch == '&' and i + 1 < n and raw[i + 1] == '&':
            segment = ''.join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            i += 2
            continue

        # || operator
        if ch == '|' and i + 1 < n and raw[i + 1] == '|':
            segment = ''.join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            i += 2
            continue

        # ; operator (but not inside $(...) or other constructs — we only
        # skip quoted regions which is the main concern; bare ; is a separator)
        if ch == ';':
            segment = ''.join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            i += 1
            continue

        # Regular character
        current.append(ch)
        i += 1

    # Flush remaining
    tail = ''.join(current).strip()
    if tail:
        segments.append(tail)

    return segments


def extract_commands(raw: str) -> List[str]:
    """Split a shell line into individual commands for safety checking.

    Handles:
    - ``&&`` (AND operator)
    - ``||`` (OR operator)
    - ``;``  (sequential operator)
    - ``sudo`` / ``timeout`` / ``nice`` / ``env`` prefixes stripped from each command

    Does NOT split on:
    - ``|`` (pipe) — piped commands are a single logical operation
    - ``$()`` or backticks — subshells are part of the parent command

    Args:
        raw: Raw shell command string, possibly chained.

    Returns:
        List of individual commands with wrapper prefixes stripped.
        Empty list if the input is empty or only whitespace.

    Examples:
        >>> extract_commands("cd /tmp && git log --oneline -n 20")
        ['cd /tmp', 'git log --oneline -n 20']
        >>> extract_commands("sudo timeout 30 nmap -sV 10.0.0.1")
        ['nmap -sV 10.0.0.1']
        >>> extract_commands("echo hello; cat /etc/passwd")
        ['echo hello', 'cat /etc/passwd']
        >>> extract_commands("nmap 10.0.0.1 | grep open")
        ['nmap 10.0.0.1 | grep open']
        >>> extract_commands("")
        []
        >>> extract_commands("echo 'hello && world'; ls")
        ["echo 'hello && world'", 'ls']
        >>> extract_commands("echo \\"semi;colon\\"; pwd")
        ['echo "semi;colon"', 'pwd']
    """
    if not raw or not raw.strip():
        return []

    segments = _split_on_operators(raw)
    result = []
    for seg in segments:
        stripped = strip_prefixes(seg)
        if stripped:
            result.append(stripped)
    return result
