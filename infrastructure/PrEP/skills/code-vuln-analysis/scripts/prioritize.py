#!/usr/bin/env python3
"""
Prioritization Scoring Algorithm for Code Vulnerability Analysis
================================================================

Implements the triage scoring formula from SKILL.md:

    Score = (Sink_Severity × 3) + (Input_Proximity × 2) + (Auth_Bypass_Potential × 2)

This scoring reduces LLM analysis invocations by ~94.5% by focusing on
high-value targets first. Maximum score is 70 (code_exec + direct_input + no_auth).

Usage:
    from prioritize import score_finding, rank_findings, SinkType, InputProximity, AuthLevel

    # Score a single finding
    score = score_finding(
        sink=SinkType.CODE_EXECUTION,
        proximity=InputProximity.DIRECT,
        auth=AuthLevel.NONE
    )

    # Rank multiple findings
    ranked = rank_findings(findings)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class SinkType(str, Enum):
    """Dangerous sink categories ordered by severity."""
    CODE_EXECUTION = "code_execution"  # system, passthru, shell_*, popen
    SQL = "sql"                         # Raw SQL queries
    FILE_OPS = "file_ops"               # File read/write/include
    DESERIALIZATION = "deserialization" # unserialize, yaml.load, etc.
    XSS = "xss"                         # DOM manipulation, innerHTML
    SSRF = "ssrf"                       # URL fetching
    LDAP = "ldap"                       # LDAP queries
    XPATH = "xpath"                     # XPath queries
    TEMPLATE = "template"               # Template injection
    REDIRECT = "redirect"               # Open redirect
    OTHER = "other"                     # Unknown/other sinks


class InputProximity(str, Enum):
    """How close user input is to the sink."""
    DIRECT = "direct"           # $_GET, $_POST, request.args, etc.
    SESSION = "session"         # Session data (user-controlled but stored)
    DB_STORED = "db_stored"     # Database-retrieved (second-order)
    CONFIG = "config"           # Configuration values
    ENVIRONMENT = "environment" # Environment variables
    HARDCODED = "hardcoded"     # Static values (lowest risk)


class AuthLevel(str, Enum):
    """Authentication requirements for reaching the sink."""
    NONE = "none"               # No authentication required
    WEAK = "weak"               # Basic auth, predictable tokens, etc.
    USER = "user"               # Standard user authentication
    ADMIN = "admin"             # Admin/elevated privileges required
    STRONG = "strong"           # MFA, certificate, etc.


# Severity scores by sink type (higher = more dangerous)
SINK_SEVERITY: Dict[SinkType, int] = {
    SinkType.CODE_EXECUTION: 10,
    SinkType.SQL: 8,
    SinkType.FILE_OPS: 7,
    SinkType.DESERIALIZATION: 7,
    SinkType.XSS: 5,
    SinkType.SSRF: 6,
    SinkType.LDAP: 6,
    SinkType.XPATH: 5,
    SinkType.TEMPLATE: 7,
    SinkType.REDIRECT: 3,
    SinkType.OTHER: 2,
}

# Proximity scores (higher = closer to user input)
INPUT_PROXIMITY: Dict[InputProximity, int] = {
    InputProximity.DIRECT: 10,
    InputProximity.SESSION: 8,
    InputProximity.DB_STORED: 7,
    InputProximity.CONFIG: 3,
    InputProximity.ENVIRONMENT: 2,
    InputProximity.HARDCODED: 0,
}

# Auth bypass potential (higher = easier to reach without auth)
AUTH_BYPASS: Dict[AuthLevel, int] = {
    AuthLevel.NONE: 10,
    AuthLevel.WEAK: 5,
    AuthLevel.USER: 3,
    AuthLevel.ADMIN: 2,
    AuthLevel.STRONG: 1,
}

# Formula weights
WEIGHT_SINK = 3
WEIGHT_PROXIMITY = 2
WEIGHT_AUTH = 2

# Maximum possible score: (10*3) + (10*2) + (10*2) = 70
MAX_SCORE = 70


@dataclass
class CodeLocation:
    """Location of a potential vulnerability in source code."""
    file: str
    line: int
    end_line: Optional[int] = None
    column: Optional[int] = None
    function: Optional[str] = None
    context: str = ""  # Code snippet


@dataclass
class TriageFinding:
    """A potential vulnerability identified during recon/triage."""
    id: str
    location: CodeLocation
    sink_type: SinkType
    sink_function: str  # e.g., "mysql_query", "system"
    input_proximity: InputProximity
    input_source: str = ""  # e.g., "$_GET['id']"
    auth_level: AuthLevel = AuthLevel.NONE
    description: str = ""
    score: float = 0.0
    confidence: float = 0.5  # Recon confidence (0-1)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


def score_finding(
    sink: SinkType,
    proximity: InputProximity,
    auth: AuthLevel,
    confidence: float = 1.0
) -> float:
    """
    Calculate priority score for a potential vulnerability.

    Formula: Score = (Sink_Severity × 3) + (Input_Proximity × 2) + (Auth_Bypass × 2)

    Args:
        sink: Type of dangerous sink
        proximity: How close user input is to the sink
        auth: Authentication level required to reach sink
        confidence: Recon confidence multiplier (0-1)

    Returns:
        Priority score (0-70, higher = higher priority)
    """
    sink_score = SINK_SEVERITY.get(sink, 2)
    proximity_score = INPUT_PROXIMITY.get(proximity, 0)
    auth_score = AUTH_BYPASS.get(auth, 1)

    raw_score = (
        (sink_score * WEIGHT_SINK) +
        (proximity_score * WEIGHT_PROXIMITY) +
        (auth_score * WEIGHT_AUTH)
    )

    return raw_score * confidence


def calculate_score(finding: TriageFinding) -> float:
    """Calculate and update score for a TriageFinding."""
    finding.score = score_finding(
        sink=finding.sink_type,
        proximity=finding.input_proximity,
        auth=finding.auth_level,
        confidence=finding.confidence
    )
    return finding.score


def rank_findings(findings: List[TriageFinding]) -> List[TriageFinding]:
    """
    Score and rank findings by priority.

    Returns findings sorted by score descending (highest priority first).
    """
    for finding in findings:
        calculate_score(finding)

    return sorted(findings, key=lambda f: f.score, reverse=True)


def categorize_priority(score: float) -> str:
    """
    Categorize score into priority bucket.

    Returns: "critical", "high", "medium", or "low"
    """
    if score >= 50:  # ~71% of max
        return "critical"
    elif score >= 35:  # ~50% of max
        return "high"
    elif score >= 20:  # ~29% of max
        return "medium"
    return "low"


def filter_by_threshold(
    findings: List[TriageFinding],
    min_score: float = 20.0
) -> List[TriageFinding]:
    """Filter findings below minimum score threshold."""
    return [f for f in findings if f.score >= min_score]


def explain_score(finding: TriageFinding) -> str:
    """Generate human-readable explanation of score components."""
    sink_score = SINK_SEVERITY.get(finding.sink_type, 2)
    proximity_score = INPUT_PROXIMITY.get(finding.input_proximity, 0)
    auth_score = AUTH_BYPASS.get(finding.auth_level, 1)

    return (
        f"Score: {finding.score:.1f}/70 ({categorize_priority(finding.score)})\n"
        f"  Sink ({finding.sink_type.value}): {sink_score} × {WEIGHT_SINK} = {sink_score * WEIGHT_SINK}\n"
        f"  Proximity ({finding.input_proximity.value}): {proximity_score} × {WEIGHT_PROXIMITY} = {proximity_score * WEIGHT_PROXIMITY}\n"
        f"  Auth ({finding.auth_level.value}): {auth_score} × {WEIGHT_AUTH} = {auth_score * WEIGHT_AUTH}\n"
        f"  Confidence: {finding.confidence:.0%}"
    )


if __name__ == "__main__":
    # Demo: Score some example findings
    examples = [
        ("RCE via system() with direct GET input, no auth", SinkType.CODE_EXECUTION, InputProximity.DIRECT, AuthLevel.NONE),
        ("SQLi in admin panel", SinkType.SQL, InputProximity.DIRECT, AuthLevel.ADMIN),
        ("Stored XSS from database", SinkType.XSS, InputProximity.DB_STORED, AuthLevel.NONE),
        ("SSRF with config value", SinkType.SSRF, InputProximity.CONFIG, AuthLevel.USER),
    ]

    print("Prioritization Scoring Demo\n" + "=" * 40)
    for desc, sink, prox, auth in examples:
        score = score_finding(sink, prox, auth)
        priority = categorize_priority(score)
        print(f"\n{desc}")
        print(f"  Score: {score:.1f}/70 [{priority.upper()}]")
