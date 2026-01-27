"""
Code Vulnerability Analysis - Utility Scripts
==============================================

Entry point detection, prioritization, and chunking utilities for
static source code vulnerability analysis.

Main exports:
- detect_entrypoints: Detect web routes, CLI scripts, cron jobs
- score_finding: Calculate triage priority score
- rank_findings: Sort findings by priority
- create_chunks: Split files into token-bounded chunks
"""

# Entry point detection
from .entrypoints import (
    detect_entrypoints,
    detect_web_routes,
    detect_cli_scripts,
    detect_cron_indicators,
    format_output,
    EntryPoint,
    EntryPointType,
)

# Prioritization scoring
from .prioritize import (
    score_finding,
    rank_findings,
    categorize_priority,
    filter_by_threshold,
    explain_score,
    SinkType,
    InputProximity,
    AuthLevel,
    TriageFinding,
    CodeLocation,
)

# Chunking (if available)
try:
    from .chunker import create_chunks, estimate_tokens
except ImportError:
    # Chunker may not be implemented yet
    pass

# Verification and sanitization
from .verification import (
    verify_agent_output,
    sanitize_findings,
    add_checksum,
    compute_checksum,
    verify_checksum,
    create_verified_output,
    VerificationConfig,
    VerificationResult,
)

__all__ = [
    # Entry points
    'detect_entrypoints',
    'detect_web_routes',
    'detect_cli_scripts',
    'detect_cron_indicators',
    'format_output',
    'EntryPoint',
    'EntryPointType',
    # Prioritization
    'score_finding',
    'rank_findings',
    'categorize_priority',
    'filter_by_threshold',
    'explain_score',
    'SinkType',
    'InputProximity',
    'AuthLevel',
    'TriageFinding',
    'CodeLocation',
    # Verification
    'verify_agent_output',
    'sanitize_findings',
    'add_checksum',
    'compute_checksum',
    'verify_checksum',
    'create_verified_output',
    'VerificationConfig',
    'VerificationResult',
]
