#!/usr/bin/env python3
"""
Validation Agent Integration Example
=====================================

This demonstrates how the Validation Agent (Phase 4) integrates the
backward taint analysis utility into the vulnerability validation workflow.

This is the glue code that connects:
- Analysis phase findings (input)
- Taint analysis utility (processing)
- Validation report (output)
"""

import sys
from pathlib import Path
from typing import Dict, List, Any

sys.path.insert(0, str(Path(__file__).parent))

from taint import (
    backward_taint,
    analyze_paths,
    detect_language,
)
from prioritize import (
    CodeLocation,
    TriageFinding,
    SinkType,
    InputProximity,
    AuthLevel,
)
from chunker import FileInfo


def validate_finding(
    finding: Dict[str, Any],
    files: Dict[str, FileInfo],
    verbose: bool = True
) -> Dict[str, Any]:
    """
    Validate a single finding from the Analysis phase.

    This is the main entry point for the Validation Agent.

    Args:
        finding: Finding dict from Analysis phase (matches SKILL.md schema)
        files: File information dict from Recon phase
        verbose: Print detailed trace

    Returns:
        Validation result dict with status, confidence, and reasoning
    """
    if verbose:
        print(f"\n{'='*70}")
        print(f"Validating: {finding['id']} - {finding['type']}")
        print(f"{'='*70}")

    # Extract location info
    location = finding['location']
    sink_location = CodeLocation(
        file=location['file'],
        line=location['line'],
        end_line=location.get('end_line'),
        context=finding.get('evidence', {}).get('code', ''),
        function=location.get('function')
    )

    vuln_type = finding['type']  # e.g., "sqli", "code_injection", "xss"
    language = detect_language(sink_location.file)

    if verbose:
        print(f"\nSink: {sink_location.file}:{sink_location.line}")
        print(f"Type: {vuln_type}")
        print(f"Language: {language}")

    # Perform backward taint analysis
    if verbose:
        print(f"\n[*] Running backward taint analysis...")

    paths = backward_taint(
        sink_location=sink_location,
        files=files,
        max_depth=10,
        max_paths=20
    )

    if verbose:
        print(f"[+] Found {len(paths)} data flow path(s)")

    # No paths found - could mean no user input reaches sink
    if len(paths) == 0:
        if verbose:
            print("\n[!] No paths from user input to sink")
            print("    This could mean:")
            print("    - Sink only uses hardcoded/safe data")
            print("    - Our analysis missed the input source")
            print("    - File reading failed")

        return {
            "finding_id": finding['id'],
            "status": "needs_more_info",
            "confidence": 0.3,
            "reason": "No data flow paths found from user input to sink",
            "recommendation": "Manual review required",
            "exploitable_paths": [],
            "blocked_paths": []
        }

    # Analyze exploitability
    analysis = analyze_paths(paths, vuln_type, language)

    if verbose:
        print(f"\n{'='*70}")
        print("ANALYSIS RESULTS")
        print(f"{'='*70}")
        print(f"Total paths: {analysis['total_paths']}")
        print(f"Exploitable: {analysis['exploitable_count']}")
        print(f"Blocked: {analysis['blocked_count']}")
        print(f"Verdict: {analysis['verdict'].upper()}")
        print(f"Confidence: {analysis['confidence']:.0%}")

    # Build validation result
    if analysis['verdict'] == 'exploitable':
        status = "confirmed"
        reason = f"Found {analysis['exploitable_count']} exploitable path(s) from user input to sink"

        # Add details about exploitable paths
        if analysis['exploitable_paths'] and verbose:
            print(f"\n[!] EXPLOITABLE PATHS:")
            for i, path in enumerate(analysis['exploitable_paths'], 1):
                print(f"    Path {i}: {path}")

        # Note if some paths are blocked but others aren't
        if analysis['blocked_count'] > 0 and verbose:
            print(f"\n[+] Note: {analysis['blocked_count']} path(s) are properly sanitized")
            print("    but at least one path remains exploitable")

    else:
        status = "false_positive"
        blocked_path = analysis['blocked_paths'][0] if analysis['blocked_paths'] else None

        if blocked_path:
            blockers = blocked_path.blocking_transforms
            reason = f"All paths blocked by sanitization: {', '.join(blockers)}"

            if verbose:
                print(f"\n[✓] FALSE POSITIVE DETECTED")
                print(f"    Blocking functions: {', '.join(blockers)}")
                for i, path in enumerate(analysis['blocked_paths'], 1):
                    print(f"    Path {i}: {path}")
        else:
            reason = "No exploitable paths found"

    return {
        "finding_id": finding['id'],
        "status": status,
        "confidence": analysis['confidence'],
        "reason": reason,
        "verdict": analysis['verdict'],
        "exploitable_path_count": analysis['exploitable_count'],
        "blocked_path_count": analysis['blocked_count'],
        "exploitable_paths": [str(p) for p in analysis.get('exploitable_paths', [])],
        "blocked_paths": [
            {
                "path": str(p),
                "blocking_transforms": p.blocking_transforms
            }
            for p in analysis.get('blocked_paths', [])
        ]
    }


def validate_all_findings(
    findings: List[Dict[str, Any]],
    files: Dict[str, FileInfo]
) -> Dict[str, Any]:
    """
    Validate all findings from Analysis phase.

    This is what the Validation Agent calls to process the full result set.

    Args:
        findings: List of findings from Analysis phase
        files: File information dict from Recon phase

    Returns:
        Complete validation report
    """
    print(f"\n{'#'*70}")
    print(f"# VALIDATION PHASE")
    print(f"# Processing {len(findings)} finding(s)")
    print(f"{'#'*70}")

    validated = []
    confirmed_count = 0
    false_positive_count = 0
    needs_review_count = 0

    for finding in findings:
        result = validate_finding(finding, files, verbose=True)
        validated.append(result)

        if result['status'] == 'confirmed':
            confirmed_count += 1
        elif result['status'] == 'false_positive':
            false_positive_count += 1
        else:
            needs_review_count += 1

    # Generate summary
    print(f"\n{'#'*70}")
    print(f"# VALIDATION SUMMARY")
    print(f"{'#'*70}")
    print(f"\nTotal findings analyzed: {len(findings)}")
    print(f"  ✓ Confirmed vulnerabilities: {confirmed_count}")
    print(f"  ✗ False positives: {false_positive_count}")
    print(f"  ? Needs manual review: {needs_review_count}")

    accuracy = (confirmed_count + false_positive_count) / len(findings) * 100 if findings else 0
    print(f"\nValidation accuracy: {accuracy:.1f}%")

    return {
        "validated_findings": validated,
        "summary": {
            "total": len(findings),
            "confirmed": confirmed_count,
            "false_positives": false_positive_count,
            "needs_review": needs_review_count,
            "accuracy_percent": accuracy
        }
    }


def example_validation_workflow():
    """
    Demonstrate complete validation workflow.

    This shows how Validation Agent processes findings from Analysis phase.
    """
    # Mock Analysis phase output (would come from previous phase)
    analysis_findings = [
        {
            "id": "VULN-001",
            "severity": "critical",
            "type": "sqli",
            "cwe": "CWE-89",
            "location": {
                "file": "/var/www/admin.php",
                "line": 42,
                "function": "mysql_query"
            },
            "description": "Unsanitized user input in SQL query",
            "evidence": {
                "code": 'mysql_query("SELECT * FROM users WHERE id = $id");',
                "trace": "$_GET['id'] → $id → mysql_query()"
            },
            "confidence": 0.85
        },
        {
            "id": "VULN-002",
            "severity": "high",
            "type": "xss",
            "cwe": "CWE-79",
            "location": {
                "file": "/var/www/profile.php",
                "line": 28,
                "function": "echo"
            },
            "description": "Reflected XSS in profile display",
            "evidence": {
                "code": 'echo htmlspecialchars($name);',
                "trace": "$_POST['name'] → $name → echo"
            },
            "confidence": 0.75
        }
    ]

    # Mock file information (would come from Recon phase)
    files = {
        "/var/www/admin.php": FileInfo(
            path="/var/www/admin.php",
            token_count=500,
            language="php"
        ),
        "/var/www/profile.php": FileInfo(
            path="/var/www/profile.php",
            token_count=300,
            language="php"
        )
    }

    # Run validation
    report = validate_all_findings(analysis_findings, files)

    # Output would go to Dame for final reporting
    print("\n" + "="*70)
    print("Validation report ready for Dame")
    print("="*70)

    return report


if __name__ == "__main__":
    print("Validation Agent Integration Demo")
    print("=" * 70)
    example_validation_workflow()
