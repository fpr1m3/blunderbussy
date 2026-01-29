#!/usr/bin/env python3
"""
Tests for validate_artifacts.py
===============================

Verifies that the rubric validator correctly passes valid artifacts and
rejects invalid ones for each pipeline stage.

Run:
    python -m pytest test_validate_artifacts.py -v
    python -m pytest test_validate_artifacts.py -v -k "recon"
"""

import sys
import textwrap
from pathlib import Path

import pytest
import yaml

# Ensure the scripts directory is on the import path regardless of where
# pytest is invoked from (project root vs. this directory).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_artifacts import (
    Color,
    ValidationResult,
    run_validation,
    validate_analysis,
    validate_brief,
    validate_recon,
    validate_triage,
    validate_validation,
)


# ---------------------------------------------------------------------------
# Fixtures - sample YAML content
# ---------------------------------------------------------------------------

VALID_RECON = {
    "manifest": {
        "files": ["admin.php", "login.php", "config.php"],
        "languages": {"php": 3},
        "total_files": 3,
    },
    "entry_points": {
        "web_routes": [
            {"file": "admin.php", "methods": ["GET", "POST"], "auth_required": "unknown"}
        ],
        "cron_jobs": [],
        "cli_scripts": [],
    },
    "dangerous_sinks": {
        "code_execution": [],
        "sql": [{"file": "login.php", "line": 45, "function": "mysql_query"}],
    },
    "user_inputs": [
        {"file": "login.php", "line": 12, "variable": "$_POST['username']", "type": "form_data"}
    ],
    "dependency_graph": {
        "includes": [{"from": "admin.php", "imports": ["config.php"]}]
    },
}

VALID_TRIAGE = {
    "priority_queue": {
        "critical": ["chunk_001"],
        "high": [],
        "medium": [],
        "low": [],
    },
    "analysis_chunks": [
        {
            "id": "chunk_001",
            "priority": "critical",
            "files": ["login.php", "config.php"],
            "focus": "SQL injection in login handler",
            "attack_surface": "sql_injection",
            "hypothesis": "User input flows directly to mysql_query",
            "token_estimate": 8000,
            "rationale": "Direct user input to SQL sink without sanitization",
        }
    ],
    "metadata": {
        "total_files_reviewed": 3,
        "files_prioritized": 2,
        "chunks_created": 1,
    },
}

VALID_ANALYSIS = {
    "findings": [
        {
            "id": "VULN-001",
            "severity": "critical",
            "type": "sql_injection",
            "cwe": "CWE-89",
            "location": {"file": "login.php", "line": "45-48"},
            "description": "SQL injection via unsanitized POST parameter.",
            "evidence": {
                "code": "$query = \"SELECT * FROM users WHERE user='\" . $_POST['username'] . \"'\";",
                "trace": "1. $_POST['username'] -> 2. string concat -> 3. mysql_query()",
            },
            "exploitability": "No authentication required. Payload: ' OR 1=1 --",
            "confidence": 0.95,
        }
    ],
    "uncertain_areas": [
        {
            "file": "config.php",
            "line": 10,
            "observation": "Hardcoded credentials",
            "reason": "May be dev-only config",
        }
    ],
}

VALID_ANALYSIS_EMPTY = {
    "findings": [],
}

VALID_VALIDATION = {
    "validated_findings": [
        {
            "finding_id": "VULN-001",
            "status": "confirmed",
            "attack_path": [
                {"step": 1, "action": "Submit login form", "location": "login.php:45"},
            ],
            "authentication_required": "none",
            "proof_of_concept": "curl -X POST http://$TARGET/login.php -d \"username=' OR 1=1 --\"",
            "impact": "Full database access, authentication bypass.",
            "cvss_estimate": 9.8,
            "reason": "Direct SQL injection confirmed with no sanitization.",
        }
    ],
}

VALID_VALIDATION_FP = {
    "validated_findings": [
        {
            "finding_id": "VULN-002",
            "status": "false_positive",
            "reason": "Input is sanitized by htmlspecialchars before reaching sink.",
        }
    ],
}

VALID_VALIDATION_NEEDS_INFO = {
    "validated_findings": [
        {
            "finding_id": "VULN-003",
            "status": "needs_more_info",
        }
    ],
}

VALID_BRIEF = textwrap.dedent("""\
    ## Vulnerability Brief: TestApp Source Analysis

    ### Executive Summary
    One critical SQL injection found in login.php.

    ### Confirmed Vulnerabilities
    #### 1. SQL Injection - CVSS 9.8
    - **Location:** login.php:45
    - **Auth Required:** none
    - **Exploit:** `curl -X POST http://$TARGET/login.php -d "username=' OR 1=1 --"`
    - **Impact:** Full database access

    ### Attack Order
    1. SQL injection on login (no auth, highest confidence)

    ### Coverage Report
    - Files analyzed: 3/3
    - Chunks processed: 1
""")

VALID_BRIEF_NO_FINDINGS = textwrap.dedent("""\
    ## Vulnerability Brief: TestApp Source Analysis

    ### Executive Summary
    No exploitable vulnerabilities identified in analyzed codebase.

    ### Coverage Report
    - Files analyzed: 3/3
    - Chunks processed: 1
""")


# ---------------------------------------------------------------------------
# Helper to write artifacts to a temp dir
# ---------------------------------------------------------------------------

def _write_yaml(directory: Path, filename: str, data: dict) -> Path:
    path = directory / filename
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False)
    return path


def _write_text(directory: Path, filename: str, content: str) -> Path:
    path = directory / filename
    path.write_text(content)
    return path


# ---------------------------------------------------------------------------
# Recon tests
# ---------------------------------------------------------------------------

class TestReconValidation:
    def test_valid_recon(self, tmp_path):
        _write_yaml(tmp_path, "01-recon-manifest.yaml", VALID_RECON)
        result = validate_recon(tmp_path)
        assert result.ok, f"Expected pass, got failures: {[(n, r) for s, n, r in result.checks if s == 'fail']}"

    def test_missing_manifest(self, tmp_path):
        data = {**VALID_RECON}
        del data["manifest"]
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert not result.ok
        assert any("manifest" in n for _, n, _ in result.checks if _ is not None)

    def test_empty_files_list(self, tmp_path):
        data = {**VALID_RECON, "manifest": {"files": [], "languages": {"php": 1}}}
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert not result.ok

    def test_empty_languages(self, tmp_path):
        data = {**VALID_RECON, "manifest": {"files": ["a.php"], "languages": {}}}
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert not result.ok

    def test_missing_entry_points(self, tmp_path):
        data = {**VALID_RECON}
        del data["entry_points"]
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert not result.ok

    def test_all_empty_entry_point_categories(self, tmp_path):
        data = {**VALID_RECON, "entry_points": {"web_routes": [], "cron_jobs": []}}
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert not result.ok

    def test_missing_dangerous_sinks(self, tmp_path):
        data = {**VALID_RECON}
        del data["dangerous_sinks"]
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert not result.ok

    def test_missing_user_inputs(self, tmp_path):
        data = {**VALID_RECON}
        del data["user_inputs"]
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert not result.ok

    def test_missing_file(self, tmp_path):
        result = validate_recon(tmp_path)
        assert not result.ok

    def test_empty_dangerous_sinks_is_ok(self, tmp_path):
        data = {**VALID_RECON, "dangerous_sinks": {}}
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert result.ok

    def test_empty_user_inputs_is_ok(self, tmp_path):
        data = {**VALID_RECON, "user_inputs": []}
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert result.ok

    def test_no_dependency_graph_is_ok(self, tmp_path):
        data = {**VALID_RECON}
        del data["dependency_graph"]
        _write_yaml(tmp_path, "01-recon-manifest.yaml", data)
        result = validate_recon(tmp_path)
        assert result.ok


# ---------------------------------------------------------------------------
# Triage tests
# ---------------------------------------------------------------------------

class TestTriageValidation:
    def test_valid_triage(self, tmp_path):
        _write_yaml(tmp_path, "02-triage-chunks.yaml", VALID_TRIAGE)
        result = validate_triage(tmp_path)
        assert result.ok, f"Expected pass, got failures: {[(n, r) for s, n, r in result.checks if s == 'fail']}"

    def test_missing_priority_queue(self, tmp_path):
        data = {**VALID_TRIAGE}
        del data["priority_queue"]
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_priority_queue_no_valid_levels(self, tmp_path):
        data = {**VALID_TRIAGE, "priority_queue": {"bogus": []}}
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_missing_analysis_chunks(self, tmp_path):
        data = {**VALID_TRIAGE}
        del data["analysis_chunks"]
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_empty_analysis_chunks(self, tmp_path):
        data = {**VALID_TRIAGE, "analysis_chunks": []}
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_chunk_missing_required_fields(self, tmp_path):
        data = {**VALID_TRIAGE, "analysis_chunks": [{"id": "chunk_001"}]}
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_chunk_empty_files(self, tmp_path):
        chunk = {**VALID_TRIAGE["analysis_chunks"][0], "files": []}
        data = {**VALID_TRIAGE, "analysis_chunks": [chunk]}
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_chunk_invalid_priority(self, tmp_path):
        chunk = {**VALID_TRIAGE["analysis_chunks"][0], "priority": "urgent"}
        data = {**VALID_TRIAGE, "analysis_chunks": [chunk]}
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_missing_metadata(self, tmp_path):
        data = {**VALID_TRIAGE}
        del data["metadata"]
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_metadata_missing_fields(self, tmp_path):
        data = {**VALID_TRIAGE, "metadata": {"total_files_reviewed": 3}}
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_missing_file(self, tmp_path):
        result = validate_triage(tmp_path)
        assert not result.ok

    def test_minimal_priority_queue_ok(self, tmp_path):
        data = {**VALID_TRIAGE, "priority_queue": {"high": ["chunk_001"]}}
        _write_yaml(tmp_path, "02-triage-chunks.yaml", data)
        result = validate_triage(tmp_path)
        assert result.ok


# ---------------------------------------------------------------------------
# Analysis tests
# ---------------------------------------------------------------------------

class TestAnalysisValidation:
    def test_valid_analysis(self, tmp_path):
        _write_yaml(tmp_path, "03-analysis-findings.yaml", VALID_ANALYSIS)
        result = validate_analysis(tmp_path)
        assert result.ok, f"Expected pass, got failures: {[(n, r) for s, n, r in result.checks if s == 'fail']}"

    def test_valid_empty_findings(self, tmp_path):
        _write_yaml(tmp_path, "03-analysis-findings.yaml", VALID_ANALYSIS_EMPTY)
        result = validate_analysis(tmp_path)
        # Empty findings should pass (with warning)
        assert result.ok
        assert result.warn_count > 0

    def test_missing_findings_key(self, tmp_path):
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"some_other_key": []})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_missing_id(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0]}
        del finding["id"]
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_invalid_severity(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "severity": "apocalyptic"}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_missing_location(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0]}
        del finding["location"]
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_location_missing_file(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "location": {"line": 45}}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_location_missing_line(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "location": {"file": "test.php"}}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_missing_evidence(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0]}
        del finding["evidence"]
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_evidence_missing_code(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "evidence": {"trace": "some trace"}}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_evidence_missing_trace(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "evidence": {"code": "some code"}}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_missing_confidence(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0]}
        del finding["confidence"]
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_confidence_out_of_range(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "confidence": 1.5}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_confidence_negative(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "confidence": -0.1}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_finding_confidence_zero_ok(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "confidence": 0.0}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert result.ok

    def test_finding_confidence_one_ok(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "confidence": 1.0}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert result.ok

    def test_finding_confidence_integer_ok(self, tmp_path):
        finding = {**VALID_ANALYSIS["findings"][0], "confidence": 1}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [finding]})
        result = validate_analysis(tmp_path)
        assert result.ok

    def test_missing_file(self, tmp_path):
        result = validate_analysis(tmp_path)
        assert not result.ok


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------

class TestValidationValidation:
    def test_valid_confirmed(self, tmp_path):
        _write_yaml(tmp_path, "04-validation-findings.yaml", VALID_VALIDATION)
        result = validate_validation(tmp_path)
        assert result.ok, f"Expected pass, got failures: {[(n, r) for s, n, r in result.checks if s == 'fail']}"

    def test_valid_false_positive(self, tmp_path):
        _write_yaml(tmp_path, "04-validation-findings.yaml", VALID_VALIDATION_FP)
        result = validate_validation(tmp_path)
        assert result.ok

    def test_valid_needs_more_info(self, tmp_path):
        _write_yaml(tmp_path, "04-validation-findings.yaml", VALID_VALIDATION_NEEDS_INFO)
        result = validate_validation(tmp_path)
        assert result.ok

    def test_missing_validated_findings_key(self, tmp_path):
        _write_yaml(tmp_path, "04-validation-findings.yaml", {"other_key": []})
        result = validate_validation(tmp_path)
        assert not result.ok

    def test_missing_finding_id(self, tmp_path):
        data = {"validated_findings": [{"status": "confirmed", "attack_path": [{"step": 1}],
                                         "proof_of_concept": "test", "impact": "test"}]}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert not result.ok

    def test_invalid_status(self, tmp_path):
        data = {"validated_findings": [{"finding_id": "VULN-001", "status": "maybe"}]}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert not result.ok

    def test_confirmed_missing_attack_path(self, tmp_path):
        data = {"validated_findings": [{
            "finding_id": "VULN-001", "status": "confirmed",
            "proof_of_concept": "test", "impact": "test",
        }]}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert not result.ok

    def test_confirmed_empty_attack_path(self, tmp_path):
        data = {"validated_findings": [{
            "finding_id": "VULN-001", "status": "confirmed",
            "attack_path": [],
            "proof_of_concept": "test", "impact": "test",
        }]}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert not result.ok

    def test_confirmed_missing_poc(self, tmp_path):
        data = {"validated_findings": [{
            "finding_id": "VULN-001", "status": "confirmed",
            "attack_path": [{"step": 1}],
            "impact": "test",
        }]}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert not result.ok

    def test_confirmed_missing_impact(self, tmp_path):
        data = {"validated_findings": [{
            "finding_id": "VULN-001", "status": "confirmed",
            "attack_path": [{"step": 1}],
            "proof_of_concept": "test",
        }]}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert not result.ok

    def test_false_positive_missing_reason(self, tmp_path):
        data = {"validated_findings": [
            {"finding_id": "VULN-001", "status": "false_positive"}
        ]}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert not result.ok

    def test_false_positive_with_reason_ok(self, tmp_path):
        data = {"validated_findings": [
            {"finding_id": "VULN-001", "status": "false_positive",
             "reason": "Input is properly escaped."}
        ]}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert result.ok

    def test_empty_validated_findings_warns(self, tmp_path):
        data = {"validated_findings": []}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert result.ok  # empty is OK, just a warning
        assert result.warn_count > 0

    def test_missing_file(self, tmp_path):
        result = validate_validation(tmp_path)
        assert not result.ok

    def test_mixed_findings(self, tmp_path):
        """Multiple findings with different statuses all valid."""
        data = {"validated_findings": [
            {
                "finding_id": "VULN-001", "status": "confirmed",
                "attack_path": [{"step": 1, "action": "test"}],
                "proof_of_concept": "curl ...", "impact": "RCE",
            },
            {
                "finding_id": "VULN-002", "status": "false_positive",
                "reason": "Sanitized input.",
            },
            {
                "finding_id": "VULN-003", "status": "needs_more_info",
            },
        ]}
        _write_yaml(tmp_path, "04-validation-findings.yaml", data)
        result = validate_validation(tmp_path)
        assert result.ok


# ---------------------------------------------------------------------------
# Brief tests
# ---------------------------------------------------------------------------

class TestBriefValidation:
    def test_valid_brief_with_findings(self, tmp_path):
        _write_text(tmp_path, "04-validation-brief.md", VALID_BRIEF)
        _write_yaml(tmp_path, "04-validation-findings.yaml", VALID_VALIDATION)
        result = validate_brief(tmp_path)
        assert result.ok, f"Expected pass, got failures: {[(n, r) for s, n, r in result.checks if s == 'fail']}"

    def test_valid_brief_no_findings(self, tmp_path):
        _write_text(tmp_path, "04-validation-brief.md", VALID_BRIEF_NO_FINDINGS)
        _write_yaml(tmp_path, "04-validation-findings.yaml", {"validated_findings": []})
        result = validate_brief(tmp_path)
        assert result.ok

    def test_missing_brief_file(self, tmp_path):
        result = validate_brief(tmp_path)
        assert not result.ok

    def test_empty_brief(self, tmp_path):
        _write_text(tmp_path, "04-validation-brief.md", "")
        result = validate_brief(tmp_path)
        assert not result.ok

    def test_whitespace_only_brief(self, tmp_path):
        _write_text(tmp_path, "04-validation-brief.md", "   \n\n  \n")
        result = validate_brief(tmp_path)
        assert not result.ok

    def test_missing_vuln_brief_header(self, tmp_path):
        content = textwrap.dedent("""\
            ## Some Other Report

            ### Executive Summary
            Nothing found.

            ### Coverage Report
            - Files: 3
        """)
        _write_text(tmp_path, "04-validation-brief.md", content)
        result = validate_brief(tmp_path)
        assert not result.ok

    def test_missing_executive_summary(self, tmp_path):
        content = textwrap.dedent("""\
            ## Vulnerability Brief

            ### Coverage Report
            - Files: 3
        """)
        _write_text(tmp_path, "04-validation-brief.md", content)
        result = validate_brief(tmp_path)
        assert not result.ok

    def test_missing_coverage_report(self, tmp_path):
        content = textwrap.dedent("""\
            ## Vulnerability Brief

            ### Executive Summary
            Nothing found.
        """)
        _write_text(tmp_path, "04-validation-brief.md", content)
        result = validate_brief(tmp_path)
        assert not result.ok

    def test_confirmed_findings_but_no_confirmed_section(self, tmp_path):
        content = textwrap.dedent("""\
            ## Vulnerability Brief

            ### Executive Summary
            Found stuff.

            ### Coverage Report
            - Files: 3
        """)
        _write_text(tmp_path, "04-validation-brief.md", content)
        _write_yaml(tmp_path, "04-validation-findings.yaml", VALID_VALIDATION)
        result = validate_brief(tmp_path)
        assert not result.ok

    def test_no_confirmed_findings_no_confirmed_section_ok(self, tmp_path):
        """When no confirmed findings, missing 'Confirmed Vulnerabilities' is OK (warn only)."""
        content = textwrap.dedent("""\
            ## Vulnerability Brief

            ### Executive Summary
            No exploitable vulns found.

            ### Coverage Report
            - Files: 3
        """)
        _write_text(tmp_path, "04-validation-brief.md", content)
        _write_yaml(tmp_path, "04-validation-findings.yaml", VALID_VALIDATION_FP)
        result = validate_brief(tmp_path)
        assert result.ok


# ---------------------------------------------------------------------------
# Integration / full pipeline tests
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def _write_all_valid(self, tmp_path):
        _write_yaml(tmp_path, "01-recon-manifest.yaml", VALID_RECON)
        _write_yaml(tmp_path, "02-triage-chunks.yaml", VALID_TRIAGE)
        _write_yaml(tmp_path, "03-analysis-findings.yaml", VALID_ANALYSIS)
        _write_yaml(tmp_path, "04-validation-findings.yaml", VALID_VALIDATION)
        _write_text(tmp_path, "04-validation-brief.md", VALID_BRIEF)

    def test_all_stages_pass(self, tmp_path):
        self._write_all_valid(tmp_path)
        results = run_validation(tmp_path)
        assert all(r.ok for r in results), \
            f"Failures: {[(r.stage_name, [(n, reason) for s, n, reason in r.checks if s == 'fail']) for r in results if not r.ok]}"

    def test_single_stage_filter(self, tmp_path):
        self._write_all_valid(tmp_path)
        results = run_validation(tmp_path, stages=["recon"])
        assert len(results) == 1
        assert results[0].stage_name.startswith("Stage 1")
        assert results[0].ok

    def test_multiple_stage_filter(self, tmp_path):
        self._write_all_valid(tmp_path)
        results = run_validation(tmp_path, stages=["recon", "analysis"])
        assert len(results) == 2

    def test_all_missing_files(self, tmp_path):
        results = run_validation(tmp_path)
        assert not any(r.ok for r in results)


# ---------------------------------------------------------------------------
# CLI / main() tests
# ---------------------------------------------------------------------------

class TestCLI:
    def test_main_returns_zero_on_pass(self, tmp_path):
        _write_yaml(tmp_path, "01-recon-manifest.yaml", VALID_RECON)
        _write_yaml(tmp_path, "02-triage-chunks.yaml", VALID_TRIAGE)
        _write_yaml(tmp_path, "03-analysis-findings.yaml", VALID_ANALYSIS)
        _write_yaml(tmp_path, "04-validation-findings.yaml", VALID_VALIDATION)
        _write_text(tmp_path, "04-validation-brief.md", VALID_BRIEF)

        from validate_artifacts import main
        rc = main([str(tmp_path), "--no-color"])
        assert rc == 0

    def test_main_returns_nonzero_on_fail(self, tmp_path):
        # Empty dir - all files missing
        from validate_artifacts import main
        rc = main([str(tmp_path), "--no-color"])
        assert rc == 1

    def test_main_stage_filter(self, tmp_path):
        _write_yaml(tmp_path, "01-recon-manifest.yaml", VALID_RECON)
        from validate_artifacts import main
        rc = main([str(tmp_path), "--stage", "recon", "--no-color"])
        assert rc == 0

    def test_main_nonexistent_dir(self, tmp_path):
        from validate_artifacts import main
        rc = main([str(tmp_path / "nonexistent"), "--no-color"])
        assert rc == 2


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_yaml_parse_error(self, tmp_path):
        bad_yaml = tmp_path / "01-recon-manifest.yaml"
        bad_yaml.write_text(": : : not valid yaml [[[")
        result = validate_recon(tmp_path)
        assert not result.ok
        assert any("YAML parse error" in (r or "") for _, _, r in result.checks)

    def test_yaml_is_scalar_not_dict(self, tmp_path):
        scalar_yaml = tmp_path / "01-recon-manifest.yaml"
        scalar_yaml.write_text("just a string")
        result = validate_recon(tmp_path)
        assert not result.ok

    def test_yaml_is_list_not_dict(self, tmp_path):
        list_yaml = tmp_path / "03-analysis-findings.yaml"
        list_yaml.write_text("- item1\n- item2\n")
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_validation_result_counts(self):
        r = ValidationResult("test", "test.yaml")
        r.passed("a")
        r.passed("b")
        r.failed("c", "reason")
        r.warned("d", "reason")
        assert r.pass_count == 2
        assert r.fail_count == 1
        assert r.warn_count == 1
        assert not r.ok

    def test_validation_result_ok_when_no_fails(self):
        r = ValidationResult("test", "test.yaml")
        r.passed("a")
        r.warned("b", "reason")
        assert r.ok

    def test_color_disable(self):
        Color.disable()
        assert Color.RED == ""
        assert Color.GREEN == ""
        # Re-enable for other tests
        Color.GREEN = "\033[32m"
        Color.RED = "\033[31m"
        Color.YELLOW = "\033[33m"
        Color.BOLD = "\033[1m"
        Color.DIM = "\033[2m"
        Color.RESET = "\033[0m"
        Color.CYAN = "\033[36m"


class TestMultipleFindings:
    """Test that multiple findings are all validated individually."""

    def test_second_finding_invalid_fails(self, tmp_path):
        findings = [
            VALID_ANALYSIS["findings"][0],
            {
                "id": "VULN-002",
                "severity": "invalid_level",
                "type": "xss",
                "location": {"file": "a.php", "line": 1},
                "evidence": {"code": "x", "trace": "y"},
                "confidence": 0.5,
            },
        ]
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": findings})
        result = validate_analysis(tmp_path)
        assert not result.ok

    def test_multiple_valid_findings_pass(self, tmp_path):
        f1 = {**VALID_ANALYSIS["findings"][0]}
        f2 = {**VALID_ANALYSIS["findings"][0], "id": "VULN-002", "severity": "high", "confidence": 0.7}
        _write_yaml(tmp_path, "03-analysis-findings.yaml", {"findings": [f1, f2]})
        result = validate_analysis(tmp_path)
        assert result.ok
