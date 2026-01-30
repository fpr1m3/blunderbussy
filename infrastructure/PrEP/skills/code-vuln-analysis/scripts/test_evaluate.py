#!/usr/bin/env python3
"""
Tests for the benchmark harness (evaluate.py + ground_truth.py).

Run: cd infrastructure/PrEP/skills/code-vuln-analysis/scripts && uv run pytest test_evaluate.py -v
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

# Ensure scripts/ is on path for sibling imports
sys.path.insert(0, str(Path(__file__).parent))

from ground_truth import (
    GroundTruth,
    GroundTruthVuln,
    VulnType,
    VULN_TYPE_ALIASES,
    load_ground_truth,
    normalize_vuln_type,
)
from evaluate import (
    EvalConfig,
    EvalResult,
    FindingMatch,
    _compute_metrics,
    _extract_findings,
    _extract_finding_location,
    _extract_performance_metrics,
    _match_file,
    _match_line,
    _match_type,
    _parse_line,
    evaluate_architecture,
    main,
    match_findings,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gt(vulns: list[dict], **kwargs) -> GroundTruth:
    """Build a GroundTruth from simple dicts."""
    gt_vulns = []
    for v in vulns:
        gt_vulns.append(GroundTruthVuln(
            id=v["id"],
            vuln_type=v.get("vuln_type", "sql_injection"),
            cwe=v.get("cwe", "CWE-89"),
            severity=v.get("severity", "high"),
            file=v.get("file", "src/test.php"),
            line=v.get("line", 10),
            end_line=v.get("end_line"),
            function=v.get("function"),
            exploitable=v.get("exploitable", True),
            description=v.get("description", ""),
            sink_function=v.get("sink_function"),
            sanitized=v.get("sanitized", False),
            tags=v.get("tags", []),
        ))
    defaults = {
        "fixture_name": "test-fixture",
        "language": "php",
        "description": "test",
        "vulnerabilities": gt_vulns,
    }
    defaults.update(kwargs)
    return GroundTruth(**defaults)


def _make_finding(fid: str, file: str, line: int, vtype: str, severity: str = "high") -> dict:
    """Build a finding dict in analysis format."""
    return {
        "id": fid,
        "severity": severity,
        "type": vtype,
        "location": {"file": file, "line": line},
        "description": "test finding",
        "evidence": {"code": "x", "trace": "y"},
        "confidence": 0.9,
    }


def _write_gt_yaml(tmpdir: Path, gt_data: dict) -> Path:
    """Write ground truth YAML to temp dir."""
    path = tmpdir / "ground_truth.yaml"
    path.write_text(yaml.dump(gt_data, default_flow_style=False))
    return path


def _write_artifacts(tmpdir: Path, findings: list[dict], validation: list[dict] | None = None,
                     state: dict | None = None) -> Path:
    """Write artifact YAML files to temp dir."""
    artifact_dir = tmpdir / "artifacts"
    artifact_dir.mkdir(exist_ok=True)

    # Analysis findings
    (artifact_dir / "03-analysis-findings.yaml").write_text(
        yaml.dump({"findings": findings}, default_flow_style=False)
    )

    # Validation findings (optional)
    if validation is not None:
        (artifact_dir / "04-validation-findings.yaml").write_text(
            yaml.dump({"validated_findings": validation}, default_flow_style=False)
        )

    # State (optional)
    if state is not None:
        (artifact_dir / "state.yaml").write_text(
            yaml.dump(state, default_flow_style=False)
        )

    return artifact_dir


# ===========================================================================
# TestGroundTruthLoading
# ===========================================================================

class TestGroundTruthLoading:
    def test_load_valid_ground_truth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gt_path = _write_gt_yaml(Path(tmpdir), {
                "fixture_name": "test-app",
                "language": "php",
                "description": "Test app",
                "total_files": 5,
                "safe_patterns": ["prepared_statements"],
                "vulnerabilities": [
                    {
                        "id": "GT-001",
                        "vuln_type": "sql_injection",
                        "cwe": "CWE-89",
                        "severity": "critical",
                        "file": "src/login.php",
                        "line": 15,
                        "exploitable": True,
                        "sanitized": False,
                    },
                    {
                        "id": "GT-SAFE-001",
                        "vuln_type": "sql_injection",
                        "cwe": "CWE-89",
                        "severity": "low",
                        "file": "src/safe.php",
                        "line": 10,
                        "exploitable": False,
                        "sanitized": True,
                    },
                ],
            })
            gt = load_ground_truth(gt_path)

            assert gt.fixture_name == "test-app"
            assert gt.language == "php"
            assert gt.total_files == 5
            assert len(gt.vulnerabilities) == 2

    def test_exploitable_filter(self):
        gt = _make_gt([
            {"id": "V1", "exploitable": True, "sanitized": False},
            {"id": "V2", "exploitable": True, "sanitized": True},
            {"id": "V3", "exploitable": False, "sanitized": True},
        ])
        assert len(gt.exploitable_vulns) == 1
        assert gt.exploitable_vulns[0].id == "V1"

    def test_sanitized_filter(self):
        gt = _make_gt([
            {"id": "V1", "sanitized": False},
            {"id": "V2", "sanitized": True},
            {"id": "V3", "sanitized": True},
        ])
        assert len(gt.sanitized_vulns) == 2

    def test_missing_optional_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gt_path = _write_gt_yaml(Path(tmpdir), {
                "fixture_name": "minimal",
                "language": "python",
                "description": "Minimal",
                "vulnerabilities": [
                    {"id": "V1", "vuln_type": "xss", "file": "a.py", "line": 1},
                ],
            })
            gt = load_ground_truth(gt_path)
            v = gt.vulnerabilities[0]
            assert v.end_line is None
            assert v.function is None
            assert v.exploitable is True  # default
            assert v.sanitized is False  # default
            assert v.tags == []

    def test_empty_vulns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gt_path = _write_gt_yaml(Path(tmpdir), {
                "fixture_name": "empty",
                "language": "go",
                "description": "No vulns",
                "vulnerabilities": [],
            })
            gt = load_ground_truth(gt_path)
            assert len(gt.vulnerabilities) == 0
            assert len(gt.exploitable_vulns) == 0


# ===========================================================================
# TestVulnTypeNormalization
# ===========================================================================

class TestVulnTypeNormalization:
    def test_canonical_match(self):
        assert normalize_vuln_type("sql_injection") == VulnType.SQL_INJECTION

    def test_aliases(self):
        assert normalize_vuln_type("sqli") == VulnType.SQL_INJECTION
        assert normalize_vuln_type("rce") == VulnType.COMMAND_INJECTION
        assert normalize_vuln_type("lfi") == VulnType.LOCAL_FILE_INCLUSION
        assert normalize_vuln_type("cmd_injection") == VulnType.COMMAND_INJECTION

    def test_unknown_returns_none(self):
        assert normalize_vuln_type("unknown_vuln_xyz") is None

    def test_case_insensitive(self):
        assert normalize_vuln_type("SQL_INJECTION") == VulnType.SQL_INJECTION
        assert normalize_vuln_type("Sqli") == VulnType.SQL_INJECTION

    def test_hyphen_underscore_normalization(self):
        assert normalize_vuln_type("sql-injection") == VulnType.SQL_INJECTION
        assert normalize_vuln_type("command-injection") == VulnType.COMMAND_INJECTION
        assert normalize_vuln_type("xss reflected") == VulnType.XSS_REFLECTED

    def test_empty_returns_none(self):
        assert normalize_vuln_type("") is None

    def test_all_vuln_types_have_self_alias(self):
        for vt in VulnType:
            assert normalize_vuln_type(vt.value) == vt


# ===========================================================================
# TestFileMatching
# ===========================================================================

class TestFileMatching:
    def test_exact_match(self):
        assert _match_file("src/login.php", "src/login.php") is True

    def test_leading_dot_slash(self):
        assert _match_file("./src/login.php", "src/login.php") is True
        assert _match_file("src/login.php", "./src/login.php") is True

    def test_prefix_suffix_path(self):
        assert _match_file("app/src/login.php", "src/login.php") is True
        assert _match_file("src/login.php", "app/src/login.php") is True

    def test_different_basename(self):
        assert _match_file("src/login.php", "src/config.php") is False

    def test_same_basename_different_dir(self):
        # basename match catches this
        assert _match_file("src/utils.py", "lib/utils.py") is True

    def test_none_values(self):
        assert _match_file(None, "src/login.php") is False
        assert _match_file("src/login.php", None) is False
        assert _match_file(None, None) is False


# ===========================================================================
# TestLineMatching
# ===========================================================================

class TestLineMatching:
    def test_exact_match(self):
        matched, dist = _match_line(15, 15)
        assert matched is True
        assert dist == 0

    def test_within_proximity(self):
        matched, dist = _match_line(17, 15, proximity=5)
        assert matched is True
        assert dist == 2

    def test_outside_proximity(self):
        matched, dist = _match_line(25, 15, proximity=5)
        assert matched is False
        assert dist == 10

    def test_range_within(self):
        matched, dist = _match_line(47, 45, gt_end_line=48)
        assert matched is True
        assert dist == 0

    def test_range_plus_proximity(self):
        matched, dist = _match_line(50, 45, gt_end_line=48, proximity=5)
        assert matched is True
        assert dist == 2

    def test_none_finding_line(self):
        matched, dist = _match_line(None, 15)
        assert matched is False
        assert dist is None

    def test_none_gt_line(self):
        matched, dist = _match_line(15, None)
        assert matched is False
        assert dist is None

    def test_string_range_parsing(self):
        assert _parse_line("45-48") == 45
        assert _parse_line("10") == 10
        assert _parse_line(15) == 15
        assert _parse_line(None) is None
        assert _parse_line("") is None
        assert _parse_line("abc") is None


# ===========================================================================
# TestMatchFindings
# ===========================================================================

class TestMatchFindings:
    def test_perfect_match_3_of_3(self):
        gt = _make_gt([
            {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php", "line": 10},
            {"id": "GT-2", "vuln_type": "xss_reflected", "file": "src/b.php", "line": 20},
            {"id": "GT-3", "vuln_type": "command_injection", "file": "src/c.php", "line": 30},
        ])
        findings = [
            _make_finding("F-1", "src/a.php", 10, "sql_injection"),
            _make_finding("F-2", "src/b.php", 20, "xss_reflected"),
            _make_finding("F-3", "src/c.php", 30, "command_injection"),
        ]
        matches, unmatched_f, unmatched_gt = match_findings(findings, gt)
        assert len(matches) == 3
        assert len(unmatched_f) == 0
        assert len(unmatched_gt) == 0

    def test_all_false_positives(self):
        gt = _make_gt([
            {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php", "line": 10},
        ])
        findings = [
            _make_finding("F-1", "src/x.php", 50, "xss_reflected"),
            _make_finding("F-2", "src/y.php", 60, "command_injection"),
        ]
        matches, unmatched_f, unmatched_gt = match_findings(findings, gt)
        assert len(matches) == 0
        assert len(unmatched_f) == 2
        assert len(unmatched_gt) == 1

    def test_all_false_negatives(self):
        gt = _make_gt([
            {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php", "line": 10},
            {"id": "GT-2", "vuln_type": "xss_reflected", "file": "src/b.php", "line": 20},
        ])
        findings = []
        matches, unmatched_f, unmatched_gt = match_findings(findings, gt)
        assert len(matches) == 0
        assert len(unmatched_f) == 0
        assert len(unmatched_gt) == 2

    def test_mixed_results(self):
        gt = _make_gt([
            {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php", "line": 10},
            {"id": "GT-2", "vuln_type": "xss_reflected", "file": "src/b.php", "line": 20},
            {"id": "GT-3", "vuln_type": "command_injection", "file": "src/c.php", "line": 30},
        ])
        findings = [
            _make_finding("F-1", "src/a.php", 10, "sql_injection"),   # TP
            _make_finding("F-2", "src/z.php", 99, "ssrf"),            # FP
        ]
        matches, unmatched_f, unmatched_gt = match_findings(findings, gt)
        assert len(matches) == 1  # TP
        assert len(unmatched_f) == 1  # FP
        assert len(unmatched_gt) == 2  # FN

    def test_greedy_closest_match(self):
        """When a finding could match multiple GT, pick closest by line."""
        gt = _make_gt([
            {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php", "line": 10},
            {"id": "GT-2", "vuln_type": "sql_injection", "file": "src/a.php", "line": 20},
        ])
        findings = [
            _make_finding("F-1", "src/a.php", 12, "sql_injection"),  # closer to GT-1
        ]
        matches, _, unmatched_gt = match_findings(findings, gt)
        assert len(matches) == 1
        assert matches[0].ground_truth_id == "GT-1"
        assert matches[0].line_distance == 2
        assert "GT-2" in unmatched_gt

    def test_sanitized_excluded_from_fn(self):
        gt = _make_gt([
            {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php", "line": 10},
            {"id": "GT-SAFE", "vuln_type": "sql_injection", "file": "src/safe.php",
             "line": 10, "sanitized": True, "exploitable": False},
        ])
        findings = []
        matches, unmatched_f, unmatched_gt = match_findings(findings, gt)
        # Only exploitable vulns should appear as FN
        assert len(unmatched_gt) == 1
        assert "GT-SAFE" not in unmatched_gt

    def test_type_alias_matching(self):
        gt = _make_gt([
            {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php", "line": 10},
        ])
        findings = [
            _make_finding("F-1", "src/a.php", 10, "sqli"),  # alias for sql_injection
        ]
        matches, _, _ = match_findings(findings, gt)
        assert len(matches) == 1

    def test_empty_findings_and_gt(self):
        gt = _make_gt([])
        findings = []
        matches, unmatched_f, unmatched_gt = match_findings(findings, gt)
        assert len(matches) == 0
        assert len(unmatched_f) == 0
        assert len(unmatched_gt) == 0


# ===========================================================================
# TestEvaluateArchitecture
# ===========================================================================

class TestEvaluateArchitecture:
    def test_perfect_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "perfect",
                "language": "php",
                "description": "test",
                "vulnerabilities": [
                    {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php",
                     "line": 10, "exploitable": True, "sanitized": False, "cwe": "CWE-89",
                     "severity": "critical"},
                    {"id": "GT-2", "vuln_type": "xss_reflected", "file": "src/b.php",
                     "line": 20, "exploitable": True, "sanitized": False, "cwe": "CWE-79",
                     "severity": "high"},
                ],
            })
            artifact_dir = _write_artifacts(tmpdir, [
                _make_finding("F-1", "src/a.php", 10, "sql_injection", "critical"),
                _make_finding("F-2", "src/b.php", 20, "xss_reflected", "high"),
            ])
            result = evaluate_architecture(artifact_dir, gt_path)
            assert result.tp == 2
            assert result.fp == 0
            assert result.fn == 0
            assert result.precision == 1.0
            assert result.recall == 1.0
            assert result.f1 == 1.0

    def test_partial_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "partial",
                "language": "php",
                "description": "test",
                "vulnerabilities": [
                    {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php",
                     "line": 10, "exploitable": True, "sanitized": False, "cwe": "CWE-89",
                     "severity": "critical"},
                    {"id": "GT-2", "vuln_type": "xss_reflected", "file": "src/b.php",
                     "line": 20, "exploitable": True, "sanitized": False, "cwe": "CWE-79",
                     "severity": "high"},
                ],
            })
            artifact_dir = _write_artifacts(tmpdir, [
                _make_finding("F-1", "src/a.php", 10, "sql_injection", "critical"),
                # GT-2 missed, one FP added
                _make_finding("F-X", "src/z.php", 99, "ssrf", "medium"),
            ])
            result = evaluate_architecture(artifact_dir, gt_path)
            assert result.tp == 1
            assert result.fp == 1
            assert result.fn == 1
            assert result.precision == pytest.approx(0.5)
            assert result.recall == pytest.approx(0.5)

    def test_no_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "none",
                "language": "php",
                "description": "test",
                "vulnerabilities": [
                    {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php",
                     "line": 10, "exploitable": True, "sanitized": False, "cwe": "CWE-89",
                     "severity": "high"},
                ],
            })
            artifact_dir = _write_artifacts(tmpdir, [])
            result = evaluate_architecture(artifact_dir, gt_path)
            assert result.tp == 0
            assert result.fp == 0
            assert result.fn == 1
            assert result.precision == 0.0
            assert result.recall == 0.0
            assert result.f1 == 0.0

    def test_all_false_positives(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "fp-only",
                "language": "php",
                "description": "test",
                "vulnerabilities": [],
            })
            artifact_dir = _write_artifacts(tmpdir, [
                _make_finding("F-1", "src/x.php", 50, "xss_reflected"),
            ])
            result = evaluate_architecture(artifact_dir, gt_path)
            assert result.tp == 0
            assert result.fp == 1
            assert result.fn == 0
            assert result.precision == 0.0

    def test_validation_preferred_over_analysis(self):
        """04-validation-findings.yaml should be preferred when present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "val-pref",
                "language": "php",
                "description": "test",
                "vulnerabilities": [
                    {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php",
                     "line": 10, "exploitable": True, "sanitized": False, "cwe": "CWE-89",
                     "severity": "critical"},
                ],
            })
            # Analysis has 2 findings, validation confirms only 1
            analysis_findings = [
                _make_finding("F-1", "src/a.php", 10, "sql_injection", "critical"),
                _make_finding("F-2", "src/x.php", 50, "xss_reflected", "high"),
            ]
            validation_findings = [
                {
                    "finding_id": "F-1",
                    "status": "confirmed",
                    "type": "sql_injection",
                    "location": {"file": "src/a.php", "line": 10},
                    "attack_path": [{"step": 1, "action": "test"}],
                    "proof_of_concept": "test",
                    "impact": "test",
                },
            ]
            artifact_dir = _write_artifacts(tmpdir, analysis_findings, validation_findings)
            result = evaluate_architecture(artifact_dir, gt_path)
            # Should use validation (1 confirmed) not analysis (2 findings)
            assert result.tp == 1
            assert result.fp == 0
            assert result.fn == 0

    def test_state_yaml_perf_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "perf",
                "language": "php",
                "description": "test",
                "vulnerabilities": [],
            })
            state = {
                "phases": {
                    "recon": {"turns": 3},
                    "triage": {"turns": 2},
                    "analysis": {"turns": 5},
                    "validation": {"turns": 4},
                },
                "time_elapsed": 120.5,
            }
            artifact_dir = _write_artifacts(tmpdir, [], state=state)
            result = evaluate_architecture(artifact_dir, gt_path)
            assert result.turns_used == 14
            assert result.time_elapsed == 120.5
            assert result.avg_turns == pytest.approx(3.5)
            assert result.avg_time == pytest.approx(30.125)


# ===========================================================================
# TestMetrics
# ===========================================================================

class TestMetrics:
    def test_perfect_scores(self):
        p, r, f = _compute_metrics(tp=5, fp=0, fn=0)
        assert p == 1.0
        assert r == 1.0
        assert f == 1.0

    def test_zero_scores(self):
        p, r, f = _compute_metrics(tp=0, fp=3, fn=2)
        assert p == 0.0
        assert r == 0.0
        assert f == 0.0

    def test_asymmetric_precision_high(self):
        p, r, f = _compute_metrics(tp=3, fp=0, fn=3)
        assert p == 1.0
        assert r == pytest.approx(0.5)
        assert f == pytest.approx(2/3)

    def test_asymmetric_recall_high(self):
        p, r, f = _compute_metrics(tp=3, fp=3, fn=0)
        assert p == pytest.approx(0.5)
        assert r == 1.0
        assert f == pytest.approx(2/3)

    def test_division_by_zero_all_zero(self):
        p, r, f = _compute_metrics(tp=0, fp=0, fn=0)
        assert p == 0.0
        assert r == 0.0
        assert f == 0.0


# ===========================================================================
# TestPerformanceExtraction
# ===========================================================================

class TestPerformanceExtraction:
    def test_turns_from_state_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            (tmpdir / "state.yaml").write_text(yaml.dump({
                "phases": {
                    "recon": {"turns": 3},
                    "triage": {"turns": 2},
                    "analysis": {"turns": 5},
                    "validation": {"turns": 4},
                },
                "time_elapsed": 60.0,
            }))
            turns, time = _extract_performance_metrics(tmpdir)
            assert turns == 14
            assert time == 60.0

    def test_missing_state_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            turns, time = _extract_performance_metrics(Path(tmpdir))
            assert turns is None
            assert time is None

    def test_empty_state_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            (tmpdir / "state.yaml").write_text("")
            turns, time = _extract_performance_metrics(tmpdir)
            assert turns is None
            assert time is None

    def test_direct_turns_used_field(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            (tmpdir / "state.yaml").write_text(yaml.dump({
                "turns_used": 10,
                "time_elapsed": 45.0,
            }))
            turns, time = _extract_performance_metrics(tmpdir)
            assert turns == 10
            assert time == 45.0


# ===========================================================================
# TestBreakdownMetrics
# ===========================================================================

class TestBreakdownMetrics:
    def test_by_severity_counts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "sev",
                "language": "php",
                "description": "test",
                "vulnerabilities": [
                    {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php",
                     "line": 10, "severity": "critical", "exploitable": True,
                     "sanitized": False, "cwe": "CWE-89"},
                    {"id": "GT-2", "vuln_type": "xss_reflected", "file": "src/b.php",
                     "line": 20, "severity": "high", "exploitable": True,
                     "sanitized": False, "cwe": "CWE-79"},
                ],
            })
            artifact_dir = _write_artifacts(tmpdir, [
                _make_finding("F-1", "src/a.php", 10, "sql_injection", "critical"),
                # GT-2 missed (FN), one FP added
                _make_finding("F-X", "src/z.php", 99, "ssrf", "medium"),
            ])
            result = evaluate_architecture(artifact_dir, gt_path)
            assert result.by_severity["critical"]["tp"] == 1
            assert result.by_severity["high"]["fn"] == 1
            assert result.by_severity["medium"]["fp"] == 1

    def test_by_type_counts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "type",
                "language": "php",
                "description": "test",
                "vulnerabilities": [
                    {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php",
                     "line": 10, "exploitable": True, "sanitized": False,
                     "cwe": "CWE-89", "severity": "critical"},
                ],
            })
            artifact_dir = _write_artifacts(tmpdir, [
                _make_finding("F-1", "src/a.php", 10, "sql_injection", "critical"),
            ])
            result = evaluate_architecture(artifact_dir, gt_path)
            assert result.by_type["sql_injection"]["tp"] == 1


# ===========================================================================
# TestEvalResultSummary
# ===========================================================================

class TestEvalResultSummary:
    def test_summary_renders(self):
        result = EvalResult(
            tp=3, fp=1, fn=1,
            precision=0.75, recall=0.75, f1=0.75,
            fixture_name="test-app",
        )
        text = result.summary(color=False)
        assert "test-app" in text
        assert "0.750" in text
        assert "True Positives" in text

    def test_summary_with_perf_metrics(self):
        result = EvalResult(
            tp=3, fp=0, fn=0,
            precision=1.0, recall=1.0, f1=1.0,
            turns_used=14, time_elapsed=60.0,
            avg_turns=3.5, avg_time=15.0,
            fixture_name="perf-app",
        )
        text = result.summary(color=False)
        assert "14" in text
        assert "60.0" in text

    def test_to_dict(self):
        result = EvalResult(tp=2, fp=1, fn=0, precision=2/3, recall=1.0, f1=0.8,
                           fixture_name="dict-test", fixture_language="php")
        d = result.to_dict()
        assert d["fixture_name"] == "dict-test"
        assert d["metrics"]["tp"] == 2
        assert d["metrics"]["fp"] == 1
        assert isinstance(d["matches"], list)


# ===========================================================================
# TestCLI
# ===========================================================================

class TestCLI:
    def test_exit_code_zero_default_threshold(self):
        """Default threshold is 0.0, so even empty results should exit 0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "cli-test",
                "language": "php",
                "description": "test",
                "vulnerabilities": [],
            })
            artifact_dir = _write_artifacts(tmpdir, [])
            exit_code = main([str(artifact_dir), str(gt_path), "--no-color"])
            assert exit_code == 0

    def test_exit_code_one_with_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "cli-fail",
                "language": "php",
                "description": "test",
                "vulnerabilities": [
                    {"id": "GT-1", "vuln_type": "sql_injection", "file": "src/a.php",
                     "line": 10, "exploitable": True, "sanitized": False, "cwe": "CWE-89",
                     "severity": "critical"},
                ],
            })
            artifact_dir = _write_artifacts(tmpdir, [])
            exit_code = main([str(artifact_dir), str(gt_path), "--no-color",
                            "--f1-threshold", "0.5"])
            assert exit_code == 1

    def test_json_output(self, capsys):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            gt_path = _write_gt_yaml(tmpdir, {
                "fixture_name": "json-test",
                "language": "php",
                "description": "test",
                "vulnerabilities": [],
            })
            artifact_dir = _write_artifacts(tmpdir, [])
            exit_code = main([str(artifact_dir), str(gt_path), "--json"])
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "metrics" in data
            assert data["fixture_name"] == "json-test"


# ===========================================================================
# TestFixtureIntegration
# ===========================================================================

class TestFixtureIntegration:
    """Run the harness against each real fixture's expected_artifacts."""

    @pytest.mark.parametrize("fixture_name", [
        "vuln-php-app",
        "vuln-python-app",
        "vuln-node-app",
    ])
    def test_fixture_f1_perfect(self, fixture_name):
        fixture_dir = FIXTURES_DIR / fixture_name
        if not fixture_dir.exists():
            pytest.skip(f"Fixture not found: {fixture_dir}")

        gt_path = fixture_dir / "ground_truth.yaml"
        artifact_dir = fixture_dir / "expected_artifacts"

        assert gt_path.exists(), f"Missing ground_truth.yaml in {fixture_dir}"
        assert artifact_dir.exists(), f"Missing expected_artifacts/ in {fixture_dir}"

        result = evaluate_architecture(artifact_dir, gt_path)

        assert result.f1 == 1.0, (
            f"Expected F1=1.0 for {fixture_name}, got {result.f1:.3f} "
            f"(TP={result.tp}, FP={result.fp}, FN={result.fn})"
        )
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.tp > 0, "Expected at least one true positive"
