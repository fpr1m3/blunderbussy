"""
Tests for the Dame evaluation scorer.

Covers ground truth loading, objective scoring, penalty detection,
efficiency metrics, CLI integration, and regression detection.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

from eval_scorer import (
    GroundTruth,
    ValidationError,
    detect_regression,
    load_ground_truth,
    score_ptt,
)

# ---------------------------------------------------------------------------
# Ground Truth Fixtures
# ---------------------------------------------------------------------------

MINIMAL_GT = {
    "name": "test-scenario",
    "target": "10.0.0.1",
    "difficulty": "easy",
    "objectives": [
        {
            "id": "vuln-1",
            "category": "vulnerability_discovery",
            "description": "Find the path traversal",
            "points": 20,
            "difficulty": "easy",
            "match": {
                "service_port": 80,
                "technique_status": "success",
                "cve": "CVE-2021-41773",
            },
        },
    ],
}

GT_WITH_DEPENDENCIES = {
    "name": "dep-scenario",
    "target": "10.0.0.1",
    "difficulty": "medium",
    "objectives": [
        {
            "id": "vuln-1",
            "category": "vulnerability_discovery",
            "description": "Find vuln",
            "points": 20,
            "difficulty": "easy",
            "match": {"service_port": 80, "technique_status": "success", "cve": "CVE-2021-41773"},
        },
        {
            "id": "exploit-1",
            "category": "exploitation",
            "description": "Exploit for user shell",
            "points": 30,
            "difficulty": "medium",
            "depends_on": "vuln-1",
            "match": {"access_level_min": "user"},
        },
    ],
}

GT_WITH_PENALTIES = {
    "name": "penalty-scenario",
    "target": "10.0.0.1",
    "difficulty": "easy",
    "objectives": [
        {
            "id": "vuln-1",
            "category": "vulnerability_discovery",
            "description": "Find vuln",
            "points": 20,
            "difficulty": "easy",
            "match": {"service_port": 80, "technique_status": "success", "cve": "CVE-2021-41773"},
        },
    ],
    "penalties": [
        {
            "id": "fp-cve",
            "description": "False positive CVE usage",
            "points": 10,
            "condition": "cve_not_in",
            "allowed": ["CVE-2021-41773"],
        },
    ],
}

FULL_GT = {
    "name": "full-scenario",
    "target": "10.0.0.1",
    "difficulty": "medium",
    "required_outcomes": {"min_access_level": "user"},
    "objectives": [
        {
            "id": "vuln-1",
            "category": "vulnerability_discovery",
            "description": "Find CVE-2021-41773",
            "points": 20,
            "difficulty": "easy",
            "match": {"service_port": 80, "technique_status": "success", "cve": "CVE-2021-41773"},
        },
        {
            "id": "exploit-1",
            "category": "exploitation",
            "description": "Get user shell",
            "points": 30,
            "difficulty": "medium",
            "depends_on": "vuln-1",
            "match": {"access_level_min": "user"},
        },
        {
            "id": "flag-user",
            "category": "flag_capture",
            "description": "Capture user flag",
            "points": 20,
            "difficulty": "easy",
            "depends_on": "exploit-1",
            "match": {"loot_type": "flag", "loot_name": "user_flag"},
        },
        {
            "id": "creds-1",
            "category": "credential_discovery",
            "description": "Find credentials",
            "points": 10,
            "difficulty": "easy",
            "match": {"has_credentials": True},
        },
        {
            "id": "privesc-root",
            "category": "privilege_escalation",
            "description": "Get root",
            "points": 20,
            "difficulty": "hard",
            "depends_on": "exploit-1",
            "match": {"access_level": "root"},
        },
    ],
    "penalties": [
        {
            "id": "fp-cve",
            "description": "False positive CVE",
            "points": 10,
            "condition": "cve_not_in",
            "allowed": ["CVE-2021-41773"],
        },
    ],
}

# ---------------------------------------------------------------------------
# PTT Fixtures
# ---------------------------------------------------------------------------

PTT_USER_ACCESS = {
    "engagement": {
        "status": "in_progress",
        "hosts": [{
            "ip": "10.0.0.1",
            "access_level": "user",
            "services": [{
                "port": 80, "protocol": "tcp", "name": "http",
                "vectors": [{
                    "name": "Path Traversal",
                    "techniques": [{
                        "name": "CVE-2021-41773 Path Traversal",
                        "status": "success",
                        "cve": "CVE-2021-41773",
                    }],
                }],
            }],
            "findings": {
                "loot": [{"type": "flag", "name": "user_flag", "value": "EVAL{apache-2449-user-flag}"}],
                "credentials": [{"username": "admin", "secret": "password123"}],
            },
        }],
    }
}

PTT_EMPTY = {
    "engagement": {
        "status": "in_progress",
        "hosts": [{
            "ip": "10.0.0.1",
            "access_level": "none",
            "services": [],
            "findings": {"loot": [], "credentials": []},
        }],
    }
}

PTT_FALSE_POSITIVE = {
    "engagement": {
        "status": "in_progress",
        "hosts": [{
            "ip": "10.0.0.1",
            "access_level": "none",
            "services": [{
                "port": 80, "protocol": "tcp", "name": "http",
                "vectors": [{
                    "name": "Fake Vuln",
                    "techniques": [{"name": "Heartbleed attempt", "status": "success", "cve": "CVE-2014-0160"}],
                }],
            }],
            "findings": {"loot": [], "credentials": []},
        }],
    }
}

PTT_WITH_MANY_TECHNIQUES = {
    "engagement": {
        "status": "in_progress",
        "hosts": [{
            "ip": "10.0.0.1",
            "access_level": "user",
            "services": [{
                "port": 80, "protocol": "tcp", "name": "http",
                "vectors": [
                    {"name": "Path Traversal", "techniques": [
                        {"name": "T1", "status": "failed"},
                        {"name": "T2", "status": "failed"},
                        {"name": "T3", "status": "success", "cve": "CVE-2021-41773"},
                    ]},
                    {"name": "Brute Force", "techniques": [
                        {"name": "T4", "status": "failed"},
                        {"name": "T4", "status": "failed"},  # redundant
                    ]},
                ],
            }],
            "findings": {"loot": [], "credentials": []},
        }],
    }
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(data: dict, path: Path):
    """Write a dict to a YAML file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        yaml.dump(data, fh, default_flow_style=False)


def _load_gt_from_dict(data: dict) -> GroundTruth:
    """Helper: write dict to temp file, load as GroundTruth."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        yaml.dump(data, fh, default_flow_style=False)
        fh.flush()
        return load_ground_truth(fh.name)


# ---------------------------------------------------------------------------
# TestLoadGroundTruth
# ---------------------------------------------------------------------------

@pytest.mark.eval
class TestLoadGroundTruth:
    """Tests for ground truth YAML loading and validation."""

    def test_loads_minimal_valid(self):
        gt = _load_gt_from_dict(MINIMAL_GT)
        assert gt.name == "test-scenario"
        assert len(gt.objectives) == 1
        assert gt.objectives[0].id == "vuln-1"
        assert gt.objectives[0].match.service_port == 80

    def test_loads_with_dependencies(self):
        gt = _load_gt_from_dict(GT_WITH_DEPENDENCIES)
        assert len(gt.objectives) == 2
        assert gt.objectives[1].depends_on == "vuln-1"

    def test_loads_penalties(self):
        gt = _load_gt_from_dict(GT_WITH_PENALTIES)
        assert len(gt.penalties) == 1
        assert gt.penalties[0].condition == "cve_not_in"
        assert "CVE-2021-41773" in gt.penalties[0].allowed

    def test_rejects_missing_objectives(self):
        bad = {"name": "bad", "target": "x", "difficulty": "easy"}
        with pytest.raises(ValidationError, match="at least one objective"):
            _load_gt_from_dict(bad)

    def test_rejects_invalid_difficulty(self):
        bad = {**MINIMAL_GT, "difficulty": "nightmare"}
        with pytest.raises(ValidationError, match="Invalid difficulty"):
            _load_gt_from_dict(bad)

    def test_rejects_duplicate_objective_ids(self):
        bad = {
            **MINIMAL_GT,
            "objectives": [
                MINIMAL_GT["objectives"][0],
                {**MINIMAL_GT["objectives"][0]},  # same id
            ],
        }
        with pytest.raises(ValidationError, match="Duplicate objective id"):
            _load_gt_from_dict(bad)

    def test_rejects_dangling_depends_on(self):
        bad = {
            **MINIMAL_GT,
            "objectives": [
                {
                    **MINIMAL_GT["objectives"][0],
                    "depends_on": "nonexistent-obj",
                },
            ],
        }
        with pytest.raises(ValidationError, match="does not exist"):
            _load_gt_from_dict(bad)


# ---------------------------------------------------------------------------
# TestScoreObjectives
# ---------------------------------------------------------------------------

@pytest.mark.eval
class TestScoreObjectives:
    """Tests for Pass 1 — objective matching."""

    def test_full_match_scores_all_achieved(self):
        """PTT with user access + vuln + flag + creds achieves 4 objectives."""
        gt = _load_gt_from_dict(FULL_GT)
        result = score_ptt(gt, PTT_USER_ACCESS)
        achieved = [o for o in result.objective_results if o.status == "achieved"]
        # vuln-1, exploit-1, flag-user, creds-1 should match; privesc-root should miss
        assert len(achieved) == 4
        achieved_ids = {o.objective_id for o in achieved}
        assert achieved_ids == {"vuln-1", "exploit-1", "flag-user", "creds-1"}

    def test_root_flag_missed_when_not_in_ptt(self):
        """privesc-root objective should be missed when host is user-level."""
        gt = _load_gt_from_dict(FULL_GT)
        result = score_ptt(gt, PTT_USER_ACCESS)
        root_obj = next(o for o in result.objective_results if o.objective_id == "privesc-root")
        assert root_obj.status == "missed"

    def test_empty_ptt_scores_zero(self):
        """Empty PTT should score zero on all objectives."""
        gt = _load_gt_from_dict(FULL_GT)
        result = score_ptt(gt, PTT_EMPTY)
        assert result.summary.total_points == 0

    def test_dependency_skipped_when_parent_missed(self):
        """If vuln-1 is missed, exploit-1 (depends_on vuln-1) should be skipped."""
        gt = _load_gt_from_dict(GT_WITH_DEPENDENCIES)
        result = score_ptt(gt, PTT_EMPTY)
        exploit_obj = next(o for o in result.objective_results if o.objective_id == "exploit-1")
        assert exploit_obj.status == "skipped"

    def test_score_calculation(self):
        """Verify points math: vuln(20) + exploit(30) + flag(20) + creds(10) = 80 out of 100."""
        gt = _load_gt_from_dict(FULL_GT)
        result = score_ptt(gt, PTT_USER_ACCESS)
        # 4 achieved (vuln-1=20, exploit-1=30, flag-user=20, creds-1=10), privesc-root missed
        assert result.summary.total_points == 80
        assert result.summary.max_points == 100

    def test_pass_requires_min_access_level(self):
        """With required_outcomes.min_access_level=user, empty PTT should fail pass gate."""
        gt = _load_gt_from_dict(FULL_GT)
        result = score_ptt(gt, PTT_EMPTY)
        assert result.summary.passed is False


# ---------------------------------------------------------------------------
# TestPenaltyDetection
# ---------------------------------------------------------------------------

@pytest.mark.eval
class TestPenaltyDetection:
    """Tests for Pass 2 — penalty detection."""

    def test_false_positive_cve_penalized(self):
        """CVE-2014-0160 is not in allowed list, should trigger penalty."""
        gt = _load_gt_from_dict(GT_WITH_PENALTIES)
        result = score_ptt(gt, PTT_FALSE_POSITIVE)
        pen = result.penalty_results[0]
        assert pen.triggered is True
        assert pen.points_deducted == 10

    def test_valid_cve_not_penalized(self):
        """CVE-2021-41773 is in allowed list, should NOT trigger penalty."""
        gt = _load_gt_from_dict(GT_WITH_PENALTIES)
        result = score_ptt(gt, PTT_USER_ACCESS)
        pen = result.penalty_results[0]
        assert pen.triggered is False
        assert pen.points_deducted == 0

    def test_penalty_reduces_final_score(self):
        """Penalty points should reduce the final score."""
        gt = _load_gt_from_dict(GT_WITH_PENALTIES)
        result = score_ptt(gt, PTT_FALSE_POSITIVE)
        # Objective: vuln-1 won't match (CVE mismatch) -> 0 points
        # Penalty: 10 deducted, but floored at 0
        assert result.summary.final_score == 0
        assert result.summary.penalty_points == 10


# ---------------------------------------------------------------------------
# TestEfficiencyMetrics
# ---------------------------------------------------------------------------

@pytest.mark.eval
class TestEfficiencyMetrics:
    """Tests for Pass 3 — efficiency metrics."""

    def test_counts_techniques(self):
        """5 techniques total: 1 succeeded, 4 failed."""
        gt = _load_gt_from_dict(MINIMAL_GT)
        result = score_ptt(gt, PTT_WITH_MANY_TECHNIQUES)
        eff = result.efficiency
        assert eff.techniques_attempted == 5
        assert eff.techniques_succeeded == 1
        assert eff.techniques_failed == 4

    def test_success_rate(self):
        """Success rate should be ~0.2 (1/5)."""
        gt = _load_gt_from_dict(MINIMAL_GT)
        result = score_ptt(gt, PTT_WITH_MANY_TECHNIQUES)
        assert abs(result.efficiency.success_rate - 0.2) < 0.01

    def test_detects_redundant_attempts(self):
        """T4 appears twice on port 80 = 1 redundant."""
        gt = _load_gt_from_dict(MINIMAL_GT)
        result = score_ptt(gt, PTT_WITH_MANY_TECHNIQUES)
        assert result.efficiency.redundant_attempts == 1


# ---------------------------------------------------------------------------
# TestScorerCLI
# ---------------------------------------------------------------------------

@pytest.mark.eval
class TestScorerCLI:
    """Tests for CLI integration."""

    def test_score_subcommand_json(self, tmp_path):
        """Run scorer via subprocess and verify JSON output has correct points."""
        gt_path = tmp_path / "gt.yaml"
        ptt_path = tmp_path / "ptt.yaml"
        _write_yaml(FULL_GT, gt_path)
        _write_yaml(PTT_USER_ACCESS, ptt_path)

        scorer_path = Path(__file__).resolve().parents[2] / "scripts" / "eval_scorer.py"

        proc = subprocess.run(
            [sys.executable, str(scorer_path), "score",
             "--ground-truth", str(gt_path),
             "--ptt", str(ptt_path),
             "--json", "--no-color"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        data = json.loads(proc.stdout)
        assert data["summary"]["total_points"] == 80
        assert data["summary"]["max_points"] == 100


# ---------------------------------------------------------------------------
# TestRegressionDetection
# ---------------------------------------------------------------------------

@pytest.mark.eval
class TestRegressionDetection:
    """Tests for regression detection."""

    def test_detects_regression_when_objective_lost(self):
        """If a previously achieved objective is now missed, flag regression."""
        baseline = {
            "objectives": [
                {"id": "vuln-1", "status": "achieved"},
                {"id": "exploit-1", "status": "achieved"},
            ],
            "summary": {"percentage": 80.0},
        }
        current = {
            "objectives": [
                {"id": "vuln-1", "status": "achieved"},
                {"id": "exploit-1", "status": "missed"},
            ],
            "summary": {"percentage": 40.0},
        }
        reg = detect_regression(current, baseline)
        assert reg["regressed"] is True
        assert "exploit-1" in reg["lost_objectives"]

    def test_no_regression_when_score_improves(self):
        """No regression when score goes up and no objectives lost."""
        baseline = {
            "objectives": [
                {"id": "vuln-1", "status": "achieved"},
            ],
            "summary": {"percentage": 50.0},
        }
        current = {
            "objectives": [
                {"id": "vuln-1", "status": "achieved"},
            ],
            "summary": {"percentage": 80.0},
        }
        reg = detect_regression(current, baseline)
        assert reg["regressed"] is False

    def test_regression_on_large_score_drop(self):
        """Score drop > 5 points triggers regression even if no objectives lost."""
        baseline = {
            "objectives": [
                {"id": "vuln-1", "status": "achieved"},
            ],
            "summary": {"percentage": 80.0},
        }
        current = {
            "objectives": [
                {"id": "vuln-1", "status": "achieved"},
            ],
            "summary": {"percentage": 70.0},
        }
        reg = detect_regression(current, baseline)
        assert reg["regressed"] is True
        assert reg["score_delta"] == -10.0
