"""
Tests for eval_scorer findings.json integration (Tasks 3, 4, 5).

Covers:
  - flag_capture matched via findings.json
  - flag_capture with wrong value not matched
  - flag_capture fallback to PTT loot (both 'value' and 'content' field names)
  - credential_discovery matched via findings.json
  - credential_discovery fallback to PTT credentials
  - CLI --findings argument integration
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
    MatchCriteria,
    Objective,
    score_ptt,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SCORER_PATH = Path(__file__).parent.parent.parent / "scripts" / "eval_scorer.py"


def _make_gt(category: str, match: MatchCriteria, points: int = 10) -> GroundTruth:
    """Build a minimal GroundTruth with a single objective."""
    return GroundTruth(
        target_name="test-target",
        target_image="docker.io/library/test:latest",
        difficulty="easy",
        objectives=[
            Objective(
                id="obj-1",
                category=category,
                description="Test objective",
                points=points,
                difficulty="easy",
                match=match,
            )
        ],
    )


def _empty_ptt() -> dict:
    """PTT with no findings, no loot, no creds."""
    return {
        "engagement": {
            "hosts": [
                {
                    "ip": "10.0.0.1",
                    "access_level": "none",
                    "services": [],
                    "findings": {"loot": [], "credentials": []},
                }
            ]
        }
    }


def _ptt_with_loot(loot_items: list[dict]) -> dict:
    ptt = _empty_ptt()
    ptt["engagement"]["hosts"][0]["findings"]["loot"] = loot_items
    return ptt


def _ptt_with_creds(cred_items: list[dict]) -> dict:
    ptt = _empty_ptt()
    ptt["engagement"]["hosts"][0]["findings"]["credentials"] = cred_items
    return ptt


# ---------------------------------------------------------------------------
# 1. flag matched via findings.json
# ---------------------------------------------------------------------------

def test_flag_matched_via_findings():
    """A matching flag finding should result in objective status=achieved."""
    gt = _make_gt(
        "flag_capture",
        MatchCriteria(flag_type="user", flag_value="EVAL{user_flag_here}"),
    )
    ptt = _empty_ptt()
    findings = [
        {"type": "flag", "flag_type": "user", "value": "EVAL{user_flag_here}", "path": "/home/user/flag.txt"},
    ]
    result = score_ptt(gt, ptt, findings=findings)
    assert result.objective_results[0].status == "achieved"
    assert "Matched finding" in result.objective_results[0].evidence


# ---------------------------------------------------------------------------
# 2. flag NOT matched — wrong value
# ---------------------------------------------------------------------------

def test_flag_not_matched_wrong_value():
    """A finding with the wrong flag value should not match."""
    gt = _make_gt(
        "flag_capture",
        MatchCriteria(flag_value="EVAL{correct_flag}"),
    )
    ptt = _empty_ptt()
    findings = [
        {"type": "flag", "flag_type": "user", "value": "EVAL{wrong_flag}", "path": "/tmp/flag"},
    ]
    result = score_ptt(gt, ptt, findings=findings)
    assert result.objective_results[0].status == "missed"


# ---------------------------------------------------------------------------
# 3. flag fallback to PTT loot (value field)
# ---------------------------------------------------------------------------

def test_flag_fallback_to_ptt_loot_value_field():
    """With no findings, a PTT loot item with a 'value' field should match."""
    gt = _make_gt(
        "flag_capture",
        MatchCriteria(flag_value="EVAL{loot_flag}"),
    )
    ptt = _ptt_with_loot([{"name": "user-flag", "type": "flag", "value": "EVAL{loot_flag}"}])
    result = score_ptt(gt, ptt, findings=None)
    assert result.objective_results[0].status == "achieved"
    assert "PTT loot" in result.objective_results[0].evidence


def test_flag_fallback_to_ptt_loot_content_field():
    """With no findings, a PTT loot item with a 'content' field should also match."""
    gt = _make_gt(
        "flag_capture",
        MatchCriteria(flag_value="EVAL{content_flag}"),
    )
    ptt = _ptt_with_loot([{"name": "root-flag", "type": "flag", "content": "EVAL{content_flag}"}])
    result = score_ptt(gt, ptt, findings=None)
    assert result.objective_results[0].status == "achieved"
    assert "PTT loot" in result.objective_results[0].evidence


# ---------------------------------------------------------------------------
# 4. credential matched via findings.json
# ---------------------------------------------------------------------------

def test_credential_matched_via_findings():
    """A credential finding should satisfy a has_credentials objective."""
    gt = _make_gt(
        "credential_discovery",
        MatchCriteria(has_credentials=True),
    )
    ptt = _empty_ptt()
    findings = [
        {"type": "credential", "username": "admin", "password": "s3cr3t", "service": "ssh"},
    ]
    result = score_ptt(gt, ptt, findings=findings)
    assert result.objective_results[0].status == "achieved"
    assert "findings" in result.objective_results[0].evidence


# ---------------------------------------------------------------------------
# 5. credential fallback to PTT
# ---------------------------------------------------------------------------

def test_credential_fallback_to_ptt():
    """With no findings, credentials in PTT should satisfy has_credentials."""
    gt = _make_gt(
        "credential_discovery",
        MatchCriteria(has_credentials=True),
    )
    ptt = _ptt_with_creds([{"username": "root", "secret": "toor"}])
    result = score_ptt(gt, ptt, findings=None)
    assert result.objective_results[0].status == "achieved"
    assert "PTT" in result.objective_results[0].evidence


# ---------------------------------------------------------------------------
# 6. CLI --findings flag
# ---------------------------------------------------------------------------

def test_cli_with_findings_flag(tmp_path):
    """Subprocess test: --findings flag loads findings.json and scores correctly."""
    # Ground truth YAML
    gt_data = {
        "target_name": "cli-test",
        "target_image": "docker.io/library/test:latest",
        "difficulty": "easy",
        "objectives": [
            {
                "id": "flag-1",
                "category": "flag_capture",
                "description": "Capture the user flag",
                "points": 20,
                "difficulty": "easy",
                "match": {
                    "flag_type": "user",
                    "flag_value": "EVAL{cli_test_flag}",
                },
            }
        ],
    }
    gt_path = tmp_path / "gt.yaml"
    gt_path.write_text(yaml.dump(gt_data))

    # Minimal PTT (no loot)
    ptt_data = {
        "engagement": {
            "hosts": [
                {
                    "ip": "10.0.0.1",
                    "access_level": "none",
                    "services": [],
                    "findings": {"loot": [], "credentials": []},
                }
            ]
        }
    }
    ptt_path = tmp_path / "ptt.yaml"
    ptt_path.write_text(yaml.dump(ptt_data))

    # findings.json with matching flag
    findings_data = [
        {"type": "flag", "flag_type": "user", "value": "EVAL{cli_test_flag}", "path": "/home/user/flag.txt"},
    ]
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(findings_data))

    result = subprocess.run(
        [
            sys.executable,
            str(SCORER_PATH),
            "score",
            "--ground-truth", str(gt_path),
            "--ptt", str(ptt_path),
            "--findings", str(findings_path),
            "--json",
            "--no-color",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode in (0, 1), f"Unexpected exit code {result.returncode}:\n{result.stderr}"
    output = json.loads(result.stdout)
    objectives = {o["id"]: o for o in output["objectives"]}
    assert objectives["flag-1"]["status"] == "achieved", (
        f"Expected flag-1 to be achieved, got: {objectives['flag-1']}"
    )
