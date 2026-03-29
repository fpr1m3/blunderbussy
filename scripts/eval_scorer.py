#!/usr/bin/env python3
"""
Dame Evaluation Scorer
=======================

Scores Dame's PTT (Pentest Task Tree) output against ground truth objectives
using a 3-pass algorithm: objectives -> penalties -> efficiency.

Usage:
    python eval_scorer.py score --ground-truth gt.yaml --ptt ptt.yaml
    python eval_scorer.py score --ground-truth gt.yaml --ptt ptt.yaml --json
    python eval_scorer.py score --ground-truth gt.yaml --ptt ptt.yaml --baseline baseline.json
"""

import argparse
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: uv pip install pyyaml", file=sys.stderr)
    sys.exit(2)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_DIFFICULTIES = {"easy", "medium", "hard"}
VALID_ACCESS_LEVELS = {"none", "user", "root"}
ACCESS_LEVEL_ORDER = {"none": 0, "user": 1, "root": 2}
VALID_CATEGORIES = {
    "vulnerability_discovery",
    "service_discovery",
    "information_extraction",
    "exploitation",
    "flag_capture",
    "credential_discovery",
    "privilege_escalation",
}


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

class Color:
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    CYAN = "\033[36m"

    @classmethod
    def disable(cls):
        cls.GREEN = cls.RED = cls.YELLOW = cls.BOLD = ""
        cls.DIM = cls.RESET = cls.CYAN = ""


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ValidationError(Exception):
    """Raised when ground truth YAML fails schema validation."""
    pass


# ---------------------------------------------------------------------------
# Ground Truth Schema (Task 2)
# ---------------------------------------------------------------------------

@dataclass
class MatchCriteria:
    """Criteria for matching a specific objective category against PTT."""
    service_port: Optional[int] = None
    technique_status: Optional[str] = None
    cve: Optional[str] = None
    access_level_min: Optional[str] = None
    loot_type: Optional[str] = None
    loot_name: Optional[str] = None
    flag_type: Optional[str] = None
    flag_value: Optional[str] = None
    has_credentials: Optional[bool] = None
    access_level: Optional[str] = None
    cve_not_in: Optional[list[str]] = None


@dataclass
class Objective:
    """A single evaluation objective."""
    id: str
    category: str
    description: str
    points: int
    difficulty: str
    match: MatchCriteria
    depends_on: Optional[str] = None


@dataclass
class Penalty:
    """A penalty rule definition."""
    id: str
    description: str
    points: int  # negative value
    match: MatchCriteria = field(default_factory=MatchCriteria)


@dataclass
class RequiredOutcomes:
    """Gate conditions that must be met for a passing score."""
    min_access_level: Optional[str] = None


@dataclass
class Efficiency:
    """Expected efficiency parameters."""
    max_techniques: Optional[int] = None
    max_redundant: Optional[int] = None


@dataclass
class GroundTruth:
    """Complete ground truth for an evaluation scenario."""
    target_name: str
    target_image: str
    difficulty: str
    objectives: list[Objective]
    eval_version: str = "1.0"
    platform: str = "linux"
    penalties: list[Penalty] = field(default_factory=list)
    efficiency: Optional[Efficiency] = None
    required_outcomes: Optional[RequiredOutcomes] = None


def _parse_match_criteria(data: dict) -> MatchCriteria:
    """Parse match criteria from a dict."""
    return MatchCriteria(
        service_port=data.get("service_port"),
        technique_status=data.get("technique_status"),
        cve=data.get("cve"),
        access_level_min=data.get("access_level_min"),
        loot_type=data.get("loot_type"),
        loot_name=data.get("loot_name"),
        flag_type=data.get("flag_type"),
        flag_value=data.get("flag_value"),
        has_credentials=data.get("has_credentials"),
        access_level=data.get("access_level"),
        cve_not_in=data.get("cve_not_in"),
    )


def load_ground_truth(path: str | Path) -> GroundTruth:
    """Load and validate a ground truth YAML file.

    Raises ValidationError on schema violations.
    """
    path = Path(path)
    with open(path) as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise ValidationError("Ground truth must be a YAML mapping")

    # Required top-level keys
    target_name = data.get("target_name", "unnamed")
    target_image = data.get("target_image", "unknown")
    eval_version = data.get("eval_version", "1.0")
    platform = data.get("platform", "linux")
    difficulty = data.get("difficulty", "medium")

    if difficulty not in VALID_DIFFICULTIES:
        raise ValidationError(
            f"Invalid difficulty '{difficulty}', must be one of {VALID_DIFFICULTIES}"
        )

    # Objectives (required, non-empty)
    raw_objectives = data.get("objectives")
    if not raw_objectives:
        raise ValidationError("Ground truth must contain at least one objective")

    objectives: list[Objective] = []
    seen_ids: set[str] = set()

    for obj_data in raw_objectives:
        obj_id = obj_data.get("id", "")
        if obj_id in seen_ids:
            raise ValidationError(f"Duplicate objective id: '{obj_id}'")
        seen_ids.add(obj_id)

        category = obj_data.get("category", "")
        if category not in VALID_CATEGORIES:
            raise ValidationError(
                f"Invalid category '{category}' in objective '{obj_id}'"
            )

        obj_difficulty = obj_data.get("difficulty", difficulty)
        if obj_difficulty not in VALID_DIFFICULTIES:
            raise ValidationError(
                f"Invalid difficulty '{obj_difficulty}' in objective '{obj_id}'"
            )

        match_data = obj_data.get("match", {})
        objectives.append(Objective(
            id=obj_id,
            category=category,
            description=obj_data.get("description", ""),
            points=int(obj_data.get("points", 0)),
            difficulty=obj_difficulty,
            match=_parse_match_criteria(match_data),
            depends_on=obj_data.get("depends_on"),
        ))

    # Validate depends_on references
    for obj in objectives:
        if obj.depends_on and obj.depends_on not in seen_ids:
            raise ValidationError(
                f"Objective '{obj.id}' depends_on '{obj.depends_on}' which does not exist"
            )

    # Penalties (optional)
    penalties: list[Penalty] = []
    for pen_data in data.get("penalties", []):
        match_data = pen_data.get("match", {})
        penalties.append(Penalty(
            id=pen_data.get("id", ""),
            description=pen_data.get("description", ""),
            points=int(pen_data.get("points", 0)),
            match=_parse_match_criteria(match_data),
        ))

    # Efficiency (optional)
    efficiency = None
    eff_data = data.get("efficiency")
    if eff_data:
        efficiency = Efficiency(
            max_techniques=eff_data.get("max_techniques"),
            max_redundant=eff_data.get("max_redundant"),
        )

    # Required outcomes (optional)
    required_outcomes = None
    ro_data = data.get("required_outcomes")
    if ro_data:
        required_outcomes = RequiredOutcomes(
            min_access_level=ro_data.get("min_access_level"),
        )

    return GroundTruth(
        target_name=target_name,
        target_image=target_image,
        eval_version=eval_version,
        platform=platform,
        difficulty=difficulty,
        objectives=objectives,
        penalties=penalties,
        efficiency=efficiency,
        required_outcomes=required_outcomes,
    )


# ---------------------------------------------------------------------------
# Scorer Result Types (Task 3)
# ---------------------------------------------------------------------------

@dataclass
class ObjectiveResult:
    """Result for a single objective evaluation."""
    id: str
    category: str
    status: str  # "achieved", "missed", "skipped"
    points: int
    points_possible: int
    evidence: str = ""


@dataclass
class PenaltyResult:
    """Result for a single penalty check."""
    penalty_id: str
    triggered: bool
    points_deducted: int
    detail: str = ""


@dataclass
class EfficiencyResult:
    """Efficiency metrics from PTT analysis."""
    techniques_attempted: int = 0
    techniques_succeeded: int = 0
    techniques_failed: int = 0
    success_rate: float = 0.0
    redundant_attempts: int = 0


@dataclass
class ScoreSummary:
    """Aggregate score breakdown."""
    points_achieved: int = 0
    points_possible: int = 0
    points_penalized: int = 0
    final_score: int = 0
    percentage: float = 0.0
    passed: bool = False


@dataclass
class EvalResult:
    """Complete evaluation result."""
    target: str = ""
    objective_results: list[ObjectiveResult] = field(default_factory=list)
    penalty_results: list[PenaltyResult] = field(default_factory=list)
    efficiency: EfficiencyResult = field(default_factory=EfficiencyResult)
    summary: ScoreSummary = field(default_factory=ScoreSummary)

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "target": self.target,
            "objectives": [
                {
                    "id": o.id,
                    "category": o.category,
                    "status": o.status,
                    "points": o.points,
                    "points_possible": o.points_possible,
                    "evidence": o.evidence,
                }
                for o in self.objective_results
            ],
            "penalties": [
                {
                    "id": p.penalty_id,
                    "triggered": p.triggered,
                    "points_deducted": p.points_deducted,
                    "detail": p.detail,
                }
                for p in self.penalty_results
            ],
            "efficiency": {
                "techniques_attempted": self.efficiency.techniques_attempted,
                "techniques_succeeded": self.efficiency.techniques_succeeded,
                "techniques_failed": self.efficiency.techniques_failed,
                "success_rate": self.efficiency.success_rate,
                "redundant_attempts": self.efficiency.redundant_attempts,
            },
            "score": {
                "points_achieved": self.summary.points_achieved,
                "points_possible": self.summary.points_possible,
                "points_penalized": self.summary.points_penalized,
                "final_score": self.summary.final_score,
                "percentage": self.summary.percentage,
                "pass": self.summary.passed,
            },
        }


# ---------------------------------------------------------------------------
# PTT Tree Walking Helpers
# ---------------------------------------------------------------------------

def _walk_techniques(ptt: dict):
    """Yield (host, service, vector, technique) tuples from PTT tree.

    Handles two PTT formats:
    - Standard: engagement.hosts[].services[].vectors[].techniques[]
    - Flat: engagement.findings.vulnerabilities[] (Dame sometimes writes this)
    """
    engagement = ptt.get("engagement", {})
    # Standard format
    for host in engagement.get("hosts", []):
        for service in host.get("services", []):
            for vector in service.get("vectors", []):
                for technique in vector.get("techniques", []):
                    yield host, service, vector, technique

    # Flat fallback: engagement.findings.vulnerabilities[] as pseudo-techniques
    flat_findings = engagement.get("findings", {})
    if isinstance(flat_findings, dict):
        for vuln in flat_findings.get("vulnerabilities", []):
            pseudo_host = {"ip": "unknown", "access_level": engagement.get("access_level", "none")}
            pseudo_service = {"port": vuln.get("port"), "protocol": "tcp", "name": "http"}
            pseudo_vector = {"name": vuln.get("name", "unknown")}
            pseudo_technique = {
                "name": vuln.get("name", "unknown"),
                "status": vuln.get("status", "unknown"),
                "cve": vuln.get("cve"),
            }
            yield pseudo_host, pseudo_service, pseudo_vector, pseudo_technique


def _get_max_access_level(ptt: dict) -> str:
    """Get the highest access level achieved across all hosts."""
    engagement = ptt.get("engagement", {})
    max_level = "none"
    for host in engagement.get("hosts", []):
        level = host.get("access_level", "none")
        if ACCESS_LEVEL_ORDER.get(level, 0) > ACCESS_LEVEL_ORDER.get(max_level, 0):
            max_level = level
    # Flat fallback: engagement.access_level
    flat_level = engagement.get("access_level", "none")
    if ACCESS_LEVEL_ORDER.get(flat_level, 0) > ACCESS_LEVEL_ORDER.get(max_level, 0):
        max_level = flat_level
    return max_level


def _get_all_loot(ptt: dict) -> list[dict]:
    """Collect all loot items from all hosts and flat findings."""
    items = []
    engagement = ptt.get("engagement", {})
    for host in engagement.get("hosts", []):
        findings = host.get("findings", {})
        items.extend(findings.get("loot", []))
    # Flat fallback: engagement.findings.loot
    flat_findings = engagement.get("findings", {})
    if isinstance(flat_findings, dict):
        items.extend(flat_findings.get("loot", []))
    return items


def _get_all_credentials(ptt: dict) -> list[dict]:
    """Collect all credential entries from all hosts and flat findings."""
    items = []
    engagement = ptt.get("engagement", {})
    for host in engagement.get("hosts", []):
        findings = host.get("findings", {})
        items.extend(findings.get("credentials", []))
    # Flat fallback: engagement.findings.credentials
    flat_findings = engagement.get("findings", {})
    if isinstance(flat_findings, dict):
        items.extend(flat_findings.get("credentials", []))
    return items


# ---------------------------------------------------------------------------
# Pass 1 — Objective Matching (Task 3)
# ---------------------------------------------------------------------------

def _topological_sort(objectives: list[Objective]) -> list[Objective]:
    """Sort objectives so dependencies come before dependents."""
    by_id = {o.id: o for o in objectives}
    visited: set[str] = set()
    result: list[Objective] = []

    def visit(obj_id: str):
        if obj_id in visited:
            return
        obj = by_id.get(obj_id)
        if obj is None:
            return
        if obj.depends_on:
            visit(obj.depends_on)
        visited.add(obj_id)
        result.append(obj)

    for obj in objectives:
        visit(obj.id)

    return result


def _match_objective(obj: Objective, ptt: dict, findings: list[dict] | None = None) -> tuple[bool, str]:
    """Check if a single objective is achieved in the PTT.

    Returns (matched, reason).
    """
    mc = obj.match

    if obj.category in ("vulnerability_discovery", "service_discovery", "information_extraction"):
        _SUCCESS = {"success", "exploited"}
        # Primary: check PTT techniques
        for _host, service, _vector, technique in _walk_techniques(ptt):
            port_ok = mc.service_port is None or service.get("port") == mc.service_port
            # Accept "exploited" as equivalent to "success" (Dame uses either)
            tech_status = technique.get("status", "")
            if mc.technique_status in _SUCCESS:
                status_ok = tech_status in _SUCCESS
            else:
                status_ok = mc.technique_status is None or tech_status == mc.technique_status
            cve_ok = mc.cve is None or technique.get("cve") == mc.cve
            if port_ok and status_ok and cve_ok:
                return True, f"Matched technique '{technique.get('name', '?')}'"

        # Fallback: check findings.json vulnerabilities
        if findings:
            for f in findings:
                if f.get("type") != "vulnerability":
                    continue
                port_ok = mc.service_port is None or f.get("service_port") == mc.service_port
                f_status = f.get("status", "")
                if mc.technique_status in _SUCCESS:
                    status_ok = f_status in _SUCCESS
                else:
                    status_ok = mc.technique_status is None or f_status == mc.technique_status
                cve_ok = mc.cve is None or f.get("cve") == mc.cve
                if port_ok and status_ok and cve_ok:
                    return True, f"Matched finding: {f.get('name', '?')} on port {f.get('service_port', '?')}"

        return False, "No matching technique found"

    elif obj.category == "exploitation":
        min_level = mc.access_level_min or "user"
        max_level = _get_max_access_level(ptt)
        if ACCESS_LEVEL_ORDER.get(max_level, 0) >= ACCESS_LEVEL_ORDER.get(min_level, 0):
            return True, f"Host access_level '{max_level}' >= '{min_level}'"
        # Fallback: infer access level from findings.json flags
        if findings:
            for f in findings:
                if f.get("type") != "flag":
                    continue
                flag_level = f.get("access_level", "none")
                if ACCESS_LEVEL_ORDER.get(flag_level, 0) >= ACCESS_LEVEL_ORDER.get(min_level, 0):
                    return True, f"Inferred access_level '{flag_level}' from {f.get('flag_type', '?')} capture"
        return False, f"No host with access_level >= '{mc.access_level_min}'"

    elif obj.category == "flag_capture":
        # Primary: check findings.json
        if findings:
            for f in findings:
                if f.get("type") != "flag":
                    continue
                type_ok = mc.flag_type is None or f.get("flag_type") == mc.flag_type
                value_ok = mc.flag_value is None or f.get("value") == mc.flag_value
                if type_ok and value_ok:
                    return True, f"Matched finding: {f.get('flag_type', '?')} from {f.get('path', '?')}"

        # Fallback: check PTT loot
        for loot in _get_all_loot(ptt):
            value = loot.get("value") or loot.get("content") or loot.get("flag") or loot.get("data") or ""
            value_ok = mc.flag_value is None or value == mc.flag_value
            if value_ok:
                return True, f"Matched PTT loot '{loot.get('name', '?')}'"
        return False, "No matching flag found"

    elif obj.category == "credential_discovery":
        # Primary: check findings.json
        if findings and mc.has_credentials:
            cred_findings = [f for f in findings if f.get("type") == "credential"]
            if cred_findings:
                return True, f"Found {len(cred_findings)} credential(s) in findings"

        # Fallback: check PTT credentials
        if mc.has_credentials:
            creds = _get_all_credentials(ptt)
            if len(creds) > 0:
                return True, f"Found {len(creds)} credential(s) in PTT"
        return False, "No credentials found"

    elif obj.category == "privilege_escalation":
        expected_level = mc.access_level or "root"
        max_level = _get_max_access_level(ptt)
        if max_level == expected_level:
            return True, f"Host has access_level '{expected_level}'"
        return False, f"No host with access_level '{expected_level}'"

    return False, f"Unknown category '{obj.category}'"


def _score_objectives(gt: GroundTruth, ptt: dict, findings: list[dict] | None = None) -> list[ObjectiveResult]:
    """Pass 1: Score objectives against PTT with dependency resolution."""
    sorted_objs = _topological_sort(gt.objectives)
    achieved_ids: set[str] = set()
    results: list[ObjectiveResult] = []

    for obj in sorted_objs:
        # Check dependency
        if obj.depends_on and obj.depends_on not in achieved_ids:
            results.append(ObjectiveResult(
                id=obj.id,
                category=obj.category,
                status="skipped",
                points=0,
                points_possible=obj.points,
                evidence=f"Dependency '{obj.depends_on}' not achieved",
            ))
            continue

        matched, reason = _match_objective(obj, ptt, findings=findings)
        if matched:
            achieved_ids.add(obj.id)
            results.append(ObjectiveResult(
                id=obj.id,
                category=obj.category,
                status="achieved",
                points=obj.points,
                points_possible=obj.points,
                evidence=reason,
            ))
        else:
            results.append(ObjectiveResult(
                id=obj.id,
                category=obj.category,
                status="missed",
                points=0,
                points_possible=obj.points,
                evidence=reason,
            ))

    return results


# ---------------------------------------------------------------------------
# Pass 2 — Penalty Detection (Task 4)
# ---------------------------------------------------------------------------

def _detect_penalties(gt: GroundTruth, ptt: dict) -> list[PenaltyResult]:
    """Pass 2: Scan PTT for penalty conditions."""
    results: list[PenaltyResult] = []

    for penalty in gt.penalties:
        if penalty.match.cve_not_in is not None:
            # Check if any technique references a CVE not in the allowed list
            allowed = penalty.match.cve_not_in
            triggered = False
            detail_parts = []
            for _host, _service, _vector, technique in _walk_techniques(ptt):
                tech_cve = technique.get("cve")
                if tech_cve and tech_cve not in allowed:
                    triggered = True
                    detail_parts.append(
                        f"{tech_cve} (technique '{technique.get('name', '?')}')"
                    )

            results.append(PenaltyResult(
                penalty_id=penalty.id,
                triggered=triggered,
                points_deducted=abs(penalty.points) if triggered else 0,
                detail=f"Disallowed CVEs: {', '.join(detail_parts)}" if triggered else "No violations",
            ))
        else:
            logger.warning("Unknown penalty match criteria for penalty: %s", penalty.id)

    return results


# ---------------------------------------------------------------------------
# Pass 3 — Efficiency Metrics (Task 5)
# ---------------------------------------------------------------------------

def _compute_efficiency(ptt: dict) -> EfficiencyResult:
    """Pass 3: Compute technique efficiency metrics from PTT."""
    attempted = 0
    succeeded = 0
    failed = 0
    # Track (technique_name, service_port) for redundancy detection
    seen_technique_service: dict[tuple[str, int], int] = defaultdict(int)
    redundant = 0

    for _host, service, _vector, technique in _walk_techniques(ptt):
        attempted += 1
        status = technique.get("status", "unknown")
        if status in ("success", "exploited"):
            succeeded += 1
        elif status == "failed":
            failed += 1

        tech_name = technique.get("name", "")
        svc_port = service.get("port", 0)
        key = (tech_name, svc_port)
        seen_technique_service[key] += 1

    # Redundant = count of duplicate occurrences (beyond the first)
    for key, count in seen_technique_service.items():
        if count > 1:
            redundant += count - 1

    success_rate = succeeded / attempted if attempted > 0 else 0.0

    return EfficiencyResult(
        techniques_attempted=attempted,
        techniques_succeeded=succeeded,
        techniques_failed=failed,
        success_rate=success_rate,
        redundant_attempts=redundant,
    )


# ---------------------------------------------------------------------------
# Score Aggregation
# ---------------------------------------------------------------------------

def score_ptt(gt: GroundTruth, ptt: dict, findings: list[dict] | None = None) -> EvalResult:
    """Run all 3 passes and produce an EvalResult."""
    # Pass 1: Objectives
    obj_results = _score_objectives(gt, ptt, findings=findings)

    # Pass 2: Penalties
    pen_results = _detect_penalties(gt, ptt)

    # Pass 3: Efficiency
    efficiency = _compute_efficiency(ptt)

    # Aggregate
    points_achieved = sum(o.points for o in obj_results)
    points_possible = sum(o.points_possible for o in obj_results)
    points_penalized = sum(p.points_deducted for p in pen_results)
    final_score = max(0, points_achieved - points_penalized)
    percentage = (final_score / points_possible * 100) if points_possible > 0 else 0.0

    # Pass gate: required outcomes
    passed = True
    if gt.required_outcomes and gt.required_outcomes.min_access_level:
        actual_level = _get_max_access_level(ptt)
        # Also infer access level from findings.json flags
        if findings:
            for f in findings:
                if f.get("type") == "flag":
                    flag_level = f.get("access_level", "none")
                    if ACCESS_LEVEL_ORDER.get(flag_level, 0) > ACCESS_LEVEL_ORDER.get(actual_level, 0):
                        actual_level = flag_level
        required_level = gt.required_outcomes.min_access_level
        if ACCESS_LEVEL_ORDER.get(actual_level, 0) < ACCESS_LEVEL_ORDER.get(required_level, 0):
            passed = False

    summary = ScoreSummary(
        points_achieved=points_achieved,
        points_possible=points_possible,
        points_penalized=points_penalized,
        final_score=final_score,
        percentage=percentage,
        passed=passed,
    )

    return EvalResult(
        target=gt.target_name,
        objective_results=obj_results,
        penalty_results=pen_results,
        efficiency=efficiency,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Regression Detection (Task 6)
# ---------------------------------------------------------------------------

def detect_regression(current_dict: dict, baseline_dict: dict) -> dict:
    """Compare current eval result dict against a baseline.

    Returns a dict with:
      - regressed: bool
      - lost_objectives: list of objective IDs that were achieved but now missed
      - score_delta: float (current - baseline percentage)
      - details: str
    """
    # Build objective status maps
    baseline_objs = {o["id"]: o["status"] for o in baseline_dict.get("objectives", [])}
    current_objs = {o["id"]: o["status"] for o in current_dict.get("objectives", [])}

    lost = []
    for obj_id, baseline_status in baseline_objs.items():
        if baseline_status == "achieved":
            current_status = current_objs.get(obj_id, "missed")
            if current_status != "achieved":
                lost.append(obj_id)

    baseline_pct = baseline_dict.get("score", {}).get("percentage", 0.0)
    current_pct = current_dict.get("score", {}).get("percentage", 0.0)
    score_delta = current_pct - baseline_pct

    regressed = len(lost) > 0 or score_delta < -5.0

    details_parts = []
    if lost:
        details_parts.append(f"Lost objectives: {', '.join(lost)}")
    if score_delta < -5.0:
        details_parts.append(f"Score dropped by {abs(score_delta):.1f} points")

    return {
        "regressed": regressed,
        "lost_objectives": lost,
        "score_delta": score_delta,
        "details": "; ".join(details_parts) if details_parts else "No regression detected",
    }


# ---------------------------------------------------------------------------
# Formatted Summary Output (Task 5)
# ---------------------------------------------------------------------------

def _format_summary(result: EvalResult, gt_name: str = "") -> str:
    """Render human-readable colored summary."""
    lines = [
        f"\n{Color.BOLD}{Color.CYAN}{'=' * 60}{Color.RESET}",
        f"{Color.BOLD}  Dame Eval: {gt_name}{Color.RESET}",
        f"{Color.BOLD}{Color.CYAN}{'=' * 60}{Color.RESET}",
        "",
    ]

    # Objectives
    lines.append(f"  {Color.BOLD}Objectives:{Color.RESET}")
    for obj in result.objective_results:
        if obj.status == "achieved":
            icon = f"{Color.GREEN}\u2713{Color.RESET}"
        elif obj.status == "skipped":
            icon = f"{Color.YELLOW}\u2298{Color.RESET}"
        else:
            icon = f"{Color.RED}\u2717{Color.RESET}"
        lines.append(
            f"    {icon} {obj.id} [{obj.category}] "
            f"{obj.points}/{obj.points_possible}pts — {obj.evidence}"
        )

    # Penalties
    if result.penalty_results:
        lines.append(f"\n  {Color.BOLD}Penalties:{Color.RESET}")
        for pen in result.penalty_results:
            if pen.triggered:
                lines.append(
                    f"    {Color.RED}\u2717{Color.RESET} {pen.penalty_id}: "
                    f"-{pen.points_deducted}pts — {pen.detail}"
                )
            else:
                lines.append(
                    f"    {Color.GREEN}\u2713{Color.RESET} {pen.penalty_id}: clean"
                )

    # Efficiency
    eff = result.efficiency
    lines.append(f"\n  {Color.BOLD}Efficiency:{Color.RESET}")
    lines.append(f"    Techniques: {eff.techniques_attempted} attempted, "
                 f"{eff.techniques_succeeded} succeeded, {eff.techniques_failed} failed")
    lines.append(f"    Success rate: {eff.success_rate:.1%}")
    lines.append(f"    Redundant attempts: {eff.redundant_attempts}")

    # Score
    s = result.summary
    pct = s.percentage
    if pct >= 80:
        score_color = Color.GREEN
    elif pct >= 50:
        score_color = Color.YELLOW
    else:
        score_color = Color.RED

    lines.append(f"\n  {Color.BOLD}Score:{Color.RESET}")
    lines.append(f"    Points: {s.points_achieved}/{s.points_possible}")
    if s.points_penalized > 0:
        lines.append(f"    Penalties: -{s.points_penalized}")
    lines.append(f"    Final: {score_color}{s.final_score}/{s.points_possible} "
                 f"({pct:.1f}%){Color.RESET}")
    lines.append(f"    Pass: {Color.GREEN if s.passed else Color.RED}"
                 f"{'YES' if s.passed else 'NO'}{Color.RESET}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI (Task 5)
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Dame evaluation scorer — score PTT against ground truth.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # score subcommand
    score_parser = subparsers.add_parser("score", help="Score a PTT against ground truth")
    score_parser.add_argument("--ground-truth", required=True, type=Path,
                              help="Path to ground truth YAML")
    score_parser.add_argument("--ptt", required=True, type=Path,
                              help="Path to PTT YAML")
    score_parser.add_argument("--findings", type=Path, default=None,
                              help="Path to findings.json (optional, supplements PTT)")
    score_parser.add_argument("--baseline", type=Path, default=None,
                              help="Path to baseline JSON for regression detection")
    score_parser.add_argument("--json", action="store_true",
                              help="Output results as JSON")
    score_parser.add_argument("--no-color", action="store_true",
                              help="Disable ANSI colors")
    score_parser.add_argument("--output", type=Path, default=None,
                              help="Write output to file instead of stdout")
    score_parser.add_argument("--verbose", action="store_true",
                              help="Verbose output with match details")

    args = parser.parse_args(argv)

    if args.command != "score":
        parser.print_help()
        return 2

    if args.no_color:
        Color.disable()

    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    # Load inputs
    try:
        gt = load_ground_truth(args.ground_truth)
    except (ValidationError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        with open(args.ptt) as fh:
            ptt = yaml.safe_load(fh)
    except (FileNotFoundError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # Load findings (optional)
    findings = None
    if args.findings:
        try:
            with open(args.findings) as fh:
                findings = json.load(fh)
            if not isinstance(findings, list):
                findings = None
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.warning("Could not load findings: %s", exc)

    # Score
    result = score_ptt(gt, ptt, findings=findings)
    result_dict = result.to_dict()

    # Regression check
    regression = None
    if args.baseline:
        try:
            with open(args.baseline) as fh:
                baseline_dict = json.load(fh)
            regression = detect_regression(result_dict, baseline_dict)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            print(f"WARNING: Could not load baseline: {exc}", file=sys.stderr)

    # Output
    if args.json:
        output_data = result_dict
        if regression:
            output_data["regression"] = regression
        text = json.dumps(output_data, indent=2)
    else:
        text = _format_summary(result, gt.target_name)
        if regression and regression["regressed"]:
            text += f"\n{Color.RED}REGRESSION DETECTED: {regression['details']}{Color.RESET}\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text)

    # Exit codes: 0=pass, 1=fail, 2=regression
    if regression and regression["regressed"]:
        return 2
    if not result.summary.passed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
