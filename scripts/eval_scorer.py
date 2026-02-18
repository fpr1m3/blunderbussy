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
    loot_value: Optional[str] = None
    has_credentials: Optional[bool] = None
    access_level: Optional[str] = None


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
    points: int
    condition: str  # e.g. "cve_not_in"
    allowed: list[str] = field(default_factory=list)


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
    name: str
    target: str
    difficulty: str
    objectives: list[Objective]
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
        loot_value=data.get("loot_value"),
        has_credentials=data.get("has_credentials"),
        access_level=data.get("access_level"),
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
    name = data.get("name", "unnamed")
    target = data.get("target", "unknown")
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
        penalties.append(Penalty(
            id=pen_data.get("id", ""),
            description=pen_data.get("description", ""),
            points=int(pen_data.get("points", 0)),
            condition=pen_data.get("condition", ""),
            allowed=pen_data.get("allowed", []),
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
        name=name,
        target=target,
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
    objective_id: str
    category: str
    status: str  # "achieved", "missed", "skipped"
    points_awarded: int
    points_possible: int
    reason: str = ""


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
    total_points: int = 0
    max_points: int = 0
    penalty_points: int = 0
    final_score: int = 0
    percentage: float = 0.0
    passed: bool = False


@dataclass
class EvalResult:
    """Complete evaluation result."""
    objective_results: list[ObjectiveResult] = field(default_factory=list)
    penalty_results: list[PenaltyResult] = field(default_factory=list)
    efficiency: EfficiencyResult = field(default_factory=EfficiencyResult)
    summary: ScoreSummary = field(default_factory=ScoreSummary)

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "objectives": [
                {
                    "id": o.objective_id,
                    "category": o.category,
                    "status": o.status,
                    "points_awarded": o.points_awarded,
                    "points_possible": o.points_possible,
                    "reason": o.reason,
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
            "summary": {
                "total_points": self.summary.total_points,
                "max_points": self.summary.max_points,
                "penalty_points": self.summary.penalty_points,
                "final_score": self.summary.final_score,
                "percentage": self.summary.percentage,
                "passed": self.summary.passed,
            },
        }


# ---------------------------------------------------------------------------
# PTT Tree Walking Helpers
# ---------------------------------------------------------------------------

def _walk_techniques(ptt: dict):
    """Yield (host, service, vector, technique) tuples from PTT tree."""
    engagement = ptt.get("engagement", {})
    for host in engagement.get("hosts", []):
        for service in host.get("services", []):
            for vector in service.get("vectors", []):
                for technique in vector.get("techniques", []):
                    yield host, service, vector, technique


def _get_max_access_level(ptt: dict) -> str:
    """Get the highest access level achieved across all hosts."""
    engagement = ptt.get("engagement", {})
    max_level = "none"
    for host in engagement.get("hosts", []):
        level = host.get("access_level", "none")
        if ACCESS_LEVEL_ORDER.get(level, 0) > ACCESS_LEVEL_ORDER.get(max_level, 0):
            max_level = level
    return max_level


def _get_all_loot(ptt: dict) -> list[dict]:
    """Collect all loot items from all hosts."""
    items = []
    engagement = ptt.get("engagement", {})
    for host in engagement.get("hosts", []):
        findings = host.get("findings", {})
        items.extend(findings.get("loot", []))
    return items


def _get_all_credentials(ptt: dict) -> list[dict]:
    """Collect all credential entries from all hosts."""
    items = []
    engagement = ptt.get("engagement", {})
    for host in engagement.get("hosts", []):
        findings = host.get("findings", {})
        items.extend(findings.get("credentials", []))
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


def _match_objective(obj: Objective, ptt: dict) -> tuple[bool, str]:
    """Check if a single objective is achieved in the PTT.

    Returns (matched, reason).
    """
    mc = obj.match

    if obj.category == "vulnerability_discovery":
        for _host, service, _vector, technique in _walk_techniques(ptt):
            port_ok = mc.service_port is None or service.get("port") == mc.service_port
            status_ok = mc.technique_status is None or technique.get("status") == mc.technique_status
            cve_ok = mc.cve is None or technique.get("cve") == mc.cve
            if port_ok and status_ok and cve_ok:
                return True, f"Matched technique '{technique.get('name', '?')}'"
        return False, "No matching technique found"

    elif obj.category == "exploitation":
        engagement = ptt.get("engagement", {})
        for host in engagement.get("hosts", []):
            host_level = host.get("access_level", "none")
            min_level = mc.access_level_min or "user"
            if ACCESS_LEVEL_ORDER.get(host_level, 0) >= ACCESS_LEVEL_ORDER.get(min_level, 0):
                return True, f"Host access_level '{host_level}' >= '{min_level}'"
        return False, f"No host with access_level >= '{mc.access_level_min}'"

    elif obj.category == "flag_capture":
        for loot in _get_all_loot(ptt):
            type_ok = mc.loot_type is None or loot.get("type") == mc.loot_type
            name_ok = mc.loot_name is None or loot.get("name") == mc.loot_name
            value_ok = mc.loot_value is None or loot.get("value") == mc.loot_value
            if type_ok and name_ok and value_ok:
                return True, f"Matched loot '{loot.get('name', '?')}'"
        return False, "No matching loot found"

    elif obj.category == "credential_discovery":
        if mc.has_credentials:
            creds = _get_all_credentials(ptt)
            if len(creds) > 0:
                return True, f"Found {len(creds)} credential(s)"
        return False, "No credentials found"

    elif obj.category == "privilege_escalation":
        expected_level = mc.access_level or "root"
        engagement = ptt.get("engagement", {})
        for host in engagement.get("hosts", []):
            if host.get("access_level") == expected_level:
                return True, f"Host has access_level '{expected_level}'"
        return False, f"No host with access_level '{expected_level}'"

    return False, f"Unknown category '{obj.category}'"


def _score_objectives(gt: GroundTruth, ptt: dict) -> list[ObjectiveResult]:
    """Pass 1: Score objectives against PTT with dependency resolution."""
    sorted_objs = _topological_sort(gt.objectives)
    achieved_ids: set[str] = set()
    results: list[ObjectiveResult] = []

    for obj in sorted_objs:
        # Check dependency
        if obj.depends_on and obj.depends_on not in achieved_ids:
            results.append(ObjectiveResult(
                objective_id=obj.id,
                category=obj.category,
                status="skipped",
                points_awarded=0,
                points_possible=obj.points,
                reason=f"Dependency '{obj.depends_on}' not achieved",
            ))
            continue

        matched, reason = _match_objective(obj, ptt)
        if matched:
            achieved_ids.add(obj.id)
            results.append(ObjectiveResult(
                objective_id=obj.id,
                category=obj.category,
                status="achieved",
                points_awarded=obj.points,
                points_possible=obj.points,
                reason=reason,
            ))
        else:
            results.append(ObjectiveResult(
                objective_id=obj.id,
                category=obj.category,
                status="missed",
                points_awarded=0,
                points_possible=obj.points,
                reason=reason,
            ))

    return results


# ---------------------------------------------------------------------------
# Pass 2 — Penalty Detection (Task 4)
# ---------------------------------------------------------------------------

def _detect_penalties(gt: GroundTruth, ptt: dict) -> list[PenaltyResult]:
    """Pass 2: Scan PTT for penalty conditions."""
    results: list[PenaltyResult] = []

    for penalty in gt.penalties:
        if penalty.condition == "cve_not_in":
            # Check if any technique references a CVE not in the allowed list
            triggered = False
            detail_parts = []
            for _host, _service, _vector, technique in _walk_techniques(ptt):
                tech_cve = technique.get("cve")
                if tech_cve and tech_cve not in penalty.allowed:
                    triggered = True
                    detail_parts.append(
                        f"{tech_cve} (technique '{technique.get('name', '?')}')"
                    )

            results.append(PenaltyResult(
                penalty_id=penalty.id,
                triggered=triggered,
                points_deducted=penalty.points if triggered else 0,
                detail=f"Disallowed CVEs: {', '.join(detail_parts)}" if triggered else "No violations",
            ))
        else:
            logger.warning("Unknown penalty condition: %s", penalty.condition)

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
        if status == "success":
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

def score_ptt(gt: GroundTruth, ptt: dict) -> EvalResult:
    """Run all 3 passes and produce an EvalResult."""
    # Pass 1: Objectives
    obj_results = _score_objectives(gt, ptt)

    # Pass 2: Penalties
    pen_results = _detect_penalties(gt, ptt)

    # Pass 3: Efficiency
    efficiency = _compute_efficiency(ptt)

    # Aggregate
    total_points = sum(o.points_awarded for o in obj_results)
    max_points = sum(o.points_possible for o in obj_results)
    penalty_points = sum(p.points_deducted for p in pen_results)
    final_score = max(0, total_points - penalty_points)
    percentage = (final_score / max_points * 100) if max_points > 0 else 0.0

    # Pass gate: required outcomes
    passed = True
    if gt.required_outcomes and gt.required_outcomes.min_access_level:
        actual_level = _get_max_access_level(ptt)
        required_level = gt.required_outcomes.min_access_level
        if ACCESS_LEVEL_ORDER.get(actual_level, 0) < ACCESS_LEVEL_ORDER.get(required_level, 0):
            passed = False

    summary = ScoreSummary(
        total_points=total_points,
        max_points=max_points,
        penalty_points=penalty_points,
        final_score=final_score,
        percentage=percentage,
        passed=passed,
    )

    return EvalResult(
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

    baseline_pct = baseline_dict.get("summary", {}).get("percentage", 0.0)
    current_pct = current_dict.get("summary", {}).get("percentage", 0.0)
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
            f"    {icon} {obj.objective_id} [{obj.category}] "
            f"{obj.points_awarded}/{obj.points_possible}pts — {obj.reason}"
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
    lines.append(f"    Points: {s.total_points}/{s.max_points}")
    if s.penalty_points > 0:
        lines.append(f"    Penalties: -{s.penalty_points}")
    lines.append(f"    Final: {score_color}{s.final_score}/{s.max_points} "
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

    # Score
    result = score_ptt(gt, ptt)
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
        text = _format_summary(result, gt.name)
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
