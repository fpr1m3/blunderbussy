#!/usr/bin/env python3
"""
Evaluation Benchmark Harness
=============================

Scores pipeline artifacts against ground truth vulnerable codebases,
computing precision/recall/F1 plus performance metrics.

Usage:
    python evaluate.py /path/to/artifacts/ /path/to/ground_truth.yaml
    python evaluate.py /path/to/artifacts/ /path/to/ground_truth.yaml --verbose
    python evaluate.py /path/to/artifacts/ /path/to/ground_truth.yaml --json
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

from ground_truth import (
    GroundTruth,
    GroundTruthVuln,
    VulnType,
    VULN_TYPE_ALIASES,
    load_ground_truth,
    normalize_vuln_type,
)


# ---------------------------------------------------------------------------
# ANSI colour helpers (matches validate_artifacts.py style)
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
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class EvalConfig:
    """Configuration for the matching algorithm."""
    line_proximity: int = 5
    require_file_match: bool = True
    require_type_match: bool = True
    include_sanitized_as_fn: bool = False


# ---------------------------------------------------------------------------
# Match result structures
# ---------------------------------------------------------------------------

@dataclass
class FindingMatch:
    """Records the match between a pipeline finding and a ground truth entry."""
    finding_id: str
    ground_truth_id: str
    match_type: str  # "tp", "fp", "fn"
    file_match: bool
    type_match: bool
    line_distance: Optional[int]
    finding_file: Optional[str] = None
    finding_line: Optional[int] = None
    finding_type: Optional[str] = None
    gt_file: Optional[str] = None
    gt_line: Optional[int] = None
    gt_type: Optional[str] = None


@dataclass
class EvalResult:
    """Complete result with metrics."""
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    turns_used: Optional[int] = None
    time_elapsed: Optional[float] = None
    avg_turns: Optional[float] = None
    avg_time: Optional[float] = None
    by_severity: dict[str, dict[str, int]] = field(default_factory=dict)
    by_type: dict[str, dict[str, int]] = field(default_factory=dict)
    matches: list[FindingMatch] = field(default_factory=list)
    unmatched_findings: list[dict] = field(default_factory=list)
    unmatched_gt: list[str] = field(default_factory=list)
    fixture_name: str = ""
    fixture_language: str = ""

    def summary(self, color: bool = True) -> str:
        """Render human-readable summary."""
        if not color:
            Color.disable()

        lines = [
            f"\n{Color.BOLD}{Color.CYAN}{'=' * 60}{Color.RESET}",
            f"{Color.BOLD}  Results: {self.fixture_name}{Color.RESET}",
            f"{Color.BOLD}{Color.CYAN}{'=' * 60}{Color.RESET}",
            "",
        ]

        # Core metrics
        p_color = Color.GREEN if self.precision >= 0.8 else Color.YELLOW if self.precision >= 0.5 else Color.RED
        r_color = Color.GREEN if self.recall >= 0.8 else Color.YELLOW if self.recall >= 0.5 else Color.RED
        f_color = Color.GREEN if self.f1 >= 0.8 else Color.YELLOW if self.f1 >= 0.5 else Color.RED

        lines.append(f"  {Color.BOLD}Metrics:{Color.RESET}")
        lines.append(f"    True Positives:  {self.tp}")
        lines.append(f"    False Positives: {self.fp}")
        lines.append(f"    False Negatives: {self.fn}")
        lines.append(f"    Precision:       {p_color}{self.precision:.3f}{Color.RESET}")
        lines.append(f"    Recall:          {r_color}{self.recall:.3f}{Color.RESET}")
        lines.append(f"    F1 Score:        {f_color}{self.f1:.3f}{Color.RESET}")

        # Performance metrics
        if self.turns_used is not None or self.time_elapsed is not None:
            lines.append(f"\n  {Color.BOLD}Performance:{Color.RESET}")
            if self.turns_used is not None:
                lines.append(f"    Turns Used:      {self.turns_used}")
            if self.time_elapsed is not None:
                lines.append(f"    Time Elapsed:    {self.time_elapsed:.1f}s")
            if self.avg_turns is not None:
                lines.append(f"    Avg Turns/Phase: {self.avg_turns:.1f}")
            if self.avg_time is not None:
                lines.append(f"    Avg Time/Phase:  {self.avg_time:.1f}s")

        # Breakdown by severity
        if self.by_severity:
            lines.append(f"\n  {Color.BOLD}By Severity:{Color.RESET}")
            lines.append(f"    {'Severity':<12} {'TP':>4} {'FP':>4} {'FN':>4}")
            lines.append(f"    {'-' * 12} {'-' * 4} {'-' * 4} {'-' * 4}")
            for sev in ("critical", "high", "medium", "low"):
                if sev in self.by_severity:
                    s = self.by_severity[sev]
                    lines.append(f"    {sev:<12} {s.get('tp', 0):>4} {s.get('fp', 0):>4} {s.get('fn', 0):>4}")

        # Breakdown by type
        if self.by_type:
            lines.append(f"\n  {Color.BOLD}By Type:{Color.RESET}")
            lines.append(f"    {'Type':<25} {'TP':>4} {'FP':>4} {'FN':>4}")
            lines.append(f"    {'-' * 25} {'-' * 4} {'-' * 4} {'-' * 4}")
            for vtype in sorted(self.by_type.keys()):
                t = self.by_type[vtype]
                lines.append(f"    {vtype:<25} {t.get('tp', 0):>4} {t.get('fp', 0):>4} {t.get('fn', 0):>4}")

        # Unmatched details
        if self.unmatched_findings:
            lines.append(f"\n  {Color.RED}False Positives ({len(self.unmatched_findings)}):{Color.RESET}")
            for uf in self.unmatched_findings:
                fid = uf.get("id", uf.get("finding_id", "?"))
                ffile = uf.get("file", "?")
                ftype = uf.get("type", "?")
                lines.append(f"    {Color.DIM}- {fid}: {ftype} in {ffile}{Color.RESET}")

        if self.unmatched_gt:
            lines.append(f"\n  {Color.RED}False Negatives ({len(self.unmatched_gt)}):{Color.RESET}")
            for gt_id in self.unmatched_gt:
                lines.append(f"    {Color.DIM}- {gt_id}{Color.RESET}")

        lines.append("")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "fixture_name": self.fixture_name,
            "fixture_language": self.fixture_language,
            "metrics": {
                "tp": self.tp,
                "fp": self.fp,
                "fn": self.fn,
                "precision": self.precision,
                "recall": self.recall,
                "f1": self.f1,
            },
            "performance": {
                "turns_used": self.turns_used,
                "time_elapsed": self.time_elapsed,
                "avg_turns": self.avg_turns,
                "avg_time": self.avg_time,
            },
            "by_severity": self.by_severity,
            "by_type": self.by_type,
            "matches": [
                {
                    "finding_id": m.finding_id,
                    "ground_truth_id": m.ground_truth_id,
                    "match_type": m.match_type,
                    "file_match": m.file_match,
                    "type_match": m.type_match,
                    "line_distance": m.line_distance,
                }
                for m in self.matches
            ],
            "unmatched_findings": [
                {"id": uf.get("id", uf.get("finding_id", "?")), "type": uf.get("type", "?")}
                for uf in self.unmatched_findings
            ],
            "unmatched_gt": self.unmatched_gt,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_line(value) -> Optional[int]:
    """Parse a line value which may be int, string range '45-48', or None."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    s = str(value).strip()
    if not s:
        return None
    # Handle range: "45-48" -> take first
    if "-" in s:
        parts = s.split("-")
        try:
            return int(parts[0].strip())
        except ValueError:
            return None
    try:
        return int(s)
    except ValueError:
        return None


def _extract_findings(artifact_dir: Path) -> list[dict]:
    """Extract findings from pipeline artifacts.

    Prefers 04-validation-findings.yaml (confirmed only),
    falls back to 03-analysis-findings.yaml.
    """
    artifact_dir = Path(artifact_dir)

    # Try validation artifacts first
    validation_path = artifact_dir / "04-validation-findings.yaml"
    if validation_path.exists():
        with open(validation_path) as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            validated = data.get("validated_findings", [])
            if isinstance(validated, list) and len(validated) > 0:
                # Only include confirmed findings
                confirmed = [f for f in validated if isinstance(f, dict) and f.get("status") == "confirmed"]
                if confirmed:
                    return confirmed

    # Fall back to analysis findings
    analysis_path = artifact_dir / "03-analysis-findings.yaml"
    if analysis_path.exists():
        with open(analysis_path) as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            findings = data.get("findings", [])
            if isinstance(findings, list):
                return findings

    return []


def _extract_finding_location(finding: dict) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """Extract (file, line, type) from a finding dict.

    Handles both analysis findings (location.file, location.line, type)
    and validation findings (finding_id, attack_path).
    """
    # Analysis format: location.file, location.line, type
    location = finding.get("location", {})
    if isinstance(location, dict):
        f = location.get("file")
        line = _parse_line(location.get("line"))
        vtype = finding.get("type")
        return (f, line, vtype)

    # Validation format: may have file/line at top level
    f = finding.get("file")
    line = _parse_line(finding.get("line"))
    vtype = finding.get("type", finding.get("vuln_type"))
    return (f, line, vtype)


def _match_file(f1: Optional[str], f2: Optional[str]) -> bool:
    """Check if two file paths refer to the same file.

    Strips leading './', then tries exact match, then basename + suffix match.
    """
    if f1 is None or f2 is None:
        return False

    # Normalize leading ./
    def strip_prefix(p: str) -> str:
        p = p.strip()
        while p.startswith("./"):
            p = p[2:]
        return p

    n1 = strip_prefix(f1)
    n2 = strip_prefix(f2)

    # Exact match
    if n1 == n2:
        return True

    # Suffix match: one path ends with the other
    if n1.endswith(n2) or n2.endswith(n1):
        return True

    # Basename match (different dirs)
    b1 = Path(n1).name
    b2 = Path(n2).name
    if b1 == b2:
        return True

    return False


def _match_type(f_type: Optional[str], gt_type: Optional[str]) -> bool:
    """Check if a finding type matches a ground truth type.

    Normalizes both through VULN_TYPE_ALIASES, falls back to substring containment.
    """
    if f_type is None or gt_type is None:
        return False

    f_norm = normalize_vuln_type(f_type)
    gt_norm = normalize_vuln_type(gt_type)

    # Both normalized successfully: compare canonical types
    if f_norm is not None and gt_norm is not None:
        return f_norm == gt_norm

    # Fallback: substring containment on lowercased, underscore-normalized strings
    f_lower = f_type.lower().replace("-", "_").replace(" ", "_")
    gt_lower = gt_type.lower().replace("-", "_").replace(" ", "_")
    return f_lower in gt_lower or gt_lower in f_lower


def _match_line(f_line: Optional[int], gt_line: Optional[int],
                gt_end_line: Optional[int] = None,
                proximity: int = 5) -> tuple[bool, Optional[int]]:
    """Check if a finding line matches a ground truth line within proximity.

    Returns (matched, distance). Handles GT ranges via end_line.
    If either line is None, returns (False, None).
    """
    if f_line is None or gt_line is None:
        return (False, None)

    # If GT has a range, check if finding is within [start - proximity, end + proximity]
    end = gt_end_line if gt_end_line is not None else gt_line

    if gt_line <= f_line <= end:
        # Exact: within the range
        return (True, 0)

    # Check proximity to range boundaries
    dist_to_start = abs(f_line - gt_line)
    dist_to_end = abs(f_line - end)
    distance = min(dist_to_start, dist_to_end)

    if distance <= proximity:
        return (True, distance)

    return (False, distance)


def _extract_performance_metrics(artifact_dir: Path) -> tuple[Optional[int], Optional[float]]:
    """Extract performance metrics from state.yaml.

    Returns (turns_used, time_elapsed).
    """
    state_path = Path(artifact_dir) / "state.yaml"
    if not state_path.exists():
        return (None, None)

    try:
        with open(state_path) as fh:
            data = yaml.safe_load(fh)
    except Exception:
        return (None, None)

    if not isinstance(data, dict):
        return (None, None)

    # Sum turns across phases
    turns = None
    phases = data.get("phases", {})
    if isinstance(phases, dict):
        total_turns = 0
        for phase_data in phases.values():
            if isinstance(phase_data, dict):
                t = phase_data.get("turns", 0)
                if isinstance(t, (int, float)):
                    total_turns += int(t)
        if total_turns > 0:
            turns = total_turns

    # Direct turns_used field
    if turns is None:
        t = data.get("turns_used")
        if isinstance(t, (int, float)):
            turns = int(t)

    # Time elapsed
    time_elapsed = None
    te = data.get("time_elapsed")
    if isinstance(te, (int, float)):
        time_elapsed = float(te)

    return (turns, time_elapsed)


# ---------------------------------------------------------------------------
# Core matching algorithm
# ---------------------------------------------------------------------------

def match_findings(findings: list[dict], ground_truth: GroundTruth,
                   config: Optional[EvalConfig] = None) -> tuple[list[FindingMatch], list[dict], list[str]]:
    """Match pipeline findings against ground truth vulnerabilities.

    Uses greedy matching: for each finding, find the best GT match
    (file + type + line all pass, smallest line distance).
    Matched GT vulns are removed from the pool.

    Returns (matches, unmatched_findings, unmatched_gt_ids).
    """
    if config is None:
        config = EvalConfig()

    # Build available pool from exploitable vulns
    available_gt: dict[str, GroundTruthVuln] = {
        v.id: v for v in ground_truth.exploitable_vulns
    }

    matches: list[FindingMatch] = []
    unmatched_findings: list[dict] = []

    for finding in findings:
        f_file, f_line, f_type = _extract_finding_location(finding)
        finding_id = finding.get("id", finding.get("finding_id", f"unknown-{id(finding)}"))

        best_match: Optional[tuple[str, bool, bool, int]] = None  # (gt_id, file_ok, type_ok, dist)
        best_dist = float("inf")

        for gt_id, gt_vuln in available_gt.items():
            file_ok = _match_file(f_file, gt_vuln.file)
            type_ok = _match_type(f_type, gt_vuln.vuln_type)
            line_ok, distance = _match_line(f_line, gt_vuln.line, gt_vuln.end_line, config.line_proximity)

            if distance is None:
                distance = 9999

            # All three must pass for a TP
            if file_ok and type_ok and line_ok:
                if distance < best_dist:
                    best_dist = distance
                    best_match = (gt_id, file_ok, type_ok, distance)

        if best_match is not None:
            gt_id, file_ok, type_ok, dist = best_match
            gt_vuln = available_gt.pop(gt_id)
            matches.append(FindingMatch(
                finding_id=str(finding_id),
                ground_truth_id=gt_id,
                match_type="tp",
                file_match=file_ok,
                type_match=type_ok,
                line_distance=dist,
                finding_file=f_file,
                finding_line=f_line,
                finding_type=f_type,
                gt_file=gt_vuln.file,
                gt_line=gt_vuln.line,
                gt_type=gt_vuln.vuln_type,
            ))
        else:
            unmatched_findings.append(finding)

    unmatched_gt_ids = list(available_gt.keys())

    return (matches, unmatched_findings, unmatched_gt_ids)


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def _compute_metrics(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    """Compute precision, recall, F1 from counts."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return (precision, recall, f1)


def _compute_breakdowns(matches: list[FindingMatch],
                        unmatched_findings: list[dict],
                        unmatched_gt: list[str],
                        ground_truth: GroundTruth) -> tuple[dict, dict]:
    """Compute by_severity and by_type breakdowns."""
    by_severity: dict[str, dict[str, int]] = {}
    by_type: dict[str, dict[str, int]] = {}

    gt_map = {v.id: v for v in ground_truth.vulnerabilities}

    # Count TPs by GT's severity and type
    for m in matches:
        gt_v = gt_map.get(m.ground_truth_id)
        if gt_v:
            sev = gt_v.severity
            by_severity.setdefault(sev, {"tp": 0, "fp": 0, "fn": 0})
            by_severity[sev]["tp"] += 1

            vtype = gt_v.vuln_type
            by_type.setdefault(vtype, {"tp": 0, "fp": 0, "fn": 0})
            by_type[vtype]["tp"] += 1

    # Count FPs: use finding's own type/severity if available
    for uf in unmatched_findings:
        sev = uf.get("severity", "unknown")
        by_severity.setdefault(sev, {"tp": 0, "fp": 0, "fn": 0})
        by_severity[sev]["fp"] += 1

        vtype = uf.get("type", "unknown")
        by_type.setdefault(vtype, {"tp": 0, "fp": 0, "fn": 0})
        by_type[vtype]["fp"] += 1

    # Count FNs by GT's severity and type
    for gt_id in unmatched_gt:
        gt_v = gt_map.get(gt_id)
        if gt_v:
            sev = gt_v.severity
            by_severity.setdefault(sev, {"tp": 0, "fp": 0, "fn": 0})
            by_severity[sev]["fn"] += 1

            vtype = gt_v.vuln_type
            by_type.setdefault(vtype, {"tp": 0, "fp": 0, "fn": 0})
            by_type[vtype]["fn"] += 1

    return (by_severity, by_type)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def evaluate_architecture(artifact_dir: str | Path,
                          ground_truth_path: str | Path,
                          config: Optional[EvalConfig] = None) -> EvalResult:
    """Score pipeline artifacts against ground truth.

    Args:
        artifact_dir: Directory containing pipeline YAML artifacts.
        ground_truth_path: Path to ground_truth.yaml file.
        config: Optional configuration.

    Returns:
        EvalResult with all metrics and match details.
    """
    artifact_dir = Path(artifact_dir)
    gt = load_ground_truth(ground_truth_path)

    if config is None:
        config = EvalConfig()

    # Extract findings from artifacts
    findings = _extract_findings(artifact_dir)

    # Run matching
    matches, unmatched_findings, unmatched_gt = match_findings(findings, gt, config)

    tp = len(matches)
    fp = len(unmatched_findings)
    fn = len(unmatched_gt)

    precision, recall, f1 = _compute_metrics(tp, fp, fn)

    # Performance metrics
    turns_used, time_elapsed = _extract_performance_metrics(artifact_dir)
    num_phases = 4  # recon, triage, analysis, validation
    avg_turns = turns_used / num_phases if turns_used is not None else None
    avg_time = time_elapsed / num_phases if time_elapsed is not None else None

    # Breakdowns
    by_severity, by_type = _compute_breakdowns(matches, unmatched_findings, unmatched_gt, gt)

    return EvalResult(
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        turns_used=turns_used,
        time_elapsed=time_elapsed,
        avg_turns=avg_turns,
        avg_time=avg_time,
        by_severity=by_severity,
        by_type=by_type,
        matches=matches,
        unmatched_findings=unmatched_findings,
        unmatched_gt=unmatched_gt,
        fixture_name=gt.fixture_name,
        fixture_language=gt.language,
    )


def validate_before_scoring(artifact_dir: Path) -> bool:
    """Optional pre-check using existing validate_artifacts.run_validation().

    Returns True if validation passes, False otherwise.
    """
    try:
        from validate_artifacts import run_validation
        results = run_validation(artifact_dir, stages=["analysis"])
        return all(r.ok for r in results)
    except ImportError:
        return True  # Skip if validator not available


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score code-vuln-analysis pipeline artifacts against ground truth.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s artifacts/ ground_truth.yaml
  %(prog)s artifacts/ ground_truth.yaml --verbose
  %(prog)s artifacts/ ground_truth.yaml --json
  %(prog)s artifacts/ ground_truth.yaml --line-proximity 10
        """,
    )
    parser.add_argument("artifact_dir", type=Path,
                        help="Directory containing pipeline artifact files")
    parser.add_argument("ground_truth", type=Path,
                        help="Path to ground truth YAML file")
    parser.add_argument("--line-proximity", type=int, default=5,
                        help="Line proximity tolerance for matching (default: 5)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--verbose", action="store_true",
                        help="Show per-finding match details")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON (for CI)")
    parser.add_argument("--f1-threshold", type=float, default=0.0,
                        help="Minimum F1 for exit code 0 (default: 0.0)")

    args = parser.parse_args(argv)

    if args.no_color:
        Color.disable()

    artifact_dir = args.artifact_dir.resolve()
    if not artifact_dir.is_dir():
        print(f"{Color.RED}ERROR:{Color.RESET} Not a directory: {artifact_dir}", file=sys.stderr)
        return 2

    gt_path = args.ground_truth.resolve()
    if not gt_path.exists():
        print(f"{Color.RED}ERROR:{Color.RESET} Ground truth not found: {gt_path}", file=sys.stderr)
        return 2

    config = EvalConfig(line_proximity=args.line_proximity)
    result = evaluate_architecture(artifact_dir, gt_path, config)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.summary(color=not args.no_color))

        if args.verbose and result.matches:
            print(f"\n{Color.BOLD}  Match Details:{Color.RESET}")
            for m in result.matches:
                print(f"    {Color.GREEN}TP{Color.RESET} {m.finding_id} -> {m.ground_truth_id} "
                      f"(file={m.file_match}, type={m.type_match}, line_dist={m.line_distance})")
            for uf in result.unmatched_findings:
                fid = uf.get("id", uf.get("finding_id", "?"))
                print(f"    {Color.RED}FP{Color.RESET} {fid} (no GT match)")
            for gt_id in result.unmatched_gt:
                print(f"    {Color.RED}FN{Color.RESET} {gt_id} (not detected)")

    if args.f1_threshold > 0 and result.f1 < args.f1_threshold:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
