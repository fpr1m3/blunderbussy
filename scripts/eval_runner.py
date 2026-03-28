#!/usr/bin/env python3
"""
Wave-based evaluation runner for Dame.

Orchestrates multi-target eval runs grouped into waves, aggregates
results across targets, compares against baselines, and outputs
category hit-rate tables for hill-climbing.

Usage:
    uv run scripts/eval_runner.py waves
    uv run scripts/eval_runner.py run wave1 [--timeout 20m] [--baseline] [--dry-run]
    uv run scripts/eval_runner.py run --targets bash-shellshock,flask-ssti
    uv run scripts/eval_runner.py baseline wave1 [--run-dir DIR]
    uv run scripts/eval_runner.py compare wave1
    uv run scripts/eval_runner.py summary <run-dir>
"""

import argparse
import json
import logging
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from eval_harness import (
    PREP_DIR,
    RESULTS_DIR,
    TARGETS_DIR,
    check_dame_image,
    collect_dame_results,
    get_compose_container_name,
    get_container_ip,
    invoke_dame,
    parse_timeout,
    prepare_dame_artifacts,
    score_workspace,
    setup_workspace,
)
from eval_scorer import (
    EvalResult,
    detect_regression,
    load_ground_truth,
    score_ptt,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

EVAL_DIR = Path(__file__).parent.parent / "tests" / "eval"
WAVES_PATH = EVAL_DIR / "waves.yaml"
BASELINES_DIR = RESULTS_DIR / "baselines"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("eval_runner")


def _setup_logging(verbose: bool = False, quiet: bool = False):
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)


# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

class C:
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class WaveDefinition:
    name: str
    targets: list[str]
    pass_criteria: dict = field(default_factory=dict)


@dataclass
class TargetRunResult:
    target: str
    score: int
    percentage: float
    passed: bool
    objectives: list[dict] = field(default_factory=list)
    penalties: list[dict] = field(default_factory=list)
    efficiency: dict = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "score": self.score,
            "percentage": self.percentage,
            "passed": self.passed,
            "objectives": self.objectives,
            "penalties": self.penalties,
            "efficiency": self.efficiency,
            "error": self.error,
        }


@dataclass
class WaveReport:
    wave: str
    wave_name: str
    timestamp: str
    targets_run: int
    targets_passed: int
    per_target: list[dict]
    category_summary: dict
    pass_criteria_results: dict
    regressions: list[dict]
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "wave": self.wave,
            "wave_name": self.wave_name,
            "timestamp": self.timestamp,
            "targets_run": self.targets_run,
            "targets_passed": self.targets_passed,
            "per_target": self.per_target,
            "category_summary": self.category_summary,
            "pass_criteria": self.pass_criteria_results,
            "regressions": self.regressions,
            "recommendation": self.recommendation,
        }


# ---------------------------------------------------------------------------
# Wave loading
# ---------------------------------------------------------------------------

def load_waves(path: Path = WAVES_PATH) -> dict[str, WaveDefinition]:
    """Load wave definitions from waves.yaml."""
    with open(path) as f:
        data = yaml.safe_load(f)

    waves = {}
    for wave_id, wave_data in data.get("waves", {}).items():
        waves[wave_id] = WaveDefinition(
            name=wave_data.get("name", wave_id),
            targets=wave_data.get("targets", []),
            pass_criteria=wave_data.get("pass_criteria", {}),
        )
    return waves


# ---------------------------------------------------------------------------
# Single target run
# ---------------------------------------------------------------------------

def run_target(
    target_name: str,
    output_dir: Path,
    timeout_seconds: int = 1200,
    dry_run: bool = False,
) -> TargetRunResult:
    """Run a single target evaluation and return results.

    In dry-run mode, scores the pre-baked seed PTT without starting
    containers or invoking Dame.
    """
    compose_path = TARGETS_DIR / target_name / "compose.yaml"
    gt_path = TARGETS_DIR / target_name / "ground_truth.yaml"

    # Load ground truth
    try:
        gt = load_ground_truth(str(gt_path))
    except Exception as exc:
        return TargetRunResult(
            target=target_name, score=0, percentage=0.0, passed=False,
            error=f"Failed to load ground truth: {exc}",
        )

    if dry_run:
        # Score the pre-baked seed PTT
        ptt_path = TARGETS_DIR / target_name / "cas" / "ptt.yaml"
        try:
            with open(ptt_path) as f:
                ptt = yaml.safe_load(f)
        except Exception:
            ptt = {"engagement": {"hosts": []}}

        result = score_ptt(gt, ptt)
        result_dict = result.to_dict()
        return TargetRunResult(
            target=target_name,
            score=result.summary.final_score,
            percentage=result.summary.percentage,
            passed=result.summary.passed,
            objectives=result_dict.get("objectives", []),
            penalties=result_dict.get("penalties", []),
            efficiency=result_dict.get("efficiency", {}),
        )

    # --- Live run ---
    # Start container
    try:
        proc = subprocess.run(
            ["podman-compose", "-f", str(compose_path), "up", "-d"],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            return TargetRunResult(
                target=target_name, score=0, percentage=0.0, passed=False,
                error=f"compose up failed: {proc.stderr[:500]}",
            )
    except FileNotFoundError:
        return TargetRunResult(
            target=target_name, score=0, percentage=0.0, passed=False,
            error="podman-compose not found",
        )
    except subprocess.TimeoutExpired:
        return TargetRunResult(
            target=target_name, score=0, percentage=0.0, passed=False,
            error="compose up timed out",
        )

    try:
        # Get container info
        container_name = get_compose_container_name(compose_path)

        # Run setup scripts (install.sh, plant_flags.sh) inside the container
        setup_dir = TARGETS_DIR / target_name / "setup"
        if setup_dir.exists() and container_name:
            # Wait for container to be ready
            time.sleep(3)
            for script in sorted(setup_dir.glob("*.sh")):
                logger.debug("Running setup script: %s", script.name)
                try:
                    subprocess.run(
                        ["podman", "exec", container_name, "sh", "-c",
                         script.read_text()],
                        capture_output=True, text=True, timeout=60,
                    )
                except (subprocess.TimeoutExpired, Exception) as exc:
                    logger.warning("Setup script %s failed: %s", script.name, exc)

        if not container_name:
            return TargetRunResult(
                target=target_name, score=0, percentage=0.0, passed=False,
                error="Could not determine container name from compose.yaml",
            )

        ip_info = get_container_ip(container_name)
        if not ip_info:
            return TargetRunResult(
                target=target_name, score=0, percentage=0.0, passed=False,
                error=f"Could not get IP for container {container_name}",
            )
        target_ip, network = ip_info

        # Setup workspace
        workspace = setup_workspace(target_name, output_dir)

        # Replace EVAL_TARGET_IP placeholder in all workspace YAML files
        for yaml_file in workspace.rglob("*.yaml"):
            content = yaml_file.read_text()
            if "EVAL_TARGET_IP" in content:
                yaml_file.write_text(content.replace("EVAL_TARGET_IP", target_ip))
                logger.debug("Replaced EVAL_TARGET_IP in %s", yaml_file)

        # Prepare Dame artifacts
        prepare_dame_artifacts(workspace, target_ip)

        # Invoke Dame
        dame_ok = invoke_dame(
            target_ip=target_ip,
            workspace=workspace,
            network=network,
            timeout_seconds=timeout_seconds,
        )
        logger.debug("Dame invocation for %s: %s", target_name, "success" if dame_ok else "failed/skipped")

        # Collect results
        collect_dame_results(workspace, target_ip)

        # Score
        result_path = score_workspace(target_name, workspace)

        # Read back the result
        with open(result_path) as f:
            result_data = yaml.safe_load(f)

        score_data = result_data.get("score", {})
        return TargetRunResult(
            target=target_name,
            score=score_data.get("final_score", 0),
            percentage=score_data.get("percentage", 0.0),
            passed=score_data.get("pass", False),
            objectives=result_data.get("objectives", []),
            penalties=result_data.get("penalties", []),
            efficiency=result_data.get("efficiency", {}),
        )

    except Exception as exc:
        logger.error("Error running %s: %s", target_name, exc)
        return TargetRunResult(
            target=target_name, score=0, percentage=0.0, passed=False,
            error=str(exc),
        )
    finally:
        # Always tear down container
        try:
            subprocess.run(
                ["podman-compose", "-f", str(compose_path), "down"],
                capture_output=True, text=True, timeout=60,
            )
        except Exception as exc:
            logger.warning("Cleanup failed for %s: %s", target_name, exc)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate_results(results: list[TargetRunResult]) -> dict:
    """Aggregate per-objective results into category hit-rate table."""
    stats: dict[str, dict] = {}

    for result in results:
        for obj in result.objectives:
            cat = obj.get("category", "unknown")
            if cat not in stats:
                stats[cat] = {"achieved": 0, "total": 0, "targets_hit": [], "targets_missed": []}
            stats[cat]["total"] += 1
            if obj.get("status") == "achieved":
                stats[cat]["achieved"] += 1
                if result.target not in stats[cat]["targets_hit"]:
                    stats[cat]["targets_hit"].append(result.target)
            else:
                if result.target not in stats[cat]["targets_missed"]:
                    stats[cat]["targets_missed"].append(result.target)

    # Compute rates
    for cat_data in stats.values():
        total = cat_data["total"]
        cat_data["rate"] = cat_data["achieved"] / total if total > 0 else 0.0

    return stats


def check_pass_criteria(
    results: list[TargetRunResult],
    category_summary: dict,
    criteria: dict,
) -> dict:
    """Check wave pass criteria and return results."""
    checks = {}

    # avg_score
    if "avg_score" in criteria:
        scores = [r.score for r in results if r.error is None]
        avg = sum(scores) / len(scores) if scores else 0.0
        target = criteria["avg_score"]
        checks["avg_score"] = {
            "target": target,
            "actual": round(avg, 1),
            "met": avg >= target,
        }

    # min_category_rate
    if "min_category_rate" in criteria:
        checks["min_category_rate"] = {}
        for cat, min_rate in criteria["min_category_rate"].items():
            actual = category_summary.get(cat, {}).get("rate", 0.0)
            checks["min_category_rate"][cat] = {
                "target": min_rate,
                "actual": round(actual, 3),
                "met": actual >= min_rate,
            }

    return checks


def generate_recommendation(category_summary: dict) -> str:
    """Generate a recommendation based on lowest-scoring category."""
    if not category_summary:
        return "No results to analyze."

    # Priority order for categories
    priority = [
        "vulnerability_discovery",
        "service_discovery",
        "information_extraction",
        "exploitation",
        "flag_capture",
        "credential_discovery",
        "privilege_escalation",
    ]

    # Find the lowest-rate category that has > 0 total objectives
    worst_cat = None
    worst_rate = 1.1
    for cat in priority:
        data = category_summary.get(cat)
        if data and data["total"] > 0 and data["rate"] < worst_rate:
            worst_rate = data["rate"]
            worst_cat = cat

    if worst_cat is None:
        return "All categories performing well."

    fixes = {
        "vulnerability_discovery": "scanning prompts or scanning-tools skill",
        "service_discovery": "nmap scan scope (ensure full port scan)",
        "information_extraction": "post-discovery data extraction prompts",
        "exploitation": "exploit skills or tool-use reasoning in GEMINI.md",
        "flag_capture": "post-exploitation flag-hunting in GEMINI.md or pentest-checklist skill",
        "credential_discovery": "credential extraction steps in post-exploitation flow",
        "privilege_escalation": "privilege escalation enumeration and exploitation skills",
    }

    fix = fixes.get(worst_cat, "relevant skill or prompt")
    rate_pct = round(worst_rate * 100, 1)
    return f"Lowest category: {worst_cat} ({rate_pct}%). Focus: improve {fix}."


# ---------------------------------------------------------------------------
# Baseline management
# ---------------------------------------------------------------------------

def save_baseline(wave_name: str, run_dir: Path):
    """Copy run results as the baseline for a wave."""
    baseline_dir = BASELINES_DIR / wave_name
    if baseline_dir.exists():
        shutil.rmtree(baseline_dir)
    shutil.copytree(run_dir, baseline_dir)
    logger.info("Saved baseline for %s at %s", wave_name, baseline_dir)


def load_baseline(wave_name: str) -> Optional[dict]:
    """Load baseline wave report for comparison."""
    report_path = BASELINES_DIR / wave_name / "wave_report.yaml"
    if not report_path.exists():
        return None
    with open(report_path) as f:
        return yaml.safe_load(f)


def compare_with_baseline(
    results: list[TargetRunResult],
    baseline: dict,
) -> list[dict]:
    """Compare current results against baseline, return regressions."""
    regressions = []
    baseline_targets = {t["target"]: t for t in baseline.get("per_target", [])}

    for result in results:
        bt = baseline_targets.get(result.target)
        if not bt:
            continue

        current_dict = {
            "objectives": result.objectives,
            "score": {"final_score": result.score, "percentage": result.percentage},
        }
        baseline_dict = {
            "objectives": bt.get("objectives", []),
            "score": {"final_score": bt.get("score", 0), "percentage": bt.get("percentage", 0.0)},
        }

        reg = detect_regression(current_dict, baseline_dict)
        if reg.get("regressed"):
            regressions.append({
                "target": result.target,
                "lost_objectives": reg.get("lost_objectives", []),
                "score_delta": reg.get("score_delta", 0.0),
                "details": reg.get("details", ""),
            })

    return regressions


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def format_summary(report: WaveReport) -> str:
    """Format wave report as human-readable summary."""
    lines = []
    lines.append("")
    lines.append(f"{C.BOLD}Wave: {report.wave} — {report.wave_name}{C.RESET}")
    lines.append(f"Run: {report.timestamp}")
    lines.append(f"Targets: {report.targets_run} run, {report.targets_passed} passed")
    lines.append("")

    # Per-target scores
    lines.append(f"{C.BOLD}Per-Target Results{C.RESET}")
    lines.append(f"{'Target':<40} {'Score':>6} {'Status':>8}")
    lines.append("-" * 56)
    for t in report.per_target:
        score = t.get("score", 0)
        passed = t.get("passed", False)
        error = t.get("error")
        if error:
            status = f"{C.RED}ERROR{C.RESET}"
        elif passed:
            status = f"{C.GREEN}PASS{C.RESET}"
        else:
            status = f"{C.RED}FAIL{C.RESET}"
        lines.append(f"{t['target']:<40} {score:>5}/100 {status}")
    lines.append("")

    # Category summary
    lines.append(f"{C.BOLD}Category Hit Rates{C.RESET}")
    lines.append(f"{'Category':<30} {'Rate':>12} {'Achieved/Total':>15}")
    lines.append("-" * 60)
    for cat, data in sorted(report.category_summary.items()):
        achieved = data.get("achieved", 0)
        total = data.get("total", 0)
        rate = data.get("rate", 0.0)
        rate_pct = f"{rate * 100:.0f}%"
        color = C.GREEN if rate >= 0.7 else (C.YELLOW if rate >= 0.4 else C.RED)
        lines.append(f"{cat:<30} {color}{rate_pct:>12}{C.RESET} {achieved:>7}/{total}")
    lines.append("")

    # Pass criteria
    if report.pass_criteria_results:
        lines.append(f"{C.BOLD}Pass Criteria{C.RESET}")
        for key, check in report.pass_criteria_results.items():
            if key == "min_category_rate":
                for cat, cat_check in check.items():
                    met = f"{C.GREEN}MET{C.RESET}" if cat_check["met"] else f"{C.RED}NOT MET{C.RESET}"
                    lines.append(f"  {cat} rate >= {cat_check['target']}: {cat_check['actual']} {met}")
            else:
                met = f"{C.GREEN}MET{C.RESET}" if check["met"] else f"{C.RED}NOT MET{C.RESET}"
                lines.append(f"  {key} >= {check['target']}: {check['actual']} {met}")
        lines.append("")

    # Regressions
    if report.regressions:
        lines.append(f"{C.RED}{C.BOLD}REGRESSIONS DETECTED{C.RESET}")
        for reg in report.regressions:
            lines.append(f"  {reg['target']}: lost {reg['lost_objectives']} (delta: {reg['score_delta']:+.1f})")
        lines.append("")

    # Recommendation
    lines.append(f"{C.CYAN}Recommendation:{C.RESET} {report.recommendation}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI: waves
# ---------------------------------------------------------------------------

def cmd_waves(args) -> int:
    """List defined waves and their targets."""
    waves = load_waves()
    print(f"\n{C.BOLD}Defined Waves{C.RESET}\n")
    for wave_id, wave_def in waves.items():
        # Check baseline
        has_baseline = (BASELINES_DIR / wave_id / "wave_report.yaml").exists()
        baseline_tag = f" {C.DIM}[has baseline]{C.RESET}" if has_baseline else ""
        print(f"  {C.BOLD}{wave_id}{C.RESET}: {wave_def.name}{baseline_tag}")
        print(f"    Targets ({len(wave_def.targets)}):")
        for t in wave_def.targets:
            print(f"      - {t}")
        if wave_def.pass_criteria:
            print(f"    Pass criteria: {wave_def.pass_criteria}")
        print()
    return 0


# ---------------------------------------------------------------------------
# CLI: run
# ---------------------------------------------------------------------------

def cmd_run(args) -> int:
    """Run a wave of targets."""
    timeout_seconds = parse_timeout(args.timeout) if args.timeout else 1200
    dry_run = args.dry_run

    # Resolve target list
    if args.targets:
        target_list = [t.strip() for t in args.targets.split(",")]
        wave_id = "adhoc"
        wave_name = f"Ad-hoc ({len(target_list)} targets)"
        pass_criteria = {}
    elif args.wave:
        waves = load_waves()
        if args.wave not in waves:
            logger.error("Unknown wave: %s (available: %s)", args.wave, ", ".join(waves.keys()))
            return 3
        wave_def = waves[args.wave]
        target_list = wave_def.targets
        wave_id = args.wave
        wave_name = wave_def.name
        pass_criteria = wave_def.pass_criteria
    else:
        logger.error("Specify a wave name or --targets")
        return 3

    # Validate targets exist
    for t in target_list:
        if not (TARGETS_DIR / t).is_dir():
            logger.error("Target not found: %s", t)
            return 3

    # Pre-flight checks (skip for dry-run)
    if not dry_run:
        if not shutil.which("podman-compose"):
            logger.error("podman-compose not found in PATH")
            return 3
        if not check_dame_image():
            logger.warning("Dame image not found — containers will start but Dame won't run")

    # Create output dir
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = RESULTS_DIR / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    mode = "DRY-RUN" if dry_run else "LIVE"
    logger.info("\n%s%sRunning %s: %s (%d targets) [%s]%s\n",
                C.BOLD, C.CYAN, wave_id, wave_name, len(target_list), mode, C.RESET)

    # Run each target
    results: list[TargetRunResult] = []
    for i, target_name in enumerate(target_list, 1):
        logger.info("  [%d/%d] %s ...", i, len(target_list), target_name)
        result = run_target(target_name, output_dir, timeout_seconds, dry_run=dry_run)
        results.append(result)

        # Inline status
        if result.error:
            logger.info("         %s%sERROR: %s%s", C.RED, C.BOLD, result.error[:80], C.RESET)
        elif result.passed:
            logger.info("         %s%d/100 PASS%s", C.GREEN, result.score, C.RESET)
        else:
            logger.info("         %s%d/100 FAIL%s", C.RED, result.score, C.RESET)

    # Aggregate
    category_summary = aggregate_results(results)
    criteria_results = check_pass_criteria(results, category_summary, pass_criteria)

    # Baseline comparison
    regressions = []
    if args.baseline:
        baseline = load_baseline(wave_id)
        if baseline:
            regressions = compare_with_baseline(results, baseline)
        else:
            logger.warning("No baseline found for %s — skipping regression check", wave_id)

    # Build report
    recommendation = generate_recommendation(category_summary)
    report = WaveReport(
        wave=wave_id,
        wave_name=wave_name,
        timestamp=timestamp,
        targets_run=len(results),
        targets_passed=sum(1 for r in results if r.passed),
        per_target=[r.to_dict() for r in results],
        category_summary={
            cat: {"achieved": d["achieved"], "total": d["total"], "rate": round(d["rate"], 3)}
            for cat, d in category_summary.items()
        },
        pass_criteria_results=criteria_results,
        regressions=regressions,
        recommendation=recommendation,
    )

    # Write report
    report_path = output_dir / "wave_report.yaml"
    with open(report_path, "w") as f:
        yaml.dump(report.to_dict(), f, default_flow_style=False, sort_keys=False)

    # Print summary
    print(format_summary(report))
    logger.info("Results saved to: %s", output_dir)

    # Determine exit code
    if regressions:
        return 2
    all_criteria_met = all(
        check.get("met", True) if not isinstance(check, dict)
        else all(v.get("met", True) for v in check.values()) if all(isinstance(v, dict) for v in check.values())
        else check.get("met", True)
        for check in criteria_results.values()
    )
    return 0 if all_criteria_met else 1


# ---------------------------------------------------------------------------
# CLI: baseline
# ---------------------------------------------------------------------------

def cmd_baseline(args) -> int:
    """Save latest run as baseline for a wave."""
    wave_name = args.wave

    if args.run_dir:
        run_dir = Path(args.run_dir)
    else:
        # Find latest run that has a wave_report.yaml
        if not RESULTS_DIR.exists():
            logger.error("No results directory found")
            return 1
        runs = sorted(
            [d for d in RESULTS_DIR.iterdir() if d.is_dir() and d.name != "baselines"],
            reverse=True,
        )
        run_dir = None
        for d in runs:
            if (d / "wave_report.yaml").exists():
                with open(d / "wave_report.yaml") as f:
                    report = yaml.safe_load(f)
                if report.get("wave") == wave_name:
                    run_dir = d
                    break
        if run_dir is None:
            logger.error("No run found for wave %s", wave_name)
            return 1

    if not (run_dir / "wave_report.yaml").exists():
        logger.error("No wave_report.yaml in %s", run_dir)
        return 1

    save_baseline(wave_name, run_dir)
    return 0


# ---------------------------------------------------------------------------
# CLI: compare
# ---------------------------------------------------------------------------

def cmd_compare(args) -> int:
    """Compare latest run against baseline for a wave."""
    wave_name = args.wave
    baseline = load_baseline(wave_name)
    if not baseline:
        logger.error("No baseline found for wave %s", wave_name)
        return 1

    # Find latest run for this wave
    if not RESULTS_DIR.exists():
        logger.error("No results directory found")
        return 1
    runs = sorted(
        [d for d in RESULTS_DIR.iterdir() if d.is_dir() and d.name != "baselines"],
        reverse=True,
    )
    current_report = None
    for d in runs:
        report_path = d / "wave_report.yaml"
        if report_path.exists():
            with open(report_path) as f:
                report = yaml.safe_load(f)
            if report.get("wave") == wave_name:
                current_report = report
                break

    if current_report is None:
        logger.error("No recent run found for wave %s", wave_name)
        return 1

    # Build TargetRunResults from current report
    results = []
    for t in current_report.get("per_target", []):
        results.append(TargetRunResult(
            target=t["target"],
            score=t.get("score", 0),
            percentage=t.get("percentage", 0.0),
            passed=t.get("passed", False),
            objectives=t.get("objectives", []),
        ))

    regressions = compare_with_baseline(results, baseline)

    if regressions:
        print(f"\n{C.RED}{C.BOLD}REGRESSIONS DETECTED{C.RESET}\n")
        for reg in regressions:
            print(f"  {reg['target']}: lost {reg['lost_objectives']} (delta: {reg['score_delta']:+.1f})")
        print()
        return 2
    else:
        print(f"\n{C.GREEN}No regressions detected.{C.RESET}\n")

        # Show improvement
        baseline_avg = 0.0
        current_avg = 0.0
        bt = {t["target"]: t for t in baseline.get("per_target", [])}
        for r in results:
            current_avg += r.score
            if r.target in bt:
                baseline_avg += bt[r.target].get("score", 0)
        n = len(results) or 1
        baseline_avg /= n
        current_avg /= n
        delta = current_avg - baseline_avg
        color = C.GREEN if delta > 0 else (C.YELLOW if delta == 0 else C.RED)
        print(f"  Average score: {baseline_avg:.1f} → {current_avg:.1f} ({color}{delta:+.1f}{C.RESET})")
        print()
        return 0


# ---------------------------------------------------------------------------
# CLI: summary
# ---------------------------------------------------------------------------

def cmd_summary(args) -> int:
    """Generate category summary from an existing run directory."""
    run_dir = Path(args.run_dir)
    report_path = run_dir / "wave_report.yaml"

    if report_path.exists():
        with open(report_path) as f:
            data = yaml.safe_load(f)
        report = WaveReport(
            wave=data.get("wave", "unknown"),
            wave_name=data.get("wave_name", "Unknown"),
            timestamp=data.get("timestamp", ""),
            targets_run=data.get("targets_run", 0),
            targets_passed=data.get("targets_passed", 0),
            per_target=data.get("per_target", []),
            category_summary=data.get("category_summary", {}),
            pass_criteria_results=data.get("pass_criteria", {}),
            regressions=data.get("regressions", []),
            recommendation=data.get("recommendation", ""),
        )
        print(format_summary(report))
        return 0

    # No wave report — scan for individual result.yaml files
    result_files = list(run_dir.glob("*-result.yaml"))
    if not result_files:
        logger.error("No wave_report.yaml or *-result.yaml files in %s", run_dir)
        return 1

    results = []
    for rf in result_files:
        with open(rf) as f:
            data = yaml.safe_load(f)
        target = data.get("target", rf.stem.replace("-result", ""))
        score = data.get("score", {})
        results.append(TargetRunResult(
            target=target,
            score=score.get("final_score", 0),
            percentage=score.get("percentage", 0.0),
            passed=score.get("pass", False),
            objectives=data.get("objectives", []),
        ))

    category_summary = aggregate_results(results)
    recommendation = generate_recommendation(category_summary)

    print(f"\n{C.BOLD}Summary for {run_dir}{C.RESET}\n")
    print(f"{'Target':<40} {'Score':>6}")
    print("-" * 48)
    for r in sorted(results, key=lambda x: x.target):
        color = C.GREEN if r.passed else C.RED
        print(f"{r.target:<40} {color}{r.score:>5}/100{C.RESET}")

    print(f"\n{C.BOLD}Category Hit Rates{C.RESET}")
    print(f"{'Category':<30} {'Rate':>12}")
    print("-" * 44)
    for cat, data in sorted(category_summary.items()):
        rate_pct = f"{data['rate'] * 100:.0f}%"
        print(f"{cat:<30} {rate_pct:>12}  ({data['achieved']}/{data['total']})")

    print(f"\n{C.CYAN}Recommendation:{C.RESET} {recommendation}\n")
    return 0


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Wave-based evaluation runner for Dame",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")

    sub = parser.add_subparsers(dest="command")

    # waves
    sub.add_parser("waves", help="List defined waves")

    # run
    p_run = sub.add_parser("run", help="Run a wave of targets")
    p_run.add_argument("wave", nargs="?", help="Wave name (e.g., wave1)")
    p_run.add_argument("--targets", help="Comma-separated target names (ad-hoc wave)")
    p_run.add_argument("--timeout", default="20m", help="Per-target timeout (default: 20m)")
    p_run.add_argument("--baseline", action="store_true", help="Compare against stored baseline")
    p_run.add_argument("--dry-run", action="store_true", help="Score pre-baked PTTs without containers")
    p_run.add_argument("--json", action="store_true", help="Output JSON report")

    # baseline
    p_base = sub.add_parser("baseline", help="Save run as baseline")
    p_base.add_argument("wave", help="Wave name")
    p_base.add_argument("--run-dir", help="Specific run directory (default: latest)")

    # compare
    p_cmp = sub.add_parser("compare", help="Compare latest run against baseline")
    p_cmp.add_argument("wave", help="Wave name")

    # summary
    p_sum = sub.add_parser("summary", help="Show summary of existing run")
    p_sum.add_argument("run_dir", help="Path to run directory")

    args = parser.parse_args()
    _setup_logging(verbose=args.verbose, quiet=args.quiet)

    if args.command is None:
        parser.print_help()
        return 1

    handlers = {
        "waves": cmd_waves,
        "run": cmd_run,
        "baseline": cmd_baseline,
        "compare": cmd_compare,
        "summary": cmd_summary,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
