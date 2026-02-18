#!/usr/bin/env python3
"""
Dame Evaluation Harness
========================

CLI to browse, verify, run, and review Dame evaluation targets.

Subcommands:
    list     Browse registered eval targets
    search   Search VulHub catalog for new targets
    verify   Sanity-check a target's setup files
    run      Execute an evaluation run
    results  View past run results

Usage:
    python eval_harness.py list [--difficulty DIFF] [--tag TAG] [--target NAME] [--verbose]
    python eval_harness.py search QUERY [--cve CVE] [--category CAT]
    python eval_harness.py verify --target NAME
    python eval_harness.py run --target NAME [--timeout 20m] [--json] [--output DIR]
    python eval_harness.py results [--run TIMESTAMP] [--verbose]
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: uv pip install pyyaml", file=sys.stderr)
    sys.exit(2)

# Import scorer utilities — available because pyproject.toml adds scripts/ to pythonpath
from eval_scorer import (
    ValidationError,
    load_ground_truth,
    score_ptt,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path Constants
# ---------------------------------------------------------------------------

EVAL_DIR = Path(__file__).parent.parent / "tests" / "eval"
TARGETS_DIR = EVAL_DIR / "targets"
REGISTRY_PATH = EVAL_DIR / "registry.yaml"
CATALOG_PATH = EVAL_DIR / "vulnhub_catalog.yaml"
RESULTS_DIR = EVAL_DIR / "results"

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
# Registry / Catalog loaders
# ---------------------------------------------------------------------------

def load_registry() -> list[dict]:
    """Load the eval registry YAML and return the targets list."""
    if not REGISTRY_PATH.exists():
        logger.warning("Registry not found: %s", REGISTRY_PATH)
        return []
    with open(REGISTRY_PATH) as fh:
        data = yaml.safe_load(fh)
    return data.get("targets", [])


def load_catalog() -> list[dict]:
    """Load the VulHub catalog YAML and return the catalog list."""
    if not CATALOG_PATH.exists():
        logger.warning("Catalog not found: %s", CATALOG_PATH)
        return []
    with open(CATALOG_PATH) as fh:
        data = yaml.safe_load(fh)
    return data.get("catalog", [])


# ---------------------------------------------------------------------------
# Timeout parsing
# ---------------------------------------------------------------------------

def parse_timeout(value: str) -> int:
    """Parse a timeout string like '20m' or '2h' into seconds."""
    m = re.match(r"^(\d+)\s*([mhsMHS]?)$", value.strip())
    if not m:
        raise ValueError(f"Invalid timeout format: '{value}' (use e.g. 20m, 2h, 300s, or plain seconds)")
    num = int(m.group(1))
    suffix = m.group(2).lower()
    if suffix == "m":
        return num * 60
    elif suffix == "h":
        return num * 3600
    elif suffix == "s" or suffix == "":
        return num
    return num


# ---------------------------------------------------------------------------
# Subcommand: list
# ---------------------------------------------------------------------------

def cmd_list(args) -> int:
    """Browse registered eval targets."""
    targets = load_registry()
    if not targets:
        print("No targets registered in registry.")
        return 0

    # Filter by difficulty
    if args.difficulty:
        targets = [t for t in targets if t.get("difficulty") == args.difficulty]

    # Filter by tag
    if args.tag:
        targets = [t for t in targets if args.tag in t.get("tags", [])]

    # Single target detail view
    if args.target:
        match = [t for t in targets if t.get("name") == args.target]
        if not match:
            # Search in unfiltered registry too
            all_targets = load_registry()
            match = [t for t in all_targets if t.get("name") == args.target]
        if not match:
            print(f"Target '{args.target}' not found in registry.", file=sys.stderr)
            return 1
        t = match[0]
        print(f"Name:         {t['name']}")
        print(f"Difficulty:   {t.get('difficulty', 'unknown')}")
        print(f"Surface:      {', '.join(t.get('attack_surface', []))}")
        print(f"Primary CVE:  {t.get('primary_cve', 'N/A')}")
        print(f"Image:        {t.get('image', 'N/A')}")
        print(f"Tags:         {', '.join(t.get('tags', []))}")

        if args.verbose:
            # Load ground truth if available
            gt_path = TARGETS_DIR / t["name"] / "ground_truth.yaml"
            if gt_path.exists():
                try:
                    gt = load_ground_truth(gt_path)
                    print(f"\nObjectives ({len(gt.objectives)}):")
                    total_points = 0
                    for obj in gt.objectives:
                        total_points += obj.points
                        dep = f" (depends: {obj.depends_on})" if obj.depends_on else ""
                        print(f"  - {obj.id}: {obj.description} [{obj.points}pts, {obj.difficulty}]{dep}")
                    print(f"\nTotal points: {total_points}")
                    if gt.penalties:
                        total_penalty = sum(p.points for p in gt.penalties)
                        print(f"Penalties ({len(gt.penalties)}):")
                        for pen in gt.penalties:
                            print(f"  - {pen.id}: {pen.description} [-{pen.points}pts]")
                        print(f"Max penalty: -{total_penalty}")
                except (ValidationError, Exception) as exc:
                    print(f"\nGround truth error: {exc}", file=sys.stderr)
            else:
                print(f"\nGround truth not found: {gt_path}")
        return 0

    # Table view
    if not targets:
        print("No targets match the given filters.")
        return 0

    # Header
    fmt = "{:<40} {:<8} {:<12} {:<20}"
    print(fmt.format("NAME", "DIFF", "SURFACE", "PRIMARY CVE"))
    print("-" * 82)
    for t in targets:
        surface = ",".join(t.get("attack_surface", []))
        print(fmt.format(
            t.get("name", "?"),
            t.get("difficulty", "?"),
            surface,
            t.get("primary_cve", "N/A"),
        ))

    return 0


# ---------------------------------------------------------------------------
# Subcommand: search
# ---------------------------------------------------------------------------

def cmd_search(args) -> int:
    """Search VulHub catalog for targets."""
    catalog = load_catalog()
    if not catalog:
        print("Catalog is empty or not found.")
        return 0

    registered_images = {t.get("image") for t in load_registry()}

    results = catalog

    # Filter by CVE
    if args.cve:
        results = [c for c in results if args.cve in c.get("cves", [])]

    # Filter by category
    if args.category:
        results = [c for c in results if c.get("category", "").lower() == args.category.lower()]

    # Keyword search across image/category/cves/notes
    if args.query:
        query = args.query.lower()
        filtered = []
        for c in results:
            searchable = " ".join([
                c.get("image", ""),
                c.get("category", ""),
                " ".join(c.get("cves", [])),
                c.get("notes", ""),
            ]).lower()
            if query in searchable:
                filtered.append(c)
        results = filtered

    if not results:
        print("No catalog entries match.")
        return 0

    for c in results:
        registered = c.get("image") in registered_images
        status = f"{Color.GREEN}[registered]{Color.RESET}" if registered else f"{Color.DIM}[available]{Color.RESET}"
        print(f"  {status} {c.get('image', '?')}")
        print(f"    CVEs:       {', '.join(c.get('cves', []))}")
        print(f"    Category:   {c.get('category', '?')}")
        print(f"    Difficulty:  {c.get('difficulty_estimate', '?')}")
        print(f"    Notes:      {c.get('notes', '')}")
        print()

    return 0


# ---------------------------------------------------------------------------
# Subcommand: verify
# ---------------------------------------------------------------------------

def cmd_verify(args) -> int:
    """Verify a target's setup files."""
    target_name = args.target
    target_dir = TARGETS_DIR / target_name

    checks = []
    all_ok = True

    def check(label: str, ok: bool, detail: str = ""):
        nonlocal all_ok
        icon = f"{Color.GREEN}\u2713{Color.RESET}" if ok else f"{Color.RED}\u2717{Color.RESET}"
        msg = f"  {icon} {label}"
        if detail:
            msg += f" — {detail}"
        checks.append(msg)
        if not ok:
            all_ok = False

    # Check target directory exists
    if not target_dir.exists():
        check("target directory", False, f"{target_dir} not found")
        for msg in checks:
            print(msg)
        return 1

    # ground_truth.yaml
    gt_path = target_dir / "ground_truth.yaml"
    if gt_path.exists():
        try:
            gt = load_ground_truth(gt_path)
            check("ground_truth.yaml", True, f"{len(gt.objectives)} objectives, {gt.difficulty}")
        except ValidationError as exc:
            check("ground_truth.yaml", False, f"validation error: {exc}")
        except Exception as exc:
            check("ground_truth.yaml", False, f"parse error: {exc}")
    else:
        check("ground_truth.yaml", False, "not found")

    # compose.yaml
    compose_path = target_dir / "compose.yaml"
    if compose_path.exists():
        try:
            with open(compose_path) as fh:
                compose_data = yaml.safe_load(fh)
            if compose_data:
                check("compose.yaml", True, "parses OK")
            else:
                check("compose.yaml", False, "empty file")
        except Exception as exc:
            check("compose.yaml", False, f"parse error: {exc}")
    else:
        check("compose.yaml", False, "not found")

    # CAS context.yaml
    cas_context = target_dir / "cas" / "context.yaml"
    if cas_context.exists():
        try:
            with open(cas_context) as fh:
                cas_data = yaml.safe_load(fh)
            if cas_data:
                check("cas/context.yaml", True, "parses OK")
            else:
                check("cas/context.yaml", False, "empty file")
        except Exception as exc:
            check("cas/context.yaml", False, f"parse error: {exc}")
    else:
        check("cas/context.yaml", False, "not found")

    # CAS ptt.yaml (PTT template)
    ptt_path = target_dir / "cas" / "ptt.yaml"
    if ptt_path.exists():
        try:
            with open(ptt_path) as fh:
                ptt_data = yaml.safe_load(fh)
            if ptt_data:
                check("cas/ptt.yaml", True, "parses OK")
            else:
                check("cas/ptt.yaml", False, "empty file")
        except Exception as exc:
            check("cas/ptt.yaml", False, f"parse error: {exc}")
    else:
        check("cas/ptt.yaml", False, "not found")

    # plant_flags.sh
    flags_path = target_dir / "setup" / "plant_flags.sh"
    if flags_path.exists():
        is_exec = os.access(flags_path, os.X_OK)
        if is_exec:
            check("setup/plant_flags.sh", True, "exists and executable")
        else:
            check("setup/plant_flags.sh", False, "exists but not executable")
    else:
        check("setup/plant_flags.sh", False, "not found")

    # Print results
    print(f"Verifying target: {target_name}")
    for msg in checks:
        print(msg)

    if all_ok:
        print(f"\n{Color.GREEN}All checks passed.{Color.RESET}")
    else:
        print(f"\n{Color.RED}Some checks failed.{Color.RESET}")

    return 0 if all_ok else 1


# ---------------------------------------------------------------------------
# Subcommand: run — workspace helpers (exported for tests)
# ---------------------------------------------------------------------------

def setup_workspace(target_name: str, base_dir: Path) -> Path:
    """Set up an evaluation workspace for the given target.

    Copies CAS context and PTT template into a temporary workspace directory.

    Args:
        target_name: Name of the target from the registry.
        base_dir: Base directory to create the workspace in.

    Returns:
        Path to the workspace directory.
    """
    target_dir = TARGETS_DIR / target_name
    workspace = base_dir / f"eval-{target_name}"
    workspace.mkdir(parents=True, exist_ok=True)

    # Copy CAS files
    cas_src = target_dir / "cas"
    cas_dst = workspace / "cas"
    if cas_src.exists():
        if cas_dst.exists():
            shutil.rmtree(cas_dst)
        shutil.copytree(cas_src, cas_dst)
        logger.debug("Copied CAS files to %s", cas_dst)

    # Copy PTT template as the workspace PTT (Dame will modify this)
    ptt_src = cas_dst / "ptt.yaml" if cas_dst.exists() else target_dir / "cas" / "ptt.yaml"
    ptt_dst = workspace / "ptt.yaml"
    if ptt_src.exists():
        shutil.copy2(ptt_src, ptt_dst)
        logger.debug("Copied PTT template to %s", ptt_dst)

    return workspace


def score_workspace(target_name: str, workspace: Path) -> Path:
    """Score a workspace's PTT against the target's ground truth.

    Args:
        target_name: Name of the target from the registry.
        workspace: Path to the evaluation workspace.

    Returns:
        Path to the result YAML file.
    """
    gt_path = TARGETS_DIR / target_name / "ground_truth.yaml"
    ptt_path = workspace / "ptt.yaml"

    gt = load_ground_truth(gt_path)

    with open(ptt_path) as fh:
        ptt = yaml.safe_load(fh) or {}

    result = score_ptt(gt, ptt)
    result_dict = result.to_dict()

    # target is already in result_dict from to_dict(); add timestamp metadata
    result_dict["meta"] = {
        "timestamp": datetime.now().isoformat(),
        "workspace": str(workspace),
    }

    result_path = workspace / "result.yaml"
    with open(result_path, "w") as fh:
        yaml.dump(result_dict, fh, default_flow_style=False)

    return result_path


def cmd_run(args) -> int:
    """Execute an evaluation run."""
    targets = load_registry()
    if not targets:
        print("No targets registered.", file=sys.stderr)
        return 1

    if args.all:
        run_targets = targets
    elif args.target:
        run_targets = [t for t in targets if t.get("name") == args.target]
        if not run_targets:
            print(f"Target '{args.target}' not found in registry.", file=sys.stderr)
            return 1
    else:
        print("Specify --target NAME or --all.", file=sys.stderr)
        return 2

    _timeout_seconds = parse_timeout(args.timeout) if args.timeout else 1200  # Used when Dame invocation is implemented

    # Output / archive directory
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(args.output) if args.output else RESULTS_DIR / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = []

    for target in run_targets:
        target_name = target["name"]
        print(f"\n{'=' * 60}")
        print(f"  Eval: {target_name}")
        print(f"{'=' * 60}")

        # Phase 1: Setup workspace
        print("  [1/6] Setting up workspace...")
        workspace = setup_workspace(target_name, output_dir)

        # Phase 2: Start container
        compose_path = TARGETS_DIR / target_name / "compose.yaml"
        container_started = False
        if compose_path.exists():
            print("  [2/6] Starting container via podman-compose...")
            try:
                proc = subprocess.run(
                    ["podman-compose", "-f", str(compose_path), "up", "-d"],
                    capture_output=True, text=True, timeout=120,
                )
                if proc.returncode == 0:
                    container_started = True
                    print("         Container started.")
                else:
                    print(f"         WARNING: podman-compose failed: {proc.stderr.strip()}")
            except FileNotFoundError:
                print("         WARNING: podman-compose not found, skipping container start.")
            except subprocess.TimeoutExpired:
                print("         WARNING: podman-compose timed out.")
        else:
            print("  [2/6] No compose.yaml found, skipping container start.")

        # Phase 3: Dame invocation (placeholder)
        print("  [3/6] Dame invocation: SKIPPED (placeholder — not yet implemented)")
        print(f"         WARNING: Dame agent not invoked. PTT will contain template data only.")

        # Phase 4: Score workspace
        print("  [4/6] Scoring workspace...")
        gt_path = TARGETS_DIR / target_name / "ground_truth.yaml"
        ptt_path = workspace / "ptt.yaml"
        if gt_path.exists() and ptt_path.exists():
            try:
                result_path = score_workspace(target_name, workspace)
                print(f"         Result: {result_path}")
                with open(result_path) as fh:
                    result_data = yaml.safe_load(fh)
                all_results.append(result_data)
            except Exception as exc:
                print(f"         ERROR: Scoring failed: {exc}")
                all_results.append({"error": str(exc), "target": target_name})
        else:
            print("         WARNING: Ground truth or PTT missing, cannot score.")
            all_results.append({"error": "missing files", "target": target_name})

        # Phase 5: Archive results
        print("  [5/6] Archiving results...")
        archive_path = output_dir / f"{target_name}-result.yaml"
        if all_results and "error" not in all_results[-1]:
            with open(archive_path, "w") as fh:
                yaml.dump(all_results[-1], fh, default_flow_style=False)
            print(f"         Archived: {archive_path}")
        else:
            print("         Nothing to archive.")

        # Phase 6: Cleanup container
        if container_started:
            print("  [6/6] Cleaning up container...")
            try:
                subprocess.run(
                    ["podman-compose", "-f", str(compose_path), "down"],
                    capture_output=True, text=True, timeout=60,
                )
                print("         Container stopped.")
            except Exception:
                print("         WARNING: Container cleanup failed.")
        else:
            print("  [6/6] No container to clean up.")

    # JSON output
    if args.json:
        print(json.dumps(all_results, indent=2, default=str))

    return 0


# ---------------------------------------------------------------------------
# Subcommand: results
# ---------------------------------------------------------------------------

def cmd_results(args) -> int:
    """View past evaluation run results."""
    if not RESULTS_DIR.exists():
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # List run directories (timestamps)
    runs = sorted([d for d in RESULTS_DIR.iterdir() if d.is_dir()], reverse=True)

    if args.run:
        runs = [r for r in runs if args.run in r.name]

    if not runs:
        print("No evaluation runs found.")
        return 0

    # Limit to last 10 unless filtered
    if not args.run:
        runs = runs[:10]

    for run_dir in runs:
        result_files = list(run_dir.glob("*-result.yaml"))
        print(f"\n  Run: {run_dir.name} ({len(result_files)} target(s))")

        for rf in sorted(result_files):
            try:
                with open(rf) as fh:
                    data = yaml.safe_load(fh)
                target = data.get("target", rf.stem)
                score_data = data.get("score", {})
                pct = score_data.get("percentage", 0.0)
                passed = score_data.get("pass", False)
                status = f"{Color.GREEN}PASS{Color.RESET}" if passed else f"{Color.RED}FAIL{Color.RESET}"
                print(f"    {target}: {pct:.1f}% {status}")

                if args.verbose:
                    for obj in data.get("objectives", []):
                        obj_status = obj.get("status", "?")
                        if obj_status == "achieved":
                            icon = f"{Color.GREEN}\u2713{Color.RESET}"
                        elif obj_status == "skipped":
                            icon = f"{Color.YELLOW}\u2298{Color.RESET}"
                        else:
                            icon = f"{Color.RED}\u2717{Color.RESET}"
                        print(f"      {icon} {obj.get('id', '?')}: {obj_status} "
                              f"({obj.get('points', 0)}/{obj.get('points_possible', 0)}pts)")
            except Exception as exc:
                print(f"    {rf.name}: ERROR reading — {exc}")

    return 0


# ---------------------------------------------------------------------------
# Subcommand: add (stub)
# ---------------------------------------------------------------------------

def cmd_add(args) -> int:
    """Scaffold a new target package (stub)."""
    print("add: not yet implemented — scaffold target manually", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Dame evaluation harness — manage and run eval targets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose/debug output")

    subparsers = parser.add_subparsers(dest="command")

    # list
    list_parser = subparsers.add_parser("list", help="Browse registered eval targets")
    list_parser.add_argument("--difficulty", choices=["easy", "medium", "hard"],
                             help="Filter by difficulty")
    list_parser.add_argument("--tag", help="Filter by tag")
    list_parser.add_argument("--target", help="Show details for a specific target")
    list_parser.add_argument("--verbose", action="store_true",
                             help="Show ground truth details with --target")

    # search
    search_parser = subparsers.add_parser("search", help="Search VulHub catalog")
    search_parser.add_argument("query", nargs="?", default="",
                               help="Keyword to search for")
    search_parser.add_argument("--cve", help="Filter by exact CVE")
    search_parser.add_argument("--category", help="Filter by category")

    # verify
    verify_parser = subparsers.add_parser("verify", help="Sanity-check target setup")
    verify_parser.add_argument("--target", required=True, help="Target name to verify")

    # run
    run_parser = subparsers.add_parser("run", help="Execute evaluation run")
    run_parser.add_argument("--target", help="Target name to run")
    run_parser.add_argument("--all", action="store_true", help="Run all targets")
    run_parser.add_argument("--timeout", default="20m",
                            help="Timeout per target (e.g. 20m, 2h)")
    run_parser.add_argument("--json", action="store_true", help="JSON output")
    run_parser.add_argument("--output", help="Output/archive directory")

    # add
    add_parser = subparsers.add_parser("add", help="Scaffold a new target package")
    add_parser.add_argument("image", help="Container image for the target")
    add_parser.add_argument("--name", required=True, help="Target name")

    # results
    results_parser = subparsers.add_parser("results", help="View past run results")
    results_parser.add_argument("--run", help="Filter by run timestamp")
    results_parser.add_argument("--verbose", action="store_true",
                                help="Show per-objective status")

    args = parser.parse_args(argv)

    if args.no_color:
        Color.disable()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    if args.command == "list":
        return cmd_list(args)
    elif args.command == "search":
        return cmd_search(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "run":
        return cmd_run(args)
    elif args.command == "add":
        return cmd_add(args)
    elif args.command == "results":
        return cmd_results(args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
