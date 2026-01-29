#!/usr/bin/env python3
"""
Artifact Rubric Validator
=========================

Validates code-vuln-analysis pipeline stage artifacts against the expected
schema/rubric derived from agent prompts.

Stages validated:
  1. Recon   (01-recon-manifest.yaml)
  2. Triage  (02-triage-chunks.yaml)
  3. Analysis (03-analysis-findings.yaml)
  4. Validation (04-validation-findings.yaml)
  5. Brief   (04-validation-brief.md)

Usage:
    python validate_artifacts.py /path/to/artifacts/
    python validate_artifacts.py /path/to/artifacts/ --stage recon
    python validate_artifacts.py /path/to/artifacts/ --strict
"""

import argparse
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print(
        "ERROR: PyYAML is required. Install with: pip install pyyaml",
        file=sys.stderr,
    )
    sys.exit(2)


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


def _pass(name: str) -> str:
    return f"  {Color.GREEN}PASS{Color.RESET}  {name}"


def _fail(name: str, reason: str) -> str:
    return f"  {Color.RED}FAIL{Color.RESET}  {name}\n        {Color.DIM}{reason}{Color.RESET}"


def _warn(name: str, reason: str) -> str:
    return f"  {Color.YELLOW}WARN{Color.RESET}  {name}\n        {Color.DIM}{reason}{Color.RESET}"


def _header(stage: str) -> str:
    return f"\n{Color.BOLD}{Color.CYAN}{'=' * 60}{Color.RESET}\n{Color.BOLD}  {stage}{Color.RESET}\n{Color.BOLD}{Color.CYAN}{'=' * 60}{Color.RESET}"


# ---------------------------------------------------------------------------
# Result accumulator
# ---------------------------------------------------------------------------

class ValidationResult:
    """Collects pass/fail/warn results for a single stage."""

    def __init__(self, stage_name: str, filename: str):
        self.stage_name = stage_name
        self.filename = filename
        self.checks: list[tuple[str, str, str | None]] = []  # (status, name, reason)

    def passed(self, name: str):
        self.checks.append(("pass", name, None))

    def failed(self, name: str, reason: str):
        self.checks.append(("fail", name, reason))

    def warned(self, name: str, reason: str):
        self.checks.append(("warn", name, reason))

    @property
    def pass_count(self) -> int:
        return sum(1 for s, _, _ in self.checks if s == "pass")

    @property
    def fail_count(self) -> int:
        return sum(1 for s, _, _ in self.checks if s == "fail")

    @property
    def warn_count(self) -> int:
        return sum(1 for s, _, _ in self.checks if s == "warn")

    @property
    def ok(self) -> bool:
        return self.fail_count == 0

    def render(self) -> str:
        lines = [_header(f"{self.stage_name}  ({self.filename})")]
        for status, name, reason in self.checks:
            if status == "pass":
                lines.append(_pass(name))
            elif status == "fail":
                lines.append(_fail(name, reason or ""))
            else:
                lines.append(_warn(name, reason or ""))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> tuple[Any, str | None]:
    """Load a YAML file, returning (data, error_string)."""
    if not path.exists():
        return None, f"File not found: {path}"
    try:
        with open(path) as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        return None, f"YAML parse error: {exc}"
    if data is None:
        return None, "File is empty or contains only comments"
    return data, None


def _check_key(data: dict, key: str, result: ValidationResult,
               check_name: str, *, required: bool = True,
               expected_type: type | None = None,
               non_empty: bool = False) -> Any:
    """Validate a top-level key exists and optionally check type/emptiness."""
    if key not in data:
        if required:
            result.failed(check_name, f"Missing required key '{key}'")
        else:
            result.warned(check_name, f"Optional key '{key}' not present")
        return None

    val = data[key]

    if expected_type is not None and not isinstance(val, expected_type):
        actual = type(val).__name__
        result.failed(check_name, f"'{key}' should be {expected_type.__name__}, got {actual}")
        return None

    if non_empty:
        if isinstance(val, (list, dict, str)) and len(val) == 0:
            result.failed(check_name, f"'{key}' must be non-empty")
            return None

    result.passed(check_name)
    return val


VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_STATUSES = {"confirmed", "false_positive", "needs_more_info"}


# ---------------------------------------------------------------------------
# Stage validators
# ---------------------------------------------------------------------------

def validate_recon(artifact_dir: Path, strict: bool = False) -> ValidationResult:
    """Stage 1: Recon manifest validation."""
    fname = "01-recon-manifest.yaml"
    result = ValidationResult("Stage 1 - Recon", fname)
    path = artifact_dir / fname

    data, err = _load_yaml(path)
    if err:
        result.failed("File loads as valid YAML", err)
        return result
    result.passed("File loads as valid YAML")

    if not isinstance(data, dict):
        result.failed("Top-level is a mapping", f"Expected dict, got {type(data).__name__}")
        return result
    result.passed("Top-level is a mapping")

    # manifest.files
    manifest = _check_key(data, "manifest", result, "Has 'manifest' key",
                          expected_type=dict, non_empty=True)
    if manifest is not None:
        _check_key(manifest, "files", result, "manifest.files exists and non-empty",
                   expected_type=list, non_empty=True)
        _check_key(manifest, "languages", result, "manifest.languages exists and non-empty",
                   expected_type=dict, non_empty=True)

    # entry_points
    ep = _check_key(data, "entry_points", result, "Has 'entry_points' key",
                    expected_type=dict)
    if ep is not None:
        has_entries = False
        for category, entries in ep.items():
            if isinstance(entries, list) and len(entries) > 0:
                has_entries = True
                break
        if has_entries:
            result.passed("entry_points has at least one non-empty category")
        else:
            result.failed("entry_points has at least one non-empty category",
                          "All entry_point categories are empty")

    # dangerous_sinks
    _check_key(data, "dangerous_sinks", result, "Has 'dangerous_sinks' key")

    # user_inputs
    _check_key(data, "user_inputs", result, "Has 'user_inputs' key")

    # Optional: dependency_graph
    _check_key(data, "dependency_graph", result,
               "Has 'dependency_graph' key (optional)", required=False)

    return result


def validate_triage(artifact_dir: Path, strict: bool = False) -> ValidationResult:
    """Stage 2: Triage chunks validation."""
    fname = "02-triage-chunks.yaml"
    result = ValidationResult("Stage 2 - Triage", fname)
    path = artifact_dir / fname

    data, err = _load_yaml(path)
    if err:
        result.failed("File loads as valid YAML", err)
        return result
    result.passed("File loads as valid YAML")

    if not isinstance(data, dict):
        result.failed("Top-level is a mapping", f"Expected dict, got {type(data).__name__}")
        return result
    result.passed("Top-level is a mapping")

    # priority_queue
    pq = _check_key(data, "priority_queue", result, "Has 'priority_queue' key",
                    expected_type=dict)
    if pq is not None:
        valid_priorities = {"critical", "high", "medium", "low"}
        found = set(pq.keys()) & valid_priorities
        if found:
            result.passed(f"priority_queue has valid levels: {', '.join(sorted(found))}")
        else:
            result.failed("priority_queue has at least one valid priority level",
                          f"Found keys: {list(pq.keys())}, expected at least one of {valid_priorities}")

    # analysis_chunks
    chunks = _check_key(data, "analysis_chunks", result,
                        "Has 'analysis_chunks' key (non-empty list)",
                        expected_type=list, non_empty=True)
    if chunks is not None:
        required_chunk_fields = {"id", "priority", "files", "focus", "attack_surface"}
        optional_chunk_fields = {"hypothesis", "token_estimate", "rationale"}

        all_valid = True
        for i, chunk in enumerate(chunks):
            if not isinstance(chunk, dict):
                result.failed(f"Chunk [{i}] is a mapping",
                              f"Expected dict, got {type(chunk).__name__}")
                all_valid = False
                continue

            missing = required_chunk_fields - set(chunk.keys())
            if missing:
                result.failed(f"Chunk [{i}] has required fields",
                              f"Missing: {', '.join(sorted(missing))}")
                all_valid = False
                continue

            # files must be non-empty
            if not isinstance(chunk.get("files"), list) or len(chunk["files"]) == 0:
                result.failed(f"Chunk [{i}].files is a non-empty list",
                              "files must be a non-empty list")
                all_valid = False
                continue

            # priority must be valid
            if chunk.get("priority") not in VALID_SEVERITIES:
                result.failed(f"Chunk [{i}].priority is valid",
                              f"Got '{chunk.get('priority')}', expected one of {VALID_SEVERITIES}")
                all_valid = False
                continue

        if all_valid:
            result.passed(f"All {len(chunks)} chunk(s) have required fields and valid structure")

        # Warn about missing optional fields
        if strict:
            for i, chunk in enumerate(chunks):
                if isinstance(chunk, dict):
                    missing_opt = optional_chunk_fields - set(chunk.keys())
                    if missing_opt:
                        result.warned(f"Chunk [{i}] optional fields",
                                      f"Missing optional: {', '.join(sorted(missing_opt))}")

    # metadata
    meta = _check_key(data, "metadata", result, "Has 'metadata' key",
                      expected_type=dict)
    if meta is not None:
        meta_fields = {"total_files_reviewed", "files_prioritized", "chunks_created"}
        missing = meta_fields - set(meta.keys())
        if missing:
            result.failed("metadata has required fields",
                          f"Missing: {', '.join(sorted(missing))}")
        else:
            result.passed("metadata has required fields (total_files_reviewed, files_prioritized, chunks_created)")

    return result


def validate_analysis(artifact_dir: Path, strict: bool = False) -> ValidationResult:
    """Stage 3: Analysis findings validation."""
    fname = "03-analysis-findings.yaml"
    result = ValidationResult("Stage 3 - Analysis", fname)
    path = artifact_dir / fname

    data, err = _load_yaml(path)
    if err:
        result.failed("File loads as valid YAML", err)
        return result
    result.passed("File loads as valid YAML")

    if not isinstance(data, dict):
        result.failed("Top-level is a mapping", f"Expected dict, got {type(data).__name__}")
        return result
    result.passed("Top-level is a mapping")

    # findings key must exist (can be empty list for "no vulns")
    findings = _check_key(data, "findings", result, "Has 'findings' key",
                          expected_type=list)

    if findings is not None and len(findings) > 0:
        all_valid = True
        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                result.failed(f"Finding [{i}] is a mapping",
                              f"Expected dict, got {type(f).__name__}")
                all_valid = False
                continue

            # Required top-level fields
            for field in ("id", "severity", "type"):
                if field not in f:
                    result.failed(f"Finding [{i}] has '{field}'",
                                  f"Missing required field '{field}'")
                    all_valid = False

            # severity validation
            sev = f.get("severity")
            if sev is not None and sev not in VALID_SEVERITIES:
                result.failed(f"Finding [{i}].severity is valid",
                              f"Got '{sev}', expected one of {VALID_SEVERITIES}")
                all_valid = False

            # location
            loc = f.get("location")
            if loc is None:
                result.failed(f"Finding [{i}] has 'location'", "Missing 'location' key")
                all_valid = False
            elif not isinstance(loc, dict):
                result.failed(f"Finding [{i}].location is a mapping",
                              f"Expected dict, got {type(loc).__name__}")
                all_valid = False
            else:
                if "file" not in loc:
                    result.failed(f"Finding [{i}].location.file exists",
                                  "Missing 'file' in location")
                    all_valid = False
                if "line" not in loc:
                    result.failed(f"Finding [{i}].location.line exists",
                                  "Missing 'line' in location")
                    all_valid = False

            # evidence
            ev = f.get("evidence")
            if ev is None:
                result.failed(f"Finding [{i}] has 'evidence'", "Missing 'evidence' key")
                all_valid = False
            elif not isinstance(ev, dict):
                result.failed(f"Finding [{i}].evidence is a mapping",
                              f"Expected dict, got {type(ev).__name__}")
                all_valid = False
            else:
                if "code" not in ev:
                    result.failed(f"Finding [{i}].evidence.code exists",
                                  "Missing 'code' in evidence")
                    all_valid = False
                if "trace" not in ev:
                    result.failed(f"Finding [{i}].evidence.trace exists",
                                  "Missing 'trace' in evidence")
                    all_valid = False

            # confidence
            conf = f.get("confidence")
            if conf is None:
                result.failed(f"Finding [{i}] has 'confidence'",
                              "Missing 'confidence' key")
                all_valid = False
            elif not isinstance(conf, (int, float)):
                result.failed(f"Finding [{i}].confidence is numeric",
                              f"Expected float, got {type(conf).__name__}")
                all_valid = False
            elif not (0.0 <= float(conf) <= 1.0):
                result.failed(f"Finding [{i}].confidence in range [0.0, 1.0]",
                              f"Got {conf}")
                all_valid = False

        if all_valid:
            result.passed(f"All {len(findings)} finding(s) have valid structure")
    elif findings is not None and len(findings) == 0:
        result.warned("findings list is empty",
                      "No vulnerabilities found (this may be correct)")

    # optional uncertain_areas
    _check_key(data, "uncertain_areas", result,
               "Has 'uncertain_areas' key (optional)", required=False)

    return result


def validate_validation(artifact_dir: Path, strict: bool = False) -> ValidationResult:
    """Stage 4: Validation findings validation."""
    fname = "04-validation-findings.yaml"
    result = ValidationResult("Stage 4 - Validation", fname)
    path = artifact_dir / fname

    data, err = _load_yaml(path)
    if err:
        result.failed("File loads as valid YAML", err)
        return result
    result.passed("File loads as valid YAML")

    if not isinstance(data, dict):
        result.failed("Top-level is a mapping", f"Expected dict, got {type(data).__name__}")
        return result
    result.passed("Top-level is a mapping")

    # validated_findings
    vf = _check_key(data, "validated_findings", result,
                    "Has 'validated_findings' key", expected_type=list)

    if vf is not None and len(vf) > 0:
        all_valid = True
        for i, f in enumerate(vf):
            if not isinstance(f, dict):
                result.failed(f"Validated finding [{i}] is a mapping",
                              f"Expected dict, got {type(f).__name__}")
                all_valid = False
                continue

            # Required fields
            if "finding_id" not in f:
                result.failed(f"Validated finding [{i}] has 'finding_id'",
                              "Missing 'finding_id'")
                all_valid = False

            status = f.get("status")
            if status is None:
                result.failed(f"Validated finding [{i}] has 'status'",
                              "Missing 'status'")
                all_valid = False
            elif status not in VALID_STATUSES:
                result.failed(f"Validated finding [{i}].status is valid",
                              f"Got '{status}', expected one of {VALID_STATUSES}")
                all_valid = False
            else:
                # Status-specific checks
                if status == "confirmed":
                    # attack_path
                    ap = f.get("attack_path")
                    if ap is None or not isinstance(ap, list) or len(ap) == 0:
                        result.failed(
                            f"Validated finding [{i}] (confirmed) has non-empty 'attack_path'",
                            "Confirmed findings must have a non-empty attack_path list")
                        all_valid = False

                    if "proof_of_concept" not in f:
                        result.failed(
                            f"Validated finding [{i}] (confirmed) has 'proof_of_concept'",
                            "Confirmed findings must include proof_of_concept")
                        all_valid = False

                    if "impact" not in f:
                        result.failed(
                            f"Validated finding [{i}] (confirmed) has 'impact'",
                            "Confirmed findings must include impact")
                        all_valid = False

                elif status == "false_positive":
                    if "reason" not in f:
                        result.failed(
                            f"Validated finding [{i}] (false_positive) has 'reason'",
                            "False positives must include reason")
                        all_valid = False

            # Optional fields
            if strict:
                for opt in ("cvss_estimate", "authentication_required"):
                    if opt not in f:
                        result.warned(f"Validated finding [{i}] has '{opt}' (optional)",
                                      f"Optional field '{opt}' not present")

        if all_valid:
            result.passed(f"All {len(vf)} validated finding(s) have valid structure")
    elif vf is not None and len(vf) == 0:
        result.warned("validated_findings is empty",
                      "No validated findings (pipeline may have found no vulns)")

    return result


def validate_brief(artifact_dir: Path, strict: bool = False) -> ValidationResult:
    """Stage 4 brief: Markdown brief validation."""
    fname = "04-validation-brief.md"
    result = ValidationResult("Brief", fname)
    path = artifact_dir / fname

    if not path.exists():
        result.failed("File exists", f"File not found: {path}")
        return result
    result.passed("File exists")

    content = path.read_text(encoding="utf-8", errors="replace")

    if len(content.strip()) == 0:
        result.failed("File is non-empty", "Brief file is empty")
        return result
    result.passed("File is non-empty")

    # Check for required sections (case-insensitive)
    lower = content.lower()

    if "vulnerability brief" in lower:
        result.passed("Contains 'Vulnerability Brief' header")
    else:
        result.failed("Contains 'Vulnerability Brief' header",
                      "Missing 'Vulnerability Brief' heading")

    if "executive summary" in lower:
        result.passed("Contains 'Executive Summary' section")
    else:
        result.failed("Contains 'Executive Summary' section",
                      "Missing 'Executive Summary' heading")

    if "coverage report" in lower:
        result.passed("Contains 'Coverage Report' section")
    else:
        result.failed("Contains 'Coverage Report' section",
                      "Missing 'Coverage Report' heading")

    # Conditional: if validation findings have confirmed items, check for section
    validation_yaml = artifact_dir / "04-validation-findings.yaml"
    has_confirmed = False
    if validation_yaml.exists():
        try:
            with open(validation_yaml) as fh:
                vdata = yaml.safe_load(fh)
            if isinstance(vdata, dict):
                vf = vdata.get("validated_findings", [])
                if isinstance(vf, list):
                    has_confirmed = any(
                        isinstance(f, dict) and f.get("status") == "confirmed"
                        for f in vf
                    )
        except Exception:
            pass

    if has_confirmed:
        if "confirmed vulnerabilities" in lower:
            result.passed("Contains 'Confirmed Vulnerabilities' section (findings exist)")
        else:
            result.failed("Contains 'Confirmed Vulnerabilities' section (findings exist)",
                          "Validation has confirmed findings but brief lacks 'Confirmed Vulnerabilities' section")
    else:
        if "confirmed vulnerabilities" in lower:
            result.passed("Contains 'Confirmed Vulnerabilities' section")
        else:
            result.warned("No 'Confirmed Vulnerabilities' section",
                          "No confirmed findings in validation YAML, section may be correctly absent")

    return result


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

STAGE_MAP = {
    "recon": validate_recon,
    "triage": validate_triage,
    "analysis": validate_analysis,
    "validation": validate_validation,
    "brief": validate_brief,
}

ALL_STAGES = ["recon", "triage", "analysis", "validation", "brief"]


def run_validation(artifact_dir: Path, stages: list[str] | None = None,
                   strict: bool = False) -> list[ValidationResult]:
    """Run validation across specified stages (default: all)."""
    if stages is None:
        stages = ALL_STAGES

    results = []
    for stage in stages:
        validator = STAGE_MAP[stage]
        results.append(validator(artifact_dir, strict=strict))
    return results


def render_summary(results: list[ValidationResult]) -> str:
    """Render a summary table of all stage results."""
    total_pass = sum(r.pass_count for r in results)
    total_fail = sum(r.fail_count for r in results)
    total_warn = sum(r.warn_count for r in results)
    total = total_pass + total_fail + total_warn

    lines = [
        f"\n{Color.BOLD}{'=' * 60}{Color.RESET}",
        f"{Color.BOLD}  Summary{Color.RESET}",
        f"{Color.BOLD}{'=' * 60}{Color.RESET}",
        "",
        f"  {'Stage':<30} {'Pass':>6} {'Fail':>6} {'Warn':>6}  {'Result':>8}",
        f"  {'-' * 30} {'-' * 6} {'-' * 6} {'-' * 6}  {'-' * 8}",
    ]

    for r in results:
        status = f"{Color.GREEN}OK{Color.RESET}" if r.ok else f"{Color.RED}FAIL{Color.RESET}"
        lines.append(
            f"  {r.stage_name:<30} {r.pass_count:>6} {r.fail_count:>6} {r.warn_count:>6}  {status:>17}"
        )

    lines.append(f"  {'-' * 30} {'-' * 6} {'-' * 6} {'-' * 6}  {'-' * 8}")
    overall = f"{Color.GREEN}ALL PASSED{Color.RESET}" if total_fail == 0 else f"{Color.RED}FAILED{Color.RESET}"
    lines.append(f"  {'TOTAL':<30} {total_pass:>6} {total_fail:>6} {total_warn:>6}  {overall:>17}")
    lines.append(f"\n  {total} checks run: "
                 f"{Color.GREEN}{total_pass} passed{Color.RESET}, "
                 f"{Color.RED}{total_fail} failed{Color.RESET}, "
                 f"{Color.YELLOW}{total_warn} warnings{Color.RESET}")
    lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate code-vuln-analysis pipeline artifacts against rubric.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Stages: recon, triage, analysis, validation, brief

Examples:
  %(prog)s /path/to/artifacts/
  %(prog)s /path/to/artifacts/ --stage recon --stage triage
  %(prog)s /path/to/artifacts/ --strict --no-color
        """,
    )
    parser.add_argument("artifact_dir", type=Path,
                        help="Directory containing pipeline artifact files")
    parser.add_argument("--stage", action="append", dest="stages",
                        choices=ALL_STAGES,
                        help="Validate specific stage(s) only (repeatable)")
    parser.add_argument("--strict", action="store_true",
                        help="Warn on missing optional fields")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")

    args = parser.parse_args(argv)

    if args.no_color:
        Color.disable()

    artifact_dir = args.artifact_dir.resolve()
    if not artifact_dir.is_dir():
        print(f"{Color.RED}ERROR:{Color.RESET} Not a directory: {artifact_dir}",
              file=sys.stderr)
        return 2

    stages = args.stages if args.stages else None
    results = run_validation(artifact_dir, stages=stages, strict=args.strict)

    for r in results:
        print(r.render())

    print(render_summary(results))

    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
