#!/usr/bin/env python3
"""
Agent Output Verification and Phase Sanitization
=================================================

Security layer for the vulnerability analysis pipeline that provides:
1. Optional checksum verification of agent outputs
2. Sanitization between pipeline phases to prevent prompt injection

These utilities implement SKILL.md sections:
- Checksum verification: lines 443-455
- Phase sanitization: lines 457-465

Usage:
    from verification import (
        verify_agent_output,
        sanitize_findings,
        VerificationConfig,
    )

    # Configure verification (checksums optional)
    config = VerificationConfig(verify_checksums=True)

    # Verify agent output
    if verify_agent_output(output, config):
        # Sanitize before passing to next phase
        clean_findings = sanitize_findings(output['findings'], source_files)
"""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional YAML support
yaml: Any = None
YAML_AVAILABLE = False
try:
    import yaml as _yaml
    yaml = _yaml
    YAML_AVAILABLE = True
except ImportError:
    pass


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class VerificationConfig:
    """
    Configuration for output verification.

    Attributes:
        verify_checksums: Enable/disable checksum verification (default: False)
        verify_structure: Validate YAML structure (default: True)
        sanitize_code_blocks: Re-read code from source files (default: True)
        validate_file_refs: Confirm referenced files exist (default: True)
        bound_numeric_values: Enforce CVSS/confidence ranges (default: True)
        strict_mode: Fail on any verification error (default: False)
    """
    verify_checksums: bool = False
    verify_structure: bool = True
    sanitize_code_blocks: bool = True
    validate_file_refs: bool = True
    bound_numeric_values: bool = True
    strict_mode: bool = False

    # Numeric bounds
    cvss_min: float = 0.0
    cvss_max: float = 10.0
    confidence_min: float = 0.0
    confidence_max: float = 100.0


@dataclass
class VerificationResult:
    """
    Result of verification operations.

    Attributes:
        valid: Overall verification status
        errors: List of error messages
        warnings: List of warning messages
        checksum_verified: Whether checksum matched (if checked)
        structure_valid: Whether structure was valid
        sanitized_count: Number of findings sanitized
    """
    valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    checksum_verified: Optional[bool] = None
    structure_valid: bool = True
    sanitized_count: int = 0

    def add_error(self, msg: str) -> None:
        """Add error and mark as invalid."""
        self.errors.append(msg)
        self.valid = False

    def add_warning(self, msg: str) -> None:
        """Add warning (doesn't affect validity)."""
        self.warnings.append(msg)


# =============================================================================
# Checksum Verification
# =============================================================================

def compute_checksum(data: Dict[str, Any], exclude_key: str = "_metadata") -> str:
    """
    Compute SHA256 checksum of data, excluding metadata.

    Args:
        data: Dictionary to checksum
        exclude_key: Key to exclude from checksum computation

    Returns:
        Checksum string in format "sha256:<hash>"
    """
    if not YAML_AVAILABLE:
        # Fallback to repr-based hash
        payload = {k: v for k, v in data.items() if k != exclude_key}
        content = repr(sorted(payload.items()))
        hash_val = hashlib.sha256(content.encode()).hexdigest()
        return f"sha256:{hash_val}"

    payload = {k: v for k, v in data.items() if k != exclude_key}
    content = yaml.dump(payload, sort_keys=True, default_flow_style=False)
    hash_val = hashlib.sha256(content.encode()).hexdigest()
    return f"sha256:{hash_val}"


def verify_checksum(output: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Verify output checksum matches payload.

    Args:
        output: Agent output with _metadata.checksum field

    Returns:
        Tuple of (valid, message)
    """
    metadata = output.get("_metadata", {})
    stored_checksum = metadata.get("checksum")

    if not stored_checksum:
        return False, "No checksum in _metadata"

    expected_checksum = compute_checksum(output)

    if stored_checksum == expected_checksum:
        return True, "Checksum verified"
    else:
        return False, f"Checksum mismatch: expected {expected_checksum}, got {stored_checksum}"


def add_checksum(output: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add checksum to output metadata.

    Use this when generating agent output to enable verification.

    Args:
        output: Agent output dictionary

    Returns:
        Output with _metadata.checksum added
    """
    if "_metadata" not in output:
        output["_metadata"] = {}

    output["_metadata"]["checksum"] = compute_checksum(output)
    return output


# =============================================================================
# Structure Validation
# =============================================================================

# Expected fields for different agent outputs
EXPECTED_SCHEMAS = {
    "recon": ["files", "entry_points", "dependencies"],
    "triage": ["prioritized_findings", "coverage"],
    "analysis": ["findings", "attack_paths"],
    "validation": ["validated_findings", "false_positives", "confirmed"],
}


def validate_structure(
    output: Dict[str, Any],
    agent_type: Optional[str] = None
) -> Tuple[bool, List[str]]:
    """
    Validate output has expected structure.

    Args:
        output: Agent output dictionary
        agent_type: Type of agent (recon, triage, analysis, validation)

    Returns:
        Tuple of (valid, list of missing fields)
    """
    if agent_type and agent_type in EXPECTED_SCHEMAS:
        expected = EXPECTED_SCHEMAS[agent_type]
        missing = [f for f in expected if f not in output]
        return len(missing) == 0, missing

    # Generic validation - just check it's a non-empty dict
    if not isinstance(output, dict):
        return False, ["Output must be a dictionary"]

    if not output:
        return False, ["Output is empty"]

    return True, []


# =============================================================================
# Phase Sanitization
# =============================================================================

def sanitize_code_evidence(
    finding: Dict[str, Any],
    source_files: Dict[str, str]
) -> Dict[str, Any]:
    """
    Re-read code evidence from source files.

    Prevents prompt injection via crafted evidence.code fields.
    SKILL.md line 465: "Never pass evidence.code directly - always re-read from source."

    Args:
        finding: Finding dictionary with location info
        source_files: Dict mapping file paths to their contents

    Returns:
        Finding with evidence.code refreshed from source
    """
    location = finding.get("location", {})
    file_path = location.get("file")
    line_num = location.get("line")
    end_line = location.get("end_line", line_num)

    if not file_path or not line_num:
        return finding

    # Read from source files dict (preferred) or filesystem
    if file_path in source_files:
        content = source_files[file_path]
    else:
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except (OSError, IOError):
            # Can't read file, keep original evidence but flag it
            if "evidence" not in finding:
                finding["evidence"] = {}
            finding["evidence"]["_unverified"] = True
            return finding

    # Extract lines from source
    lines = content.splitlines()
    start_idx = max(0, line_num - 1)
    end_idx = min(len(lines), end_line if end_line else line_num)

    # Get code with context (2 lines before/after)
    context_start = max(0, start_idx - 2)
    context_end = min(len(lines), end_idx + 2)
    code_lines = lines[context_start:context_end]

    # Update evidence
    if "evidence" not in finding:
        finding["evidence"] = {}

    finding["evidence"]["code"] = "\n".join(code_lines)
    finding["evidence"]["_verified_from_source"] = True
    finding["evidence"]["_source_lines"] = f"{context_start + 1}-{context_end}"

    return finding


def validate_file_reference(file_path: str, base_paths: Optional[List[str]] = None) -> bool:
    """
    Validate that a file reference exists and is safe.

    Args:
        file_path: Path to validate
        base_paths: Allowed base directories (for path traversal prevention)

    Returns:
        True if file exists and is within allowed paths
    """
    path = Path(file_path)

    # Check existence
    if not path.exists():
        return False

    # Check for path traversal if base_paths specified
    if base_paths:
        resolved = path.resolve()
        for base in base_paths:
            base_resolved = Path(base).resolve()
            try:
                resolved.relative_to(base_resolved)
                return True
            except ValueError:
                continue
        return False

    return True


def bound_numeric_value(
    value: Any,
    min_val: float,
    max_val: float,
    default: Optional[float] = None
) -> float:
    """
    Bound a numeric value to valid range.

    Args:
        value: Value to bound
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        default: Default if value is not numeric

    Returns:
        Bounded value
    """
    try:
        num = float(value)
        return max(min_val, min(max_val, num))
    except (TypeError, ValueError):
        return default if default is not None else min_val


def sanitize_finding(
    finding: Dict[str, Any],
    source_files: Dict[str, str],
    config: VerificationConfig
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Sanitize a single finding for safe passage between phases.

    Args:
        finding: Finding dictionary
        source_files: Dict mapping file paths to contents
        config: Verification configuration

    Returns:
        Tuple of (sanitized finding, list of modifications made)
    """
    modifications = []

    # 1. Re-read code from source
    if config.sanitize_code_blocks:
        original_code = finding.get("evidence", {}).get("code", "")
        finding = sanitize_code_evidence(finding, source_files)
        new_code = finding.get("evidence", {}).get("code", "")
        if original_code != new_code:
            modifications.append("code_evidence_refreshed")

    # 2. Validate file references
    if config.validate_file_refs:
        file_path = finding.get("location", {}).get("file")
        if file_path and file_path not in source_files:
            if not validate_file_reference(file_path):
                modifications.append(f"invalid_file_ref:{file_path}")
                finding["_validation_warnings"] = finding.get("_validation_warnings", [])
                finding["_validation_warnings"].append(f"File not found: {file_path}")

    # 3. Bound numeric values
    if config.bound_numeric_values:
        # CVSS score
        if "cvss" in finding:
            original = finding["cvss"]
            finding["cvss"] = bound_numeric_value(
                original, config.cvss_min, config.cvss_max
            )
            if finding["cvss"] != original:
                modifications.append(f"cvss_bounded:{original}->{finding['cvss']}")

        # Confidence score
        if "confidence" in finding:
            original = finding["confidence"]
            finding["confidence"] = bound_numeric_value(
                original, config.confidence_min, config.confidence_max
            )
            if finding["confidence"] != original:
                modifications.append(f"confidence_bounded:{original}->{finding['confidence']}")

        # Priority score (typically 0-70 per SKILL.md)
        if "priority_score" in finding:
            original = finding["priority_score"]
            finding["priority_score"] = bound_numeric_value(original, 0, 70)
            if finding["priority_score"] != original:
                modifications.append(f"priority_bounded:{original}->{finding['priority_score']}")

    return finding, modifications


def sanitize_findings(
    findings: List[Dict[str, Any]],
    source_files: Dict[str, str],
    config: Optional[VerificationConfig] = None
) -> Tuple[List[Dict[str, Any]], VerificationResult]:
    """
    Sanitize all findings for safe passage between phases.

    This is the main entry point for phase sanitization.

    Args:
        findings: List of finding dictionaries
        source_files: Dict mapping file paths to contents
        config: Verification configuration (uses defaults if None)

    Returns:
        Tuple of (sanitized findings, verification result)
    """
    if config is None:
        config = VerificationConfig()

    result = VerificationResult()
    sanitized = []

    for i, finding in enumerate(findings):
        clean_finding, mods = sanitize_finding(finding.copy(), source_files, config)
        sanitized.append(clean_finding)

        if mods:
            result.sanitized_count += 1
            for mod in mods:
                if mod.startswith("invalid_file_ref"):
                    result.add_warning(f"Finding {i}: {mod}")
                else:
                    # Info-level, not a warning
                    pass

    return sanitized, result


# =============================================================================
# Main Verification Entry Point
# =============================================================================

def verify_agent_output(
    output: Dict[str, Any],
    config: Optional[VerificationConfig] = None,
    agent_type: Optional[str] = None
) -> VerificationResult:
    """
    Verify agent output integrity and structure.

    This is the main entry point for output verification.

    Args:
        output: Agent output dictionary
        config: Verification configuration (uses defaults if None)
        agent_type: Type of agent for schema validation

    Returns:
        VerificationResult with status and any errors/warnings
    """
    if config is None:
        config = VerificationConfig()

    result = VerificationResult()

    # 1. Structure validation
    if config.verify_structure:
        valid, missing = validate_structure(output, agent_type)
        result.structure_valid = valid
        if not valid:
            msg = f"Invalid structure: missing fields {missing}"
            if config.strict_mode:
                result.add_error(msg)
            else:
                result.add_warning(msg)

    # 2. Checksum verification (optional)
    if config.verify_checksums:
        valid, msg = verify_checksum(output)
        result.checksum_verified = valid
        if not valid:
            if config.strict_mode:
                result.add_error(f"Checksum verification failed: {msg}")
            else:
                result.add_warning(f"Checksum verification failed: {msg}")

    return result


# =============================================================================
# Convenience Functions
# =============================================================================

def create_verified_output(
    data: Dict[str, Any],
    agent_type: str,
    include_checksum: bool = True
) -> Dict[str, Any]:
    """
    Create a verified output structure for agent response.

    Use this when generating agent output to ensure proper format.

    Args:
        data: Output data dictionary
        agent_type: Type of agent (recon, triage, analysis, validation)
        include_checksum: Whether to include checksum in metadata

    Returns:
        Output with proper structure and optional checksum
    """
    output = dict(data)

    # Add metadata
    output["_metadata"] = output.get("_metadata", {})
    output["_metadata"]["agent"] = agent_type

    # Add checksum if requested
    if include_checksum:
        output = add_checksum(output)

    return output


# =============================================================================
# Demo
# =============================================================================

if __name__ == "__main__":
    print("Verification Module Demo")
    print("=" * 60)

    # Sample finding (simulating analysis phase output)
    sample_finding = {
        "id": "VULN-001",
        "type": "sqli",
        "location": {
            "file": "/tmp/test.php",
            "line": 42,
        },
        "evidence": {
            "code": "POTENTIALLY INJECTED CODE BLOCK - SHOULD BE RE-READ FROM SOURCE",
        },
        "cvss": 15.5,  # Invalid - should be bounded to 10
        "confidence": 150,  # Invalid - should be bounded to 100
    }

    # Test config
    config = VerificationConfig(
        verify_checksums=True,
        strict_mode=False
    )

    print("\n1. Testing numeric bounding:")
    print(f"   Original CVSS: {sample_finding['cvss']}")
    print(f"   Original confidence: {sample_finding['confidence']}")

    bounded_cvss = bound_numeric_value(sample_finding['cvss'], 0, 10)
    bounded_conf = bound_numeric_value(sample_finding['confidence'], 0, 100)
    print(f"   Bounded CVSS: {bounded_cvss}")
    print(f"   Bounded confidence: {bounded_conf}")

    print("\n2. Testing checksum generation:")
    sample_output = {
        "findings": [sample_finding],
        "summary": "Test output"
    }
    with_checksum = add_checksum(sample_output.copy())
    print(f"   Checksum: {with_checksum['_metadata']['checksum']}")

    print("\n3. Testing checksum verification:")
    valid, msg = verify_checksum(with_checksum)
    print(f"   Valid: {valid}")
    print(f"   Message: {msg}")

    # Tamper with output
    with_checksum["findings"][0]["cvss"] = 9.9
    valid, msg = verify_checksum(with_checksum)
    print(f"\n   After tampering:")
    print(f"   Valid: {valid}")
    print(f"   Message: {msg}")

    print("\n4. Testing full verification:")
    result = verify_agent_output(
        {"findings": [], "attack_paths": []},
        config,
        agent_type="analysis"
    )
    print(f"   Valid: {result.valid}")
    print(f"   Errors: {result.errors}")
    print(f"   Warnings: {result.warnings}")

    print("\n" + "=" * 60)
    print("Demo complete")
