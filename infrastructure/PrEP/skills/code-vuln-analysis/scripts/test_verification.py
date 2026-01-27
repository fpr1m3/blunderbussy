#!/usr/bin/env python3
"""
Tests for verification.py - Output checksum and phase sanitization.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from verification import (
    VerificationConfig,
    VerificationResult,
    compute_checksum,
    add_checksum,
    verify_checksum,
    verify_agent_output,
    sanitize_findings,
    sanitize_code_evidence,
    bound_numeric_value,
    validate_file_reference,
    create_verified_output,
)


def test_checksum_computation():
    """Test checksum generation and verification."""
    data = {"findings": [{"id": "VULN-001"}], "summary": "test"}

    checksum = compute_checksum(data)
    assert checksum.startswith("sha256:"), "Checksum should have sha256 prefix"
    assert len(checksum) == 71, "SHA256 hex + prefix should be 71 chars"

    # Same data should produce same checksum
    checksum2 = compute_checksum(data)
    assert checksum == checksum2, "Same data should produce same checksum"

    # Different data should produce different checksum
    data2 = {"findings": [{"id": "VULN-002"}], "summary": "test"}
    checksum3 = compute_checksum(data2)
    assert checksum != checksum3, "Different data should produce different checksum"

    print("[PASS] test_checksum_computation")


def test_add_and_verify_checksum():
    """Test adding and verifying checksum."""
    data = {"findings": [], "attack_paths": []}

    # Add checksum
    with_checksum = add_checksum(data.copy())
    assert "_metadata" in with_checksum
    assert "checksum" in with_checksum["_metadata"]

    # Verify should pass
    valid, msg = verify_checksum(with_checksum)
    assert valid, f"Checksum should verify: {msg}"

    # Tamper with data
    with_checksum["findings"].append({"id": "injected"})
    valid, msg = verify_checksum(with_checksum)
    assert not valid, "Tampered data should fail verification"

    print("[PASS] test_add_and_verify_checksum")


def test_bound_numeric_value():
    """Test numeric value bounding."""
    # Normal values
    assert bound_numeric_value(5.0, 0, 10) == 5.0

    # Over max
    assert bound_numeric_value(15.5, 0, 10) == 10.0

    # Under min
    assert bound_numeric_value(-5, 0, 10) == 0.0

    # At bounds
    assert bound_numeric_value(0, 0, 10) == 0.0
    assert bound_numeric_value(10, 0, 10) == 10.0

    # Invalid type with default
    assert bound_numeric_value("invalid", 0, 10, default=5.0) == 5.0

    # Invalid type without default
    assert bound_numeric_value("invalid", 0, 10) == 0.0

    print("[PASS] test_bound_numeric_value")


def test_sanitize_findings():
    """Test finding sanitization."""
    findings = [
        {
            "id": "VULN-001",
            "type": "sqli",
            "location": {"file": "/nonexistent/file.php", "line": 42},
            "evidence": {"code": "INJECTED CODE"},
            "cvss": 15.5,  # Invalid
            "confidence": -10,  # Invalid
        }
    ]

    config = VerificationConfig(
        sanitize_code_blocks=True,
        validate_file_refs=True,
        bound_numeric_values=True,
    )

    sanitized, result = sanitize_findings(findings, {}, config)

    # Check bounds were applied
    assert sanitized[0]["cvss"] == 10.0, "CVSS should be bounded to 10"
    assert sanitized[0]["confidence"] == 0.0, "Confidence should be bounded to 0"

    # Check file warning
    assert result.sanitized_count > 0

    print("[PASS] test_sanitize_findings")


def test_verify_agent_output():
    """Test full output verification."""
    # Valid analysis output
    output = {
        "findings": [{"id": "VULN-001"}],
        "attack_paths": [{"id": "PATH-001"}],
    }

    config = VerificationConfig(
        verify_checksums=False,
        verify_structure=True,
    )

    result = verify_agent_output(output, config, agent_type="analysis")
    assert result.valid, f"Should be valid: {result.errors}"
    assert result.structure_valid

    # Missing fields
    bad_output = {"findings": []}
    result = verify_agent_output(bad_output, config, agent_type="analysis")
    assert len(result.warnings) > 0, "Should warn about missing fields"

    print("[PASS] test_verify_agent_output")


def test_create_verified_output():
    """Test verified output creation."""
    data = {"findings": [], "attack_paths": []}

    output = create_verified_output(data, "analysis", include_checksum=True)

    assert "_metadata" in output
    assert output["_metadata"]["agent"] == "analysis"
    assert "checksum" in output["_metadata"]

    # Verify checksum
    valid, _ = verify_checksum(output)
    assert valid, "Created output should have valid checksum"

    print("[PASS] test_create_verified_output")


def test_verification_config_defaults():
    """Test config defaults are sensible."""
    config = VerificationConfig()

    # Checksums off by default (optional feature)
    assert config.verify_checksums is False

    # Safety features on by default
    assert config.verify_structure is True
    assert config.sanitize_code_blocks is True
    assert config.validate_file_refs is True
    assert config.bound_numeric_values is True

    # Not strict by default
    assert config.strict_mode is False

    print("[PASS] test_verification_config_defaults")


def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("Running verification.py tests")
    print("=" * 60)

    test_checksum_computation()
    test_add_and_verify_checksum()
    test_bound_numeric_value()
    test_sanitize_findings()
    test_verify_agent_output()
    test_create_verified_output()
    test_verification_config_defaults()

    print("=" * 60)
    print("All tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
