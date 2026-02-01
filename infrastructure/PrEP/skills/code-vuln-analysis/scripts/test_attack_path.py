#!/usr/bin/env python3
"""
Tests for attack_path.py

Run with: python3 -m pytest test_attack_path.py -v
"""

import pytest
from attack_path import (
    AttackStep,
    AttackPath,
    generate_attack_path,
    generate_poc,
    calculate_complexity,
    calculate_success_probability,
    _generate_entry_action,
    _generate_entry_payload,
    _generate_sink_action,
)
from prioritize import (
    TriageFinding,
    CodeLocation,
    SinkType,
    InputProximity,
    AuthLevel,
)


class TestAttackStep:
    """Test AttackStep dataclass."""

    def test_attack_step_creation(self):
        step = AttackStep(
            step_num=1,
            action="Send malicious request",
            location="test.php:10",
            payload="'; DROP TABLE users--",
            auth_required="none",
            details="No CSRF protection"
        )

        assert step.step_num == 1
        assert step.action == "Send malicious request"
        assert step.payload == "'; DROP TABLE users--"

    def test_attack_step_to_dict(self):
        step = AttackStep(
            step_num=1,
            action="Test action",
            location="file.php:20",
            payload="test",
            details="Test details"
        )

        d = step.to_dict()
        assert d["step"] == 1
        assert d["action"] == "Test action"
        assert d["location"] == "file.php:20"
        assert d["payload"] == "test"
        assert d["details"] == "Test details"

    def test_attack_step_optional_fields(self):
        step = AttackStep(
            step_num=2,
            action="Simple action",
            location="file.php"
        )

        d = step.to_dict()
        assert "payload" not in d
        assert "auth_required" not in d


class TestAttackPath:
    """Test AttackPath dataclass."""

    def test_attack_path_creation(self):
        steps = [
            AttackStep(1, "Action 1", "loc1"),
            AttackStep(2, "Action 2", "loc2")
        ]

        path = AttackPath(
            steps=steps,
            total_auth_required="user",
            complexity="medium",
            success_probability=0.75
        )

        assert len(path.steps) == 2
        assert path.total_auth_required == "user"
        assert path.complexity == "medium"
        assert path.success_probability == 0.75

    def test_attack_path_to_dict(self):
        steps = [AttackStep(1, "Test", "test.php")]
        path = AttackPath(
            steps=steps,
            total_auth_required="none",
            complexity="low",
            success_probability=0.9
        )

        d = path.to_dict()
        assert len(d["steps"]) == 1
        assert d["total_auth_required"] == "none"
        assert d["complexity"] == "low"
        assert d["success_probability"] == 0.9


class TestComplexityCalculation:
    """Test attack complexity calculation."""

    def test_low_complexity_no_auth(self):
        steps = [AttackStep(1, "Test", "test.php")]
        complexity = calculate_complexity(steps, AuthLevel.NONE)
        assert complexity == "low"

    def test_medium_complexity_user_auth(self):
        steps = [AttackStep(1, "Test", "test.php")]
        complexity = calculate_complexity(steps, AuthLevel.USER)
        assert complexity == "medium"

    def test_high_complexity_admin_auth(self):
        steps = [AttackStep(1, "Test", "test.php")]
        complexity = calculate_complexity(steps, AuthLevel.ADMIN)
        assert complexity == "high"

    def test_complexity_increases_with_steps(self):
        few_steps = [AttackStep(i, "Test", "test.php") for i in range(1, 2)]
        many_steps = [AttackStep(i, "Test", "test.php") for i in range(1, 6)]

        complexity_few = calculate_complexity(few_steps, AuthLevel.NONE)
        complexity_many = calculate_complexity(many_steps, AuthLevel.NONE)

        # More steps should result in higher complexity
        assert complexity_few == "low"
        assert complexity_many in ["medium", "high"]


class TestSuccessProbability:
    """Test success probability calculation."""

    def test_high_probability_direct_no_auth(self):
        finding = TriageFinding(
            id="TEST-1",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.CODE_EXECUTION,
            sink_function="system",
            input_proximity=InputProximity.DIRECT,
            auth_level=AuthLevel.NONE
        )

        prob = calculate_success_probability(finding, 1, "low")
        assert prob > 0.7  # Should be high probability

    def test_low_probability_admin_auth(self):
        finding = TriageFinding(
            id="TEST-2",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.SQL,
            sink_function="mysql_query",
            input_proximity=InputProximity.DIRECT,
            auth_level=AuthLevel.ADMIN
        )

        prob = calculate_success_probability(finding, 1, "high")
        assert prob < 0.5  # Should be lower probability

    def test_probability_decreases_with_steps(self):
        finding = TriageFinding(
            id="TEST-3",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.CODE_EXECUTION,
            sink_function="system",
            input_proximity=InputProximity.DIRECT,
            auth_level=AuthLevel.NONE
        )

        prob_1_step = calculate_success_probability(finding, 1, "low")
        prob_5_steps = calculate_success_probability(finding, 5, "low")

        assert prob_5_steps < prob_1_step


class TestEntryActionGeneration:
    """Test entry action string generation."""

    def test_get_request_action(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.SQL,
            sink_function="query",
            input_proximity=InputProximity.DIRECT,
            input_source="$_GET['id']"
        )

        action = _generate_entry_action(finding)
        assert "GET" in action

    def test_post_request_action(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.SQL,
            sink_function="query",
            input_proximity=InputProximity.DIRECT,
            input_source="$_POST['data']"
        )

        action = _generate_entry_action(finding)
        assert "POST" in action

    def test_session_action(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.XSS,
            sink_function="echo",
            input_proximity=InputProximity.SESSION
        )

        action = _generate_entry_action(finding)
        assert "session" in action.lower()


class TestPayloadGeneration:
    """Test payload generation."""

    def test_rce_payload(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.CODE_EXECUTION,
            sink_function="system",
            input_proximity=InputProximity.DIRECT
        )

        payload = _generate_entry_payload(finding)
        assert payload is not None
        assert "$LHOST" in payload or "nc" in payload

    def test_sql_payload(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.SQL,
            sink_function="query",
            input_proximity=InputProximity.DIRECT
        )

        payload = _generate_entry_payload(finding)
        assert payload is not None
        assert "'" in payload or "OR" in payload

    def test_xss_payload(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.XSS,
            sink_function="echo",
            input_proximity=InputProximity.DIRECT
        )

        payload = _generate_entry_payload(finding)
        assert payload is not None
        assert "<script>" in payload


class TestSinkActionGeneration:
    """Test sink action string generation."""

    def test_rce_sink_action(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.CODE_EXECUTION,
            sink_function="system",
            input_proximity=InputProximity.DIRECT
        )

        action = _generate_sink_action(finding)
        assert "command" in action.lower() or "execute" in action.lower()

    def test_sql_sink_action(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.SQL,
            sink_function="query",
            input_proximity=InputProximity.DIRECT
        )

        action = _generate_sink_action(finding)
        assert "SQL" in action or "data" in action.lower()


class TestAttackPathGeneration:
    """Test full attack path generation."""

    def test_generate_simple_attack_path(self):
        finding = TriageFinding(
            id="VULN-001",
            location=CodeLocation("vuln.php", 42, function="handler"),
            sink_type=SinkType.CODE_EXECUTION,
            sink_function="system",
            input_proximity=InputProximity.DIRECT,
            input_source="$_GET['cmd']",
            auth_level=AuthLevel.NONE
        )

        taint_path = {"vuln.php"}

        path = generate_attack_path(finding, taint_path)

        assert len(path.steps) >= 2  # Entry + Sink at minimum
        assert path.total_auth_required == "none"
        assert path.complexity in ["low", "medium", "high"]
        assert 0.0 <= path.success_probability <= 1.0

    def test_generate_complex_attack_path(self):
        finding = TriageFinding(
            id="VULN-002",
            location=CodeLocation("admin.php", 100),
            sink_type=SinkType.SQL,
            sink_function="mysql_query",
            input_proximity=InputProximity.DB_STORED,
            auth_level=AuthLevel.ADMIN
        )

        taint_path = {"admin.php", "db.php", "user.php", "config.php"}

        path = generate_attack_path(finding, taint_path)

        # Should have multiple steps due to complex taint path
        assert len(path.steps) >= 2
        assert path.total_auth_required == "admin"


class TestPoCGeneration:
    """Test proof-of-concept code generation."""

    def test_generate_bash_poc_rce(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.CODE_EXECUTION,
            sink_function="system",
            input_proximity=InputProximity.DIRECT
        )

        path = generate_attack_path(finding, {"test.php"})
        poc = generate_poc(path, SinkType.CODE_EXECUTION, "/vuln.php", "cmd", "bash")

        assert "#!/bin/bash" in poc
        assert "$TARGET" in poc
        assert "$LHOST" in poc
        assert "$LPORT" in poc

    def test_generate_python_poc_sql(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.SQL,
            sink_function="query",
            input_proximity=InputProximity.DIRECT
        )

        path = generate_attack_path(finding, {"test.php"})
        poc = generate_poc(path, SinkType.SQL, "/search.php", "q", "python")

        assert "#!/usr/bin/env python3" in poc
        assert "import requests" in poc
        assert "TARGET" in poc

    def test_generate_poc_with_custom_endpoint(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.XSS,
            sink_function="echo",
            input_proximity=InputProximity.DIRECT
        )

        path = generate_attack_path(finding, {"test.php"})
        poc = generate_poc(path, SinkType.XSS, "/custom/endpoint.php", "param", "bash")

        assert "/custom/endpoint.php" in poc
        assert "param" in poc

    def test_generic_poc_fallback(self):
        finding = TriageFinding(
            id="TEST",
            location=CodeLocation("test.php", 10),
            sink_type=SinkType.OTHER,  # No specific template
            sink_function="unknown",
            input_proximity=InputProximity.DIRECT
        )

        path = generate_attack_path(finding, {"test.php"})
        poc = generate_poc(path, SinkType.OTHER, "/test.php", "input", "bash")

        # Should still generate something
        assert len(poc) > 0
        assert "$TARGET" in poc or "TARGET" in poc


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
