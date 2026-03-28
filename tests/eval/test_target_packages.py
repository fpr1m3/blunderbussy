"""
Parametrized tests for all eval target packages.

Validates ground truth, package completeness, compose files,
registry consistency, and scorer integration for every target.
"""

import os
from pathlib import Path

import pytest
import yaml

from eval_scorer import (
    GroundTruth,
    ValidationError,
    load_ground_truth,
    score_ptt,
)

from conftest import (
    EVAL_DIR,
    REGISTRY_PATH,
    TARGETS_DIR,
    build_perfect_ptt,
    discover_targets,
)

# ---------------------------------------------------------------------------
# Target list (evaluated at collection time for parametrize)
# ---------------------------------------------------------------------------

ALL_TARGETS = discover_targets()

MULTI_CONTAINER_TARGETS = [
    "php-fpm-rce",
    "confluence-ognl-injection",
    "kibana-prototype-pollution",
    "zabbix-trapper-rce",
]


def _gt_path(target_name: str) -> Path:
    return TARGETS_DIR / target_name / "ground_truth.yaml"


def _load_gt(target_name: str) -> GroundTruth:
    return load_ground_truth(str(_gt_path(target_name)))


def _load_compose(target_name: str) -> dict:
    path = TARGETS_DIR / target_name / "compose.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


def _load_registry() -> dict:
    with open(REGISTRY_PATH) as f:
        return yaml.safe_load(f)


# ===========================================================================
# Section 1: Ground Truth Validation
# ===========================================================================


@pytest.mark.eval
class TestGroundTruthValidation:
    """Validate ground_truth.yaml for every target."""

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_ground_truth_loads(self, target_name: str):
        """Ground truth loads without ValidationError."""
        gt = _load_gt(target_name)
        assert isinstance(gt, GroundTruth)

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_ground_truth_structure(self, target_name: str):
        """Core fields are valid."""
        gt = _load_gt(target_name)
        assert gt.target_name == target_name
        assert gt.difficulty in ("easy", "medium", "hard")
        assert gt.eval_version == "1.0"
        assert gt.platform == "linux"

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_objectives_sum_to_100(self, target_name: str):
        """Objective points total exactly 100."""
        gt = _load_gt(target_name)
        total = sum(obj.points for obj in gt.objectives)
        assert total == 100, f"{target_name}: objectives sum to {total}, expected 100"

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_dependencies_resolve(self, target_name: str):
        """All depends_on references point to existing objective IDs."""
        gt = _load_gt(target_name)
        obj_ids = {obj.id for obj in gt.objectives}
        for obj in gt.objectives:
            if obj.depends_on:
                assert obj.depends_on in obj_ids, (
                    f"{target_name}: objective '{obj.id}' depends on "
                    f"'{obj.depends_on}' which does not exist"
                )

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_has_penalties(self, target_name: str):
        """Every target defines at least one penalty."""
        gt = _load_gt(target_name)
        assert len(gt.penalties) > 0, f"{target_name}: no penalties defined"

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_has_efficiency(self, target_name: str):
        """Every target defines efficiency constraints."""
        gt = _load_gt(target_name)
        assert gt.efficiency is not None, f"{target_name}: no efficiency section"


# ===========================================================================
# Section 2: Package Completeness
# ===========================================================================


REQUIRED_FILES = [
    "ground_truth.yaml",
    "compose.yaml",
    "cas/context.yaml",
    "cas/ptt.yaml",
    "setup/plant_flags.sh",
    "README.md",
]


@pytest.mark.eval
class TestPackageCompleteness:
    """Verify every target has all required files."""

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_required_files_exist(self, target_name: str):
        """All 6 required files are present."""
        target_dir = TARGETS_DIR / target_name
        missing = [f for f in REQUIRED_FILES if not (target_dir / f).exists()]
        assert not missing, f"{target_name}: missing files: {missing}"

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_plant_flags_executable(self, target_name: str):
        """plant_flags.sh has execute permission."""
        path = TARGETS_DIR / target_name / "setup" / "plant_flags.sh"
        assert os.access(path, os.X_OK), f"{target_name}: plant_flags.sh not executable"

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_cas_context_parses(self, target_name: str):
        """CAS context.yaml loads and has expected keys."""
        path = TARGETS_DIR / target_name / "cas" / "context.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)
        assert "target" in data, f"{target_name}: context.yaml missing 'target' key"
        assert "services" in data, f"{target_name}: context.yaml missing 'services' key"

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_cas_ptt_parses(self, target_name: str):
        """CAS ptt.yaml loads and has required structure."""
        path = TARGETS_DIR / target_name / "cas" / "ptt.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict), f"{target_name}: ptt.yaml is not a dict"
        # Accept: engagement.hosts (full PTT), engagement.target (seed),
        # or top-level target key
        assert "engagement" in data or "target" in data, (
            f"{target_name}: ptt.yaml must have 'engagement' or 'target' key"
        )


# ===========================================================================
# Section 3: Compose Validation
# ===========================================================================


@pytest.mark.eval
class TestComposeValidation:
    """Validate compose.yaml for every target."""

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_compose_parses(self, target_name: str):
        """compose.yaml loads and has 'services' key."""
        data = _load_compose(target_name)
        assert "services" in data, f"{target_name}: compose.yaml missing 'services'"

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_images_fully_qualified(self, target_name: str):
        """All images use fully-qualified docker.io/ prefix."""
        data = _load_compose(target_name)
        for svc_name, svc_config in data["services"].items():
            image = svc_config.get("image", "")
            assert image.startswith("docker.io/"), (
                f"{target_name}: service '{svc_name}' image '{image}' "
                "must start with 'docker.io/'"
            )

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_has_port_mappings(self, target_name: str):
        """At least one service exposes ports."""
        data = _load_compose(target_name)
        has_ports = any(
            "ports" in svc for svc in data["services"].values()
        )
        assert has_ports, f"{target_name}: no service has 'ports' mapping"

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_has_network(self, target_name: str):
        """compose.yaml defines a network."""
        data = _load_compose(target_name)
        assert "networks" in data, f"{target_name}: compose.yaml missing 'networks'"


# ===========================================================================
# Section 4: Registry Consistency
# ===========================================================================


@pytest.mark.eval
class TestRegistryConsistency:
    """Verify registry.yaml matches target packages."""

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_target_in_registry(self, target_name: str):
        """Every target directory has a matching registry entry."""
        reg = _load_registry()
        names = {t["name"] for t in reg.get("targets", [])}
        assert target_name in names, (
            f"{target_name}: not found in registry.yaml"
        )

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_registry_difficulty_matches(self, target_name: str):
        """Registry difficulty matches ground truth."""
        reg = _load_registry()
        gt = _load_gt(target_name)
        for entry in reg.get("targets", []):
            if entry["name"] == target_name:
                assert entry["difficulty"] == gt.difficulty, (
                    f"{target_name}: registry says '{entry['difficulty']}', "
                    f"ground truth says '{gt.difficulty}'"
                )
                return
        pytest.fail(f"{target_name}: not found in registry")

    def test_registry_count(self):
        """Registry entry count matches target directory count."""
        reg = _load_registry()
        n_registry = len(reg.get("targets", []))
        n_dirs = len(ALL_TARGETS)
        assert n_registry == n_dirs, (
            f"Registry has {n_registry} entries but there are {n_dirs} target directories"
        )


# ===========================================================================
# Section 5: Scorer Integration
# ===========================================================================


@pytest.mark.eval
class TestScorerIntegration:
    """Score PTTs against ground truth for every target."""

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_perfect_ptt_scores_100(self, target_name: str):
        """A programmatically-constructed perfect PTT scores 100%."""
        gt = _load_gt(target_name)
        ptt = build_perfect_ptt(gt)
        result = score_ptt(gt, ptt)
        assert result.summary.final_score == 100, (
            f"{target_name}: expected 100, got {result.summary.final_score}. "
            f"Objectives: {[(r.id, r.status, r.evidence) for r in result.objective_results]}"
        )
        assert result.summary.passed is True

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_empty_ptt_scores_zero(self, target_name: str):
        """An empty PTT scores 0 points."""
        gt = _load_gt(target_name)
        empty_ptt = {"engagement": {"hosts": []}}
        result = score_ptt(gt, empty_ptt)
        assert result.summary.points_achieved == 0

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_partial_scores_between(self, target_name: str):
        """A PTT satisfying only the first objective scores > 0 and < 100."""
        gt = _load_gt(target_name)
        ptt = build_perfect_ptt(gt)

        # Strip loot, credentials, and reduce access to none
        # This should satisfy technique-based objectives but miss
        # exploitation, flag_capture, and credential_discovery
        host = ptt["engagement"]["hosts"][0]
        host["access_level"] = "none"
        host["findings"] = {"loot": [], "credentials": []}

        result = score_ptt(gt, ptt)
        assert result.summary.points_achieved > 0, (
            f"{target_name}: expected > 0, got {result.summary.points_achieved}"
        )
        assert result.summary.points_achieved < 100, (
            f"{target_name}: expected < 100, got {result.summary.points_achieved}"
        )


# ===========================================================================
# Section 6: Special-Case Tests
# ===========================================================================


@pytest.mark.eval
class TestInfoDisclosureTargets:
    """Info-disclosure-only targets (dns-zone-transfer, grafana) don't require RCE."""

    def test_dns_no_rce_required(self):
        gt = _load_gt("dns-zone-transfer")
        assert gt.required_outcomes.min_access_level == "none"

    def test_grafana_no_rce_required(self):
        gt = _load_gt("grafana-cve-2021-43798")
        assert gt.required_outcomes.min_access_level == "none"

    def test_dns_perfect_score_with_access_none(self):
        """Info-disclosure target passes even with access_level='none'."""
        gt = _load_gt("dns-zone-transfer")
        ptt = build_perfect_ptt(gt)
        # Verify the builder set access to none
        assert ptt["engagement"]["hosts"][0]["access_level"] == "none"
        result = score_ptt(gt, ptt)
        assert result.summary.final_score == 100
        assert result.summary.passed is True

    def test_grafana_perfect_score_with_access_none(self):
        gt = _load_gt("grafana-cve-2021-43798")
        ptt = build_perfect_ptt(gt)
        assert ptt["engagement"]["hosts"][0]["access_level"] == "none"
        result = score_ptt(gt, ptt)
        assert result.summary.final_score == 100
        assert result.summary.passed is True


@pytest.mark.eval
class TestMultiContainerTargets:
    """Multi-container targets have correct compose structure."""

    def test_php_fpm_has_two_services(self):
        data = _load_compose("php-fpm-rce")
        assert len(data["services"]) == 2

    def test_confluence_has_two_services(self):
        data = _load_compose("confluence-ognl-injection")
        assert len(data["services"]) == 2

    def test_kibana_has_two_services(self):
        data = _load_compose("kibana-prototype-pollution")
        assert len(data["services"]) == 2

    def test_zabbix_has_four_services(self):
        data = _load_compose("zabbix-trapper-rce")
        assert len(data["services"]) == 4

    @pytest.mark.parametrize("target_name", MULTI_CONTAINER_TARGETS)
    def test_multi_container_share_network(self, target_name: str):
        """All multi-container targets define a shared network."""
        data = _load_compose(target_name)
        assert "networks" in data, f"{target_name}: missing networks section"


@pytest.mark.eval
class TestJenkinsCustomScoring:
    """Jenkins uses a custom 6-objective scoring model."""

    def test_jenkins_has_six_objectives(self):
        gt = _load_gt("jenkins-file-read")
        assert len(gt.objectives) == 6

    def test_jenkins_dependency_chain(self):
        """vuln-discovery -> file-read -> cred-extraction -> initial-access-rce -> flag-root."""
        gt = _load_gt("jenkins-file-read")
        deps = {obj.id: obj.depends_on for obj in gt.objectives}
        assert deps["file-read"] == "vuln-discovery-jenkins"
        assert deps["cred-extraction"] == "file-read"
        assert deps["initial-access-rce"] == "cred-extraction"
        assert deps["flag-root"] == "initial-access-rce"

    def test_jenkins_perfect_score(self):
        gt = _load_gt("jenkins-file-read")
        ptt = build_perfect_ptt(gt)
        result = score_ptt(gt, ptt)
        assert result.summary.final_score == 100
