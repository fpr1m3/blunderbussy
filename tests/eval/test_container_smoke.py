"""
Container smoke tests for eval targets.

Verifies that target containers actually start, expose expected ports,
and shut down cleanly.  Requires podman-compose.

Marked as integration tests -- skipped in CI by default.
Run with: uv run pytest tests/eval/test_container_smoke.py -v -m "eval and integration"
"""

import logging
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from conftest import TARGETS_DIR, discover_targets

logger = logging.getLogger("eval_test.smoke")

ALL_TARGETS = discover_targets()

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def podman_available():
    """Skip all container tests if podman-compose is not installed."""
    if shutil.which("podman-compose") is None:
        pytest.skip("podman-compose not available")


def _get_port_mappings(target_name: str) -> list[int]:
    """Extract host ports from compose.yaml."""
    compose_path = TARGETS_DIR / target_name / "compose.yaml"
    with open(compose_path) as f:
        data = yaml.safe_load(f)
    host_ports = []
    for svc in data.get("services", {}).values():
        for mapping in svc.get("ports", []):
            mapping_str = str(mapping)
            # Formats: "8080:80", "8080:80/tcp", "53:53/udp"
            host_part = mapping_str.split(":")[0].strip('"')
            try:
                host_ports.append(int(host_part))
            except ValueError:
                continue
    return host_ports


def _compose_up(target_name: str) -> subprocess.CompletedProcess:
    compose_path = TARGETS_DIR / target_name / "compose.yaml"
    return subprocess.run(
        ["podman-compose", "-f", str(compose_path), "up", "-d"],
        capture_output=True,
        text=True,
        timeout=120,
    )


def _compose_down(target_name: str) -> subprocess.CompletedProcess:
    compose_path = TARGETS_DIR / target_name / "compose.yaml"
    return subprocess.run(
        ["podman-compose", "-f", str(compose_path), "down"],
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture
def container_lifecycle(podman_available):
    """Start containers before test, tear down after regardless of outcome."""
    started_targets: list[str] = []

    def _start(target_name: str):
        result = _compose_up(target_name)
        started_targets.append(target_name)
        return result

    yield _start

    # Cleanup
    for name in started_targets:
        try:
            _compose_down(name)
        except Exception as exc:
            logger.warning("Cleanup failed for %s: %s", name, exc)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.eval
@pytest.mark.integration
class TestContainerSmoke:
    """Smoke tests that verify containers start and expose ports."""

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_compose_up(self, target_name: str, container_lifecycle):
        """podman-compose up -d succeeds."""
        result = container_lifecycle(target_name)
        assert result.returncode == 0, (
            f"{target_name}: compose up failed.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_ports_reachable(self, target_name: str, container_lifecycle):
        """All mapped TCP ports are reachable after startup."""
        result = container_lifecycle(target_name)
        if result.returncode != 0:
            pytest.skip(f"compose up failed for {target_name}")

        host_ports = _get_port_mappings(target_name)
        # Filter out UDP-only ports (DNS)
        compose_path = TARGETS_DIR / target_name / "compose.yaml"
        with open(compose_path) as f:
            data = yaml.safe_load(f)
        tcp_ports = []
        for svc in data.get("services", {}).values():
            for mapping in svc.get("ports", []):
                mapping_str = str(mapping)
                if "/udp" in mapping_str:
                    continue
                host_part = mapping_str.split(":")[0].strip('"')
                try:
                    tcp_ports.append(int(host_part))
                except ValueError:
                    continue

        # Give containers a moment to start listening
        time.sleep(3)

        unreachable = []
        for port in tcp_ports:
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                sock.close()
            except (ConnectionRefusedError, OSError, TimeoutError):
                unreachable.append(port)

        assert not unreachable, (
            f"{target_name}: ports not reachable after startup: {unreachable}"
        )

    @pytest.mark.parametrize("target_name", ALL_TARGETS)
    def test_compose_down_clean(self, target_name: str, podman_available):
        """podman-compose down exits cleanly (standalone, no prior up needed)."""
        result = _compose_down(target_name)
        # down should succeed (rc=0) or warn that nothing is running
        assert result.returncode == 0, (
            f"{target_name}: compose down failed.\n"
            f"stderr: {result.stderr}"
        )
