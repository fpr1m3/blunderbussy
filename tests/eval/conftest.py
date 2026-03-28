"""Shared fixtures and helpers for eval target package tests."""

import logging
import os
from pathlib import Path
from typing import Optional

import pytest
import yaml

from eval_scorer import (
    ACCESS_LEVEL_ORDER,
    GroundTruth,
    load_ground_truth,
)

logger = logging.getLogger("eval_test")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s: %(message)s"))
    logger.addHandler(handler)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

EVAL_DIR = Path(__file__).parent
TARGETS_DIR = EVAL_DIR / "targets"
REGISTRY_PATH = EVAL_DIR / "registry.yaml"
CATALOG_PATH = EVAL_DIR / "vulnhub_catalog.yaml"


# ---------------------------------------------------------------------------
# Target discovery (used by parametrize at collection time)
# ---------------------------------------------------------------------------

def discover_targets() -> list[str]:
    """Return sorted list of all target directory names."""
    if not TARGETS_DIR.is_dir():
        return []
    return sorted(
        d.name
        for d in TARGETS_DIR.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def registry_data() -> dict:
    """Load and cache registry.yaml for the entire test session."""
    with open(REGISTRY_PATH) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# PTT construction helpers
# ---------------------------------------------------------------------------

def build_perfect_ptt(gt: GroundTruth) -> dict:
    """Programmatically construct a PTT that satisfies every objective.

    Reads the ground truth objectives and builds a minimal PTT dict
    that the scorer will score as 100%.  This avoids hand-crafting
    PTTs for each of the 23 targets.
    """
    # Determine required access level
    max_access = "none"
    for obj in gt.objectives:
        mc = obj.match
        # exploitation checks access_level_min
        if mc.access_level_min:
            if ACCESS_LEVEL_ORDER.get(mc.access_level_min, 0) > ACCESS_LEVEL_ORDER.get(max_access, 0):
                max_access = mc.access_level_min
        # privilege_escalation checks access_level
        if mc.access_level:
            if ACCESS_LEVEL_ORDER.get(mc.access_level, 0) > ACCESS_LEVEL_ORDER.get(max_access, 0):
                max_access = mc.access_level

    logger.debug("Target %s: max_access_level=%s", gt.target_name, max_access)

    # Collect all unique service ports from objectives
    ports: set[int] = set()
    for obj in gt.objectives:
        if obj.match.service_port is not None:
            ports.add(obj.match.service_port)
    # Ensure at least one port so techniques have a service to attach to
    if not ports:
        ports.add(80)

    # Build techniques per service port
    # Walk objectives that need technique matching
    technique_categories = {
        "vulnerability_discovery",
        "service_discovery",
        "information_extraction",
    }
    # Map port -> list of techniques
    port_techniques: dict[int, list[dict]] = {p: [] for p in ports}
    # Also track objectives that need techniques but have no port
    portless_techniques: list[dict] = []

    for obj in gt.objectives:
        if obj.category not in technique_categories:
            continue
        tech: dict = {
            "name": f"{obj.id} technique",
            "status": obj.match.technique_status or "success",
        }
        if obj.match.cve:
            tech["cve"] = obj.match.cve
        if obj.match.service_port is not None:
            port_techniques[obj.match.service_port].append(tech)
        else:
            portless_techniques.append(tech)

    # Attach portless techniques to the first port's service
    if portless_techniques:
        first_port = sorted(ports)[0]
        port_techniques[first_port].extend(portless_techniques)

    # Build service entries
    services = []
    for port in sorted(ports):
        techniques = port_techniques.get(port, [])
        # Ensure at least one success technique per service
        if not techniques:
            techniques = [{"name": "generic-scan", "status": "success"}]
        services.append({
            "port": port,
            "protocol": "tcp",
            "name": f"service-{port}",
            "vectors": [
                {
                    "name": "eval-vector",
                    "techniques": techniques,
                }
            ],
        })

    # Build loot from flag_capture objectives
    loot = []
    for obj in gt.objectives:
        if obj.category == "flag_capture":
            mc = obj.match
            loot.append({
                "type": mc.loot_type or "flag",
                "name": mc.loot_name or "flag",
                "value": mc.flag_value or "EVAL{unknown}",
            })

    # Build credentials from credential_discovery objectives
    credentials = []
    for obj in gt.objectives:
        if obj.category == "credential_discovery":
            if obj.match.has_credentials:
                credentials.append({
                    "username": "admin",
                    "secret": "password123",
                })

    # Assemble the PTT
    ptt = {
        "engagement": {
            "status": "completed",
            "hosts": [
                {
                    "ip": "10.0.0.1",
                    "hostname": f"eval-{gt.target_name}",
                    "access_level": max_access,
                    "services": services,
                    "findings": {
                        "loot": loot,
                        "credentials": credentials,
                    },
                }
            ],
        }
    }

    logger.debug(
        "Built perfect PTT for %s: %d services, %d loot, %d creds, access=%s",
        gt.target_name,
        len(services),
        len(loot),
        len(credentials),
        max_access,
    )
    return ptt
