"""Root pytest configuration for tests."""
import sys
from pathlib import Path

# CRITICAL: Add paths BEFORE pytest import to ensure they're available
# when pytest's assertion rewriter compiles test files
_root = Path(__file__).parent.parent
_prep_path = str(_root / "infrastructure" / "PrEP")
_hexstrike_path = str(_root / "infrastructure" / "hexstrike-recon")
_hooks_path = str(_root / "infrastructure" / "PrEP" / "hooks")

if _prep_path not in sys.path:
    sys.path.insert(0, _prep_path)
if _hexstrike_path not in sys.path:
    sys.path.insert(0, _hexstrike_path)
if _hooks_path not in sys.path:
    sys.path.insert(0, _hooks_path)

import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test (uses real parsers)"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow (involves network operations or long timeouts)"
    )
    config.addinivalue_line(
        "markers", "qdrant: mark test as requiring Qdrant container (session memory tests)"
    )
