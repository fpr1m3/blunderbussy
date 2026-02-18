"""Root pytest configuration for tests."""
import shutil
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
import yaml


_SESSIONS_DIR = _root / "tests" / "fixtures" / "sessions"


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
    config.addinivalue_line(
        "markers", "replay: mark test as hook trace replay (requires frozen fixtures)"
    )


@pytest.fixture
def session_fixture(tmp_path, monkeypatch):
    """Copy a frozen session fixture into tmp_path and set env vars.

    Usage::

        def test_hook(session_fixture):
            artifact_dir = session_fixture("gavel-full-session")
            # artifact_dir / "context.yaml" exists
            # os.environ["ARTIFACTS_PATH"] points at tmp_path
            # os.environ["TARGET"] is the fixture name
    """

    def _load(name: str) -> Path:
        src = _SESSIONS_DIR / name
        if not src.exists():
            raise FileNotFoundError(f"No fixture named '{name}' in {_SESSIONS_DIR}")

        dest = tmp_path / name
        shutil.copytree(src, dest)

        # Set env vars so hooks can discover the target
        monkeypatch.setenv("ARTIFACTS_PATH", str(tmp_path))
        monkeypatch.setenv("TARGET", name)

        # Write .current_target so hooks that read it find the right target
        (tmp_path / ".current_target").write_text(name)

        return dest

    return _load
