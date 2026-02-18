"""Tests for the session fixture conftest helper."""

import os
from pathlib import Path

import pytest
import yaml


FIXTURE_NAMES = [
    "gavel-full-session",
    "expressway-completed",
    "conversor-rich",
    "high-surface",
    "empty-workspace",
    "stale-wrong-ip",
]


class TestSessionFixtureHelper:
    """Verify the session_fixture conftest helper."""

    def test_fixture_copies_to_tmpdir(self, session_fixture):
        """Fixture tree is copied into tmp_path."""
        path = session_fixture("gavel-full-session")
        assert (path / "context.yaml").exists()

    def test_sets_artifacts_path_env(self, session_fixture, monkeypatch):
        """ARTIFACTS_PATH env var points at tmp_path parent."""
        path = session_fixture("gavel-full-session")
        assert os.environ.get("ARTIFACTS_PATH") is not None
        assert Path(os.environ["ARTIFACTS_PATH"]).exists()

    def test_sets_target_env(self, session_fixture):
        """TARGET env var is set to fixture name."""
        path = session_fixture("gavel-full-session")
        assert os.environ.get("TARGET") is not None

    def test_cas_is_valid_yaml(self, session_fixture):
        """Copied context.yaml is valid YAML."""
        path = session_fixture("conversor-rich")
        cas = yaml.safe_load((path / "context.yaml").read_text())
        assert cas["cas_version"] in ("1.0", "1.1", "1.2")

    @pytest.mark.parametrize("name", FIXTURE_NAMES)
    def test_all_fixtures_loadable(self, session_fixture, name):
        """Every named fixture is loadable."""
        path = session_fixture(name)
        assert path.exists()
        assert (path / "context.yaml").exists()

    def test_unknown_fixture_raises(self, session_fixture):
        """Requesting a nonexistent fixture raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            session_fixture("does-not-exist")
