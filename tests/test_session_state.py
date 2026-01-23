#!/usr/bin/env python3
"""
Unit tests for Session State Management
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

import pytest

# Add infrastructure path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "infrastructure" / "PrEP"))

from session_state import (
    SessionStateManager,
    SessionState,
    Credential,
    CredentialType,
    CredentialStore,
    Hypothesis,
    HypothesisStatus,
    HypothesisStore,
    QueryCacheEntry,
    QueryCache,
    ShellSession,
    ShellType,
    AccessLevel,
    AnalyzedFile,
    extract_credentials_from_output,
    CREDENTIAL_PATTERNS,
    ConfidenceDelta,
    ConfidenceLevel,
)


@pytest.fixture
def temp_artifacts():
    """Create a temporary artifacts directory."""
    tmpdir = tempfile.mkdtemp(prefix="test_session_")
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def manager(temp_artifacts):
    """Create a SessionStateManager with temp directory."""
    return SessionStateManager.from_target("10.129.5.135", base_path=temp_artifacts)


class TestSessionStateManager:
    """Tests for SessionStateManager lifecycle."""

    def test_from_target_creates_new_session(self, temp_artifacts):
        """Test that from_target creates a new session if none exists."""
        mgr = SessionStateManager.from_target("10.129.5.135", base_path=temp_artifacts)

        assert mgr.state is not None
        assert mgr.state.target == "10.129.5.135"
        assert mgr.state.session_id.startswith("sess-")
        assert mgr.state.current_access_level == AccessLevel.NONE

    def test_save_and_load_preserves_state(self, manager, temp_artifacts):
        """Test that save_all and load_all preserve state."""
        # Modify state
        manager.state.current_access_level = AccessLevel.USER
        manager.state.flags_captured["user"] = "test_flag_123"
        manager.save_all()

        # Load fresh
        mgr2 = SessionStateManager.from_target("10.129.5.135", base_path=temp_artifacts)

        assert mgr2.state.current_access_level == AccessLevel.USER
        assert mgr2.state.flags_captured.get("user") == "test_flag_123"

    def test_session_directory_created(self, manager):
        """Test that session directory is created with correct structure."""
        manager.save_all()

        session_dir = manager.session_dir
        assert session_dir.exists()
        assert (session_dir / "state.yaml").exists()
        assert (session_dir / "files").is_dir()

    def test_file_permissions(self, manager):
        """Test that files have restrictive permissions."""
        manager.save_all()

        # Check directory permissions
        dir_mode = os.stat(manager.session_dir).st_mode & 0o777
        assert dir_mode == 0o700

        # Check file permissions
        state_mode = os.stat(manager.session_dir / "state.yaml").st_mode & 0o777
        assert state_mode == 0o600


class TestCredentialManagement:
    """Tests for credential operations."""

    def test_add_credential(self, manager):
        """Test adding a new credential."""
        cred = Credential(
            username="admin",
            secret="password123",
            secret_type=CredentialType.PASSWORD,
            source="hydra"
        )
        cred_id = manager.add_credential(cred)

        assert cred_id is not None
        assert len(manager.get_all_credentials()) == 1

    def test_credential_deduplication(self, manager):
        """Test that duplicate credentials are merged."""
        cred1 = Credential(username="admin", secret="pass1", source="test1")
        cred2 = Credential(username="admin", secret="pass2", source="test2")

        id1 = manager.add_credential(cred1)
        id2 = manager.add_credential(cred2)

        assert id1 == id2  # Same ID returned
        assert len(manager.get_all_credentials()) == 1

        # Secret should be updated
        stored = manager.get_all_credentials()[0]
        assert stored.secret == "pass2"

    def test_credential_with_domain(self, manager):
        """Test credentials with domain are separate from local."""
        local = Credential(username="admin", secret="local_pass")
        domain = Credential(username="admin", secret="domain_pass", domain="CORP")

        manager.add_credential(local)
        manager.add_credential(domain)

        assert len(manager.get_all_credentials()) == 2

    def test_mark_credential_verified(self, manager):
        """Test marking a credential as verified for a service."""
        cred = Credential(username="test", secret="pass")
        cred_id = manager.add_credential(cred)

        manager.mark_credential_verified(cred_id, "ssh")
        manager.mark_credential_verified(cred_id, "mysql")

        stored = manager.get_all_credentials()[0]
        assert stored.verified is True
        assert "ssh" in stored.valid_for
        assert "mysql" in stored.valid_for

    def test_get_credentials_for_service(self, manager):
        """Test filtering credentials by service."""
        cred1 = Credential(username="admin", secret="p1", valid_for=["ssh"])
        cred2 = Credential(username="root", secret="p2", valid_for=["mysql"])
        cred3 = Credential(username="web", secret="p3", valid_for=["ssh", "ftp"])

        manager.add_credential(cred1)
        manager.add_credential(cred2)
        manager.add_credential(cred3)

        ssh_creds = manager.get_credentials_for_service("ssh")
        assert len(ssh_creds) == 2
        assert all("ssh" in c.valid_for for c in ssh_creds)


class TestHypothesisManagement:
    """Tests for hypothesis operations."""

    def test_add_hypothesis(self, manager):
        """Test adding a new hypothesis."""
        hyp_id = manager.add_hypothesis(
            description="Kernel CVE-2024-1086",
            confidence=0.8,
            priority=1,
            evidence=["Kernel 5.15 detected"]
        )

        assert hyp_id.startswith("hyp-")
        hypotheses = manager.get_active_hypotheses()
        assert len(hypotheses) == 1
        assert hypotheses[0].description == "Kernel CVE-2024-1086"

    def test_update_hypothesis_confidence(self, manager):
        """Test updating hypothesis confidence."""
        hyp_id = manager.add_hypothesis("Test hypothesis", confidence=0.5)
        manager.update_hypothesis(hyp_id, confidence_delta=0.2)

        hyp = manager.get_active_hypotheses()[0]
        assert hyp.confidence == pytest.approx(0.7, abs=0.01)

    def test_update_hypothesis_evidence(self, manager):
        """Test adding evidence to hypothesis."""
        hyp_id = manager.add_hypothesis("Test", confidence=0.5)
        manager.update_hypothesis(hyp_id, evidence_for="New supporting evidence")
        manager.update_hypothesis(hyp_id, evidence_against="Contradicting evidence")

        hyp = manager.get_active_hypotheses()[0]
        assert "New supporting evidence" in hyp.evidence_for
        assert "Contradicting evidence" in hyp.evidence_against

    def test_update_hypothesis_status(self, manager):
        """Test changing hypothesis status."""
        hyp_id = manager.add_hypothesis("Test", confidence=0.8)
        manager.update_hypothesis(hyp_id, status=HypothesisStatus.CONFIRMED)

        # Should not appear in active hypotheses
        active = manager.get_active_hypotheses()
        assert len(active) == 0

    def test_hypothesis_sorting(self, manager):
        """Test hypotheses are sorted by priority then confidence."""
        manager.add_hypothesis("Low priority high conf", confidence=0.9, priority=3)
        manager.add_hypothesis("High priority low conf", confidence=0.3, priority=1)
        manager.add_hypothesis("High priority high conf", confidence=0.8, priority=1)

        hypotheses = manager.get_active_hypotheses()
        assert hypotheses[0].priority == 1
        assert hypotheses[0].confidence == 0.8  # Higher conf first within same priority


class TestQueryCache:
    """Tests for query caching."""

    def test_cache_query(self, manager):
        """Test caching a query."""
        manager.cache_query(
            query="linux privesc",
            tool="qdrant-find",
            results_summary="Found 3 techniques"
        )

        cached = manager.check_query_cache("linux privesc", "qdrant-find")
        assert cached is not None
        assert cached.results_summary == "Found 3 techniques"

    def test_cache_hit_increments_count(self, manager):
        """Test that cache hits increment the counter."""
        manager.cache_query("test query", "qdrant-find", "results")

        manager.check_query_cache("test query", "qdrant-find")
        manager.check_query_cache("test query", "qdrant-find")

        entry = manager.check_query_cache("test query", "qdrant-find")
        assert entry.hit_count == 3

    def test_cache_miss_for_different_tool(self, manager):
        """Test that same query for different tool is a cache miss."""
        manager.cache_query("test query", "qdrant-find", "results")

        cached = manager.check_query_cache("test query", "google_web_search")
        assert cached is None

    def test_cache_case_insensitive(self, manager):
        """Test that cache queries are case-insensitive."""
        manager.cache_query("Linux Privesc", "qdrant-find", "results")

        cached = manager.check_query_cache("linux privesc", "qdrant-find")
        assert cached is not None

    def test_cache_expiration(self, manager):
        """Test that expired entries are not returned."""
        manager.cache_query("test", "qdrant-find", "results", ttl_minutes=0)

        # Manually expire the entry
        entry = manager.query_cache.entries[0]
        entry.timestamp = (datetime.utcnow() - timedelta(hours=1)).isoformat()

        cached = manager.check_query_cache("test", "qdrant-find")
        assert cached is None

    def test_cache_max_entries(self, manager):
        """Test that cache enforces max entries."""
        manager.query_cache.max_entries = 5

        for i in range(10):
            manager.cache_query(f"query {i}", "qdrant-find", f"result {i}")

        assert len(manager.query_cache.entries) == 5


class TestShellManagement:
    """Tests for shell session tracking."""

    def test_add_shell(self, manager):
        """Test adding a shell session."""
        shell = ShellSession(
            session_id="pwncat-1",
            session_type=ShellType.REVERSE,
            user="www-data",
            host="10.129.5.135",
            access_level=AccessLevel.USER
        )
        manager.add_shell(shell)

        shells = manager.get_active_shells()
        assert len(shells) == 1
        assert shells[0].user == "www-data"

    def test_shell_updates_access_level(self, manager):
        """Test that adding shell updates access level."""
        assert manager.state.current_access_level == AccessLevel.NONE

        shell = ShellSession(
            session_id="1",
            access_level=AccessLevel.USER
        )
        manager.add_shell(shell)
        assert manager.state.current_access_level == AccessLevel.USER

        root_shell = ShellSession(
            session_id="2",
            access_level=AccessLevel.ROOT
        )
        manager.add_shell(root_shell)
        assert manager.state.current_access_level == AccessLevel.ROOT

    def test_capture_flag(self, manager):
        """Test flag capture recording."""
        manager.capture_flag("user", "a1b2c3d4e5f6789012345678abcdef12")

        assert manager.state.flags_captured.get("user") == "a1b2c3d4e5f6789012345678abcdef12"


class TestAttackLog:
    """Tests for attack logging."""

    def test_log_action(self, manager):
        """Test logging an action."""
        manager.log_action("technique_start", {"technique_id": "123", "name": "test"})

        log_path = manager.session_dir / "attack_log.jsonl"
        assert log_path.exists()

        import json
        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["action_type"] == "technique_start"
        assert entry["technique_id"] == "123"
        assert "timestamp" in entry

    def test_log_append_only(self, manager):
        """Test that log is append-only."""
        manager.log_action("action1", {"data": 1})
        manager.log_action("action2", {"data": 2})
        manager.log_action("action3", {"data": 3})

        log_path = manager.session_dir / "attack_log.jsonl"
        with open(log_path) as f:
            lines = f.readlines()

        assert len(lines) == 3


class TestMemoryBlock:
    """Tests for memory block generation."""

    def test_generate_memory_block(self, manager):
        """Test memory block generation with populated state."""
        # Add some state
        manager.state.current_access_level = AccessLevel.USER
        manager.state.flags_captured["user"] = "testflag"

        manager.add_credential(Credential(username="admin", secret="pass", verified=True, valid_for=["ssh"]))
        manager.add_hypothesis("Test hypothesis", confidence=0.8, priority=1)
        manager.add_shell(ShellSession(session_id="1", user="www-data", access_level=AccessLevel.USER))
        manager.cache_query("test query", "qdrant-find", "results")

        block = manager.generate_memory_block()

        assert "## Current Session State" in block
        assert "user captured" in block.lower()
        assert "admin" in block
        assert "[HIGH 0.8]" in block  # Updated format: [LABEL confidence]
        assert "www-data" in block
        assert "test query" in block

    def test_memory_block_masks_secrets(self, manager):
        """Test that secrets are masked in memory block."""
        manager.add_credential(Credential(username="admin", secret="supersecretpassword"))

        block = manager.generate_memory_block()

        assert "supersecretpassword" not in block
        assert "***" in block


class TestCredentialExtraction:
    """Tests for credential extraction from output."""

    def test_extract_hydra_credentials(self):
        """Test extracting credentials from hydra output."""
        output = """
        [22][ssh] host: 10.129.5.135   login: admin   password: secret123
        [22][ssh] host: 10.129.5.135   login: root   password: toor
        """
        creds = extract_credentials_from_output(output, source="hydra")

        assert len(creds) == 2
        assert any(c.username == "admin" and c.secret == "secret123" for c in creds)
        assert any(c.username == "root" and c.secret == "toor" for c in creds)

    def test_extract_hash(self):
        """Test extracting password hashes."""
        output = """
        root:$6$rounds=5000$saltsalt$hashhashhash:18000:0:99999:7:::
        admin:$1$salt$md5hash:18000:0:99999:7:::
        """
        creds = extract_credentials_from_output(output)

        assert len(creds) >= 2
        assert all(c.secret_type == CredentialType.HASH for c in creds)

    def test_extract_mysql_creds(self):
        """Test extracting MySQL credentials."""
        output = """
        CREATE USER 'dbuser'@'localhost' IDENTIFIED BY 'dbpassword123';
        """
        creds = extract_credentials_from_output(output)

        assert len(creds) >= 1
        assert any(c.username == "dbuser" and c.secret == "dbpassword123" for c in creds)

    def test_extract_env_secrets(self):
        """Test extracting secrets from .env output."""
        output = """
        DB_PASSWORD=mydbpass
        SECRET=api_key_12345
        """
        creds = extract_credentials_from_output(output)

        assert len(creds) >= 2
        assert any(c.secret == "mydbpass" for c in creds)
        assert any(c.secret == "api_key_12345" for c in creds)


class TestFileCache:
    """Tests for file analysis caching."""

    def test_cache_file_analysis(self, manager):
        """Test caching file analysis."""
        manager.cache_file_analysis(
            sha256="a" * 64,
            remote_path="/etc/passwd",
            local_path="/tmp/passwd",
            findings=["Contains root user", "www-data user found"]
        )

        cached = manager.get_cached_file("a" * 64)
        assert cached is not None
        assert cached.remote_path == "/etc/passwd"
        assert len(cached.findings) == 2


class TestPydanticModels:
    """Tests for Pydantic model validation."""

    def test_hypothesis_confidence_bounds(self):
        """Test that confidence is bounded 0-1."""
        with pytest.raises(ValueError):
            Hypothesis(description="test", confidence=1.5)

        with pytest.raises(ValueError):
            Hypothesis(description="test", confidence=-0.1)

    def test_hypothesis_priority_bounds(self):
        """Test that priority is bounded 1-5."""
        with pytest.raises(ValueError):
            Hypothesis(description="test", confidence=0.5, priority=0)

        with pytest.raises(ValueError):
            Hypothesis(description="test", confidence=0.5, priority=6)

    def test_query_cache_entry_expiration(self):
        """Test query cache entry expiration check."""
        entry = QueryCacheEntry(
            query_hash="test",
            query_text="test",
            tool="qdrant-find",
            ttl_minutes=60
        )
        assert not entry.is_expired()

        # Manually set old timestamp
        entry.timestamp = (datetime.utcnow() - timedelta(hours=2)).isoformat()
        assert entry.is_expired()


# =============================================================================
# Phase 5: Hypothesis Ranking Tests
# =============================================================================

class TestConfidenceConstants:
    """Tests for confidence constants."""

    def test_confidence_deltas(self):
        """Test confidence delta values."""
        assert ConfidenceDelta.EVIDENCE_CONFIRMS == 0.15
        assert ConfidenceDelta.EVIDENCE_CONTRADICTS == -0.20
        assert ConfidenceDelta.TECHNIQUE_SUCCESS == 0.10
        assert ConfidenceDelta.TECHNIQUE_FAIL == -0.05
        assert ConfidenceDelta.STALE_DECAY == -0.02
        assert ConfidenceDelta.BLOCKED_THRESHOLD == 0.1

    def test_confidence_levels(self):
        """Test confidence level thresholds."""
        assert ConfidenceLevel.HIGH == 0.7
        assert ConfidenceLevel.MEDIUM == 0.4
        assert ConfidenceLevel.LOW == 0.2
        assert ConfidenceLevel.ARCHIVE == 0.2
        assert ConfidenceLevel.PROMOTE == 0.9


class TestHypothesisRanking:
    """Tests for hypothesis ranking and confidence updates."""

    def test_get_hypothesis_by_id(self, manager):
        """Test getting hypothesis by ID."""
        hyp_id = manager.add_hypothesis(
            description="Test hypothesis",
            confidence=0.5,
            priority=2
        )

        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp is not None
        assert hyp.description == "Test hypothesis"

    def test_get_hypothesis_by_id_not_found(self, manager):
        """Test getting non-existent hypothesis."""
        hyp = manager.get_hypothesis_by_id("nonexistent")
        assert hyp is None

    def test_get_hypotheses_by_technique(self, manager):
        """Test finding hypotheses linked to a technique."""
        hyp_id = manager.add_hypothesis(
            description="SQLi to RCE",
            confidence=0.6,
            priority=2
        )
        hyp = manager.get_hypothesis_by_id(hyp_id)
        hyp.related_technique_ids = ["sqli_union", "file_write"]

        results = manager.get_hypotheses_by_technique("sqli_union")
        assert len(results) == 1
        assert results[0].id == hyp_id

    def test_update_hypothesis_for_technique_success(self, manager):
        """Test updating hypothesis confidence on technique success."""
        hyp_id = manager.add_hypothesis(
            description="Kernel exploit",
            confidence=0.5,
            priority=1
        )
        hyp = manager.get_hypothesis_by_id(hyp_id)
        hyp.related_technique_ids = ["kernel_exploit"]

        updated = manager.update_hypothesis_for_technique_outcome(
            technique_id="kernel_exploit",
            success=True,
            evidence="Exploit completed successfully"
        )

        assert hyp_id in updated
        updated_hyp = manager.get_hypothesis_by_id(hyp_id)
        assert updated_hyp.confidence == 0.5 + ConfidenceDelta.TECHNIQUE_SUCCESS
        assert "Exploit completed successfully" in updated_hyp.evidence_for

    def test_update_hypothesis_for_technique_failure(self, manager):
        """Test updating hypothesis confidence on technique failure."""
        hyp_id = manager.add_hypothesis(
            description="SSH brute force",
            confidence=0.6,
            priority=2
        )
        hyp = manager.get_hypothesis_by_id(hyp_id)
        hyp.related_technique_ids = ["ssh_brute"]

        updated = manager.update_hypothesis_for_technique_outcome(
            technique_id="ssh_brute",
            success=False,
            evidence="Authentication failed"
        )

        assert hyp_id in updated
        updated_hyp = manager.get_hypothesis_by_id(hyp_id)
        assert updated_hyp.confidence == 0.6 + ConfidenceDelta.TECHNIQUE_FAIL
        assert "Authentication failed" in updated_hyp.evidence_against

    def test_update_hypothesis_confidence(self, manager):
        """Test direct hypothesis confidence update."""
        hyp_id = manager.add_hypothesis(
            description="Test hypothesis",
            confidence=0.5,
            priority=2
        )

        result = manager.update_hypothesis_confidence(
            hyp_id=hyp_id,
            delta=0.15,
            reason="Evidence found",
            is_contradiction=False
        )

        assert result is True
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.confidence == 0.65
        assert "Evidence found" in hyp.evidence_for

    def test_update_hypothesis_confidence_contradiction(self, manager):
        """Test hypothesis confidence update with contradiction."""
        hyp_id = manager.add_hypothesis(
            description="Test hypothesis",
            confidence=0.5,
            priority=2
        )

        result = manager.update_hypothesis_confidence(
            hyp_id=hyp_id,
            delta=-0.20,
            reason="Disproved by scan",
            is_contradiction=True
        )

        assert result is True
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.confidence == 0.3
        assert "Disproved by scan" in hyp.evidence_against

    def test_block_hypothesis(self, manager):
        """Test blocking a hypothesis."""
        hyp_id = manager.add_hypothesis(
            description="Blocked hypothesis",
            confidence=0.7,
            priority=1
        )

        result = manager.block_hypothesis(hyp_id, "Firewall detected")

        assert result is True
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.status == HypothesisStatus.BLOCKED
        assert hyp.confidence == ConfidenceDelta.BLOCKED_THRESHOLD
        assert "Blocked: Firewall detected" in hyp.evidence_against

    def test_confidence_label(self, manager):
        """Test confidence label generation."""
        assert SessionStateManager.confidence_label(0.9) == "HIGH"
        assert SessionStateManager.confidence_label(0.7) == "HIGH"
        assert SessionStateManager.confidence_label(0.5) == "MED"
        assert SessionStateManager.confidence_label(0.4) == "MED"
        assert SessionStateManager.confidence_label(0.3) == "LOW"
        assert SessionStateManager.confidence_label(0.2) == "LOW"
        assert SessionStateManager.confidence_label(0.1) == "VERY LOW"

    def test_confidence_bounds(self, manager):
        """Test that confidence stays within 0-1 bounds."""
        hyp_id = manager.add_hypothesis(
            description="Bound test",
            confidence=0.95,
            priority=2
        )

        # Try to exceed 1.0
        manager.update_hypothesis_confidence(hyp_id, 0.20, "Big boost")
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.confidence == 1.0

        # Reset status and confidence to test lower bound
        hyp.status = HypothesisStatus.ACTIVE
        hyp.confidence = 0.05
        manager.update_hypothesis_confidence(hyp_id, -0.20, "Big drop", is_contradiction=True)
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.confidence == 0.0

    def test_auto_promote_on_high_confidence(self, manager):
        """Test that hypotheses are promoted when confidence reaches threshold."""
        hyp_id = manager.add_hypothesis(
            description="High confidence test",
            confidence=0.85,
            priority=1
        )
        hyp = manager.get_hypothesis_by_id(hyp_id)
        hyp.related_technique_ids = ["test_tech"]

        # This should push confidence to 0.95 and trigger promotion
        manager.update_hypothesis_for_technique_outcome(
            technique_id="test_tech",
            success=True
        )

        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.confidence >= ConfidenceLevel.PROMOTE
        assert hyp.status == HypothesisStatus.CONFIRMED


class TestHypothesisDecay:
    """Tests for hypothesis staleness decay."""

    def test_decay_stale_hypotheses(self, manager):
        """Test decaying stale hypotheses."""
        hyp_id = manager.add_hypothesis(
            description="Stale test",
            confidence=0.5,
            priority=2
        )

        # Manually set old updated_at
        hyp = manager.get_hypothesis_by_id(hyp_id)
        hyp.updated_at = (datetime.utcnow() - timedelta(hours=1)).isoformat()

        decayed = manager.decay_stale_hypotheses(stale_minutes=30)

        assert hyp_id in decayed
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.confidence < 0.5  # Should have decayed

    def test_no_decay_for_recent_hypotheses(self, manager):
        """Test that recent hypotheses don't decay."""
        hyp_id = manager.add_hypothesis(
            description="Recent test",
            confidence=0.5,
            priority=2
        )

        decayed = manager.decay_stale_hypotheses(stale_minutes=30)

        assert hyp_id not in decayed
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.confidence == 0.5


class TestHypothesisPruning:
    """Tests for hypothesis pruning."""

    def test_prune_promotes_high_confidence(self, manager):
        """Test that pruning promotes high confidence hypotheses."""
        hyp_id = manager.add_hypothesis(
            description="High confidence",
            confidence=0.95,
            priority=1
        )

        result = manager.prune_hypotheses()

        assert hyp_id in result["promoted"]
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.status == HypothesisStatus.CONFIRMED

    def test_prune_archives_low_confidence_old(self, manager):
        """Test that pruning archives low confidence old hypotheses."""
        hyp_id = manager.add_hypothesis(
            description="Low confidence old",
            confidence=0.1,
            priority=3
        )

        # Make it old enough to archive
        hyp = manager.get_hypothesis_by_id(hyp_id)
        hyp.created_at = (datetime.utcnow() - timedelta(hours=3)).isoformat()

        result = manager.prune_hypotheses()

        assert hyp_id in result["archived"]
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.status == HypothesisStatus.REJECTED

    def test_prune_keeps_low_confidence_new(self, manager):
        """Test that pruning keeps low confidence but new hypotheses."""
        hyp_id = manager.add_hypothesis(
            description="Low confidence new",
            confidence=0.15,
            priority=3
        )

        result = manager.prune_hypotheses()

        assert hyp_id not in result["archived"]
        hyp = manager.get_hypothesis_by_id(hyp_id)
        assert hyp.status == HypothesisStatus.ACTIVE


class TestMemoryBlockWithLabels:
    """Tests for memory block generation with confidence labels."""

    def test_memory_block_includes_labels(self, manager):
        """Test that memory block shows confidence labels."""
        manager.add_hypothesis(
            description="High priority kernel exploit",
            confidence=0.8,
            priority=1
        )
        manager.add_hypothesis(
            description="Medium SQLi path",
            confidence=0.5,
            priority=2
        )

        block = manager.generate_memory_block()

        assert "[HIGH 0.8]" in block
        assert "[MED 0.5]" in block


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
