#!/usr/bin/env python3
"""
Integration tests for session state persistence and restart scenarios.

Tests verify that:
- SessionMemory collections persist in Qdrant across instance restarts
- SessionStateManager state persists to disk and restores correctly
- Attack logs survive manager restarts
- Memory blocks regenerate accurately from persisted state

Run with:
    uv run pytest tests/integration/test_state_persistence.py -v

Qdrant tests only:
    uv run pytest tests/integration/test_state_persistence.py -v -m qdrant
"""

import json
import sys
from pathlib import Path

import pytest

# Add infrastructure/PrEP to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "infrastructure" / "PrEP"))

from session_state import (
    SessionStateManager,
    Credential,
    CredentialType,
    ShellSession,
    ShellType,
    AccessLevel,
)


# =============================================================================
# SessionMemory Persistence Tests (Qdrant-backed)
# =============================================================================

@pytest.mark.qdrant
class TestSessionMemoryPersistence:
    """Tests for SessionMemory collection persistence in Qdrant."""

    def test_collection_persistence_across_instances(self, session_memory_factory):
        """
        Collections should persist in Qdrant after SessionMemory instance is deleted.

        Scenario:
        1. Create SessionMemory, index an event
        2. Delete the instance
        3. Create new SessionMemory for same target
        4. Search should find the previously indexed event
        """
        target_name = "persistence_test_target"

        # Create first instance and index an event
        mem1 = session_memory_factory(target_name)
        collection_name = mem1.collection_name

        success = mem1.index_event(
            event_type="technique_attempt",
            context="Exploited CVE-2021-44228 Log4Shell via JNDI injection",
            outcome="success",
            technique_id="log4shell_exploit",
            tags=["cve-2021-44228", "rce", "java"],
        )
        assert success is True

        # Verify the event was indexed
        stats = mem1.get_stats()
        assert stats["points_count"] >= 1

        # Delete the first instance
        del mem1

        # Create a new instance for the same target
        mem2 = session_memory_factory(target_name)

        # Should get the same collection name (deterministic hash)
        assert mem2.collection_name == collection_name

        # Search should find the event indexed by the first instance
        results = mem2.search("Log4Shell JNDI")

        assert len(results) >= 1
        assert results[0].technique_id == "log4shell_exploit"
        assert "Log4Shell" in results[0].context or "JNDI" in results[0].context
        assert results[0].outcome == "success"


# =============================================================================
# SessionStateManager Persistence Tests (File-backed)
# =============================================================================

class TestSessionStateManagerPersistence:
    """Tests for SessionStateManager disk persistence."""

    def test_state_manager_full_persistence_cycle(self, tmp_path):
        """
        All state components should survive manager restart.

        Scenario:
        1. Create manager with populated state:
           - 2 credentials
           - 1 hypothesis
           - 1 shell session
           - 3 cached queries
        2. Save all state
        3. Delete manager instance
        4. Create new manager for same target/directory
        5. Verify all state is restored correctly
        """
        target = "10.129.99.42"

        # Create first manager instance
        mgr1 = SessionStateManager.from_target(target, base_path=str(tmp_path))
        session_id = mgr1.state.session_id

        # Add 2 credentials
        cred1 = Credential(
            username="admin",
            secret="P@ssw0rd123",
            secret_type=CredentialType.PASSWORD,
            source="hydra brute force",
            valid_for=["ssh", "mysql"],
            verified=True,
        )
        cred2 = Credential(
            username="backup",
            secret="$6$rounds=5000$salt$hashvalue",
            secret_type=CredentialType.HASH,
            source="/etc/shadow",
            domain="CORP",
        )
        cred1_id = mgr1.add_credential(cred1)
        cred2_id = mgr1.add_credential(cred2)

        # Add 1 hypothesis
        hyp_id = mgr1.add_hypothesis(
            description="Kernel CVE-2024-1086 for privilege escalation",
            confidence=0.75,
            priority=1,
            evidence=["Kernel version 5.15.0 detected", "SUID binary found"]
        )

        # Add 1 shell session
        shell = ShellSession(
            session_id="pwncat-1",
            session_type=ShellType.REVERSE,
            user="www-data",
            host="10.129.99.42",
            access_level=AccessLevel.USER,
            technique_id="web_shell_upload",
        )
        mgr1.add_shell(shell)

        # Add 3 cached queries
        mgr1.cache_query("linux privesc kernel", "qdrant-find", "Found 5 techniques")
        mgr1.cache_query("CVE-2024-1086", "google_web_search", "PoC available on GitHub")
        mgr1.cache_query("dirty pipe exploit", "qdrant-find", "Technique requires kernel < 5.16")

        # Save all state
        mgr1.save_all()

        # Delete the first manager
        del mgr1

        # Create new manager instance for same target
        mgr2 = SessionStateManager.from_target(target, base_path=str(tmp_path))

        # Verify session ID persisted (same session continues)
        assert mgr2.state.session_id == session_id

        # Verify credentials restored
        creds = mgr2.get_all_credentials()
        assert len(creds) == 2

        admin_cred = next((c for c in creds if c.username == "admin"), None)
        assert admin_cred is not None
        assert admin_cred.secret == "P@ssw0rd123"
        assert admin_cred.verified is True
        assert "ssh" in admin_cred.valid_for
        assert "mysql" in admin_cred.valid_for

        backup_cred = next((c for c in creds if c.username == "backup"), None)
        assert backup_cred is not None
        assert backup_cred.secret_type == CredentialType.HASH
        assert backup_cred.domain == "CORP"

        # Verify hypothesis restored
        hyp = mgr2.get_hypothesis_by_id(hyp_id)
        assert hyp is not None
        assert "CVE-2024-1086" in hyp.description
        assert hyp.confidence == 0.75
        assert hyp.priority == 1
        assert len(hyp.evidence_for) == 2

        # Verify shell session restored
        shells = mgr2.get_active_shells()
        assert len(shells) == 1
        assert shells[0].session_id == "pwncat-1"
        assert shells[0].user == "www-data"
        assert shells[0].access_level == AccessLevel.USER

        # Verify access level updated from shell
        assert mgr2.state.current_access_level == AccessLevel.USER

        # Verify query cache restored
        cached1 = mgr2.check_query_cache("linux privesc kernel", "qdrant-find")
        assert cached1 is not None
        assert "5 techniques" in cached1.results_summary

        cached2 = mgr2.check_query_cache("CVE-2024-1086", "google_web_search")
        assert cached2 is not None
        assert "GitHub" in cached2.results_summary

        cached3 = mgr2.check_query_cache("dirty pipe exploit", "qdrant-find")
        assert cached3 is not None

    def test_attack_log_survives_restart(self, tmp_path):
        """
        Attack log entries should persist across manager restarts.

        Scenario:
        1. Log 5 actions via manager.log_action()
        2. Delete manager instance
        3. Create new manager for same target
        4. Read attack_log.jsonl
        5. Verify all 5 entries are present
        """
        target = "10.129.77.15"

        # Create manager and log 5 actions
        mgr1 = SessionStateManager.from_target(target, base_path=str(tmp_path))

        # Log diverse action types
        mgr1.log_action("technique_start", {
            "technique_id": "sqli_union",
            "target_service": "http://10.129.77.15:80/login"
        })
        mgr1.log_action("technique_complete", {
            "technique_id": "sqli_union",
            "success": False,
            "reason": "WAF blocking"
        })
        mgr1.log_action("credential_discovered", {
            "username": "admin",
            "source": "database dump",
            "credential_id": "cred-abc123"
        })
        mgr1.log_action("shell_established", {
            "session_id": "rev-001",
            "user": "www-data",
            "access_level": "user"
        })
        mgr1.log_action("flag_captured", {
            "flag_type": "user",
            "flag_value": "HTB{test_flag_12345}"
        })

        # Save state (though log is append-only)
        mgr1.save_all()

        # Delete manager
        session_dir = mgr1.session_dir
        del mgr1

        # Create new manager instance
        mgr2 = SessionStateManager.from_target(target, base_path=str(tmp_path))

        # Read the attack log directly
        log_path = mgr2.session_dir / "attack_log.jsonl"
        assert log_path.exists()

        with open(log_path, 'r') as f:
            lines = f.readlines()

        assert len(lines) == 5

        # Parse and verify entries
        entries = [json.loads(line) for line in lines]

        action_types = [e["action_type"] for e in entries]
        assert "technique_start" in action_types
        assert "technique_complete" in action_types
        assert "credential_discovered" in action_types
        assert "shell_established" in action_types
        assert "flag_captured" in action_types

        # Verify specific entry content
        flag_entry = next(e for e in entries if e["action_type"] == "flag_captured")
        assert flag_entry["flag_type"] == "user"
        assert flag_entry["flag_value"] == "HTB{test_flag_12345}"
        assert "timestamp" in flag_entry

    def test_memory_block_regenerates_from_persisted_state(self, tmp_path):
        """
        Memory block should accurately reflect persisted state after restart.

        Scenario:
        1. Populate full state and save
        2. Delete manager instance
        3. Create new manager and generate memory block
        4. Verify block contains all persisted data
        """
        target = "10.129.55.88"

        # Create and populate manager
        mgr1 = SessionStateManager.from_target(target, base_path=str(tmp_path))

        # Set access level and flag
        mgr1.state.current_access_level = AccessLevel.USER
        mgr1.state.flags_captured["user"] = "HTB{persistence_test_flag}"

        # Add credentials
        mgr1.add_credential(Credential(
            username="dbadmin",
            secret="db_secret_pass",
            verified=True,
            valid_for=["mysql", "postgres"],
        ))
        mgr1.add_credential(Credential(
            username="sysadmin",
            secret="sys_secret_key",
            secret_type=CredentialType.SSH_KEY,
            valid_for=["ssh"],
        ))

        # Add hypotheses with different confidence levels
        mgr1.add_hypothesis(
            description="MySQL UDF for root escalation",
            confidence=0.85,
            priority=1,
        )
        mgr1.add_hypothesis(
            description="Cron job misconfiguration",
            confidence=0.55,
            priority=2,
        )

        # Add shell
        mgr1.add_shell(ShellSession(
            session_id="ssh-session-1",
            session_type=ShellType.SSH,
            user="dbadmin",
            access_level=AccessLevel.USER,
        ))

        # Add query cache entry
        mgr1.cache_query("mysql privilege escalation", "qdrant-find", "Found UDF technique")

        # Save all
        mgr1.save_all()
        del mgr1

        # Create new manager and generate memory block
        mgr2 = SessionStateManager.from_target(target, base_path=str(tmp_path))
        block = mgr2.generate_memory_block()

        # Verify block content
        assert "## Current Session State" in block

        # Target and access level
        assert target in block
        assert "user" in block.lower()

        # Flags
        assert "user captured" in block.lower()

        # Credentials (secrets should be masked)
        assert "dbadmin" in block
        assert "sysadmin" in block
        assert "***" in block  # Secrets masked
        assert "db_secret_pass" not in block  # Secret not exposed
        assert "sys_secret_key" not in block  # Secret not exposed

        # Hypotheses with labels
        assert "MySQL UDF" in block or "root escalation" in block
        assert "[HIGH" in block  # 0.85 confidence = HIGH
        assert "0.85" in block or "0.8" in block  # Confidence value

        # Shells
        assert "ssh" in block.lower()
        assert "dbadmin" in block

        # Query cache
        assert "mysql" in block.lower()


# =============================================================================
# Edge Cases and Concurrency
# =============================================================================

class TestPersistenceEdgeCases:
    """Edge case tests for persistence scenarios."""

    def test_empty_state_persists_correctly(self, tmp_path):
        """Manager with no added state should persist and restore cleanly."""
        target = "10.129.1.1"

        # Create empty manager
        mgr1 = SessionStateManager.from_target(target, base_path=str(tmp_path))
        session_id = mgr1.state.session_id
        mgr1.save_all()
        del mgr1

        # Restore
        mgr2 = SessionStateManager.from_target(target, base_path=str(tmp_path))

        assert mgr2.state.session_id == session_id
        assert mgr2.state.current_access_level == AccessLevel.NONE
        assert len(mgr2.get_all_credentials()) == 0
        assert len(mgr2.get_active_hypotheses()) == 0
        assert len(mgr2.get_active_shells()) == 0

    def test_incremental_updates_persist(self, tmp_path):
        """Multiple save cycles should accumulate state correctly."""
        target = "10.129.2.2"

        # First session: add credential
        mgr1 = SessionStateManager.from_target(target, base_path=str(tmp_path))
        mgr1.add_credential(Credential(username="user1", secret="pass1"))
        mgr1.save_all()
        del mgr1

        # Second session: add another credential
        mgr2 = SessionStateManager.from_target(target, base_path=str(tmp_path))
        assert len(mgr2.get_all_credentials()) == 1
        mgr2.add_credential(Credential(username="user2", secret="pass2"))
        mgr2.save_all()
        del mgr2

        # Third session: add hypothesis
        mgr3 = SessionStateManager.from_target(target, base_path=str(tmp_path))
        assert len(mgr3.get_all_credentials()) == 2
        mgr3.add_hypothesis("Test hypothesis", 0.6)
        mgr3.save_all()
        del mgr3

        # Final verification
        mgr4 = SessionStateManager.from_target(target, base_path=str(tmp_path))
        assert len(mgr4.get_all_credentials()) == 2
        assert len(mgr4.get_active_hypotheses()) == 1

        usernames = [c.username for c in mgr4.get_all_credentials()]
        assert "user1" in usernames
        assert "user2" in usernames


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
