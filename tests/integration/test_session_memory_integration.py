#!/usr/bin/env python3
"""
Integration tests for SessionMemory with real Qdrant.

These tests require a running Qdrant instance at localhost:6333.
Start with: podman-compose up -d qdrant

Run with: uv run pytest tests/integration/test_session_memory_integration.py -v -m qdrant
Skip with: uv run pytest -m "not qdrant"
"""

import pytest

# Mark all tests in this module as requiring Qdrant
pytestmark = pytest.mark.qdrant


class TestQdrantFixtures:
    """Verify the Qdrant fixtures work correctly."""

    def test_qdrant_available_fixture(self, qdrant_available):
        """qdrant_available should return True or False."""
        assert isinstance(qdrant_available, bool)

    def test_skip_without_qdrant_skips_when_unavailable(self, skip_without_qdrant):
        """If we get here, Qdrant is available."""
        # This test only runs if Qdrant is up
        pass

    def test_qdrant_url_fixture(self, qdrant_url):
        """qdrant_url should return localhost URL."""
        assert qdrant_url == "http://localhost:6333"

    def test_session_memory_factory_creates_instance(self, session_memory_factory):
        """session_memory_factory should create SessionMemory with test prefix."""
        mem = session_memory_factory("my_target")

        # Should auto-prefix with test_
        assert "test" in mem.target.lower()
        assert mem.qdrant_url == "http://localhost:6333"
        assert mem.collection_name.startswith("dame_session_")


class TestSessionMemorySmoke:
    """Smoke tests for basic SessionMemory operations with real Qdrant."""

    def test_collection_creation(self, session_memory_factory):
        """Should create collection on first index."""
        mem = session_memory_factory("smoke_test_target")

        # Get stats before (collection shouldn't exist)
        stats_before = mem.get_stats()

        # Index an event (creates collection)
        success = mem.index_event(
            event_type="discovery",
            context="Found open SSH port on target",
            tags=["ssh", "port_22"],
        )

        assert success is True

        # Collection should now exist
        stats_after = mem.get_stats()
        assert stats_after["exists"] is True
        assert stats_after["points_count"] == 1

    def test_index_and_search_roundtrip(self, session_memory_factory):
        """Should index event and find it via search."""
        mem = session_memory_factory("roundtrip_test")

        # Index a distinctive event
        mem.index_event(
            event_type="technique_attempt",
            context="Attempted SQL injection UNION SELECT on login form",
            outcome="blocked",
            technique_id="sqli_union",
            tags=["sqli", "waf"],
        )

        # Search should find it
        results = mem.search("SQL injection login")

        assert len(results) >= 1
        assert results[0].event_type == "technique_attempt"
        assert "SQL" in results[0].context or "login" in results[0].context

    def test_collection_cleanup(self, session_memory_factory, qdrant_url):
        """Collections should be cleaned up after test."""
        mem = session_memory_factory("cleanup_test")
        collection_name = mem.collection_name

        # Create collection
        mem.index_event(
            event_type="discovery",
            context="Test event for cleanup verification",
        )

        # Verify it exists
        import requests
        resp = requests.get(f"{qdrant_url}/collections/{collection_name}")
        assert resp.status_code == 200

        # Note: Actual cleanup happens after the test via fixture teardown
        # This test just verifies we can create and verify collections
