#!/usr/bin/env python3
"""
Tests for session_memory module.

Run with: uv run pytest tests/test_session_memory.py -v
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add infrastructure/PrEP to path
sys.path.insert(0, str(Path(__file__).parent.parent / "infrastructure" / "PrEP"))

from session_memory import (
    SessionMemory,
    SessionEvent,
    SearchResult,
    EventType,
    Outcome,
)


class TestSessionMemory:
    """Tests for SessionMemory class."""

    def test_collection_name_generation(self):
        """Collection name should be deterministic hash of target."""
        mem1 = SessionMemory("10.129.5.135", qdrant_url="http://localhost:6333")
        mem2 = SessionMemory("10.129.5.135", qdrant_url="http://localhost:6333")
        mem3 = SessionMemory("10.129.5.136", qdrant_url="http://localhost:6333")

        assert mem1.collection_name == mem2.collection_name
        assert mem1.collection_name != mem3.collection_name
        assert mem1.collection_name.startswith("dame_session_")

    def test_for_target_factory(self):
        """for_target factory should create SessionMemory with correct URL."""
        with patch.dict("os.environ", {"QDRANT_URL": "http://custom:6333"}):
            mem = SessionMemory.for_target("10.129.5.135")
            assert mem.qdrant_url == "http://custom:6333"
            assert mem.target == "10.129.5.135"

    def test_for_target_default_url(self):
        """for_target should use default URL if not specified."""
        with patch.dict("os.environ", {}, clear=True):
            mem = SessionMemory.for_target("10.129.5.135")
            assert mem.qdrant_url == "http://qdrant:6333"


class TestSessionEvent:
    """Tests for SessionEvent dataclass."""

    def test_event_creation(self):
        """Event should be created with all fields."""
        event = SessionEvent(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Tried SQLi on login form",
            outcome=Outcome.BLOCKED,
            technique_id="sqli_union",
            resolution="Need to bypass WAF",
            tags=["sqli", "waf"],
        )

        assert event.event_type == EventType.TECHNIQUE_ATTEMPT
        assert event.context == "Tried SQLi on login form"
        assert event.outcome == Outcome.BLOCKED
        assert event.technique_id == "sqli_union"
        assert event.resolution == "Need to bypass WAF"
        assert event.tags == ["sqli", "waf"]
        assert event.timestamp  # Auto-generated

    def test_event_to_payload(self):
        """to_payload should convert to dict for Qdrant."""
        event = SessionEvent(
            event_type=EventType.ERROR_RESOLUTION,
            context="Fixed WAF bypass",
            outcome=Outcome.SUCCESS,
            tags=["waf", "bypass"],
        )

        payload = event.to_payload()

        assert payload["event_type"] == "error_resolution"
        assert payload["context"] == "Fixed WAF bypass"
        assert payload["outcome"] == "success"
        assert payload["tags"] == ["waf", "bypass"]
        assert payload["technique_id"] is None
        assert payload["resolution"] is None

    def test_event_minimal(self):
        """Event with only required fields."""
        event = SessionEvent(
            event_type=EventType.DISCOVERY,
            context="Found interesting file",
        )

        assert event.outcome is None
        assert event.technique_id is None
        assert event.tags == []


class TestSearchResult:
    """Tests for SearchResult dataclass."""

    def test_search_result_creation(self):
        """SearchResult should hold all search result fields."""
        result = SearchResult(
            score=0.95,
            event_type="technique_attempt",
            context="SQLi attempt on port 80",
            timestamp="2026-01-23T10:00:00",
            technique_id="sqli_union",
            outcome="blocked",
            resolution=None,
            tags=["sqli"],
        )

        assert result.score == 0.95
        assert result.event_type == "technique_attempt"
        assert result.context == "SQLi attempt on port 80"
        assert result.outcome == "blocked"


class TestEventType:
    """Tests for EventType enum."""

    def test_event_types(self):
        """All event types should be defined."""
        assert EventType.TECHNIQUE_ATTEMPT.value == "technique_attempt"
        assert EventType.ERROR_RESOLUTION.value == "error_resolution"
        assert EventType.DISCOVERY.value == "discovery"
        assert EventType.CREDENTIAL_FOUND.value == "credential_found"
        assert EventType.ACCESS_GAINED.value == "access_gained"
        assert EventType.FLAG_CAPTURED.value == "flag_captured"


class TestOutcome:
    """Tests for Outcome enum."""

    def test_outcomes(self):
        """All outcomes should be defined."""
        assert Outcome.SUCCESS.value == "success"
        assert Outcome.FAILED.value == "failed"
        assert Outcome.BLOCKED.value == "blocked"
        assert Outcome.PARTIAL.value == "partial"
        assert Outcome.PENDING.value == "pending"


class TestSessionMemoryMocked:
    """Tests for SessionMemory with mocked Qdrant."""

    @pytest.fixture
    def mock_requests(self):
        """Mock requests module."""
        with patch("session_memory.requests") as mock:
            mock.get.return_value = MagicMock(status_code=200, json=lambda: {"result": {}})
            mock.put.return_value = MagicMock(status_code=200)
            mock.post.return_value = MagicMock(status_code=200, json=lambda: {"result": []})
            yield mock

    @pytest.fixture
    def mock_model(self):
        """Mock sentence transformer model."""
        with patch("session_memory.SentenceTransformer") as mock:
            model_instance = MagicMock()
            model_instance.encode.return_value = MagicMock(tolist=lambda: [0.1] * 384)
            mock.return_value = model_instance
            yield mock

    def test_get_stats_no_collection(self, mock_requests):
        """get_stats should return exists=False if collection missing."""
        mock_requests.get.return_value = MagicMock(status_code=404)

        mem = SessionMemory("10.129.5.135")
        stats = mem.get_stats()

        assert stats["exists"] is False
        assert stats["points_count"] == 0

    def test_get_stats_with_collection(self, mock_requests):
        """get_stats should return collection info."""
        mock_requests.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "result": {
                    "points_count": 42,
                    "vectors_count": 42,
                    "status": "green",
                }
            }
        )

        mem = SessionMemory("10.129.5.135")
        stats = mem.get_stats()

        assert stats["exists"] is True
        assert stats["points_count"] == 42
        assert stats["status"] == "green"

    def test_ensure_collection_creates_if_missing(self, mock_requests):
        """_ensure_collection should create collection if it doesn't exist."""
        mock_requests.get.return_value = MagicMock(status_code=404)
        mock_requests.put.return_value = MagicMock(status_code=200)

        mem = SessionMemory("10.129.5.135")
        result = mem._ensure_collection()

        assert result is True
        mock_requests.put.assert_called_once()

    def test_index_event_success(self, mock_requests, mock_model):
        """index_event should embed and upsert to Qdrant."""
        mock_requests.get.return_value = MagicMock(status_code=200)
        mock_requests.put.return_value = MagicMock(status_code=200)

        mem = SessionMemory("10.129.5.135")
        result = mem.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Tried SSH brute force",
            outcome=Outcome.FAILED,
            tags=["ssh", "brute_force"],
        )

        assert result is True
        mock_model.return_value.encode.assert_called_once_with("Tried SSH brute force")

    def test_index_event_string_types(self, mock_requests, mock_model):
        """index_event should accept string event_type and outcome."""
        mock_requests.get.return_value = MagicMock(status_code=200)
        mock_requests.put.return_value = MagicMock(status_code=200)

        mem = SessionMemory("10.129.5.135")
        result = mem.index_event(
            event_type="discovery",
            context="Found interesting file",
            outcome="success",
        )

        assert result is True

    def test_search_no_collection(self, mock_requests, mock_model):
        """search should return empty if collection doesn't exist."""
        mock_requests.get.return_value = MagicMock(status_code=404)

        mem = SessionMemory("10.129.5.135")
        results = mem.search("test query")

        assert results == []

    def test_search_with_results(self, mock_requests, mock_model):
        """search should return SearchResult objects."""
        mock_requests.get.return_value = MagicMock(status_code=200)
        mock_requests.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "result": [
                    {
                        "score": 0.9,
                        "payload": {
                            "event_type": "technique_attempt",
                            "context": "SQLi on login",
                            "timestamp": "2026-01-23T10:00:00",
                            "technique_id": "sqli",
                            "outcome": "blocked",
                            "resolution": None,
                            "tags": ["sqli"],
                        }
                    }
                ]
            }
        )

        mem = SessionMemory("10.129.5.135")
        results = mem.search("SQLi attempt")

        assert len(results) == 1
        assert isinstance(results[0], SearchResult)
        assert results[0].score == 0.9
        assert results[0].event_type == "technique_attempt"
        assert results[0].context == "SQLi on login"

    def test_search_with_filters(self, mock_requests, mock_model):
        """search should apply event_type and outcome filters."""
        mock_requests.get.return_value = MagicMock(status_code=200)
        mock_requests.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"result": []}
        )

        mem = SessionMemory("10.129.5.135")
        mem.search(
            "error",
            event_type=EventType.ERROR_RESOLUTION,
            outcome=Outcome.SUCCESS,
        )

        # Check filter was included in request
        call_args = mock_requests.post.call_args
        body = call_args[1]["json"]
        assert "filter" in body
        assert body["filter"]["must"][0]["key"] == "event_type"
        assert body["filter"]["must"][1]["key"] == "outcome"

    def test_search_errors_convenience(self, mock_requests, mock_model):
        """search_errors should filter by error_resolution and success."""
        mock_requests.get.return_value = MagicMock(status_code=200)
        mock_requests.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"result": []}
        )

        mem = SessionMemory("10.129.5.135")
        mem.search_errors("WAF blocking")

        call_args = mock_requests.post.call_args
        body = call_args[1]["json"]
        assert "filter" in body
        filters = {f["key"]: f["match"]["value"] for f in body["filter"]["must"]}
        assert filters["event_type"] == "error_resolution"
        assert filters["outcome"] == "success"

    def test_delete_collection(self, mock_requests):
        """delete_collection should call DELETE on Qdrant."""
        mock_requests.delete.return_value = MagicMock(status_code=200)

        mem = SessionMemory("10.129.5.135")
        result = mem.delete_collection()

        assert result is True
        mock_requests.delete.assert_called_once()


class TestEventIdGeneration:
    """Tests for event ID generation."""

    def test_event_id_deterministic(self):
        """Same event should get same ID."""
        mem = SessionMemory("10.129.5.135")

        event1 = SessionEvent(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Test context",
            timestamp="2026-01-23T10:00:00",
        )
        event2 = SessionEvent(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Test context",
            timestamp="2026-01-23T10:00:00",
        )

        id1 = mem._event_id(event1)
        id2 = mem._event_id(event2)

        assert id1 == id2

    def test_event_id_different_context(self):
        """Different context should get different ID."""
        mem = SessionMemory("10.129.5.135")

        event1 = SessionEvent(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Context A",
            timestamp="2026-01-23T10:00:00",
        )
        event2 = SessionEvent(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Context B",
            timestamp="2026-01-23T10:00:00",
        )

        id1 = mem._event_id(event1)
        id2 = mem._event_id(event2)

        assert id1 != id2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
