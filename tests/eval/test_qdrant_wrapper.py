"""Tests for qdrant-wrapper.py semantic search."""

import json
import sys
import urllib.request
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Import the wrapper module (hyphenated filename requires importlib)
sys.path.insert(0, str(Path(__file__).parents[2] / "infrastructure" / "PrEP" / "servers"))
import importlib
qdrant_wrapper = importlib.import_module("qdrant-wrapper")


class TestHandleFind:
    """Tests for handle_find() vector search."""

    def test_returns_unavailable_when_qdrant_down(self):
        """When Qdrant is unreachable, returns helpful unavailable message."""
        qdrant_wrapper._available = None

        with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
            result = qdrant_wrapper.handle_find("drupal exploit")

        assert not result.get("isError", False)
        text = result["content"][0]["text"]
        assert "QDRANT UNAVAILABLE" in text

    def test_returns_formatted_technique_cards(self):
        """When Qdrant returns results, formats them as readable technique cards."""
        qdrant_wrapper._available = True

        fake_embedding = [0.1] * 384
        fake_qdrant_response = json.dumps({
            "result": [
                {
                    "id": "abc123",
                    "score": 0.85,
                    "payload": {
                        "document": "service: http | Drupal RCE",
                        "metadata": {
                            "name": "Exploit Drupal File Upload",
                            "category": "exploitation",
                            "trigger": {"service": "http", "indicators": ["Drupal 8.x"]},
                            "prerequisites": {"access": "none", "tools": ["curl"]},
                            "execution": ["curl -X POST http://$TARGET/user/register ..."],
                            "success_indicators": ["uid=www-data"],
                            "references": {"cve": "CVE-2018-7600"},
                        },
                    },
                }
            ],
            "status": "ok",
        }).encode()

        mock_vec = MagicMock()
        mock_vec.tolist.return_value = fake_embedding
        mock_embed_instance = MagicMock()
        mock_embed_instance.embed.return_value = [mock_vec]

        with patch.object(qdrant_wrapper, "_embedder", mock_embed_instance), \
             patch.object(qdrant_wrapper, "_available", True), \
             patch("urllib.request.urlopen") as mock_urlopen:

            mock_resp = MagicMock()
            mock_resp.read.return_value = fake_qdrant_response
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = qdrant_wrapper.handle_find("drupal rce exploit")

        text = result["content"][0]["text"]
        assert "Exploit Drupal File Upload" in text
        assert "CVE-2018-7600" in text
        assert "exploitation" in text
        assert "curl" in text
        assert "0.85" in text

    def test_returns_no_results_message(self):
        """When Qdrant returns empty results, returns helpful message."""
        qdrant_wrapper._available = True

        fake_qdrant_response = json.dumps({
            "result": [],
            "status": "ok",
        }).encode()

        mock_vec = MagicMock()
        mock_vec.tolist.return_value = [0.1] * 384
        mock_embed_instance = MagicMock()
        mock_embed_instance.embed.return_value = [mock_vec]

        with patch.object(qdrant_wrapper, "_embedder", mock_embed_instance), \
             patch.object(qdrant_wrapper, "_available", True), \
             patch("urllib.request.urlopen") as mock_urlopen:

            mock_resp = MagicMock()
            mock_resp.read.return_value = fake_qdrant_response
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = qdrant_wrapper.handle_find("nonexistent technique xyz")

        text = result["content"][0]["text"]
        assert "No techniques found" in text


def _qdrant_reachable() -> bool:
    """Check if Qdrant is reachable on localhost for integration tests."""
    try:
        req = urllib.request.Request("http://localhost:6333/healthz", method="GET")
        with urllib.request.urlopen(req, timeout=2):
            return True
    except Exception:
        return False


def _fastembed_available() -> bool:
    """Check if fastembed is installed."""
    try:
        import fastembed  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(
    not _qdrant_reachable() or not _fastembed_available(),
    reason="Qdrant not running or fastembed not installed",
)
class TestQdrantIntegration:
    """Integration tests requiring a running Qdrant instance with fastembed."""

    def test_search_returns_relevant_results(self):
        """Searching for 'smb anonymous share' returns technique cards."""
        qdrant_wrapper._available = None  # Reset cache
        qdrant_wrapper.QDRANT_URL = "http://localhost:6333"

        result = qdrant_wrapper.handle_find("smb anonymous share enumeration")
        text = result["content"][0]["text"]

        # Should return technique cards, not unavailable/error message
        assert "QDRANT UNAVAILABLE" not in text
        assert "EMBEDDING MODEL UNAVAILABLE" not in text
        assert "##" in text  # Has at least one technique card header
