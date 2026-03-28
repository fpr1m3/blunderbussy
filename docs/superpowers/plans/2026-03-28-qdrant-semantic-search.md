# Qdrant Semantic Vector Search Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace broken keyword search in qdrant-wrapper.py with proper vector similarity search using fastembed embeddings.

**Architecture:** Install fastembed in the Dame container image with model weights baked in at build time. Rewrite the wrapper's `handle_find()` to embed queries via fastembed, then search Qdrant's `/points/search` REST endpoint using the named vector `fast-all-minilm-l6-v2`.

**Tech Stack:** fastembed (ONNX-based embeddings), Qdrant REST API, Python 3 stdlib (urllib)

**Spec:** `docs/superpowers/specs/2026-03-28-qdrant-semantic-search-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `infrastructure/dame/Dockerfile` | Modify (lines 86-87) | Add fastembed install + model pre-download |
| `infrastructure/PrEP/servers/qdrant-wrapper.py` | Rewrite (lines 43-76) | Replace broken handle_find() with vector search |
| `tests/eval/test_qdrant_wrapper.py` | Create | Unit tests for wrapper search + formatting |

---

### Task 1: Add fastembed to Dame Dockerfile

**Files:**
- Modify: `infrastructure/dame/Dockerfile:84-86`

- [ ] **Step 1: Add fastembed install and model pre-download to Dockerfile**

After the code-analysis-venv block (line 86), add a new section:

```dockerfile
# =============================================================================
# SEMANTIC SEARCH DEPENDENCIES
# =============================================================================
# fastembed: Lightweight ONNX-based embeddings for qdrant-wrapper semantic search
# Model baked in at build time to avoid download latency in ephemeral containers
RUN uv pip install --system fastembed && \
    python3 -c "from fastembed import TextEmbedding; TextEmbedding('sentence-transformers/all-MiniLM-L6-v2')"
```

Insert this between line 86 (`semgrep tiktoken tree-sitter chromadb`) and line 88 (`npm install -g @google/gemini-cli`).

- [ ] **Step 2: Verify Dockerfile syntax**

Run: `podman build --build-arg TARGET_PLATFORM=linux -t dame:linux -f infrastructure/dame/Dockerfile infrastructure/dame/ --dry-run 2>&1 | head -5`

If `--dry-run` isn't supported, just verify no syntax errors by checking the file parses:
Run: `grep -n 'fastembed' infrastructure/dame/Dockerfile`
Expected: Two lines — the pip install and the python3 pre-download.

- [ ] **Step 3: Commit**

```bash
git add infrastructure/dame/Dockerfile
git commit -m "feat(dame): add fastembed for semantic qdrant search"
```

---

### Task 2: Write failing tests for vector search wrapper

**Files:**
- Create: `tests/eval/test_qdrant_wrapper.py`

- [ ] **Step 1: Write test file with three test cases**

```python
"""Tests for qdrant-wrapper.py semantic search."""

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Import the wrapper module
sys.path.insert(0, str(Path(__file__).parents[2] / "infrastructure" / "PrEP" / "servers"))
import importlib
qdrant_wrapper = importlib.import_module("qdrant-wrapper")


class TestHandleFind:
    """Tests for handle_find() vector search."""

    def test_returns_unavailable_when_qdrant_down(self):
        """When Qdrant is unreachable, returns helpful unavailable message."""
        # Reset cached availability
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

        mock_embed_instance = MagicMock()
        mock_embed_instance.embed.return_value = [fake_embedding]

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

        mock_embed_instance = MagicMock()
        mock_embed_instance.embed.return_value = [[0.1] * 384]

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/eval/test_qdrant_wrapper.py -v`
Expected: FAIL — `_embedder` attribute doesn't exist, `handle_find` doesn't use vector search yet.

- [ ] **Step 3: Commit failing tests**

```bash
git add tests/eval/test_qdrant_wrapper.py
git commit -m "test(eval): add failing tests for qdrant vector search"
```

---

### Task 3: Rewrite qdrant-wrapper.py with vector search

**Files:**
- Modify: `infrastructure/PrEP/servers/qdrant-wrapper.py`

- [ ] **Step 1: Add embedder initialization at module level**

Replace the existing module-level cache variable (line 24) and add the embedder:

```python
# Cache availability and embedder for process lifetime
_available: bool | None = None
_embedder = None

FASTEMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
VECTOR_NAME = "fast-all-minilm-l6-v2"


def get_embedder():
    """Lazy-load fastembed TextEmbedding model. Returns None if unavailable."""
    global _embedder
    if _embedder is not None:
        return _embedder
    try:
        from fastembed import TextEmbedding
        _embedder = TextEmbedding(FASTEMBED_MODEL)
        return _embedder
    except ImportError:
        return None
```

- [ ] **Step 2: Replace handle_find() with vector search implementation**

Replace the entire `handle_find()` function (lines 43-76) with:

```python
def handle_find(query: str) -> dict:
    """Handle qdrant-find tool call with semantic vector search."""
    if not check_qdrant():
        return {
            "content": [{
                "type": "text",
                "text": (
                    "QDRANT UNAVAILABLE: The skills knowledge base is not reachable. "
                    "Proceed without skill lookups — use your built-in knowledge of "
                    "common vulnerabilities and exploitation techniques instead. "
                    "Do NOT retry qdrant-find during this session."
                ),
            }],
            "isError": False,
        }

    embedder = get_embedder()
    if embedder is None:
        # fastembed not installed — fall back to unavailable message
        return {
            "content": [{
                "type": "text",
                "text": (
                    "EMBEDDING MODEL UNAVAILABLE: fastembed is not installed. "
                    "Proceed without skill lookups — use your built-in knowledge instead."
                ),
            }],
            "isError": False,
        }

    try:
        # Embed query
        embeddings = list(embedder.embed([query]))
        vector = embeddings[0].tolist()

        # Search Qdrant with named vector
        search_url = f"{QDRANT_URL}/collections/{COLLECTION}/points/search"
        body = json.dumps({
            "vector": {
                "name": VECTOR_NAME,
                "vector": vector,
            },
            "limit": 5,
            "with_payload": True,
        }).encode()
        req = urllib.request.Request(
            search_url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        results = data.get("result", [])
        if not results:
            return {
                "content": [{"type": "text", "text": f"No techniques found for: {query}"}],
            }

        # Format results as technique cards
        cards = []
        for r in results:
            meta = r.get("payload", {}).get("metadata", {})
            score = r.get("score", 0)
            name = meta.get("name", "Unknown")
            category = meta.get("category", "")
            cve = meta.get("references", {}).get("cve")
            execution = meta.get("execution", [])
            prereqs = meta.get("prerequisites", {})
            indicators = meta.get("trigger", {}).get("indicators", [])
            success = meta.get("success_indicators", [])

            card = f"## {name}"
            if cve:
                card += f" ({cve})"
            card += f"\nScore: {score:.2f} | Category: {category}"
            if indicators:
                card += f"\nTriggers: {', '.join(str(i) for i in indicators)}"
            if prereqs:
                tools = prereqs.get("tools", [])
                card += f"\nPrereqs: access={prereqs.get('access', '?')}"
                if tools:
                    card += f", tools={tools}"
            if execution:
                card += "\nExecution:"
                for i, step in enumerate(execution, 1):
                    card += f"\n  {i}. {step}"
            if success:
                card += f"\nSuccess indicators: {', '.join(str(s) for s in success)}"
            cards.append(card)

        return {
            "content": [{"type": "text", "text": "\n\n".join(cards)}],
        }

    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Qdrant search failed: {e}"}],
            "isError": True,
        }
```

- [ ] **Step 3: Run the tests**

Run: `uv run pytest tests/eval/test_qdrant_wrapper.py -v`
Expected: All 3 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add infrastructure/PrEP/servers/qdrant-wrapper.py
git commit -m "feat(grimoire): rewrite qdrant-wrapper with fastembed vector search"
```

---

### Task 4: Integration test with live Qdrant

**Files:**
- Modify: `tests/eval/test_qdrant_wrapper.py`

- [ ] **Step 1: Add integration test that queries live Qdrant**

Append to `tests/eval/test_qdrant_wrapper.py`:

```python
@pytest.mark.skipif(
    not _qdrant_reachable(),
    reason="Qdrant not running on localhost:6333",
)
class TestQdrantIntegration:
    """Integration tests requiring a running Qdrant instance."""

    def test_search_returns_relevant_results(self):
        """Searching for 'smb anonymous share' returns SMB-related techniques."""
        qdrant_wrapper._available = None  # Reset cache
        qdrant_wrapper.QDRANT_URL = "http://localhost:6333"

        result = qdrant_wrapper.handle_find("smb anonymous share enumeration")
        text = result["content"][0]["text"]

        # Should return technique cards, not unavailable message
        assert "QDRANT UNAVAILABLE" not in text
        assert "##" in text  # Has at least one technique card header


def _qdrant_reachable() -> bool:
    """Check if Qdrant is reachable on localhost for integration tests."""
    try:
        req = urllib.request.Request("http://localhost:6333/healthz", method="GET")
        with urllib.request.urlopen(req, timeout=2):
            return True
    except Exception:
        return False
```

Add the missing import at the top of the file:

```python
import urllib.request
```

- [ ] **Step 2: Run integration test (requires Qdrant running)**

Run: `uv run pytest tests/eval/test_qdrant_wrapper.py -v -m "not skipif"`
Expected: Integration test PASSES if Qdrant is running, SKIPPED otherwise. Unit tests always pass.

- [ ] **Step 3: Commit**

```bash
git add tests/eval/test_qdrant_wrapper.py
git commit -m "test(eval): add qdrant vector search integration test"
```

---

### Task 5: Build Dame image and end-to-end validation

**Files:**
- No file changes — validation only

- [ ] **Step 1: Build Dame image with fastembed**

Run: `podman build --build-arg TARGET_PLATFORM=linux -t dame:linux -f infrastructure/dame/Dockerfile infrastructure/dame/`
Expected: Build succeeds. Look for `fastembed` install and model download in build output.

- [ ] **Step 2: Verify fastembed is available inside the image**

Run: `podman run --rm --entrypoint "" dame:linux python3 -c "from fastembed import TextEmbedding; e = TextEmbedding('sentence-transformers/all-MiniLM-L6-v2'); print('OK:', len(list(e.embed(['test']))))"`
Expected: `OK: 1`

- [ ] **Step 3: Run a quick eval to verify grimoire returns real results**

Run: `uv run scripts/eval_harness.py run --target drupal-drupalgeddon2 --timeout 5m`
Then check the dame.log for qdrant-find responses containing technique cards instead of errors.

Run: `grep -A5 "qdrant-find\|technique\|Score:" tests/eval/results/*/eval-drupal-drupalgeddon2/dame.log | head -30`

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest tests/eval/ -v --tb=short`
Expected: All tests pass.

- [ ] **Step 5: Commit any fixes found during validation**

Only if issues were discovered during steps 1-4.
