# Qdrant Semantic Vector Search for Dame Eval

**Date**: 2026-03-28
**Status**: Approved
**Scope**: Replace broken keyword search in qdrant-wrapper.py with proper vector similarity search using fastembed

## Problem

The `qdrant-wrapper.py` MCP server cannot perform vector similarity search because it has no embedding model. When Qdrant is reachable, it attempts to spawn `uvx mcp-server-qdrant` via subprocess — which doesn't work as a query mechanism. The fallback keyword matching on the `document` payload field returns irrelevant results (e.g., "drupal rce" returns SSH brute force techniques).

The Qdrant `skills` collection contains 1,148 technique cards with 384-dim embeddings indexed by `all-MiniLM-L6-v2`. These embeddings are usable but the wrapper never queries them.

## Solution

Install `fastembed` in the Dame container image and rewrite the wrapper to embed queries client-side, then search Qdrant's vector search REST API.

### Why fastembed

- Qdrant's own lightweight embedding library (~50MB installed)
- Supports `all-MiniLM-L6-v2` via ONNX runtime (no PyTorch)
- Model weights ~23MB, baked into image at build time
- Compatible with the existing named vector `fast-all-minilm-l6-v2`

## Components

### 1. Dockerfile changes

Add to `infrastructure/dame/Dockerfile`:

```dockerfile
# Install fastembed for semantic search in qdrant-wrapper
RUN uv pip install --system fastembed

# Pre-download embedding model so it's baked into the image
RUN python3 -c "from fastembed import TextEmbedding; TextEmbedding('all-MiniLM-L6-v2')"
```

This adds ~73MB to the image (50MB fastembed + 23MB model weights). The Dame image is Kali-based and already ~2GB+, so this is negligible.

### 2. qdrant-wrapper.py rewrite

Replace `handle_find()` with:

```
1. Lazy-load TextEmbedding("all-MiniLM-L6-v2") on first call (cached for process lifetime)
2. Embed query string → list[float] (384 dimensions)
3. POST to {QDRANT_URL}/collections/{COLLECTION}/points/search:
   {
     "vector": {
       "name": "fast-all-minilm-l6-v2",
       "vector": [0.1, 0.2, ...]
     },
     "limit": 5,
     "with_payload": true
   }
4. Format results as technique cards with name, CVE, category, triggers, execution steps, success indicators
5. Return as MCP text content
```

Graceful degradation preserved: if Qdrant is unreachable, return the existing "QDRANT UNAVAILABLE" message. If fastembed import fails, fall back to the keyword search (current behavior minus the broken subprocess path).

### 3. Response format

Each technique card returned to Dame:

```
## Technique Name (CVE-XXXX-YYYY)
Score: 0.85
Category: exploitation
Triggers: Nibbleblog version 4.0.3, Vulnerability CVE-2015-7179
Prerequisites: access=user, tools=['curl']
Execution:
  1. Upload PHP shell via /admin/index.php?controller=plugins&action=install
  2. Navigate to /content/private/plugins/my_image/image.php
Success indicators: PHP code execution confirmed
```

### 4. No changes to indexer

`index_skills.py` continues to use `sentence-transformers` for indexing. The wrapper uses `fastembed` for query-time embedding only. Both produce compatible `all-MiniLM-L6-v2` embeddings.

## Testing

- Unit test: mock Qdrant HTTP responses, verify wrapper formats results correctly
- Integration test: query running Qdrant with known technique, verify relevant results returned
- Verify `fastembed` and `sentence-transformers` produce compatible embeddings for the same input (cosine similarity > 0.99)

## Files Modified

| File | Change |
|------|--------|
| `infrastructure/dame/Dockerfile` | Add fastembed install + model pre-download |
| `infrastructure/PrEP/servers/qdrant-wrapper.py` | Rewrite handle_find() with vector search |

## Not in scope

- Adding new technique cards to the collection (separate task)
- Changing the indexing pipeline
- Server-side embedding in Qdrant (not supported in v1.16.3)
