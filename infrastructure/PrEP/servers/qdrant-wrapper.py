#!/usr/bin/env python3
"""
Qdrant MCP Wrapper — Graceful Degradation
==========================================
Wraps mcp-server-qdrant with connectivity checks so Dame gets a clear
"unavailable" message instead of cryptic connection errors.

On first tool call, probes Qdrant via HTTP. If unreachable, caches that
result and returns a helpful message telling Dame to proceed without
skill lookups (and not retry).
"""

import os
import sys
import json
import urllib.request
import urllib.error

QDRANT_URL = os.environ.get("QDRANT_URL", "http://qdrant:6333")
COLLECTION = os.environ.get("COLLECTION_NAME", "skills")
PROBE_TIMEOUT = 3  # seconds

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


def check_qdrant() -> bool:
    """Probe Qdrant health endpoint. Returns True if reachable."""
    global _available
    if _available is not None:
        return _available

    try:
        req = urllib.request.Request(f"{QDRANT_URL}/healthz", method="GET")
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT):
            _available = True
    except (urllib.error.URLError, OSError, TimeoutError):
        _available = False

    return _available


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


def main():
    """MCP stdio server — read JSON-RPC from stdin, respond on stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method", "")
        req_id = request.get("id")

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "qdrant-wrapper", "version": "1.0.0"},
                },
            }
        elif method == "tools/list":
            tool_desc = os.environ.get(
                "TOOL_FIND_DESCRIPTION",
                "Search the skills knowledge base for attack techniques matching a query.",
            )
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [{
                        "name": "qdrant-find",
                        "description": tool_desc,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "Search query for skills/techniques",
                                }
                            },
                            "required": ["query"],
                        },
                    }]
                },
            }
        elif method == "tools/call":
            args = request.get("params", {}).get("arguments", {})
            query = args.get("query", "")
            result = handle_find(query)
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }
        elif method == "notifications/initialized":
            continue  # No response needed for notifications
        else:
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown method: {method}"},
            }

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
