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

# Cache availability for process lifetime
_available: bool | None = None


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
    """Handle qdrant-find tool call with graceful degradation."""
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
            "isError": False,  # Not an error — just unavailable
        }

    # Qdrant is available — delegate to the real server
    # This path is used in production with the real mcp-server-qdrant
    # In eval mode, we never reach here (qdrant is unavailable)
    try:
        import subprocess
        result = subprocess.run(
            ["uvx", "mcp-server-qdrant"],
            input=json.dumps({"query": query}),
            capture_output=True, text=True, timeout=30,
        )
        return json.loads(result.stdout) if result.stdout else {
            "content": [{"type": "text", "text": "No results found."}]
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Qdrant query failed: {e}"}],
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
