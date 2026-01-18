#!/usr/bin/env python3
"""
opulence-artifacts MCP Server
=============================
MCP server for artifact management in Agent Opulence.

Tools:
- artifact__read: Read artifact content by ID or path
- artifact__list: List artifacts with optional filtering
- artifact__search: Search artifacts by content or metadata

Protocol: JSON-RPC 2.0 over stdio
"""

import json
import sys
import os
import glob
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

# Configuration
ARTIFACTS_DIR = os.environ.get("OPULENCE_ARTIFACTS_DIR", "/artifacts")
CAS_DIR = os.path.join(ARTIFACTS_DIR, "cas")
RAW_DIR = os.path.join(ARTIFACTS_DIR, "raw")


class ArtifactServer:
    """MCP server for artifact operations."""

    def __init__(self):
        self.server_info = {
            "name": "opulence-artifacts",
            "version": "1.0.0",
            "protocol_version": "2024-11-05"
        }
        self.tools = {
            "artifact__read": {
                "description": "Read artifact content by ID or path. Returns the full content of the artifact.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "artifact_id": {
                            "type": "string",
                            "description": "Artifact ID (e.g., 'nmap_10.10.10.5_20260115') or relative path within artifacts directory"
                        },
                        "format": {
                            "type": "string",
                            "enum": ["raw", "cas", "auto"],
                            "default": "auto",
                            "description": "Format to read: 'raw' for original output, 'cas' for enriched YAML, 'auto' to detect"
                        }
                    },
                    "required": ["artifact_id"]
                }
            },
            "artifact__list": {
                "description": "List artifacts with optional filtering by type, date range, or target.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "artifact_type": {
                            "type": "string",
                            "enum": ["nmap", "nuclei", "httpx", "subfinder", "msf", "sliver", "all"],
                            "default": "all",
                            "description": "Filter by artifact type"
                        },
                        "target": {
                            "type": "string",
                            "description": "Filter by target IP/hostname (supports wildcards)"
                        },
                        "since": {
                            "type": "string",
                            "description": "ISO datetime - only artifacts after this time"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 50,
                            "description": "Maximum number of artifacts to return"
                        },
                        "format": {
                            "type": "string",
                            "enum": ["raw", "cas", "both"],
                            "default": "both",
                            "description": "Which artifact store to list"
                        }
                    }
                }
            },
            "artifact__search": {
                "description": "Search artifacts by content or metadata. Supports regex patterns.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query (regex supported)"
                        },
                        "search_in": {
                            "type": "string",
                            "enum": ["content", "metadata", "both"],
                            "default": "both",
                            "description": "Where to search"
                        },
                        "artifact_type": {
                            "type": "string",
                            "enum": ["nmap", "nuclei", "httpx", "subfinder", "msf", "sliver", "all"],
                            "default": "all",
                            "description": "Filter by artifact type"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 20,
                            "description": "Maximum number of results"
                        }
                    },
                    "required": ["query"]
                }
            }
        }

    def _ensure_dirs(self):
        """Ensure artifact directories exist."""
        os.makedirs(CAS_DIR, exist_ok=True)
        os.makedirs(RAW_DIR, exist_ok=True)

    def _parse_artifact_id(self, artifact_id: str) -> tuple[str, str, str]:
        """Parse artifact ID into (type, target, timestamp)."""
        parts = artifact_id.split("_")
        if len(parts) >= 3:
            return parts[0], parts[1], "_".join(parts[2:])
        return "unknown", artifact_id, ""

    def _find_artifact(self, artifact_id: str, format_type: str = "auto") -> Optional[Path]:
        """Find artifact file by ID."""
        self._ensure_dirs()

        # Direct path check
        if "/" in artifact_id:
            full_path = Path(ARTIFACTS_DIR) / artifact_id
            if full_path.exists():
                return full_path
            return None

        # Search by ID pattern
        search_dirs = []
        if format_type in ("cas", "auto"):
            search_dirs.append(CAS_DIR)
        if format_type in ("raw", "auto"):
            search_dirs.append(RAW_DIR)

        for search_dir in search_dirs:
            # Try exact match first
            for ext in [".yaml", ".yml", ".json", ".xml", ".txt", ""]:
                candidate = Path(search_dir) / f"{artifact_id}{ext}"
                if candidate.exists():
                    return candidate

            # Try glob pattern
            pattern = os.path.join(search_dir, f"**/*{artifact_id}*")
            matches = glob.glob(pattern, recursive=True)
            if matches:
                return Path(matches[0])

        return None

    def artifact_read(self, artifact_id: str, format_type: str = "auto") -> dict[str, Any]:
        """Read artifact content."""
        artifact_path = self._find_artifact(artifact_id, format_type)

        if not artifact_path:
            return {
                "error": f"Artifact not found: {artifact_id}",
                "searched_dirs": [CAS_DIR, RAW_DIR]
            }

        try:
            content = artifact_path.read_text()

            # Try to parse as YAML/JSON for structured data
            parsed = None
            if artifact_path.suffix in (".yaml", ".yml"):
                try:
                    parsed = yaml.safe_load(content)
                except yaml.YAMLError:
                    pass
            elif artifact_path.suffix == ".json":
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    pass

            artifact_type, target, timestamp = self._parse_artifact_id(artifact_path.stem)

            return {
                "artifact_id": artifact_path.stem,
                "path": str(artifact_path),
                "format": "cas" if str(CAS_DIR) in str(artifact_path) else "raw",
                "type": artifact_type,
                "target": target,
                "size_bytes": artifact_path.stat().st_size,
                "modified": datetime.fromtimestamp(artifact_path.stat().st_mtime).isoformat(),
                "content": parsed if parsed else content,
                "content_type": "structured" if parsed else "text"
            }
        except Exception as e:
            return {"error": f"Failed to read artifact: {str(e)}"}

    def artifact_list(
        self,
        artifact_type: str = "all",
        target: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 50,
        format_type: str = "both"
    ) -> dict[str, Any]:
        """List artifacts with filtering."""
        self._ensure_dirs()

        artifacts = []
        search_dirs = []

        if format_type in ("cas", "both"):
            search_dirs.append(("cas", CAS_DIR))
        if format_type in ("raw", "both"):
            search_dirs.append(("raw", RAW_DIR))

        since_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            except ValueError:
                pass

        for store_type, search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue

            for root, _, files in os.walk(search_dir):
                for filename in files:
                    filepath = Path(root) / filename

                    # Parse artifact info
                    art_type, art_target, _ = self._parse_artifact_id(filepath.stem)

                    # Apply filters
                    if artifact_type != "all" and art_type != artifact_type:
                        continue

                    if target:
                        target_pattern = target.replace("*", ".*")
                        if not re.match(target_pattern, art_target, re.IGNORECASE):
                            continue

                    stat = filepath.stat()
                    mtime = datetime.fromtimestamp(stat.st_mtime)

                    if since_dt and mtime < since_dt:
                        continue

                    artifacts.append({
                        "artifact_id": filepath.stem,
                        "path": str(filepath),
                        "store": store_type,
                        "type": art_type,
                        "target": art_target,
                        "size_bytes": stat.st_size,
                        "modified": mtime.isoformat()
                    })

        # Sort by modified time (newest first) and limit
        artifacts.sort(key=lambda x: x["modified"], reverse=True)
        artifacts = artifacts[:limit]

        return {
            "count": len(artifacts),
            "limit": limit,
            "filters": {
                "artifact_type": artifact_type,
                "target": target,
                "since": since,
                "format": format_type
            },
            "artifacts": artifacts
        }

    def artifact_search(
        self,
        query: str,
        search_in: str = "both",
        artifact_type: str = "all",
        limit: int = 20
    ) -> dict[str, Any]:
        """Search artifacts by content or metadata."""
        self._ensure_dirs()

        results = []
        pattern = re.compile(query, re.IGNORECASE | re.MULTILINE)

        for search_dir in [CAS_DIR, RAW_DIR]:
            if not os.path.exists(search_dir):
                continue

            for root, _, files in os.walk(search_dir):
                for filename in files:
                    filepath = Path(root) / filename

                    # Filter by type
                    art_type, art_target, _ = self._parse_artifact_id(filepath.stem)
                    if artifact_type != "all" and art_type != artifact_type:
                        continue

                    matches = []

                    # Search in metadata (filename)
                    if search_in in ("metadata", "both"):
                        if pattern.search(filename):
                            matches.append({
                                "location": "filename",
                                "match": filename
                            })

                    # Search in content
                    if search_in in ("content", "both"):
                        try:
                            content = filepath.read_text()
                            content_matches = pattern.findall(content)
                            if content_matches:
                                # Get context around matches
                                for match in content_matches[:5]:  # Limit matches per file
                                    idx = content.find(match)
                                    start = max(0, idx - 50)
                                    end = min(len(content), idx + len(match) + 50)
                                    context = content[start:end]
                                    matches.append({
                                        "location": "content",
                                        "match": match,
                                        "context": f"...{context}..."
                                    })
                        except Exception:
                            continue

                    if matches:
                        stat = filepath.stat()
                        results.append({
                            "artifact_id": filepath.stem,
                            "path": str(filepath),
                            "type": art_type,
                            "target": art_target,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "matches": matches
                        })

                    if len(results) >= limit:
                        break

                if len(results) >= limit:
                    break

        return {
            "query": query,
            "search_in": search_in,
            "result_count": len(results),
            "limit": limit,
            "results": results
        }

    def handle_request(self, request: dict) -> dict:
        """Handle a JSON-RPC request."""
        method = request.get("method", "")
        params = request.get("params", {})
        req_id = request.get("id")

        response = {"jsonrpc": "2.0", "id": req_id}

        try:
            if method == "initialize":
                response["result"] = {
                    "protocolVersion": self.server_info["protocol_version"],
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": self.server_info["name"],
                        "version": self.server_info["version"]
                    }
                }

            elif method == "tools/list":
                tools_list = []
                for name, spec in self.tools.items():
                    tools_list.append({
                        "name": name,
                        "description": spec["description"],
                        "inputSchema": spec["inputSchema"]
                    })
                response["result"] = {"tools": tools_list}

            elif method == "tools/call":
                tool_name = params.get("name", "")
                tool_args = params.get("arguments", {})

                if tool_name == "artifact__read":
                    result = self.artifact_read(
                        artifact_id=tool_args.get("artifact_id", ""),
                        format_type=tool_args.get("format", "auto")
                    )
                elif tool_name == "artifact__list":
                    result = self.artifact_list(
                        artifact_type=tool_args.get("artifact_type", "all"),
                        target=tool_args.get("target"),
                        since=tool_args.get("since"),
                        limit=tool_args.get("limit", 50),
                        format_type=tool_args.get("format", "both")
                    )
                elif tool_name == "artifact__search":
                    result = self.artifact_search(
                        query=tool_args.get("query", ""),
                        search_in=tool_args.get("search_in", "both"),
                        artifact_type=tool_args.get("artifact_type", "all"),
                        limit=tool_args.get("limit", 20)
                    )
                else:
                    response["error"] = {
                        "code": -32601,
                        "message": f"Unknown tool: {tool_name}"
                    }
                    return response

                response["result"] = {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2, default=str)
                        }
                    ]
                }

            elif method == "notifications/initialized":
                # No response needed for notifications
                return None

            else:
                response["error"] = {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }

        except Exception as e:
            response["error"] = {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }

        return response

    def run(self):
        """Run the MCP server on stdio."""
        sys.stderr.write(f"[{self.server_info['name']}] Starting MCP server...\n")
        sys.stderr.flush()

        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                try:
                    request = json.loads(line)
                except json.JSONDecodeError as e:
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32700,
                            "message": f"Parse error: {str(e)}"
                        }
                    }
                    print(json.dumps(error_response), flush=True)
                    continue

                response = self.handle_request(request)

                if response is not None:
                    print(json.dumps(response), flush=True)

            except KeyboardInterrupt:
                break
            except Exception as e:
                sys.stderr.write(f"[{self.server_info['name']}] Error: {str(e)}\n")
                sys.stderr.flush()


if __name__ == "__main__":
    server = ArtifactServer()
    server.run()
