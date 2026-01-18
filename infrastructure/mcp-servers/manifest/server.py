#!/usr/bin/env python3
"""
opulence-manifest MCP Server
============================
MCP server for operation manifest management in Agent Opulence.

The manifest tracks:
- Operation metadata (target, scope, timestamps)
- Session history and state
- Key findings and progress
- Agent handoffs and context

Tools:
- manifest__query: Query current manifest state
- manifest__get_sessions: Get session history with filtering
- manifest__update: Update manifest with new findings/state

Protocol: JSON-RPC 2.0 over stdio
"""

import json
import sys
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from copy import deepcopy

import yaml

# Configuration
MANIFEST_DIR = os.environ.get("OPULENCE_MANIFEST_DIR", "/manifest")
MANIFEST_FILE = os.path.join(MANIFEST_DIR, "operation.yaml")
SESSIONS_DIR = os.path.join(MANIFEST_DIR, "sessions")


class ManifestServer:
    """MCP server for manifest operations."""

    def __init__(self):
        self.server_info = {
            "name": "opulence-manifest",
            "version": "1.0.0",
            "protocol_version": "2024-11-05"
        }
        self.tools = {
            "manifest__query": {
                "description": "Query the current operation manifest. Returns operation state, scope, findings, and session info.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "section": {
                            "type": "string",
                            "enum": ["all", "meta", "scope", "findings", "sessions", "context", "agents"],
                            "default": "all",
                            "description": "Which section of the manifest to query"
                        },
                        "depth": {
                            "type": "string",
                            "enum": ["summary", "full"],
                            "default": "summary",
                            "description": "Level of detail to return"
                        }
                    }
                }
            },
            "manifest__get_sessions": {
                "description": "Get session history with optional filtering by agent, status, or time range.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent": {
                            "type": "string",
                            "description": "Filter by agent name (e.g., 'the-dame', 'date-planner')"
                        },
                        "status": {
                            "type": "string",
                            "enum": ["active", "completed", "failed", "all"],
                            "default": "all",
                            "description": "Filter by session status"
                        },
                        "since": {
                            "type": "string",
                            "description": "ISO datetime - only sessions after this time"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 20,
                            "description": "Maximum number of sessions to return"
                        },
                        "include_context": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include full context snapshot for each session"
                        }
                    }
                }
            },
            "manifest__update": {
                "description": "Update the manifest with new findings, state changes, or session data. Supports atomic updates.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "update_type": {
                            "type": "string",
                            "enum": ["finding", "session", "scope", "context", "meta"],
                            "description": "Type of update to apply"
                        },
                        "data": {
                            "type": "object",
                            "description": "Update payload - structure depends on update_type"
                        },
                        "merge_strategy": {
                            "type": "string",
                            "enum": ["replace", "merge", "append"],
                            "default": "merge",
                            "description": "How to apply the update"
                        }
                    },
                    "required": ["update_type", "data"]
                }
            }
        }
        self._manifest_cache = None
        self._cache_time = None

    def _ensure_dirs(self):
        """Ensure manifest directories exist."""
        os.makedirs(MANIFEST_DIR, exist_ok=True)
        os.makedirs(SESSIONS_DIR, exist_ok=True)

    def _get_default_manifest(self) -> dict[str, Any]:
        """Return default manifest structure."""
        return {
            "meta": {
                "operation_id": None,
                "operation_name": None,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "updated_at": datetime.utcnow().isoformat() + "Z",
                "status": "initialized",
                "version": "1.0.0"
            },
            "scope": {
                "targets": [],
                "in_scope_cidrs": [],
                "out_of_scope": [],
                "expansion_requests": [],
                "flags_captured": []
            },
            "findings": {
                "key_findings": [],
                "vulnerabilities": [],
                "credentials": [],
                "services": [],
                "hosts": []
            },
            "sessions": {
                "current": None,
                "history": []
            },
            "context": {
                "active_agents": [],
                "handoff_stack": [],
                "shared_context": {}
            },
            "agents": {
                "the-dame": {"status": "idle", "last_active": None},
                "date-planner": {"status": "idle", "last_active": None},
                "party-line-operator": {"status": "idle", "last_active": None}
            }
        }

    def _load_manifest(self, force_reload: bool = False) -> dict[str, Any]:
        """Load manifest from disk with caching."""
        self._ensure_dirs()

        # Check cache (5 second validity)
        if not force_reload and self._manifest_cache and self._cache_time:
            if (datetime.utcnow() - self._cache_time).total_seconds() < 5:
                return deepcopy(self._manifest_cache)

        if os.path.exists(MANIFEST_FILE):
            try:
                with open(MANIFEST_FILE, "r") as f:
                    manifest = yaml.safe_load(f) or {}
                    # Merge with defaults for any missing keys
                    default = self._get_default_manifest()
                    for key in default:
                        if key not in manifest:
                            manifest[key] = default[key]
                    self._manifest_cache = manifest
                    self._cache_time = datetime.utcnow()
                    return deepcopy(manifest)
            except Exception as e:
                sys.stderr.write(f"[manifest] Error loading manifest: {e}\n")
                sys.stderr.flush()

        # Return default manifest
        manifest = self._get_default_manifest()
        self._manifest_cache = manifest
        self._cache_time = datetime.utcnow()
        return deepcopy(manifest)

    def _save_manifest(self, manifest: dict[str, Any]) -> bool:
        """Save manifest to disk."""
        self._ensure_dirs()

        manifest["meta"]["updated_at"] = datetime.utcnow().isoformat() + "Z"

        try:
            # Write atomically via temp file
            temp_file = MANIFEST_FILE + ".tmp"
            with open(temp_file, "w") as f:
                yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            os.rename(temp_file, MANIFEST_FILE)

            # Update cache
            self._manifest_cache = deepcopy(manifest)
            self._cache_time = datetime.utcnow()
            return True
        except Exception as e:
            sys.stderr.write(f"[manifest] Error saving manifest: {e}\n")
            sys.stderr.flush()
            return False

    def _summarize_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Create a summary view of the manifest."""
        findings = manifest.get("findings", {})
        sessions = manifest.get("sessions", {})
        scope = manifest.get("scope", {})

        return {
            "meta": manifest.get("meta", {}),
            "scope_summary": {
                "target_count": len(scope.get("targets", [])),
                "in_scope_cidrs": scope.get("in_scope_cidrs", []),
                "flags_captured": len(scope.get("flags_captured", [])),
                "pending_expansions": len(scope.get("expansion_requests", []))
            },
            "findings_summary": {
                "key_findings_count": len(findings.get("key_findings", [])),
                "vulnerabilities_count": len(findings.get("vulnerabilities", [])),
                "credentials_count": len(findings.get("credentials", [])),
                "services_count": len(findings.get("services", [])),
                "hosts_count": len(findings.get("hosts", []))
            },
            "session_summary": {
                "current_session": sessions.get("current"),
                "total_sessions": len(sessions.get("history", []))
            },
            "agents": manifest.get("agents", {})
        }

    def manifest_query(self, section: str = "all", depth: str = "summary") -> dict[str, Any]:
        """Query the manifest."""
        manifest = self._load_manifest()

        if section == "all":
            if depth == "summary":
                return self._summarize_manifest(manifest)
            return manifest
        elif section in manifest:
            data = manifest[section]
            if depth == "summary" and section == "findings":
                return {
                    "key_findings": data.get("key_findings", [])[:5],
                    "vulnerabilities_count": len(data.get("vulnerabilities", [])),
                    "credentials_count": len(data.get("credentials", [])),
                    "services_count": len(data.get("services", [])),
                    "hosts_count": len(data.get("hosts", []))
                }
            return data
        else:
            return {"error": f"Unknown section: {section}"}

    def manifest_get_sessions(
        self,
        agent: Optional[str] = None,
        status: str = "all",
        since: Optional[str] = None,
        limit: int = 20,
        include_context: bool = False
    ) -> dict[str, Any]:
        """Get session history."""
        manifest = self._load_manifest()
        sessions = manifest.get("sessions", {})
        history = sessions.get("history", [])

        # Parse since datetime
        since_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            except ValueError:
                pass

        # Load individual session files for more detail
        session_files = []
        if os.path.exists(SESSIONS_DIR):
            session_files = sorted(
                Path(SESSIONS_DIR).glob("*.yaml"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )

        results = []

        # Process session files
        for session_file in session_files:
            try:
                with open(session_file, "r") as f:
                    session_data = yaml.safe_load(f) or {}

                # Apply filters
                if agent and session_data.get("agent") != agent:
                    continue

                if status != "all" and session_data.get("status") != status:
                    continue

                if since_dt:
                    session_time = session_data.get("started_at", "")
                    if session_time:
                        try:
                            st = datetime.fromisoformat(session_time.replace("Z", "+00:00"))
                            if st < since_dt:
                                continue
                        except ValueError:
                            pass

                # Build result
                result = {
                    "session_id": session_data.get("session_id", session_file.stem),
                    "agent": session_data.get("agent"),
                    "status": session_data.get("status"),
                    "started_at": session_data.get("started_at"),
                    "ended_at": session_data.get("ended_at"),
                    "summary": session_data.get("summary"),
                    "artifacts": session_data.get("artifacts", [])
                }

                if include_context:
                    result["context"] = session_data.get("context", {})

                results.append(result)

                if len(results) >= limit:
                    break

            except Exception:
                continue

        # Fallback to history list if no session files
        if not results and history:
            for session in history:
                if agent and session.get("agent") != agent:
                    continue
                if status != "all" and session.get("status") != status:
                    continue
                results.append(session)
                if len(results) >= limit:
                    break

        return {
            "count": len(results),
            "limit": limit,
            "filters": {
                "agent": agent,
                "status": status,
                "since": since
            },
            "current_session": sessions.get("current"),
            "sessions": results
        }

    def manifest_update(
        self,
        update_type: str,
        data: dict[str, Any],
        merge_strategy: str = "merge"
    ) -> dict[str, Any]:
        """Update the manifest."""
        manifest = self._load_manifest(force_reload=True)

        timestamp = datetime.utcnow().isoformat() + "Z"

        try:
            if update_type == "finding":
                findings = manifest.setdefault("findings", {})
                finding_type = data.get("type", "key_findings")

                if finding_type not in findings:
                    findings[finding_type] = []

                new_finding = {
                    "id": data.get("id", f"finding_{len(findings[finding_type])+1}"),
                    "timestamp": timestamp,
                    **data
                }

                if merge_strategy == "append":
                    findings[finding_type].append(new_finding)
                elif merge_strategy == "replace":
                    # Replace finding with same ID
                    existing_idx = None
                    for i, f in enumerate(findings[finding_type]):
                        if f.get("id") == new_finding.get("id"):
                            existing_idx = i
                            break
                    if existing_idx is not None:
                        findings[finding_type][existing_idx] = new_finding
                    else:
                        findings[finding_type].append(new_finding)
                else:  # merge
                    findings[finding_type].append(new_finding)

            elif update_type == "session":
                sessions = manifest.setdefault("sessions", {"current": None, "history": []})

                if data.get("action") == "start":
                    # Start new session
                    session_id = data.get("session_id", f"session_{timestamp.replace(':', '-')}")
                    new_session = {
                        "session_id": session_id,
                        "agent": data.get("agent"),
                        "status": "active",
                        "started_at": timestamp,
                        "context": data.get("context", {})
                    }
                    sessions["current"] = session_id

                    # Save session file
                    session_file = os.path.join(SESSIONS_DIR, f"{session_id}.yaml")
                    with open(session_file, "w") as f:
                        yaml.dump(new_session, f, default_flow_style=False)

                elif data.get("action") == "end":
                    # End current session
                    session_id = data.get("session_id") or sessions.get("current")
                    if session_id:
                        session_file = os.path.join(SESSIONS_DIR, f"{session_id}.yaml")
                        session_data = {}
                        if os.path.exists(session_file):
                            with open(session_file, "r") as f:
                                session_data = yaml.safe_load(f) or {}

                        session_data["status"] = data.get("status", "completed")
                        session_data["ended_at"] = timestamp
                        session_data["summary"] = data.get("summary")
                        session_data["artifacts"] = data.get("artifacts", [])

                        with open(session_file, "w") as f:
                            yaml.dump(session_data, f, default_flow_style=False)

                        sessions["history"].append({
                            "session_id": session_id,
                            "agent": session_data.get("agent"),
                            "status": session_data["status"],
                            "started_at": session_data.get("started_at"),
                            "ended_at": timestamp
                        })
                        sessions["current"] = None

                elif data.get("action") == "update":
                    # Update current session
                    session_id = data.get("session_id") or sessions.get("current")
                    if session_id:
                        session_file = os.path.join(SESSIONS_DIR, f"{session_id}.yaml")
                        if os.path.exists(session_file):
                            with open(session_file, "r") as f:
                                session_data = yaml.safe_load(f) or {}
                            session_data.update(data.get("updates", {}))
                            with open(session_file, "w") as f:
                                yaml.dump(session_data, f, default_flow_style=False)

            elif update_type == "scope":
                scope = manifest.setdefault("scope", {})

                if merge_strategy == "replace":
                    scope.update(data)
                elif merge_strategy == "append":
                    for key, value in data.items():
                        if key in scope and isinstance(scope[key], list) and isinstance(value, list):
                            scope[key].extend(value)
                        else:
                            scope[key] = value
                else:  # merge
                    for key, value in data.items():
                        if key in scope and isinstance(scope[key], list) and isinstance(value, list):
                            # Deduplicate on merge
                            existing = set(str(x) for x in scope[key])
                            for item in value:
                                if str(item) not in existing:
                                    scope[key].append(item)
                        else:
                            scope[key] = value

            elif update_type == "context":
                context = manifest.setdefault("context", {})

                if merge_strategy == "replace":
                    context.update(data)
                else:
                    for key, value in data.items():
                        if key == "active_agents" and isinstance(value, list):
                            context["active_agents"] = value
                        elif key == "handoff_stack" and isinstance(value, list):
                            if merge_strategy == "append":
                                context.setdefault("handoff_stack", []).extend(value)
                            else:
                                context["handoff_stack"] = value
                        elif key == "shared_context" and isinstance(value, dict):
                            context.setdefault("shared_context", {}).update(value)
                        else:
                            context[key] = value

            elif update_type == "meta":
                meta = manifest.setdefault("meta", {})
                meta.update(data)

            elif update_type == "agents":
                agents = manifest.setdefault("agents", {})
                for agent_name, agent_data in data.items():
                    if agent_name in agents:
                        agents[agent_name].update(agent_data)
                    else:
                        agents[agent_name] = agent_data

            else:
                return {"error": f"Unknown update_type: {update_type}"}

            # Save updated manifest
            if self._save_manifest(manifest):
                return {
                    "success": True,
                    "update_type": update_type,
                    "timestamp": timestamp,
                    "merge_strategy": merge_strategy
                }
            else:
                return {"error": "Failed to save manifest"}

        except Exception as e:
            return {"error": f"Update failed: {str(e)}"}

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

                if tool_name == "manifest__query":
                    result = self.manifest_query(
                        section=tool_args.get("section", "all"),
                        depth=tool_args.get("depth", "summary")
                    )
                elif tool_name == "manifest__get_sessions":
                    result = self.manifest_get_sessions(
                        agent=tool_args.get("agent"),
                        status=tool_args.get("status", "all"),
                        since=tool_args.get("since"),
                        limit=tool_args.get("limit", 20),
                        include_context=tool_args.get("include_context", False)
                    )
                elif tool_name == "manifest__update":
                    result = self.manifest_update(
                        update_type=tool_args.get("update_type", ""),
                        data=tool_args.get("data", {}),
                        merge_strategy=tool_args.get("merge_strategy", "merge")
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
    server = ManifestServer()
    server.run()
