#!/usr/bin/env python3
"""
opulence-scope MCP Server
=========================
MCP server for scope validation and management in Agent Opulence.

The scope system ensures:
- All targets are validated against authorized scope
- Out-of-scope targets are blocked
- Scope expansions require explicit approval
- Clear audit trail of scope decisions

Tools:
- scope__validate: Validate if a target is in scope
- scope__request_expansion: Request scope expansion for a new target
- scope__list: List current scope configuration

Protocol: JSON-RPC 2.0 over stdio
"""

import json
import sys
import os
import re
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import yaml

# Configuration
SCOPE_DIR = os.environ.get("OPULENCE_SCOPE_DIR", "/scope")
SCOPE_FILE = os.path.join(SCOPE_DIR, "scope.yaml")
EXPANSION_REQUESTS_FILE = os.path.join(SCOPE_DIR, "expansion_requests.yaml")


class ScopeServer:
    """MCP server for scope operations."""

    def __init__(self):
        self.server_info = {
            "name": "opulence-scope",
            "version": "1.0.0",
            "protocol_version": "2024-11-05"
        }
        self.tools = {
            "scope__validate": {
                "description": "Validate if a target (IP, hostname, URL, or CIDR) is within authorized scope. Returns validation result with details.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target to validate (IP address, hostname, URL, or CIDR range)"
                        },
                        "action": {
                            "type": "string",
                            "enum": ["scan", "exploit", "c2", "exfil", "any"],
                            "default": "any",
                            "description": "Type of action being validated (some actions may have stricter requirements)"
                        },
                        "agent": {
                            "type": "string",
                            "description": "Agent requesting validation (for audit trail)"
                        }
                    },
                    "required": ["target"]
                }
            },
            "scope__request_expansion": {
                "description": "Request scope expansion to include a new target. Creates a pending request that requires human approval.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target to add to scope (IP, hostname, CIDR)"
                        },
                        "justification": {
                            "type": "string",
                            "description": "Reason for requesting scope expansion"
                        },
                        "discovered_via": {
                            "type": "string",
                            "description": "How this target was discovered (e.g., 'DNS enumeration', 'service discovery')"
                        },
                        "agent": {
                            "type": "string",
                            "description": "Agent requesting expansion"
                        },
                        "urgency": {
                            "type": "string",
                            "enum": ["low", "medium", "high"],
                            "default": "medium",
                            "description": "Urgency level of the request"
                        }
                    },
                    "required": ["target", "justification"]
                }
            },
            "scope__list": {
                "description": "List current scope configuration including in-scope targets, exclusions, and pending expansion requests.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "include_pending": {
                            "type": "boolean",
                            "default": True,
                            "description": "Include pending expansion requests in output"
                        },
                        "include_history": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include historical scope changes"
                        }
                    }
                }
            }
        }
        self._scope_cache = None
        self._cache_time = None

    def _ensure_dirs(self):
        """Ensure scope directories exist."""
        os.makedirs(SCOPE_DIR, exist_ok=True)

    def _get_default_scope(self) -> dict[str, Any]:
        """Return default scope structure."""
        return {
            "meta": {
                "operation_id": None,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "updated_at": datetime.utcnow().isoformat() + "Z",
                "version": "1.0.0"
            },
            "in_scope": {
                "cidrs": [],
                "hostnames": [],
                "urls": [],
                "domains": []
            },
            "out_of_scope": {
                "cidrs": [],
                "hostnames": [],
                "patterns": []
            },
            "restrictions": {
                "no_dos": True,
                "no_social_engineering": True,
                "business_hours_only": False,
                "max_concurrent_scans": 5
            },
            "action_policies": {
                "scan": "ALLOW",
                "exploit": "ASK",
                "c2": "ASK",
                "exfil": "DENY"
            },
            "history": []
        }

    def _load_scope(self, force_reload: bool = False) -> dict[str, Any]:
        """Load scope from disk with caching."""
        self._ensure_dirs()

        # Check cache (5 second validity)
        if not force_reload and self._scope_cache and self._cache_time:
            if (datetime.utcnow() - self._cache_time).total_seconds() < 5:
                return self._scope_cache.copy()

        if os.path.exists(SCOPE_FILE):
            try:
                with open(SCOPE_FILE, "r") as f:
                    scope = yaml.safe_load(f) or {}
                    # Merge with defaults
                    default = self._get_default_scope()
                    for key in default:
                        if key not in scope:
                            scope[key] = default[key]
                    self._scope_cache = scope
                    self._cache_time = datetime.utcnow()
                    return scope.copy()
            except Exception as e:
                sys.stderr.write(f"[scope] Error loading scope: {e}\n")
                sys.stderr.flush()

        scope = self._get_default_scope()
        self._scope_cache = scope
        self._cache_time = datetime.utcnow()
        return scope.copy()

    def _save_scope(self, scope: dict[str, Any]) -> bool:
        """Save scope to disk."""
        self._ensure_dirs()

        scope["meta"]["updated_at"] = datetime.utcnow().isoformat() + "Z"

        try:
            temp_file = SCOPE_FILE + ".tmp"
            with open(temp_file, "w") as f:
                yaml.dump(scope, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            os.rename(temp_file, SCOPE_FILE)

            self._scope_cache = scope.copy()
            self._cache_time = datetime.utcnow()
            return True
        except Exception as e:
            sys.stderr.write(f"[scope] Error saving scope: {e}\n")
            sys.stderr.flush()
            return False

    def _load_expansion_requests(self) -> list[dict]:
        """Load pending expansion requests."""
        self._ensure_dirs()

        if os.path.exists(EXPANSION_REQUESTS_FILE):
            try:
                with open(EXPANSION_REQUESTS_FILE, "r") as f:
                    data = yaml.safe_load(f)
                    return data.get("requests", []) if data else []
            except Exception:
                pass
        return []

    def _save_expansion_requests(self, requests: list[dict]) -> bool:
        """Save expansion requests."""
        self._ensure_dirs()

        try:
            with open(EXPANSION_REQUESTS_FILE, "w") as f:
                yaml.dump({"requests": requests}, f, default_flow_style=False)
            return True
        except Exception:
            return False

    def _parse_target(self, target: str) -> dict[str, Any]:
        """Parse a target string into its components."""
        result = {
            "original": target,
            "type": "unknown",
            "ip": None,
            "hostname": None,
            "cidr": None,
            "port": None,
            "domain": None
        }

        target = target.strip()

        # Check if it's a URL
        if target.startswith(("http://", "https://")):
            result["type"] = "url"
            parsed = urlparse(target)
            result["hostname"] = parsed.hostname
            result["port"] = parsed.port

            # Check if hostname is an IP
            try:
                ipaddress.ip_address(parsed.hostname)
                result["ip"] = parsed.hostname
            except ValueError:
                result["domain"] = self._extract_domain(parsed.hostname)
            return result

        # Check if it's a CIDR
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                result["type"] = "cidr"
                result["cidr"] = str(network)
                return result
            except ValueError:
                pass

        # Check if it's an IP address
        try:
            ip = ipaddress.ip_address(target)
            result["type"] = "ip"
            result["ip"] = str(ip)
            return result
        except ValueError:
            pass

        # Check if it's an IP:port
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
                result["port"] = port
                try:
                    ip = ipaddress.ip_address(host)
                    result["type"] = "ip"
                    result["ip"] = str(ip)
                    return result
                except ValueError:
                    result["type"] = "hostname"
                    result["hostname"] = host
                    result["domain"] = self._extract_domain(host)
                    return result
            except ValueError:
                pass

        # Assume it's a hostname
        result["type"] = "hostname"
        result["hostname"] = target
        result["domain"] = self._extract_domain(target)
        return result

    def _extract_domain(self, hostname: str) -> Optional[str]:
        """Extract the registrable domain from a hostname."""
        if not hostname:
            return None
        parts = hostname.lower().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname

    def _check_ip_in_cidrs(self, ip_str: str, cidrs: list[str]) -> bool:
        """Check if an IP is in any of the CIDR ranges."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for cidr in cidrs:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if ip in network:
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def _check_hostname_match(self, hostname: str, patterns: list[str]) -> bool:
        """Check if a hostname matches any patterns (supports wildcards)."""
        if not hostname:
            return False
        hostname = hostname.lower()
        for pattern in patterns:
            pattern = pattern.lower()
            if pattern.startswith("*."):
                # Wildcard subdomain match
                suffix = pattern[2:]
                if hostname == suffix or hostname.endswith("." + suffix):
                    return True
            elif pattern == hostname:
                return True
        return False

    def scope_validate(
        self,
        target: str,
        action: str = "any",
        agent: Optional[str] = None
    ) -> dict[str, Any]:
        """Validate if a target is in scope."""
        scope = self._load_scope()
        parsed = self._parse_target(target)

        timestamp = datetime.utcnow().isoformat() + "Z"

        result = {
            "target": target,
            "parsed": parsed,
            "action": action,
            "agent": agent,
            "timestamp": timestamp,
            "in_scope": False,
            "blocked": False,
            "reason": None,
            "policy": None,
            "requires_approval": False
        }

        in_scope = scope.get("in_scope", {})
        out_scope = scope.get("out_of_scope", {})
        action_policies = scope.get("action_policies", {})

        # Check out-of-scope first (explicit denies)
        if parsed["ip"]:
            if self._check_ip_in_cidrs(parsed["ip"], out_scope.get("cidrs", [])):
                result["blocked"] = True
                result["reason"] = "IP is in explicit out-of-scope CIDR"
                return result

        if parsed["hostname"]:
            if self._check_hostname_match(parsed["hostname"], out_scope.get("hostnames", [])):
                result["blocked"] = True
                result["reason"] = "Hostname is explicitly out of scope"
                return result

            # Check patterns (regex)
            for pattern in out_scope.get("patterns", []):
                try:
                    if re.match(pattern, parsed["hostname"], re.IGNORECASE):
                        result["blocked"] = True
                        result["reason"] = f"Hostname matches out-of-scope pattern: {pattern}"
                        return result
                except re.error:
                    continue

        # Check in-scope
        in_scope_match = False
        match_reason = None

        if parsed["ip"]:
            if self._check_ip_in_cidrs(parsed["ip"], in_scope.get("cidrs", [])):
                in_scope_match = True
                match_reason = "IP is within in-scope CIDR"

        if not in_scope_match and parsed["hostname"]:
            if self._check_hostname_match(parsed["hostname"], in_scope.get("hostnames", [])):
                in_scope_match = True
                match_reason = "Hostname is explicitly in scope"

        if not in_scope_match and parsed["domain"]:
            if parsed["domain"] in [d.lower() for d in in_scope.get("domains", [])]:
                in_scope_match = True
                match_reason = "Domain is in scope"

        if not in_scope_match and parsed["type"] == "url":
            for url_pattern in in_scope.get("urls", []):
                if target.lower().startswith(url_pattern.lower()):
                    in_scope_match = True
                    match_reason = "URL matches in-scope pattern"
                    break

        result["in_scope"] = in_scope_match
        result["reason"] = match_reason if in_scope_match else "Target not found in scope definition"

        # Check action policy
        if action != "any" and action in action_policies:
            policy = action_policies[action]
            result["policy"] = policy

            if policy == "DENY":
                result["blocked"] = True
                result["reason"] = f"Action '{action}' is not permitted by policy"
            elif policy == "ASK":
                result["requires_approval"] = True

        return result

    def scope_request_expansion(
        self,
        target: str,
        justification: str,
        discovered_via: Optional[str] = None,
        agent: Optional[str] = None,
        urgency: str = "medium"
    ) -> dict[str, Any]:
        """Request scope expansion."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        parsed = self._parse_target(target)

        # First validate to see current status
        validation = self.scope_validate(target, agent=agent)

        if validation.get("in_scope"):
            return {
                "success": False,
                "reason": "Target is already in scope",
                "target": target,
                "validation": validation
            }

        if validation.get("blocked"):
            return {
                "success": False,
                "reason": "Target is explicitly blocked - cannot request expansion",
                "target": target,
                "validation": validation
            }

        # Create expansion request
        requests = self._load_expansion_requests()

        # Check for duplicate pending request
        for req in requests:
            if req.get("target") == target and req.get("status") == "pending":
                return {
                    "success": False,
                    "reason": "Expansion request already pending for this target",
                    "existing_request": req
                }

        request_id = f"exp_{timestamp.replace(':', '-').replace('.', '-')}"

        new_request = {
            "request_id": request_id,
            "target": target,
            "parsed": parsed,
            "justification": justification,
            "discovered_via": discovered_via,
            "agent": agent,
            "urgency": urgency,
            "status": "pending",
            "created_at": timestamp,
            "reviewed_at": None,
            "reviewed_by": None,
            "decision": None
        }

        requests.append(new_request)

        if self._save_expansion_requests(requests):
            return {
                "success": True,
                "request_id": request_id,
                "target": target,
                "status": "pending",
                "message": "Expansion request submitted - awaiting human approval",
                "request": new_request
            }
        else:
            return {
                "success": False,
                "reason": "Failed to save expansion request"
            }

    def scope_list(
        self,
        include_pending: bool = True,
        include_history: bool = False
    ) -> dict[str, Any]:
        """List current scope configuration."""
        scope = self._load_scope()

        result = {
            "meta": scope.get("meta", {}),
            "in_scope": scope.get("in_scope", {}),
            "out_of_scope": scope.get("out_of_scope", {}),
            "restrictions": scope.get("restrictions", {}),
            "action_policies": scope.get("action_policies", {})
        }

        # Summary counts
        in_scope = scope.get("in_scope", {})
        result["summary"] = {
            "total_cidrs": len(in_scope.get("cidrs", [])),
            "total_hostnames": len(in_scope.get("hostnames", [])),
            "total_domains": len(in_scope.get("domains", [])),
            "total_urls": len(in_scope.get("urls", []))
        }

        if include_pending:
            requests = self._load_expansion_requests()
            pending = [r for r in requests if r.get("status") == "pending"]
            result["pending_expansions"] = pending
            result["summary"]["pending_expansion_count"] = len(pending)

        if include_history:
            result["history"] = scope.get("history", [])
            # Also include approved/denied expansion requests
            requests = self._load_expansion_requests()
            processed = [r for r in requests if r.get("status") != "pending"]
            result["expansion_history"] = processed

        return result

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

                if tool_name == "scope__validate":
                    result = self.scope_validate(
                        target=tool_args.get("target", ""),
                        action=tool_args.get("action", "any"),
                        agent=tool_args.get("agent")
                    )
                elif tool_name == "scope__request_expansion":
                    result = self.scope_request_expansion(
                        target=tool_args.get("target", ""),
                        justification=tool_args.get("justification", ""),
                        discovered_via=tool_args.get("discovered_via"),
                        agent=tool_args.get("agent"),
                        urgency=tool_args.get("urgency", "medium")
                    )
                elif tool_name == "scope__list":
                    result = self.scope_list(
                        include_pending=tool_args.get("include_pending", True),
                        include_history=tool_args.get("include_history", False)
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
    server = ScopeServer()
    server.run()
