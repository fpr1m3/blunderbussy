#!/usr/bin/env python3
"""
Findings MCP Server
===================
Exposes typed MCP tools for Dame to submit exploitation findings.
Each finding is appended to {FINDINGS_DIR}/{TARGET}/findings.json.

Tools:
  - submit_flag        — record a captured flag
  - submit_credential  — record a discovered credential
  - submit_vulnerability — record a discovered/exploited vulnerability

Atomic writes are used (write to .tmp, then os.replace) to avoid partial
reads by the scorer.

Runs as a stdio JSON-RPC MCP server. Python stdlib only.
"""

import os
import sys
import json
import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

FINDINGS_DIR = os.environ.get("FINDINGS_DIR", "/artifacts")
TARGET = os.environ.get("TARGET", "unknown")

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "submit_flag",
        "description": (
            "Record a captured flag (user or root). "
            "Call this immediately when you obtain a flag value."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "flag_type": {
                    "type": "string",
                    "enum": ["user_flag", "root_flag"],
                    "description": "Type of flag captured",
                },
                "value": {
                    "type": "string",
                    "description": "The flag value (e.g. HTB{...} or hash string)",
                },
                "path": {
                    "type": "string",
                    "description": "Filesystem path where the flag was found",
                },
                "access_level": {
                    "type": "string",
                    "enum": ["user", "root"],
                    "description": "Access level at time of capture",
                },
            },
            "required": ["flag_type", "value", "path", "access_level"],
        },
    },
    {
        "name": "submit_credential",
        "description": (
            "Record a discovered credential (password, hash, key, or token). "
            "Call this when you find any usable credential."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Username the credential belongs to",
                },
                "password": {
                    "type": "string",
                    "description": "The credential value (plaintext, hash, key material, or token)",
                },
                "credential_type": {
                    "type": "string",
                    "enum": ["password", "hash", "key", "token"],
                    "description": "Type of credential",
                },
                "service": {
                    "type": "string",
                    "description": "Service or application the credential is for",
                },
                "access_level": {
                    "type": "string",
                    "enum": ["none", "user", "root"],
                    "description": "Access level granted by this credential",
                    "default": "none",
                },
            },
            "required": ["username", "password", "credential_type", "service"],
        },
    },
    {
        "name": "submit_vulnerability",
        "description": (
            "Record a discovered or exploited vulnerability. "
            "Call this when you identify or successfully exploit a vulnerability."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Vulnerability name or short description",
                },
                "service_port": {
                    "type": "integer",
                    "description": "Port number of the affected service",
                },
                "status": {
                    "type": "string",
                    "enum": ["discovered", "exploited"],
                    "description": "Whether vulnerability was only discovered or also exploited",
                },
                "cve": {
                    "type": "string",
                    "description": "CVE identifier if applicable (optional)",
                },
            },
            "required": ["name", "service_port", "status"],
        },
    },
]

# ---------------------------------------------------------------------------
# Enum validation maps
# ---------------------------------------------------------------------------

ENUM_FIELDS = {
    "submit_flag": {
        "flag_type": ["user_flag", "root_flag"],
        "access_level": ["user", "root"],
    },
    "submit_credential": {
        "credential_type": ["password", "hash", "key", "token"],
        "access_level": ["none", "user", "root"],
    },
    "submit_vulnerability": {
        "status": ["discovered", "exploited"],
    },
}

REQUIRED_FIELDS = {
    "submit_flag": ["flag_type", "value", "path", "access_level"],
    "submit_credential": ["username", "password", "credential_type", "service"],
    "submit_vulnerability": ["name", "service_port", "status"],
}

# ---------------------------------------------------------------------------
# Findings persistence
# ---------------------------------------------------------------------------


def _findings_path() -> str:
    return os.path.join(FINDINGS_DIR, TARGET, "findings.json")


def _load_findings(path: str) -> list:
    if os.path.exists(path):
        try:
            with open(path) as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _save_findings(path: str, findings: list) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(findings, fh, indent=2)
    os.replace(tmp, path)


def _append_finding(finding: dict) -> None:
    path = _findings_path()
    findings = _load_findings(path)
    findings.append(finding)
    _save_findings(path, findings)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate(tool_name: str, args: dict) -> str | None:
    """Return an error message string if validation fails, else None."""
    # Check required fields (reject absent, None, and empty string)
    for field in REQUIRED_FIELDS.get(tool_name, []):
        if field not in args or args[field] is None or args[field] == "":
            return f"Missing required field: '{field}'"

    # Check enum values
    for field, allowed in ENUM_FIELDS.get(tool_name, {}).items():
        if field in args and args[field] not in allowed:
            return (
                f"Invalid value for '{field}': '{args[field]}'. "
                f"Must be one of: {', '.join(allowed)}"
            )

    # Check service_port is integer
    if "service_port" in args:
        if not isinstance(args["service_port"], int):
            try:
                args["service_port"] = int(args["service_port"])
            except (ValueError, TypeError):
                return "Invalid value for 'service_port': must be an integer"

    return None


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


def _handle_submit_flag(args: dict) -> dict:
    error = _validate("submit_flag", args)
    if error:
        return {"content": [{"type": "text", "text": error}], "isError": True}

    finding = {
        "type": "flag",
        "flag_type": args["flag_type"],
        "value": args["value"],
        "path": args["path"],
        "access_level": args["access_level"],
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    _append_finding(finding)

    return {
        "content": [
            {
                "type": "text",
                "text": (
                    f"Flag recorded: {args['flag_type']} at {args['path']}. "
                    "If you haven't already, activate_skill('flag-capture') for "
                    "guidance on post-flag enumeration and privilege escalation steps."
                ),
            }
        ],
        "isError": False,
    }


def _handle_submit_credential(args: dict) -> dict:
    error = _validate("submit_credential", args)
    if error:
        return {"content": [{"type": "text", "text": error}], "isError": True}

    finding = {
        "type": "credential",
        "username": args["username"],
        "password": args["password"],
        "credential_type": args["credential_type"],
        "service": args["service"],
        "access_level": args.get("access_level", "none"),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    _append_finding(finding)

    return {
        "content": [
            {
                "type": "text",
                "text": (
                    f"Credential recorded: {args['credential_type']} for "
                    f"{args['username']} on {args['service']}. "
                    "If you haven't already, activate_skill('flag-capture') for "
                    "guidance on leveraging credentials to escalate access."
                ),
            }
        ],
        "isError": False,
    }


def _handle_submit_vulnerability(args: dict) -> dict:
    error = _validate("submit_vulnerability", args)
    if error:
        return {"content": [{"type": "text", "text": error}], "isError": True}

    finding = {
        "type": "vulnerability",
        "name": args["name"],
        "service_port": args["service_port"],
        "status": args["status"],
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    if "cve" in args and args["cve"]:
        finding["cve"] = args["cve"]

    _append_finding(finding)

    return {
        "content": [
            {
                "type": "text",
                "text": (
                    f"Vulnerability recorded: {args['name']} on port "
                    f"{args['service_port']} ({args['status']})."
                    + (f" CVE: {args['cve']}." if args.get("cve") else "")
                ),
            }
        ],
        "isError": False,
    }


HANDLERS = {
    "submit_flag": _handle_submit_flag,
    "submit_credential": _handle_submit_credential,
    "submit_vulnerability": _handle_submit_vulnerability,
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


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
                    "serverInfo": {"name": "findings-server", "version": "1.0.0"},
                },
            }
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOLS},
            }
        elif method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name", "")
            args = params.get("arguments", {})

            if tool_name not in HANDLERS:
                result = {
                    "content": [
                        {"type": "text", "text": f"Unknown tool: {tool_name}"}
                    ],
                    "isError": True,
                }
            else:
                result = HANDLERS[tool_name](args)

            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }
        elif method == "notifications/initialized":
            continue  # No response for notifications
        else:
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Unknown method: {method}",
                },
            }

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
