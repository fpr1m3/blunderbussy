#!/usr/bin/env python3
"""
HexStrike MCP Wrapper
Wraps HexStrike-AI Flask API as an MCP server for tool aggregation.
"""

import argparse
import json
import sys
import requests
from typing import Any

# MCP Protocol constants
JSONRPC_VERSION = "2.0"


def send_response(id: Any, result: Any = None, error: Any = None):
    """Send JSON-RPC response to stdout."""
    response = {"jsonrpc": JSONRPC_VERSION, "id": id}
    if error:
        response["error"] = error
    else:
        response["result"] = result
    print(json.dumps(response), flush=True)


def send_error(id: Any, code: int, message: str, data: str = None):
    """Send JSON-RPC error response."""
    error = {"code": code, "message": message}
    if data:
        error["data"] = data
    send_response(id, error=error)


class HexStrikeMCP:
    """MCP wrapper for HexStrike-AI Flask backend."""

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')
        self.tools = {}
        self._discover_tools()

    def _discover_tools(self):
        """Discover available tools from HexStrike backend."""
        try:
            resp = requests.get(f"{self.server_url}/tools", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for tool in data.get("tools", []):
                    self.tools[tool["name"]] = tool
        except Exception as e:
            # If discovery fails, define a basic set of tools
            self._define_fallback_tools()

    def _define_fallback_tools(self):
        """Define fallback tools if discovery fails."""
        fallback = [
            {"name": "nmap_scan", "description": "Network port scanner",
             "parameters": {"target": "string", "ports": "string", "options": "string"}},
            {"name": "gobuster_scan", "description": "Directory/file brute forcer",
             "parameters": {"url": "string", "wordlist": "string", "options": "string"}},
            {"name": "nuclei_scan", "description": "Vulnerability scanner",
             "parameters": {"target": "string", "templates": "string", "options": "string"}},
            {"name": "sqlmap_scan", "description": "SQL injection scanner",
             "parameters": {"url": "string", "options": "string"}},
            {"name": "hydra_attack", "description": "Password brute forcer",
             "parameters": {"target": "string", "service": "string", "userlist": "string", "passlist": "string"}},
        ]
        for tool in fallback:
            self.tools[tool["name"]] = tool

    def handle_initialize(self, id: Any, params: dict):
        """Handle initialize request."""
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "hexstrike-mcp",
                "version": "1.0.0"
            }
        }
        send_response(id, result)

    def handle_list_tools(self, id: Any, params: dict):
        """Handle tools/list request."""
        tools = []
        for name, tool in self.tools.items():
            schema = {
                "type": "object",
                "properties": {},
            }
            for param, ptype in tool.get("parameters", {}).items():
                schema["properties"][param] = {
                    "type": ptype if ptype in ["string", "integer", "boolean"] else "string",
                    "description": f"{param} parameter"
                }

            tools.append({
                "name": name,
                "description": tool.get("description", f"HexStrike tool: {name}"),
                "inputSchema": schema
            })

        send_response(id, {"tools": tools})

    def handle_call_tool(self, id: Any, params: dict):
        """Handle tools/call request."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name not in self.tools:
            send_error(id, -32602, "Tool not found", f"Unknown tool: {tool_name}")
            return

        try:
            # Call HexStrike backend
            resp = requests.post(
                f"{self.server_url}/execute",
                json={"tool": tool_name, "args": arguments},
                timeout=300  # 5 min timeout for long scans
            )

            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "content": [{
                        "type": "text",
                        "text": json.dumps(data, indent=2),
                        "mimeType": "application/json"
                    }]
                }
                send_response(id, result)
            else:
                result = {
                    "content": [{
                        "type": "text",
                        "text": f"HexStrike error: {resp.status_code} - {resp.text}"
                    }],
                    "isError": True
                }
                send_response(id, result)

        except requests.exceptions.Timeout:
            result = {
                "content": [{"type": "text", "text": "Tool execution timed out (>5 min)"}],
                "isError": True
            }
            send_response(id, result)
        except Exception as e:
            result = {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True
            }
            send_response(id, result)

    def run(self):
        """Main loop - read JSON-RPC messages from stdin."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError as e:
                send_error(None, -32700, "Parse error", str(e))
                continue

            method = msg.get("method")
            id = msg.get("id")
            params = msg.get("params", {})

            if method == "initialize":
                self.handle_initialize(id, params)
            elif method == "tools/list":
                self.handle_list_tools(id, params)
            elif method == "tools/call":
                self.handle_call_tool(id, params)
            else:
                send_error(id, -32601, "Method not found", f"Unknown method: {method}")


def main():
    parser = argparse.ArgumentParser(description="HexStrike MCP Server")
    parser.add_argument("--server", default="http://localhost:8888",
                        help="HexStrike Flask server URL")
    args = parser.parse_args()

    mcp = HexStrikeMCP(args.server)
    mcp.run()


if __name__ == "__main__":
    main()
