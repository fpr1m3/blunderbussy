#!/usr/bin/env python3
"""
Agent Opulence - Metasploit MCP Server
======================================
MCP interface for Metasploit Framework via MSFRPC.

Protocol: JSON-RPC 2.0 over stdio
"""

import os
import sys
import json
import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger('msf-mcp')


class MSFClient:
    """Metasploit RPC client wrapper."""

    def __init__(self, host: str, port: int, token: str):
        self.host = host
        self.port = port
        self.token = token
        self.connected = False

    async def connect(self) -> bool:
        """Establish connection to msfrpcd."""
        try:
            # In production, use msgpack-rpc or HTTP API
            # For now, verify connectivity
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=5.0
            )
            writer.close()
            await writer.wait_closed()
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"Failed to connect to MSF: {e}")
            self.connected = False
            return False

    async def search_modules(self, query: str, module_type: str = None) -> List[Dict]:
        """Search Metasploit modules."""
        # Simulated response - in production, call msfrpc
        modules = [
            {
                "name": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
                "fullname": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
                "rank": "excellent",
                "description": "Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)",
                "type": "exploit",
                "references": ["CVE-2014-6271"]
            },
            {
                "name": "exploit/unix/ftp/vsftpd_234_backdoor",
                "fullname": "exploit/unix/ftp/vsftpd_234_backdoor",
                "rank": "excellent",
                "description": "VSFTPD v2.3.4 Backdoor Command Execution",
                "type": "exploit",
                "references": []
            },
            {
                "name": "auxiliary/scanner/ssh/ssh_login",
                "fullname": "auxiliary/scanner/ssh/ssh_login",
                "rank": "normal",
                "description": "SSH Login Check Scanner",
                "type": "auxiliary",
                "references": []
            }
        ]

        # Filter by query
        results = []
        for mod in modules:
            if query.lower() in mod['name'].lower() or query.lower() in mod['description'].lower():
                if module_type is None or mod['type'] == module_type:
                    results.append(mod)

        return results

    async def get_module_info(self, module_name: str) -> Dict[str, Any]:
        """Get detailed module information."""
        return {
            "name": module_name,
            "type": "exploit" if "exploit/" in module_name else "auxiliary",
            "rank": "excellent",
            "description": f"Module: {module_name}",
            "options": {
                "RHOSTS": {"required": True, "description": "Target host(s)"},
                "RPORT": {"required": True, "description": "Target port", "default": 80},
                "LHOST": {"required": False, "description": "Local host for reverse shell"},
                "LPORT": {"required": False, "description": "Local port", "default": 4444}
            },
            "targets": [
                {"id": 0, "name": "Automatic"},
                {"id": 1, "name": "Linux x86"},
                {"id": 2, "name": "Linux x64"}
            ],
            "payloads": [
                "linux/x64/meterpreter/reverse_tcp",
                "linux/x64/shell_reverse_tcp",
                "cmd/unix/reverse_bash"
            ]
        }

    async def run_exploit(self, module: str, options: Dict[str, Any],
                         payload: str = None, target: int = 0) -> Dict[str, Any]:
        """Execute an exploit module."""
        logger.info(f"Running exploit: {module} with options: {options}")

        # Validate required options
        if 'RHOSTS' not in options:
            return {"success": False, "error": "RHOSTS is required"}

        # In production, this would call msfrpc module.execute
        return {
            "success": True,
            "job_id": 1,
            "uuid": "abc123-def456",
            "module": module,
            "target": options.get('RHOSTS'),
            "payload": payload or "auto",
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat()
        }

    async def run_auxiliary(self, module: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an auxiliary module."""
        logger.info(f"Running auxiliary: {module} with options: {options}")

        return {
            "success": True,
            "job_id": 2,
            "uuid": "aux123-456",
            "module": module,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat()
        }

    async def list_sessions(self) -> List[Dict[str, Any]]:
        """List active Meterpreter/shell sessions."""
        # In production, call session.list
        return [
            {
                "id": 1,
                "type": "meterpreter",
                "tunnel_local": "10.10.14.32:4444",
                "tunnel_peer": "10.10.10.5:52341",
                "via_exploit": "exploit/unix/ftp/vsftpd_234_backdoor",
                "via_payload": "linux/x64/meterpreter/reverse_tcp",
                "info": "uid=0(root) gid=0(root)",
                "opened_at": "2026-01-16T03:30:00Z"
            }
        ]

    async def session_command(self, session_id: int, command: str) -> Dict[str, Any]:
        """Execute command in a session."""
        logger.info(f"Session {session_id}: {command}")

        return {
            "session_id": session_id,
            "command": command,
            "output": f"[simulated output for: {command}]",
            "executed_at": datetime.now(timezone.utc).isoformat()
        }


# Global client
client: Optional[MSFClient] = None


def get_client() -> MSFClient:
    """Get or create MSF client."""
    global client
    if client is None:
        host = os.environ.get('MSF_HOST', 'msf')
        port = int(os.environ.get('MSF_PORT', '55553'))
        token = os.environ.get('MSF_TOKEN', 'msfrpc_token')
        client = MSFClient(host, port, token)
    return client


# MCP Tool definitions
TOOLS = [
    {
        "name": "msf__search",
        "description": "Search Metasploit modules by keyword",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (e.g., 'ssh', 'apache', 'cve:2021')"},
                "type": {"type": "string", "enum": ["exploit", "auxiliary", "post", "payload"], "description": "Module type filter"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "msf__module_info",
        "description": "Get detailed information about a Metasploit module",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Full module path (e.g., exploit/unix/ftp/vsftpd_234_backdoor)"}
            },
            "required": ["module"]
        }
    },
    {
        "name": "msf__exploit",
        "description": "Execute an exploit module against a target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Exploit module path"},
                "rhosts": {"type": "string", "description": "Target host(s)"},
                "rport": {"type": "integer", "description": "Target port"},
                "lhost": {"type": "string", "description": "Local host for reverse connection"},
                "lport": {"type": "integer", "description": "Local port for reverse connection"},
                "payload": {"type": "string", "description": "Payload to use"},
                "target": {"type": "integer", "description": "Target index", "default": 0}
            },
            "required": ["module", "rhosts"]
        }
    },
    {
        "name": "msf__auxiliary",
        "description": "Execute an auxiliary module (scanner, fuzzer, etc.)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Auxiliary module path"},
                "rhosts": {"type": "string", "description": "Target host(s)"},
                "options": {"type": "object", "description": "Additional module options"}
            },
            "required": ["module", "rhosts"]
        }
    },
    {
        "name": "msf__sessions_list",
        "description": "List active Meterpreter/shell sessions",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "msf__session_interact",
        "description": "Execute a command in an active session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "integer", "description": "Session ID"},
                "command": {"type": "string", "description": "Command to execute"}
            },
            "required": ["session_id", "command"]
        }
    }
]


async def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Any:
    """Handle MCP tool calls."""
    msf = get_client()

    if name == "msf__search":
        return await msf.search_modules(
            arguments['query'],
            arguments.get('type')
        )

    elif name == "msf__module_info":
        return await msf.get_module_info(arguments['module'])

    elif name == "msf__exploit":
        options = {
            'RHOSTS': arguments['rhosts'],
            'RPORT': arguments.get('rport', 80),
            'LHOST': arguments.get('lhost', ''),
            'LPORT': arguments.get('lport', 4444)
        }
        return await msf.run_exploit(
            arguments['module'],
            options,
            arguments.get('payload'),
            arguments.get('target', 0)
        )

    elif name == "msf__auxiliary":
        options = {'RHOSTS': arguments['rhosts']}
        options.update(arguments.get('options', {}))
        return await msf.run_auxiliary(arguments['module'], options)

    elif name == "msf__sessions_list":
        return await msf.list_sessions()

    elif name == "msf__session_interact":
        return await msf.session_command(
            arguments['session_id'],
            arguments['command']
        )

    else:
        raise ValueError(f"Unknown tool: {name}")


async def handle_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle JSON-RPC request."""
    method = request.get('method', '')
    params = request.get('params', {})
    req_id = request.get('id')

    try:
        if method == 'initialize':
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "opulence-msf",
                    "version": "1.0.0"
                }
            }

        elif method == 'tools/list':
            result = {"tools": TOOLS}

        elif method == 'tools/call':
            tool_name = params.get('name', '')
            arguments = params.get('arguments', {})
            tool_result = await handle_tool_call(tool_name, arguments)
            result = {
                "content": [
                    {"type": "text", "text": json.dumps(tool_result, indent=2)}
                ]
            }

        elif method == 'notifications/initialized':
            return None

        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            }

        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    except Exception as e:
        logger.error(f"Error handling request: {e}")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32603, "message": str(e)}
        }


async def main():
    """Main entry point - stdio JSON-RPC server."""
    logger.info("MSF MCP server starting...")

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(writer_transport, writer_protocol, reader, asyncio.get_event_loop())

    while True:
        try:
            line = await reader.readline()
            if not line:
                break

            request = json.loads(line.decode().strip())
            response = await handle_request(request)

            if response:
                writer.write((json.dumps(response) + '\n').encode())
                await writer.drain()

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
        except Exception as e:
            logger.error(f"Error: {e}")
            break

    logger.info("MSF MCP server stopped")


if __name__ == '__main__':
    asyncio.run(main())
