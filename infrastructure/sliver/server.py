#!/usr/bin/env python3
"""
Agent Opulence - Sliver C2 MCP Server
=====================================
MCP interface for Sliver C2 Framework via gRPC.

Protocol: JSON-RPC 2.0 over stdio
"""

import os
import sys
import json
import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from enum import Enum

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger('sliver-mcp')


class ImplantOS(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "darwin"


class ImplantArch(Enum):
    AMD64 = "amd64"
    X86 = "386"
    ARM64 = "arm64"


class ImplantFormat(Enum):
    EXECUTABLE = "exe"
    SHARED_LIB = "shared"
    SHELLCODE = "shellcode"
    SERVICE = "service"


class SliverClient:
    """Sliver C2 gRPC client wrapper."""

    def __init__(self, host: str, port: int, operator_config: str = None):
        self.host = host
        self.port = port
        self.operator_config = operator_config
        self.connected = False

    async def connect(self) -> bool:
        """Establish gRPC connection to Sliver server."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=5.0
            )
            writer.close()
            await writer.wait_closed()
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Sliver: {e}")
            self.connected = False
            return False

    async def generate_implant(self, name: str, os: str, arch: str,
                               format: str, c2_urls: List[str],
                               options: Dict = None) -> Dict[str, Any]:
        """Generate a Sliver implant."""
        logger.info(f"Generating implant: {name} ({os}/{arch})")

        # In production, call Sliver gRPC API
        return {
            "success": True,
            "name": name,
            "os": os,
            "arch": arch,
            "format": format,
            "c2": c2_urls,
            "file_path": f"/artifacts/implants/{name}.{format}",
            "sha256": "abc123def456...",
            "size_bytes": 8192000,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "beacon_interval": options.get('beacon_interval', '60s') if options else '60s',
                "jitter": options.get('jitter', '30') if options else '30',
                "evasion": options.get('evasion', True) if options else True
            }
        }

    async def list_listeners(self) -> List[Dict[str, Any]]:
        """List active listeners."""
        return [
            {
                "id": "mtls-1",
                "protocol": "mtls",
                "host": "0.0.0.0",
                "port": 8888,
                "status": "active",
                "started_at": "2026-01-16T03:00:00Z"
            },
            {
                "id": "https-1",
                "protocol": "https",
                "host": "0.0.0.0",
                "port": 443,
                "domain": "cdn.example.com",
                "status": "active",
                "started_at": "2026-01-16T03:00:00Z"
            }
        ]

    async def start_listener(self, protocol: str, host: str, port: int,
                            options: Dict = None) -> Dict[str, Any]:
        """Start a new listener."""
        logger.info(f"Starting {protocol} listener on {host}:{port}")

        listener_id = f"{protocol}-{port}"
        return {
            "success": True,
            "id": listener_id,
            "protocol": protocol,
            "host": host,
            "port": port,
            "status": "active",
            "started_at": datetime.now(timezone.utc).isoformat()
        }

    async def stop_listener(self, listener_id: str) -> Dict[str, Any]:
        """Stop a listener."""
        return {
            "success": True,
            "id": listener_id,
            "status": "stopped",
            "stopped_at": datetime.now(timezone.utc).isoformat()
        }

    async def list_sessions(self) -> List[Dict[str, Any]]:
        """List active implant sessions."""
        return [
            {
                "id": "session-abc123",
                "name": "DESKTOP-XYZ",
                "hostname": "DESKTOP-XYZ",
                "username": "SYSTEM",
                "os": "windows",
                "arch": "amd64",
                "remote_addr": "10.10.10.5:52341",
                "transport": "mtls",
                "pid": 1234,
                "last_checkin": "2026-01-16T03:35:00Z",
                "is_dead": False
            }
        ]

    async def session_info(self, session_id: str) -> Dict[str, Any]:
        """Get detailed session information."""
        return {
            "id": session_id,
            "name": "DESKTOP-XYZ",
            "hostname": "DESKTOP-XYZ",
            "username": "SYSTEM",
            "uid": "S-1-5-18",
            "gid": "S-1-5-18",
            "os": "windows",
            "arch": "amd64",
            "version": "10.0.19041",
            "remote_addr": "10.10.10.5:52341",
            "transport": "mtls",
            "pid": 1234,
            "filename": "svchost.exe",
            "first_contact": "2026-01-16T03:30:00Z",
            "last_checkin": "2026-01-16T03:35:00Z"
        }

    async def execute(self, session_id: str, command: str,
                     args: List[str] = None) -> Dict[str, Any]:
        """Execute a command on a session."""
        logger.info(f"Session {session_id}: {command} {args or ''}")

        return {
            "session_id": session_id,
            "command": command,
            "args": args or [],
            "output": f"[simulated output for: {command}]",
            "status": 0,
            "executed_at": datetime.now(timezone.utc).isoformat()
        }

    async def download(self, session_id: str, remote_path: str,
                      local_path: str) -> Dict[str, Any]:
        """Download a file from session."""
        return {
            "session_id": session_id,
            "remote_path": remote_path,
            "local_path": local_path,
            "size_bytes": 1024,
            "sha256": "abc123...",
            "downloaded_at": datetime.now(timezone.utc).isoformat()
        }

    async def upload(self, session_id: str, local_path: str,
                    remote_path: str) -> Dict[str, Any]:
        """Upload a file to session."""
        return {
            "session_id": session_id,
            "local_path": local_path,
            "remote_path": remote_path,
            "uploaded_at": datetime.now(timezone.utc).isoformat()
        }


# Global client
client: Optional[SliverClient] = None


def get_client() -> SliverClient:
    """Get or create Sliver client."""
    global client
    if client is None:
        host = os.environ.get('SLIVER_HOST', 'sliver')
        port = int(os.environ.get('SLIVER_PORT', '31337'))
        config = os.environ.get('SLIVER_CONFIG', '')
        client = SliverClient(host, port, config)
    return client


# MCP Tool definitions
TOOLS = [
    {
        "name": "sliver__implant_generate",
        "description": "Generate a Sliver implant (beacon or session)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Implant name"},
                "os": {"type": "string", "enum": ["windows", "linux", "darwin"], "description": "Target OS"},
                "arch": {"type": "string", "enum": ["amd64", "386", "arm64"], "description": "Target architecture"},
                "format": {"type": "string", "enum": ["exe", "shared", "shellcode", "service"], "description": "Output format"},
                "c2_urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "C2 callback URLs (e.g., mtls://10.10.14.32:8888)"
                },
                "beacon_interval": {"type": "string", "description": "Beacon interval (e.g., '60s')", "default": "60s"},
                "jitter": {"type": "string", "description": "Jitter percentage", "default": "30"},
                "evasion": {"type": "boolean", "description": "Enable evasion features", "default": True}
            },
            "required": ["name", "os", "arch", "format", "c2_urls"]
        }
    },
    {
        "name": "sliver__listeners_list",
        "description": "List active Sliver listeners",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "sliver__listener_start",
        "description": "Start a new listener (mtls, https, http, dns)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "protocol": {"type": "string", "enum": ["mtls", "https", "http", "dns", "wg"], "description": "Listener protocol"},
                "host": {"type": "string", "description": "Bind address", "default": "0.0.0.0"},
                "port": {"type": "integer", "description": "Bind port"},
                "domain": {"type": "string", "description": "Domain for HTTPS/DNS listeners"}
            },
            "required": ["protocol", "port"]
        }
    },
    {
        "name": "sliver__listener_stop",
        "description": "Stop a listener",
        "inputSchema": {
            "type": "object",
            "properties": {
                "listener_id": {"type": "string", "description": "Listener ID to stop"}
            },
            "required": ["listener_id"]
        }
    },
    {
        "name": "sliver__sessions_list",
        "description": "List active implant sessions",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "sliver__session_info",
        "description": "Get detailed information about a session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "sliver__execute",
        "description": "Execute a command on an implant session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID"},
                "command": {"type": "string", "description": "Command to execute"},
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Command arguments"
                }
            },
            "required": ["session_id", "command"]
        }
    },
    {
        "name": "sliver__download",
        "description": "Download a file from an implant session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID"},
                "remote_path": {"type": "string", "description": "Path on target"},
                "local_path": {"type": "string", "description": "Local save path"}
            },
            "required": ["session_id", "remote_path", "local_path"]
        }
    },
    {
        "name": "sliver__upload",
        "description": "Upload a file to an implant session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID"},
                "local_path": {"type": "string", "description": "Local file path"},
                "remote_path": {"type": "string", "description": "Target path"}
            },
            "required": ["session_id", "local_path", "remote_path"]
        }
    }
]


async def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Any:
    """Handle MCP tool calls."""
    sliver = get_client()

    if name == "sliver__implant_generate":
        options = {
            'beacon_interval': arguments.get('beacon_interval', '60s'),
            'jitter': arguments.get('jitter', '30'),
            'evasion': arguments.get('evasion', True)
        }
        return await sliver.generate_implant(
            name=arguments['name'],
            os=arguments['os'],
            arch=arguments['arch'],
            format=arguments['format'],
            c2_urls=arguments['c2_urls'],
            options=options
        )

    elif name == "sliver__listeners_list":
        return await sliver.list_listeners()

    elif name == "sliver__listener_start":
        return await sliver.start_listener(
            protocol=arguments['protocol'],
            host=arguments.get('host', '0.0.0.0'),
            port=arguments['port'],
            options={'domain': arguments.get('domain')}
        )

    elif name == "sliver__listener_stop":
        return await sliver.stop_listener(arguments['listener_id'])

    elif name == "sliver__sessions_list":
        return await sliver.list_sessions()

    elif name == "sliver__session_info":
        return await sliver.session_info(arguments['session_id'])

    elif name == "sliver__execute":
        return await sliver.execute(
            session_id=arguments['session_id'],
            command=arguments['command'],
            args=arguments.get('args', [])
        )

    elif name == "sliver__download":
        return await sliver.download(
            session_id=arguments['session_id'],
            remote_path=arguments['remote_path'],
            local_path=arguments['local_path']
        )

    elif name == "sliver__upload":
        return await sliver.upload(
            session_id=arguments['session_id'],
            local_path=arguments['local_path'],
            remote_path=arguments['remote_path']
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
                    "name": "opulence-sliver",
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
    logger.info("Sliver MCP server starting...")

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

    logger.info("Sliver MCP server stopped")


if __name__ == '__main__':
    asyncio.run(main())
