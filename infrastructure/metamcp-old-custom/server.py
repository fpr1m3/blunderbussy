#!/usr/bin/env python3
"""
Agent Opulence - MetaMCP Capability Gateway
============================================
Aggregates tool backends (MSF, Sliver, etc.) into unified MCP interface.
Routes requests to appropriate backends based on capability discovery.

Protocol: JSON-RPC 2.0 over stdio
"""

import os
import sys
import json
import asyncio
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger('metamcp')


class BackendStatus(Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


@dataclass
class Backend:
    """Registered tool backend."""
    name: str
    type: str  # msf, sliver, custom
    host: str
    port: int
    capabilities: List[str] = field(default_factory=list)
    status: BackendStatus = BackendStatus.UNKNOWN
    last_health_check: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class MetaMCPServer:
    """Capability gateway for tool aggregation."""

    def __init__(self):
        self.backends: Dict[str, Backend] = {}
        self._init_default_backends()

    def _init_default_backends(self):
        """Initialize default backends from environment."""
        # MSF backend
        msf_host = os.environ.get('MSF_HOST', 'msf')
        msf_port = int(os.environ.get('MSF_PORT', '55553'))
        self.backends['msf'] = Backend(
            name='msf',
            type='msf',
            host=msf_host,
            port=msf_port,
            capabilities=[
                'msf__search', 'msf__module_info', 'msf__exploit',
                'msf__sessions_list', 'msf__session_interact', 'msf__auxiliary'
            ]
        )

        # Sliver backend
        sliver_host = os.environ.get('SLIVER_HOST', 'sliver')
        sliver_port = int(os.environ.get('SLIVER_PORT', '31337'))
        self.backends['sliver'] = Backend(
            name='sliver',
            type='sliver',
            host=sliver_host,
            port=sliver_port,
            capabilities=[
                'sliver__implant_generate', 'sliver__listeners_list',
                'sliver__listener_start', 'sliver__sessions_list',
                'sliver__session_interact', 'sliver__execute'
            ]
        )

    def list_backends(self) -> List[Dict[str, Any]]:
        """List all registered backends."""
        return [
            {
                'name': b.name,
                'type': b.type,
                'host': b.host,
                'port': b.port,
                'status': b.status.value,
                'capabilities_count': len(b.capabilities),
                'last_health_check': b.last_health_check
            }
            for b in self.backends.values()
        ]

    def discover_capabilities(self) -> Dict[str, List[str]]:
        """Discover all capabilities across backends."""
        capabilities = {}
        for backend in self.backends.values():
            capabilities[backend.name] = backend.capabilities
        return capabilities

    def get_backend_for_tool(self, tool_name: str) -> Optional[Backend]:
        """Find backend that provides a specific tool."""
        for backend in self.backends.values():
            if tool_name in backend.capabilities:
                return backend
        return None

    def register_backend(self, name: str, type: str, host: str, port: int,
                        capabilities: List[str], metadata: Dict = None) -> Dict[str, Any]:
        """Register a new backend."""
        backend = Backend(
            name=name,
            type=type,
            host=host,
            port=port,
            capabilities=capabilities,
            metadata=metadata or {}
        )
        self.backends[name] = backend
        return {'registered': True, 'backend': name}

    def unregister_backend(self, name: str) -> Dict[str, Any]:
        """Unregister a backend."""
        if name in self.backends:
            del self.backends[name]
            return {'unregistered': True, 'backend': name}
        return {'unregistered': False, 'error': 'Backend not found'}

    async def check_health(self, backend_name: str = None) -> Dict[str, Any]:
        """Check health of backends."""
        results = {}
        targets = [backend_name] if backend_name else list(self.backends.keys())

        for name in targets:
            if name not in self.backends:
                results[name] = {'status': 'not_found'}
                continue

            backend = self.backends[name]
            # Attempt TCP connection check
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(backend.host, backend.port),
                    timeout=5.0
                )
                writer.close()
                await writer.wait_closed()
                backend.status = BackendStatus.ONLINE
                results[name] = {'status': 'online', 'host': backend.host, 'port': backend.port}
            except asyncio.TimeoutError:
                backend.status = BackendStatus.OFFLINE
                results[name] = {'status': 'timeout'}
            except Exception as e:
                backend.status = BackendStatus.OFFLINE
                results[name] = {'status': 'offline', 'error': str(e)}

            backend.last_health_check = datetime.now(timezone.utc).isoformat()

        return results

    def route_info(self, tool_name: str) -> Dict[str, Any]:
        """Get routing info for a tool."""
        backend = self.get_backend_for_tool(tool_name)
        if backend:
            return {
                'tool': tool_name,
                'backend': backend.name,
                'host': backend.host,
                'port': backend.port,
                'status': backend.status.value
            }
        return {'tool': tool_name, 'error': 'No backend provides this tool'}


# Global server instance
server = MetaMCPServer()


# MCP Tool definitions
TOOLS = [
    {
        "name": "metamcp__list_backends",
        "description": "List all registered tool backends (MSF, Sliver, etc.)",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "metamcp__discover",
        "description": "Discover all available capabilities across all backends",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "metamcp__health",
        "description": "Check health status of backends",
        "inputSchema": {
            "type": "object",
            "properties": {
                "backend": {
                    "type": "string",
                    "description": "Specific backend to check (optional, checks all if omitted)"
                }
            },
            "required": []
        }
    },
    {
        "name": "metamcp__route",
        "description": "Get routing information for a specific tool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "description": "Tool name to route (e.g., msf__exploit)"
                }
            },
            "required": ["tool"]
        }
    },
    {
        "name": "metamcp__register",
        "description": "Register a new tool backend",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Backend name"},
                "type": {"type": "string", "description": "Backend type (msf, sliver, custom)"},
                "host": {"type": "string", "description": "Backend host"},
                "port": {"type": "integer", "description": "Backend port"},
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of tool names this backend provides"
                }
            },
            "required": ["name", "type", "host", "port", "capabilities"]
        }
    }
]


async def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Any:
    """Handle MCP tool calls."""
    if name == "metamcp__list_backends":
        return server.list_backends()

    elif name == "metamcp__discover":
        return server.discover_capabilities()

    elif name == "metamcp__health":
        backend = arguments.get('backend')
        return await server.check_health(backend)

    elif name == "metamcp__route":
        tool = arguments.get('tool', '')
        return server.route_info(tool)

    elif name == "metamcp__register":
        return server.register_backend(
            name=arguments['name'],
            type=arguments['type'],
            host=arguments['host'],
            port=arguments['port'],
            capabilities=arguments['capabilities'],
            metadata=arguments.get('metadata', {})
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
                    "name": "opulence-metamcp",
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
            return None  # No response for notifications

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
    logger.info("MetaMCP server starting...")

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

    logger.info("MetaMCP server stopped")


if __name__ == '__main__':
    asyncio.run(main())
