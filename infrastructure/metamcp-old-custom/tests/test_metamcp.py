#!/usr/bin/env python3
"""
Tests for MetaMCP Capability Gateway
"""

import json
import subprocess
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import MetaMCPServer, Backend, BackendStatus


class TestMetaMCPServer:
    """Unit tests for MetaMCPServer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server = MetaMCPServer()

    def test_default_backends_registered(self):
        """Test that MSF and Sliver backends are registered by default."""
        assert 'msf' in self.server.backends
        assert 'sliver' in self.server.backends

    def test_list_backends(self):
        """Test listing all backends."""
        backends = self.server.list_backends()
        assert len(backends) >= 2
        names = [b['name'] for b in backends]
        assert 'msf' in names
        assert 'sliver' in names

    def test_discover_capabilities(self):
        """Test capability discovery."""
        caps = self.server.discover_capabilities()
        assert 'msf' in caps
        assert 'sliver' in caps
        assert 'msf__search' in caps['msf']
        assert 'sliver__implant_generate' in caps['sliver']

    def test_get_backend_for_tool(self):
        """Test finding backend for a tool."""
        backend = self.server.get_backend_for_tool('msf__exploit')
        assert backend is not None
        assert backend.name == 'msf'

        backend = self.server.get_backend_for_tool('sliver__sessions_list')
        assert backend is not None
        assert backend.name == 'sliver'

        backend = self.server.get_backend_for_tool('unknown__tool')
        assert backend is None

    def test_register_backend(self):
        """Test registering a new backend."""
        result = self.server.register_backend(
            name='custom',
            type='custom',
            host='localhost',
            port=9999,
            capabilities=['custom__tool1', 'custom__tool2']
        )
        assert result['registered'] is True
        assert 'custom' in self.server.backends

    def test_unregister_backend(self):
        """Test unregistering a backend."""
        # First register
        self.server.register_backend(
            name='temp',
            type='custom',
            host='localhost',
            port=8888,
            capabilities=['temp__tool']
        )
        assert 'temp' in self.server.backends

        # Then unregister
        result = self.server.unregister_backend('temp')
        assert result['unregistered'] is True
        assert 'temp' not in self.server.backends

    def test_unregister_nonexistent(self):
        """Test unregistering non-existent backend."""
        result = self.server.unregister_backend('nonexistent')
        assert result['unregistered'] is False

    def test_route_info(self):
        """Test getting route info for a tool."""
        info = self.server.route_info('msf__search')
        assert info['tool'] == 'msf__search'
        assert info['backend'] == 'msf'
        assert 'host' in info
        assert 'port' in info

    def test_route_info_unknown_tool(self):
        """Test route info for unknown tool."""
        info = self.server.route_info('unknown__tool')
        assert 'error' in info


def test_mcp_protocol():
    """Test MCP JSON-RPC protocol compliance."""
    server_path = Path(__file__).parent.parent / 'server.py'

    # Test initialize
    request = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }) + "\n"

    proc = subprocess.Popen(
        ['python3', str(server_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = proc.communicate(input=request, timeout=5)

    response = json.loads(stdout.strip())
    assert response['jsonrpc'] == '2.0'
    assert response['id'] == 1
    assert 'result' in response
    assert response['result']['serverInfo']['name'] == 'opulence-metamcp'


def test_tools_list():
    """Test tools/list method."""
    server_path = Path(__file__).parent.parent / 'server.py'

    requests = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n",
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
    ]

    proc = subprocess.Popen(
        ['python3', str(server_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = proc.communicate(input=''.join(requests), timeout=5)

    lines = stdout.strip().split('\n')
    assert len(lines) >= 2

    tools_response = json.loads(lines[1])
    assert 'result' in tools_response
    assert 'tools' in tools_response['result']

    tool_names = [t['name'] for t in tools_response['result']['tools']]
    assert 'metamcp__list_backends' in tool_names
    assert 'metamcp__discover' in tool_names


if __name__ == '__main__':
    # Run tests
    import pytest
    pytest.main([__file__, '-v'])
