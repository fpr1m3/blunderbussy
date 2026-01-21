#!/usr/bin/env python3
"""
Tests for Pwncat MCP Server
"""

import json
import subprocess
import sys
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestPwncatClient:
    """Tests for PwncatClient class."""

    def test_client_initialization(self):
        """Verify PwncatClient() creates instance with correct defaults."""
        from server import PwncatClient

        client = PwncatClient()

        assert client.manager is None
        assert client.sessions == {}
        assert client._pwncat_sessions == {}
        assert client._listeners == {}
        assert client._initialized is False

    def test_client_not_initialized_error(self):
        """Verify methods raise RuntimeError before initialize()."""
        from server import PwncatClient

        client = PwncatClient()

        async def run_test():
            # listen() should raise RuntimeError when not initialized
            with pytest.raises(RuntimeError, match="not initialized"):
                await client.listen(port=4444)

            # connect() should raise RuntimeError when not initialized
            with pytest.raises(RuntimeError, match="not initialized"):
                await client.connect(host="127.0.0.1", port=4444)

        asyncio.run(run_test())

    def test_generate_session_id(self):
        """Verify session IDs are unique 8-char strings."""
        from server import PwncatClient

        client = PwncatClient()

        # Generate multiple session IDs
        session_ids = [client._generate_session_id() for _ in range(100)]

        # Check all are 8 characters
        for session_id in session_ids:
            assert len(session_id) == 8
            assert isinstance(session_id, str)

        # Check uniqueness
        assert len(set(session_ids)) == len(session_ids), "Session IDs should be unique"

    def test_list_sessions_empty(self):
        """Verify empty list returned when no sessions."""
        from server import PwncatClient

        client = PwncatClient()

        async def run_test():
            sessions = await client.list_sessions()
            assert sessions == []
            assert isinstance(sessions, list)

        asyncio.run(run_test())


class TestMCPProtocol:
    """Tests for MCP JSON-RPC protocol handling."""

    def test_mcp_initialize(self):
        """Verify initialize response has correct structure."""
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
        assert 'result' in response
        assert response['result']['serverInfo']['name'] == 'opulence-pwncat'
        assert response['result']['protocolVersion'] == '2024-11-05'
        assert 'capabilities' in response['result']
        assert 'tools' in response['result']['capabilities']

    def test_mcp_tools_list(self):
        """Verify tools/list returns all 8 tools."""
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

        assert 'result' in tools_response
        assert 'tools' in tools_response['result']

        tools = tools_response['result']['tools']
        assert len(tools) == 8

        tool_names = [t['name'] for t in tools]
        expected_tools = [
            'pwncat__listen',
            'pwncat__connect',
            'pwncat__sessions',
            'pwncat__command',
            'pwncat__module',
            'pwncat__upload',
            'pwncat__download',
            'pwncat__close'
        ]

        for expected in expected_tools:
            assert expected in tool_names, f"Missing tool: {expected}"

    def test_mcp_tool_schemas(self):
        """Verify each tool has valid inputSchema."""
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
        tools = tools_response['result']['tools']

        for tool in tools:
            assert 'name' in tool, f"Tool missing name"
            assert 'description' in tool, f"Tool {tool.get('name')} missing description"
            assert 'inputSchema' in tool, f"Tool {tool['name']} missing inputSchema"

            schema = tool['inputSchema']
            assert 'type' in schema, f"Tool {tool['name']} schema missing type"
            assert schema['type'] == 'object', f"Tool {tool['name']} schema type should be object"
            assert 'properties' in schema, f"Tool {tool['name']} schema missing properties"
            assert 'required' in schema, f"Tool {tool['name']} schema missing required"

    def test_mcp_unknown_method(self):
        """Verify unknown methods return error."""
        server_path = Path(__file__).parent.parent / 'server.py'

        requests = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "unknown/method", "params": {}}) + "\n"
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
        error_response = json.loads(lines[1])

        assert 'error' in error_response
        assert error_response['error']['code'] == -32601
        assert 'Method not found' in error_response['error']['message']


class TestToolSchemas:
    """Tests for individual tool schema validation."""

    @pytest.fixture
    def tools(self):
        """Fixture to get tools list."""
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
        return {t['name']: t for t in tools_response['result']['tools']}

    def test_listen_schema(self, tools):
        """Verify pwncat__listen has required 'port' field."""
        listen_tool = tools['pwncat__listen']
        schema = listen_tool['inputSchema']

        assert 'port' in schema['properties']
        assert 'port' in schema['required']
        assert schema['properties']['port']['type'] == 'integer'

        # Optional fields
        assert 'host' in schema['properties']
        assert 'timeout' in schema['properties']
        assert 'host' not in schema['required']
        assert 'timeout' not in schema['required']

    def test_connect_schema(self, tools):
        """Verify pwncat__connect has required 'host' and 'port'."""
        connect_tool = tools['pwncat__connect']
        schema = connect_tool['inputSchema']

        assert 'host' in schema['properties']
        assert 'port' in schema['properties']
        assert 'host' in schema['required']
        assert 'port' in schema['required']
        assert schema['properties']['host']['type'] == 'string'
        assert schema['properties']['port']['type'] == 'integer'

        # Optional platform field
        assert 'platform' in schema['properties']
        assert 'platform' not in schema['required']

    def test_command_schema(self, tools):
        """Verify pwncat__command has required 'session_id' and 'command'."""
        command_tool = tools['pwncat__command']
        schema = command_tool['inputSchema']

        assert 'session_id' in schema['properties']
        assert 'command' in schema['properties']
        assert 'session_id' in schema['required']
        assert 'command' in schema['required']
        assert schema['properties']['session_id']['type'] == 'string'
        assert schema['properties']['command']['type'] == 'string'


class TestHandleToolCall:
    """Tests for handle_tool_call with mocking."""

    def test_handle_unknown_tool(self):
        """Verify ValueError raised for unknown tool."""
        from server import handle_tool_call

        async def run_test():
            with pytest.raises(ValueError, match="Unknown tool"):
                await handle_tool_call("pwncat__nonexistent", {})

        # Need to mock ensure_client_initialized to return a client
        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = MagicMock()
            mock_client._initialized = True
            mock_ensure.return_value = mock_client

            asyncio.run(run_test())

    def test_handle_sessions_returns_list(self):
        """Mock client, verify list returned for sessions."""
        from server import handle_tool_call

        async def run_test():
            result = await handle_tool_call("pwncat__sessions", {})
            assert isinstance(result, list)

        mock_sessions = [
            {"session_id": "abc12345", "platform": "linux", "hostname": "target", "user": "root"}
        ]

        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = AsyncMock()
            mock_client._initialized = True
            mock_client.list_sessions = AsyncMock(return_value=mock_sessions)
            mock_ensure.return_value = mock_client

            asyncio.run(run_test())

    def test_handle_listen_calls_client(self):
        """Verify listen tool calls client.listen with correct args."""
        from server import handle_tool_call

        async def run_test():
            result = await handle_tool_call("pwncat__listen", {"port": 4444, "host": "0.0.0.0"})
            return result

        mock_result = {"session_id": "test1234", "platform": "linux"}

        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = AsyncMock()
            mock_client._initialized = True
            mock_client.listen = AsyncMock(return_value=mock_result)
            mock_ensure.return_value = mock_client

            result = asyncio.run(run_test())

            mock_client.listen.assert_called_once_with(port=4444, host="0.0.0.0", timeout=None)
            assert result == mock_result

    def test_handle_connect_calls_client(self):
        """Verify connect tool calls client.connect with correct args."""
        from server import handle_tool_call

        async def run_test():
            result = await handle_tool_call("pwncat__connect", {"host": "10.10.10.5", "port": 4444})
            return result

        mock_result = {"session_id": "conn1234", "platform": "linux"}

        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = AsyncMock()
            mock_client._initialized = True
            mock_client.connect = AsyncMock(return_value=mock_result)
            mock_ensure.return_value = mock_client

            result = asyncio.run(run_test())

            mock_client.connect.assert_called_once_with(host="10.10.10.5", port=4444, platform="linux")
            assert result == mock_result

    def test_handle_command_calls_client(self):
        """Verify command tool calls client.run_command with correct args."""
        from server import handle_tool_call

        async def run_test():
            result = await handle_tool_call("pwncat__command", {
                "session_id": "abc12345",
                "command": "whoami"
            })
            return result

        mock_result = {"command": "whoami", "output": "root", "exit_code": 0}

        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = AsyncMock()
            mock_client._initialized = True
            mock_client.run_command = AsyncMock(return_value=mock_result)
            mock_ensure.return_value = mock_client

            result = asyncio.run(run_test())

            mock_client.run_command.assert_called_once_with(session_id="abc12345", command="whoami")
            assert result == mock_result

    def test_handle_module_calls_client(self):
        """Verify module tool calls client.run_module with correct args."""
        from server import handle_tool_call

        async def run_test():
            result = await handle_tool_call("pwncat__module", {
                "session_id": "abc12345",
                "module": "enumerate.system.uname",
                "options": {"verbose": True}
            })
            return result

        mock_result = {"module": "enumerate.system.uname", "results": ["Linux target 5.4.0"]}

        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = AsyncMock()
            mock_client._initialized = True
            mock_client.run_module = AsyncMock(return_value=mock_result)
            mock_ensure.return_value = mock_client

            result = asyncio.run(run_test())

            mock_client.run_module.assert_called_once_with(
                session_id="abc12345",
                module="enumerate.system.uname",
                verbose=True
            )
            assert result == mock_result

    def test_handle_upload_calls_client(self):
        """Verify upload tool calls client.upload with correct args."""
        from server import handle_tool_call

        async def run_test():
            result = await handle_tool_call("pwncat__upload", {
                "session_id": "abc12345",
                "local_path": "/tmp/linpeas.sh",
                "remote_path": "/tmp/linpeas.sh"
            })
            return result

        mock_result = {"success": True, "bytes_transferred": 12345}

        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = AsyncMock()
            mock_client._initialized = True
            mock_client.upload = AsyncMock(return_value=mock_result)
            mock_ensure.return_value = mock_client

            result = asyncio.run(run_test())

            mock_client.upload.assert_called_once_with(
                session_id="abc12345",
                local_path="/tmp/linpeas.sh",
                remote_path="/tmp/linpeas.sh"
            )
            assert result == mock_result

    def test_handle_download_calls_client(self):
        """Verify download tool calls client.download with correct args."""
        from server import handle_tool_call

        async def run_test():
            result = await handle_tool_call("pwncat__download", {
                "session_id": "abc12345",
                "remote_path": "/etc/passwd",
                "local_path": "/tmp/passwd"
            })
            return result

        mock_result = {"success": True, "bytes_transferred": 1234}

        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = AsyncMock()
            mock_client._initialized = True
            mock_client.download = AsyncMock(return_value=mock_result)
            mock_ensure.return_value = mock_client

            result = asyncio.run(run_test())

            mock_client.download.assert_called_once_with(
                session_id="abc12345",
                remote_path="/etc/passwd",
                local_path="/tmp/passwd"
            )
            assert result == mock_result

    def test_handle_close_calls_client(self):
        """Verify close tool calls client.close_session with correct args."""
        from server import handle_tool_call

        async def run_test():
            result = await handle_tool_call("pwncat__close", {"session_id": "abc12345"})
            return result

        mock_result = {"session_id": "abc12345", "status": "closed"}

        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = AsyncMock()
            mock_client._initialized = True
            mock_client.close_session = AsyncMock(return_value=mock_result)
            mock_ensure.return_value = mock_client

            result = asyncio.run(run_test())

            mock_client.close_session.assert_called_once_with(session_id="abc12345")
            assert result == mock_result

    def test_handle_timeout_error(self):
        """Verify timeout errors are returned as error dict, not raised."""
        from server import handle_tool_call

        async def run_test():
            result = await handle_tool_call("pwncat__listen", {"port": 4444, "timeout": 1})
            return result

        with patch('server.ensure_client_initialized') as mock_ensure:
            mock_client = AsyncMock()
            mock_client._initialized = True
            mock_client.listen = AsyncMock(side_effect=TimeoutError("No connection received"))
            mock_ensure.return_value = mock_client

            result = asyncio.run(run_test())

            assert result['error'] == 'timeout'
            assert 'message' in result


class TestToolCallViaMCP:
    """Integration tests for tool calls via MCP protocol."""

    def test_tool_call_sessions(self):
        """Test tools/call for pwncat__sessions via MCP protocol."""
        server_path = Path(__file__).parent.parent / 'server.py'

        requests = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n",
            json.dumps({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "pwncat__sessions",
                    "arguments": {}
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
    pytest.main([__file__, '-v'])
