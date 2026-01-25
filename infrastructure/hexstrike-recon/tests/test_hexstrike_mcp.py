"""Tests for hexstrike_mcp.py MCP wrapper."""

import json
import pytest
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add hexstrike-recon to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from hexstrike_mcp import (
    HexStrikeMCP,
    send_response,
    send_error,
    JSONRPC_VERSION,
)


class TestSendResponse:
    """Tests for send_response() function."""

    def test_outputs_valid_json(self, capsys):
        """Should output valid JSON to stdout."""
        send_response(1, result={"test": "data"})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert isinstance(parsed, dict)

    def test_includes_jsonrpc_version(self, capsys):
        """Should include JSON-RPC version."""
        send_response(1, result={})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["jsonrpc"] == JSONRPC_VERSION

    def test_includes_id(self, capsys):
        """Should include the request id."""
        send_response(42, result={})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["id"] == 42

    def test_includes_result_when_provided(self, capsys):
        """Should include result field when provided."""
        send_response(1, result={"output": "test"})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["result"] == {"output": "test"}

    def test_includes_error_when_provided(self, capsys):
        """Should include error field when provided."""
        error = {"code": -32600, "message": "Invalid Request"}
        send_response(1, error=error)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["error"] == error

    def test_handles_string_id(self, capsys):
        """Should handle string IDs."""
        send_response("req-123", result={})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["id"] == "req-123"

    def test_handles_none_id(self, capsys):
        """Should handle None ID (notifications)."""
        send_response(None, result={})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["id"] is None


class TestSendError:
    """Tests for send_error() function."""

    def test_formats_error_correctly(self, capsys):
        """Should format error with code and message."""
        send_error(1, -32600, "Invalid Request")
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["error"]["code"] == -32600
        assert parsed["error"]["message"] == "Invalid Request"

    def test_includes_data_when_provided(self, capsys):
        """Should include data field when provided."""
        send_error(1, -32602, "Invalid params", data="Missing 'target'")
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["error"]["data"] == "Missing 'target'"

    def test_omits_data_when_not_provided(self, capsys):
        """Should not include data field when not provided."""
        send_error(1, -32600, "Error")
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert "data" not in parsed["error"]


class TestHexStrikeMCPInit:
    """Tests for HexStrikeMCP initialization."""

    @patch('hexstrike_mcp.requests.get')
    def test_stores_server_url(self, mock_get):
        """Should store the server URL."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888")
        assert mcp.server_url == "http://localhost:8888"

    @patch('hexstrike_mcp.requests.get')
    def test_strips_trailing_slash(self, mock_get):
        """Should strip trailing slash from server URL."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888/")
        assert mcp.server_url == "http://localhost:8888"


class TestHexStrikeMCPDiscoverTools:
    """Tests for tool discovery."""

    @patch('hexstrike_mcp.requests.get')
    def test_discovers_tools_from_backend(self, mock_get):
        """Should populate tools from backend response."""
        tools = [
            {"name": "nmap_scan", "description": "Port scanner", "parameters": {}},
            {"name": "gobuster_scan", "description": "Dir buster", "parameters": {}},
        ]
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": tools})

        mcp = HexStrikeMCP("http://localhost:8888")
        assert "nmap_scan" in mcp.tools
        assert "gobuster_scan" in mcp.tools

    @patch('hexstrike_mcp.requests.get')
    def test_uses_fallback_on_connection_error(self, mock_get):
        """Should use fallback tools when backend unavailable."""
        mock_get.side_effect = Exception("Connection refused")

        mcp = HexStrikeMCP("http://localhost:8888")
        # Should have fallback tools
        assert len(mcp.tools) > 0

    @patch('hexstrike_mcp.requests.get')
    def test_empty_tools_on_non_200_response(self, mock_get):
        """Tools should be empty on non-200 status (no fallback)."""
        mock_get.return_value = MagicMock(status_code=500)

        mcp = HexStrikeMCP("http://localhost:8888")
        # Code doesn't call fallback on non-200, just leaves tools empty
        assert len(mcp.tools) == 0


class TestHexStrikeMCPFallbackTools:
    """Tests for fallback tool definitions."""

    @patch('hexstrike_mcp.requests.get')
    def test_fallback_includes_nmap(self, mock_get):
        """Fallback should include nmap_scan."""
        mock_get.side_effect = Exception("fail")
        mcp = HexStrikeMCP("http://localhost:8888")
        assert "nmap_scan" in mcp.tools

    @patch('hexstrike_mcp.requests.get')
    def test_fallback_includes_gobuster(self, mock_get):
        """Fallback should include gobuster_scan."""
        mock_get.side_effect = Exception("fail")
        mcp = HexStrikeMCP("http://localhost:8888")
        assert "gobuster_scan" in mcp.tools

    @patch('hexstrike_mcp.requests.get')
    def test_fallback_includes_nuclei(self, mock_get):
        """Fallback should include nuclei_scan."""
        mock_get.side_effect = Exception("fail")
        mcp = HexStrikeMCP("http://localhost:8888")
        assert "nuclei_scan" in mcp.tools

    @patch('hexstrike_mcp.requests.get')
    def test_fallback_includes_sqlmap(self, mock_get):
        """Fallback should include sqlmap_scan."""
        mock_get.side_effect = Exception("fail")
        mcp = HexStrikeMCP("http://localhost:8888")
        assert "sqlmap_scan" in mcp.tools

    @patch('hexstrike_mcp.requests.get')
    def test_fallback_includes_hydra(self, mock_get):
        """Fallback should include hydra_attack."""
        mock_get.side_effect = Exception("fail")
        mcp = HexStrikeMCP("http://localhost:8888")
        assert "hydra_attack" in mcp.tools


class TestHexStrikeMCPHandleInitialize:
    """Tests for handle_initialize() method."""

    @patch('hexstrike_mcp.requests.get')
    def test_returns_protocol_version(self, mock_get, capsys):
        """Should return MCP protocol version."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888")

        mcp.handle_initialize(1, {})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())

        assert parsed["result"]["protocolVersion"] == "2024-11-05"

    @patch('hexstrike_mcp.requests.get')
    def test_returns_capabilities(self, mock_get, capsys):
        """Should return capabilities object."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888")

        mcp.handle_initialize(1, {})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())

        assert "capabilities" in parsed["result"]
        assert "tools" in parsed["result"]["capabilities"]

    @patch('hexstrike_mcp.requests.get')
    def test_returns_server_info(self, mock_get, capsys):
        """Should return server info."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888")

        mcp.handle_initialize(1, {})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())

        assert parsed["result"]["serverInfo"]["name"] == "hexstrike-mcp"


class TestHexStrikeMCPHandleListTools:
    """Tests for handle_list_tools() method."""

    @patch('hexstrike_mcp.requests.get')
    def test_returns_tools_array(self, mock_get, capsys):
        """Should return array of tools."""
        tools = [{"name": "nmap_scan", "description": "Scanner", "parameters": {"target": "string"}}]
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": tools})
        mcp = HexStrikeMCP("http://localhost:8888")

        mcp.handle_list_tools(1, {})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())

        assert "tools" in parsed["result"]
        assert isinstance(parsed["result"]["tools"], list)

    @patch('hexstrike_mcp.requests.get')
    def test_tools_have_input_schema(self, mock_get, capsys):
        """Tools should have inputSchema."""
        tools = [{"name": "nmap_scan", "description": "Scanner", "parameters": {"target": "string"}}]
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": tools})
        mcp = HexStrikeMCP("http://localhost:8888")

        mcp.handle_list_tools(1, {})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())

        tool = parsed["result"]["tools"][0]
        assert "inputSchema" in tool
        assert tool["inputSchema"]["type"] == "object"


class TestHexStrikeMCPHandleCallTool:
    """Tests for handle_call_tool() method."""

    @patch('hexstrike_mcp.requests.get')
    @patch('hexstrike_mcp.requests.post')
    def test_successful_tool_execution(self, mock_post, mock_get, capsys):
        """Should return tool result on success."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": [
            {"name": "nmap_scan", "description": "test", "parameters": {}}
        ]})
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"output": "scan complete", "ports": [22, 80]}
        )

        mcp = HexStrikeMCP("http://localhost:8888")
        mcp.handle_call_tool(1, {"name": "nmap_scan", "arguments": {"target": "10.10.10.5"}})

        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())

        assert parsed["result"]["content"][0]["type"] == "text"
        assert "scan complete" in parsed["result"]["content"][0]["text"]

    @patch('hexstrike_mcp.requests.get')
    def test_tool_not_found_error(self, mock_get, capsys):
        """Should return error for unknown tool."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888")

        mcp.handle_call_tool(1, {"name": "unknown_tool", "arguments": {}})

        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())

        assert "error" in parsed
        assert parsed["error"]["code"] == -32602

    @patch('hexstrike_mcp.requests.get')
    @patch('hexstrike_mcp.requests.post')
    def test_timeout_returns_error_content(self, mock_post, mock_get, capsys):
        """Should return isError content on timeout."""
        import requests
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": [
            {"name": "nmap_scan", "description": "test", "parameters": {}}
        ]})
        mock_post.side_effect = requests.exceptions.Timeout()

        mcp = HexStrikeMCP("http://localhost:8888")
        mcp.handle_call_tool(1, {"name": "nmap_scan", "arguments": {}})

        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())

        assert parsed["result"]["isError"] is True
        assert "timed out" in parsed["result"]["content"][0]["text"].lower()

    @patch('hexstrike_mcp.requests.get')
    @patch('hexstrike_mcp.requests.post')
    def test_http_error_returns_error_content(self, mock_post, mock_get, capsys):
        """Should return isError content on HTTP error."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": [
            {"name": "nmap_scan", "description": "test", "parameters": {}}
        ]})
        mock_post.return_value = MagicMock(status_code=500, text="Internal Server Error")

        mcp = HexStrikeMCP("http://localhost:8888")
        mcp.handle_call_tool(1, {"name": "nmap_scan", "arguments": {}})

        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())

        assert parsed["result"]["isError"] is True
        assert "500" in parsed["result"]["content"][0]["text"]


class TestHexStrikeMCPRun:
    """Tests for run() main loop."""

    @patch('hexstrike_mcp.requests.get')
    def test_handles_initialize_method(self, mock_get, capsys, monkeypatch):
        """Should handle initialize method."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888")

        # Simulate stdin with initialize message
        stdin = StringIO('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
        monkeypatch.setattr('sys.stdin', stdin)

        mcp.run()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert "protocolVersion" in parsed["result"]

    @patch('hexstrike_mcp.requests.get')
    def test_handles_malformed_json(self, mock_get, capsys, monkeypatch):
        """Should return parse error for malformed JSON."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888")

        stdin = StringIO('not valid json\n')
        monkeypatch.setattr('sys.stdin', stdin)

        mcp.run()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["error"]["code"] == -32700  # Parse error

    @patch('hexstrike_mcp.requests.get')
    def test_handles_unknown_method(self, mock_get, capsys, monkeypatch):
        """Should return method not found for unknown methods."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888")

        stdin = StringIO('{"jsonrpc":"2.0","id":1,"method":"unknown/method","params":{}}\n')
        monkeypatch.setattr('sys.stdin', stdin)

        mcp.run()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["error"]["code"] == -32601  # Method not found

    @patch('hexstrike_mcp.requests.get')
    def test_skips_empty_lines(self, mock_get, capsys, monkeypatch):
        """Should skip empty lines in input."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"tools": []})
        mcp = HexStrikeMCP("http://localhost:8888")

        stdin = StringIO('\n\n{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n\n')
        monkeypatch.setattr('sys.stdin', stdin)

        mcp.run()

        captured = capsys.readouterr()
        # Should only have one response (for the initialize)
        lines = [l for l in captured.out.strip().split('\n') if l]
        assert len(lines) == 1
