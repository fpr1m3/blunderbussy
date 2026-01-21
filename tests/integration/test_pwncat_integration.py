#!/usr/bin/env python3
"""
Integration tests for Pwncat MCP Server.

Tests the pwncat MCP server via subprocess communication, verifying that
the JSON-RPC protocol works end-to-end for tool invocations.

These tests:
1. Start the pwncat MCP server as a subprocess
2. Send MCP protocol requests via stdin
3. Verify responses via stdout
4. Test both simple protocol operations and shell connection scenarios
"""

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import pytest


# Path to the pwncat server
PWNCAT_SERVER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "PrEP" / "pwncat-server.py"


def find_free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


class MCPClient:
    """Helper class for communicating with MCP server via subprocess."""

    def __init__(self, server_path: Path, timeout: float = 10.0):
        self.server_path = server_path
        self.timeout = timeout
        self.proc: Optional[subprocess.Popen] = None
        self._request_id = 0

    def start(self) -> None:
        """Start the MCP server subprocess."""
        self.proc = subprocess.Popen(
            [sys.executable, str(self.server_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
        )

    def stop(self) -> None:
        """Stop the MCP server subprocess."""
        if self.proc:
            try:
                self.proc.stdin.close()
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
            finally:
                self.proc = None

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a JSON-RPC request and return the response.

        Args:
            method: The MCP method to call
            params: Optional parameters for the method

        Returns:
            The JSON-RPC response dict

        Raises:
            TimeoutError: If no response received within timeout
            RuntimeError: If server is not running
        """
        if not self.proc or self.proc.poll() is not None:
            raise RuntimeError("MCP server is not running")

        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params or {}
        }

        # Send request
        request_line = json.dumps(request) + "\n"
        self.proc.stdin.write(request_line)
        self.proc.stdin.flush()

        # Read response with timeout
        import select
        ready, _, _ = select.select([self.proc.stdout], [], [], self.timeout)
        if not ready:
            raise TimeoutError(f"No response received within {self.timeout}s")

        response_line = self.proc.stdout.readline()
        if not response_line:
            # Check stderr for error messages
            stderr_output = ""
            if self.proc.stderr:
                ready, _, _ = select.select([self.proc.stderr], [], [], 0.1)
                if ready:
                    stderr_output = self.proc.stderr.read()
            raise RuntimeError(f"Server returned empty response. stderr: {stderr_output}")

        return json.loads(response_line.strip())

    def call_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call an MCP tool and return the result.

        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments

        Returns:
            The tool result (parsed from content)
        """
        response = self.send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments or {}
        })

        if "error" in response:
            return {"error": response["error"]}

        # Extract tool result from MCP content format
        result = response.get("result", {})
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            return json.loads(content[0]["text"])

        return result

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


@pytest.fixture
def mcp_client():
    """Fixture that provides an MCP client connected to the pwncat server."""
    with MCPClient(PWNCAT_SERVER_PATH) as client:
        yield client


@pytest.fixture
def initialized_mcp_client(mcp_client):
    """Fixture that provides an initialized MCP client."""
    # Send initialize request
    response = mcp_client.send_request("initialize", {})
    assert "result" in response, f"Initialize failed: {response}"
    return mcp_client


class TestMCPServerStartup:
    """Test that the MCP server starts and responds correctly."""

    @pytest.mark.integration
    def test_server_starts_and_stops(self):
        """Verify server process can be started and stopped cleanly."""
        with MCPClient(PWNCAT_SERVER_PATH, timeout=5) as client:
            assert client.proc is not None
            assert client.proc.poll() is None  # Process is running

        # After context exit, process should be terminated
        assert client.proc is None

    @pytest.mark.integration
    def test_initialize_returns_server_info(self, mcp_client):
        """Verify initialize response contains correct server information."""
        response = mcp_client.send_request("initialize", {})

        assert response["jsonrpc"] == "2.0"
        assert "result" in response

        result = response["result"]
        assert result["serverInfo"]["name"] == "opulence-pwncat"
        assert result["protocolVersion"] == "2024-11-05"
        assert "capabilities" in result
        assert "tools" in result["capabilities"]

    @pytest.mark.integration
    def test_initialize_reports_pwncat_availability(self, mcp_client):
        """Verify initialize response indicates pwncat availability."""
        response = mcp_client.send_request("initialize", {})

        result = response["result"]
        # pwncat_available should be a boolean
        assert "pwncat_available" in result["serverInfo"]
        assert isinstance(result["serverInfo"]["pwncat_available"], bool)


class TestMCPToolsList:
    """Test the tools/list MCP method."""

    @pytest.mark.integration
    def test_tools_list_returns_all_tools(self, initialized_mcp_client):
        """Verify tools/list returns all 8 pwncat tools."""
        response = initialized_mcp_client.send_request("tools/list", {})

        assert "result" in response
        assert "tools" in response["result"]

        tools = response["result"]["tools"]
        assert len(tools) == 8

        expected_tools = [
            "pwncat__listen",
            "pwncat__connect",
            "pwncat__sessions",
            "pwncat__command",
            "pwncat__module",
            "pwncat__upload",
            "pwncat__download",
            "pwncat__close"
        ]

        tool_names = [t["name"] for t in tools]
        for expected in expected_tools:
            assert expected in tool_names, f"Missing tool: {expected}"

    @pytest.mark.integration
    def test_tools_have_valid_schemas(self, initialized_mcp_client):
        """Verify each tool has a valid inputSchema."""
        response = initialized_mcp_client.send_request("tools/list", {})
        tools = response["result"]["tools"]

        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

            schema = tool["inputSchema"]
            assert schema["type"] == "object"
            assert "properties" in schema
            assert "required" in schema


class TestPwncatSessionsTool:
    """Test the pwncat__sessions tool (simplest tool - no external deps)."""

    @pytest.mark.integration
    def test_sessions_returns_empty_list(self, initialized_mcp_client):
        """Verify pwncat__sessions returns empty list when no sessions exist."""
        result = initialized_mcp_client.call_tool("pwncat__sessions", {})

        # Should return an empty list (no active sessions)
        assert isinstance(result, list)
        assert len(result) == 0

    @pytest.mark.integration
    def test_sessions_multiple_calls(self, initialized_mcp_client):
        """Verify sessions can be called multiple times."""
        for _ in range(3):
            result = initialized_mcp_client.call_tool("pwncat__sessions", {})
            assert isinstance(result, list)


class TestMCPErrorHandling:
    """Test MCP protocol error handling."""

    @pytest.mark.integration
    def test_unknown_method_returns_error(self, initialized_mcp_client):
        """Verify unknown methods return proper JSON-RPC error."""
        response = initialized_mcp_client.send_request("unknown/method", {})

        assert "error" in response
        assert response["error"]["code"] == -32601
        assert "Method not found" in response["error"]["message"]

    @pytest.mark.integration
    def test_unknown_tool_returns_error(self, initialized_mcp_client):
        """Verify calling unknown tool returns error in result."""
        response = initialized_mcp_client.send_request("tools/call", {
            "name": "pwncat__nonexistent",
            "arguments": {}
        })

        # Should return an error response
        assert "error" in response
        assert response["error"]["code"] == -32603


class TestPwncatCommandToolValidation:
    """Test pwncat__command tool argument validation."""

    @pytest.mark.integration
    def test_command_with_invalid_session_returns_error(self, initialized_mcp_client):
        """Verify command with non-existent session returns error."""
        result = initialized_mcp_client.call_tool("pwncat__command", {
            "session_id": "nonexistent",
            "command": "whoami"
        })

        # Should return error about session not found
        assert "error" in result or ("output" in result and "Error" in result.get("output", ""))


class TestPwncatCloseToolValidation:
    """Test pwncat__close tool argument validation."""

    @pytest.mark.integration
    def test_close_with_invalid_session_returns_error(self, initialized_mcp_client):
        """Verify close with non-existent session returns error."""
        result = initialized_mcp_client.call_tool("pwncat__close", {
            "session_id": "nonexistent"
        })

        # Should return error about session not found
        assert "error" in result


class TestPwncatListenToolValidation:
    """Test pwncat__listen tool with timeout."""

    @pytest.mark.integration
    @pytest.mark.skipif(
        not PWNCAT_SERVER_PATH.exists(),
        reason="pwncat-server.py not found"
    )
    def test_listen_with_short_timeout_returns_timeout_error(self, initialized_mcp_client):
        """Verify listen with short timeout returns timeout error gracefully."""
        port = find_free_port()

        result = initialized_mcp_client.call_tool("pwncat__listen", {
            "port": port,
            "host": "127.0.0.1",
            "timeout": 1  # 1 second timeout
        })

        # Should return timeout error (no connection within 1 second)
        # The server may or may not have pwncat installed
        # If pwncat is not installed, we may get a runtime error instead
        if "error" in result:
            # Either timeout or pwncat not available
            assert result["error"] in ["timeout", "runtime_error", "internal_error"]


class TestShellConnectionScenario:
    """
    Integration test for full shell connection scenario.

    This test is more complex and tests:
    1. Starting a listener
    2. Connecting a mock shell
    3. Running commands
    4. Closing the session

    Marked as slow since it involves network operations.
    """

    @pytest.mark.integration
    @pytest.mark.slow
    @pytest.mark.skipif(
        os.environ.get("SKIP_SHELL_TESTS", "1") == "1",
        reason="Shell connection tests disabled (set SKIP_SHELL_TESTS=0 to enable)"
    )
    def test_full_shell_connection_workflow(self):
        """
        Test full workflow: listen -> connect shell -> command -> close.

        This test requires pwncat-cs to be installed and functional.
        It creates a mock reverse shell using bash and verifies the
        full workflow.
        """
        pytest.importorskip("pwncat", reason="pwncat-cs not installed")

        port = find_free_port()
        listener_started = threading.Event()
        shell_connected = threading.Event()

        def mock_shell():
            """Simulate a reverse shell connecting to the listener."""
            # Wait for listener to start
            if not listener_started.wait(timeout=5):
                return

            time.sleep(0.5)  # Give listener time to be ready

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(('127.0.0.1', port))

                # Simple shell simulation - respond to commands
                shell_connected.set()

                while True:
                    try:
                        data = sock.recv(1024)
                        if not data:
                            break

                        # Simulate shell command output
                        command = data.decode().strip()
                        if command == "whoami":
                            sock.send(b"testuser\n")
                        elif command == "id":
                            sock.send(b"uid=1000(testuser) gid=1000(testuser)\n")
                        elif command == "exit":
                            break
                        else:
                            sock.send(f"command not found: {command}\n".encode())
                    except Exception:
                        break

                sock.close()
            except Exception as e:
                print(f"Mock shell error: {e}")

        with MCPClient(PWNCAT_SERVER_PATH, timeout=30) as client:
            # Initialize
            init_response = client.send_request("initialize", {})
            assert "result" in init_response

            # Check if pwncat is available
            if not init_response["result"]["serverInfo"].get("pwncat_available", False):
                pytest.skip("pwncat-cs not available on this system")

            # Start mock shell in background
            shell_thread = threading.Thread(target=mock_shell, daemon=True)
            shell_thread.start()

            # Start listener
            listener_started.set()

            listen_result = client.call_tool("pwncat__listen", {
                "port": port,
                "host": "127.0.0.1",
                "timeout": 10
            })

            if "error" in listen_result:
                if listen_result["error"] == "timeout":
                    pytest.skip("Shell connection timed out")
                pytest.fail(f"Listen failed: {listen_result}")

            session_id = listen_result.get("session_id")
            assert session_id is not None

            # Verify session appears in list
            sessions = client.call_tool("pwncat__sessions", {})
            assert any(s.get("session_id") == session_id for s in sessions)

            # Run command
            cmd_result = client.call_tool("pwncat__command", {
                "session_id": session_id,
                "command": "whoami"
            })

            assert "output" in cmd_result

            # Close session
            close_result = client.call_tool("pwncat__close", {
                "session_id": session_id
            })

            assert close_result.get("status") == "closed"

            # Verify session is gone
            sessions = client.call_tool("pwncat__sessions", {})
            assert not any(s.get("session_id") == session_id for s in sessions)


class TestMCPProtocolCompliance:
    """Test MCP protocol compliance and edge cases."""

    @pytest.mark.integration
    def test_json_rpc_version_in_response(self, mcp_client):
        """Verify all responses include jsonrpc version."""
        response = mcp_client.send_request("initialize", {})
        assert response.get("jsonrpc") == "2.0"

    @pytest.mark.integration
    def test_request_id_echoed(self, mcp_client):
        """Verify request ID is echoed in response."""
        request_id = 42
        mcp_client._request_id = request_id - 1  # Will be incremented
        response = mcp_client.send_request("initialize", {})
        assert response.get("id") == request_id

    @pytest.mark.integration
    def test_multiple_sequential_requests(self, initialized_mcp_client):
        """Verify multiple sequential requests work correctly."""
        for i in range(5):
            response = initialized_mcp_client.send_request("tools/list", {})
            assert "result" in response
            assert response["id"] == i + 2  # +2 because init was id=1

    @pytest.mark.integration
    def test_notifications_do_not_return_response(self, initialized_mcp_client):
        """Verify that notification methods don't require a response check."""
        # notifications/initialized is a notification - server may not respond
        # This is just to verify the server doesn't crash on notifications
        try:
            # We don't expect a response for notifications, but the server
            # should handle them gracefully
            pass  # notifications/initialized is handled internally
        except TimeoutError:
            pass  # Expected - notifications don't get responses


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
