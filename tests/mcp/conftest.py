"""
Pytest configuration for MCP server input validation tests.

These tests validate Pydantic input models WITHOUT requiring the actual
backends (pwncat, metasploit, sliver) to be installed or running.

We mock the MCP and backend-specific imports since we only need to test
the Pydantic models for input validation.
"""

import pytest
import sys
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

# Add servers directory to path so we can import the input models
servers_path = Path(__file__).parent.parent.parent / "infrastructure/PrEP/servers"
sys.path.insert(0, str(servers_path))


def _mock_unavailable_modules():
    """Mock modules that aren't installed in the test environment."""
    mock_modules = [
        'mcp',
        'mcp.server',
        'mcp.server.fastmcp',
        'pwncat',
        'pwncat.manager',
        'sliver',
        'httpx',
        'aiohttp',
        'aiohttp.web',
    ]

    for mod_name in mock_modules:
        if mod_name not in sys.modules:
            mock = MagicMock()
            # FastMCP decorator needs to be callable
            if mod_name == 'mcp.server.fastmcp':
                mock.FastMCP = MagicMock(return_value=MagicMock())
            sys.modules[mod_name] = mock


def _load_module_from_file(module_name: str, file_name: str):
    """Load a Python module from a file with non-standard name (hyphens)."""
    _mock_unavailable_modules()

    file_path = servers_path / file_name
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


# Pre-load modules with hyphenated names so they can be imported normally
# These modules have hyphens in their filenames which Python can't import directly
_load_module_from_file("pwncat_server", "pwncat-server.py")
_load_module_from_file("msf_server", "msf-server.py")
_load_module_from_file("sliver_server", "sliver-server.py")


@pytest.fixture
def valid_session_id():
    """Return a valid session ID string."""
    return "a1b2c3d4"


@pytest.fixture
def valid_port():
    """Return a valid port number."""
    return 4444


@pytest.fixture
def valid_host():
    """Return a valid host/IP address."""
    return "10.10.14.5"
