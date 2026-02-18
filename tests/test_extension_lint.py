"""Extension linter — static validation of the PrEP extension tree.

No LLM calls. Validates structural integrity of the gemini-cli extension:
manifest, skills, agents, hooks, and commands.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

PREP_DIR = Path(__file__).parent.parent / "infrastructure" / "PrEP"


class TestManifestIntegrity:
    """3a. gemini-extension.json structural checks."""

    def test_manifest_is_valid_json(self):
        """gemini-extension.json parses as valid JSON."""
        manifest_path = PREP_DIR / "gemini-extension.json"
        assert manifest_path.exists(), "gemini-extension.json not found"
        manifest = json.loads(manifest_path.read_text())
        assert "name" in manifest
        assert "mcpServers" in manifest

    def test_mcp_servers_have_commands(self):
        """Every MCP server has a command entry."""
        manifest = json.loads((PREP_DIR / "gemini-extension.json").read_text())
        for name, config in manifest.get("mcpServers", {}).items():
            assert "command" in config, f"MCP server '{name}' missing 'command'"

    def test_mcp_server_scripts_exist(self):
        """Server scripts referenced in manifest exist (for local scripts)."""
        manifest = json.loads((PREP_DIR / "gemini-extension.json").read_text())
        for name, config in manifest.get("mcpServers", {}).items():
            args = config.get("args", [])
            for arg in args:
                # Only check paths that look like local files
                if arg.startswith("/ext/opulence/"):
                    # Map container path to host path
                    rel = arg.replace("/ext/opulence/", "")
                    host_path = PREP_DIR / rel
                    assert host_path.exists(), (
                        f"MCP server '{name}' references missing file: {arg} "
                        f"(expected at {host_path})"
                    )
