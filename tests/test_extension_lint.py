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


class TestSkillStructure:
    """3b. Every skill directory has valid structure."""

    def _get_skill_dirs(self):
        """Return all skill directories (excluding SCHEMA.md)."""
        skills_dir = PREP_DIR / "skills"
        return [
            d for d in skills_dir.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]

    def test_skills_dir_exists(self):
        """skills/ directory exists."""
        assert (PREP_DIR / "skills").is_dir()

    def test_every_skill_has_skill_md(self):
        """Every skill directory contains SKILL.md."""
        for skill_dir in self._get_skill_dirs():
            skill_md = skill_dir / "SKILL.md"
            assert skill_md.exists(), f"Skill '{skill_dir.name}' missing SKILL.md"

    def test_skill_md_not_empty(self):
        """SKILL.md files are non-empty."""
        for skill_dir in self._get_skill_dirs():
            skill_md = skill_dir / "SKILL.md"
            if skill_md.exists():
                content = skill_md.read_text().strip()
                assert len(content) > 0, f"Skill '{skill_dir.name}/SKILL.md' is empty"

    def test_script_references_resolve(self):
        """Scripts referenced in skill directories exist and are readable."""
        for skill_dir in self._get_skill_dirs():
            scripts_dir = skill_dir / "scripts"
            if scripts_dir.exists():
                for script in scripts_dir.iterdir():
                    if script.suffix in (".py", ".sh"):
                        assert script.stat().st_size > 0, (
                            f"Script '{script}' is empty"
                        )


class TestAgentReferences:
    """3c. Agent markdown files integrity."""

    def _get_agent_files(self):
        """Return all .md files in agents/."""
        agents_dir = PREP_DIR / "agents"
        return list(agents_dir.glob("*.md"))

    def test_agents_dir_exists(self):
        """agents/ directory exists."""
        assert (PREP_DIR / "agents").is_dir()

    def test_agent_files_not_empty(self):
        """Every agent .md is non-empty."""
        for agent_file in self._get_agent_files():
            content = agent_file.read_text().strip()
            assert len(content) > 0, f"Agent '{agent_file.name}' is empty"

    def test_agent_files_have_title_or_frontmatter(self):
        """Every agent .md starts with a heading or YAML frontmatter."""
        for agent_file in self._get_agent_files():
            content = agent_file.read_text().strip()
            first_line = content.split("\n")[0]
            assert first_line.startswith("#") or first_line == "---", (
                f"Agent '{agent_file.name}' missing title heading or frontmatter. "
                f"First line: {first_line[:50]}"
            )

    def test_no_dangling_agent_references(self):
        """Skills referencing agents point to files that exist."""
        agents_dir = PREP_DIR / "agents"
        existing_agents = {f.stem for f in agents_dir.glob("*.md")}

        skills_dir = PREP_DIR / "skills"
        for skill_dir in skills_dir.iterdir():
            if not skill_dir.is_dir():
                continue
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.exists():
                continue
            content = skill_md.read_text()
            # Look for delegate_to_agent references
            refs = re.findall(r'delegate_to_agent\s*\(\s*["\']([^"\']+)["\']', content)
            for ref in refs:
                assert ref in existing_agents, (
                    f"Skill '{skill_dir.name}' references agent '{ref}' "
                    f"but no agents/{ref}.md exists"
                )


VALID_HOOK_EVENTS = {
    "SessionStart",
    "SessionEnd",
    "BeforeAgent",
    "AfterAgent",
    "BeforeModel",
    "AfterModel",
    "BeforeToolSelection",
    "BeforeTool",
    "AfterTool",
    "PreCompress",
    "Notification",
}


class TestHookWiring:
    """3d. Hook configuration integrity."""

    def _load_hooks_json(self):
        hooks_path = PREP_DIR / "hooks" / "hooks.json"
        assert hooks_path.exists(), "hooks/hooks.json not found"
        return json.loads(hooks_path.read_text())

    def test_hooks_json_valid(self):
        """hooks.json parses as valid JSON."""
        config = self._load_hooks_json()
        assert "hooks" in config

    def test_hook_events_are_valid(self):
        """Hook event types are recognized gemini-cli events."""
        config = self._load_hooks_json()
        for event_type in config["hooks"]:
            assert event_type in VALID_HOOK_EVENTS, (
                f"Unknown hook event type: '{event_type}'. "
                f"Valid: {VALID_HOOK_EVENTS}"
            )

    def test_hook_scripts_exist(self):
        """Every hook command references a script that exists."""
        config = self._load_hooks_json()
        hooks_dir = PREP_DIR / "hooks"

        for event_type, event_config in config["hooks"].items():
            for group in event_config:
                for hook in group.get("hooks", []):
                    cmd = hook.get("command", "")
                    # Extract script filename from command like
                    # "python3 ${extensionPath}/hooks/before_tool.py"
                    match = re.search(r'/hooks/(\S+\.py)', cmd)
                    if match:
                        script_name = match.group(1)
                        script_path = hooks_dir / script_name
                        assert script_path.exists(), (
                            f"Hook '{hook.get('name', 'unnamed')}' references "
                            f"missing script: {script_name}"
                        )

    def test_hook_scripts_importable(self):
        """Every hook .py script is importable (catches broken imports).

        This catches issues like the watcher module import problem
        documented in the design doc.
        """
        config = self._load_hooks_json()
        hooks_dir = PREP_DIR / "hooks"

        for event_type, event_config in config["hooks"].items():
            for group in event_config:
                for hook in group.get("hooks", []):
                    cmd = hook.get("command", "")
                    match = re.search(r'/hooks/(\S+\.py)', cmd)
                    if not match:
                        continue

                    script_name = match.group(1)
                    script_path = hooks_dir / script_name

                    # Use subprocess to test import in isolated process
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            f"import sys; sys.path.insert(0, '{hooks_dir}'); "
                            f"sys.path.insert(0, '{PREP_DIR}'); "
                            f"import importlib.util; "
                            f"spec = importlib.util.spec_from_file_location('hook', '{script_path}'); "
                            f"mod = importlib.util.module_from_spec(spec); "
                            f"spec.loader.exec_module(mod)",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    assert result.returncode == 0, (
                        f"Hook script '{script_name}' failed to import:\n"
                        f"{result.stderr[:500]}"
                    )


class TestCommandIntegrity:
    """3e. Command TOML files parse correctly."""

    def _get_command_files(self):
        commands_dir = PREP_DIR / "commands"
        return list(commands_dir.glob("*.toml"))

    def test_commands_dir_exists(self):
        """commands/ directory exists."""
        assert (PREP_DIR / "commands").is_dir()

    def test_toml_files_parse(self):
        """Every .toml in commands/ parses correctly."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        for toml_file in self._get_command_files():
            try:
                with open(toml_file, "rb") as f:
                    data = tomllib.load(f)
            except Exception as e:
                pytest.fail(f"Command '{toml_file.name}' failed to parse: {e}")

            assert "description" in data, (
                f"Command '{toml_file.name}' missing 'description' field"
            )
            assert "prompt" in data, (
                f"Command '{toml_file.name}' missing 'prompt' field"
            )
