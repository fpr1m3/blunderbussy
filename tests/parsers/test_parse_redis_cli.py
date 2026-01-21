"""
Unit tests for parse-redis-cli.py parser.

Tests parsing of Redis CLI output including INFO, KEYS, and CONFIG GET commands.
"""

import importlib.util
import json
from pathlib import Path
import pytest


# Load the parser module
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-redis-cli.py"
spec = importlib.util.spec_from_file_location("parse_redis_cli", PARSER_PATH)
parse_redis_cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_redis_cli)


@pytest.fixture
def redis_cli_fixtures():
    """Return path to redis-cli test fixtures directory."""
    return Path(__file__).parent.parent / "fixtures" / "redis-cli"


class TestParseRedisCli:
    """Test suite for Redis CLI parser."""

    def test_parses_basic_fixture(self, redis_cli_fixtures):
        """Test parsing of basic Redis CLI output."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        # Basic structure
        assert result["type"] == "redis-cli"
        assert "target" in result
        assert "parsed_at" in result
        assert "raw_file" in result

        # Check main sections exist
        assert "server_info" in result
        assert "keys" in result
        assert "databases" in result
        assert "config" in result
        assert "stats" in result

    def test_parses_server_info(self, redis_cli_fixtures):
        """Test parsing of Redis server information."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        server_info = result["server_info"]
        assert "redis_version" in server_info
        assert server_info["redis_version"] == "6.2.6"
        assert "os" in server_info
        assert "Linux" in server_info["os"]
        assert "tcp_port" in server_info
        assert server_info["tcp_port"] == "6379"

    def test_parses_keyspace_databases(self, redis_cli_fixtures):
        """Test parsing of database statistics from Keyspace section."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        databases = result["databases"]
        assert len(databases) >= 3
        assert "db0" in databases
        assert "db1" in databases
        assert "db2" in databases

        # Check db0 structure
        db0 = databases["db0"]
        assert "keys" in db0
        assert db0["keys"] == 42
        assert "expires" in db0
        assert db0["expires"] == 10

        # Check db1
        db1 = databases["db1"]
        assert db1["keys"] == 15
        assert db1["expires"] == 5

    def test_parses_keys_listing(self, redis_cli_fixtures):
        """Test parsing of KEYS command output."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        keys = result["keys"]
        assert isinstance(keys, list)
        assert len(keys) > 0

        # Check for specific keys
        assert "user:1001" in keys
        assert "session:abc123" in keys
        assert "config:app" in keys
        assert "admin:token" in keys

    def test_parses_config_output(self, redis_cli_fixtures):
        """Test parsing of CONFIG GET output."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        config = result["config"]
        assert isinstance(config, dict)
        assert len(config) > 0

        # Check specific config values
        assert "port" in config
        assert config["port"] == "6379"
        assert "maxclients" in config
        assert config["maxclients"] == "10000"
        assert "timeout" in config
        assert config["timeout"] == "0"
        assert "databases" in config
        assert config["databases"] == "16"

    def test_identifies_sensitive_keys(self, redis_cli_fixtures):
        """Test identification of potentially sensitive keys."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]
        assert isinstance(interesting, list)
        assert len(interesting) > 0

        # Check that sensitive keys are flagged
        interesting_text = " ".join(interesting)
        assert "sensitive keys" in interesting_text.lower() or "admin:token" in interesting_text

    def test_identifies_security_issues(self, redis_cli_fixtures):
        """Test identification of security configuration issues."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]
        interesting_text = " ".join(interesting).lower()

        # Should flag no password
        assert "password" in interesting_text or "requirepass" in interesting_text

        # Should flag protected mode
        assert "protected" in interesting_text or "protected-mode" in interesting_text

    def test_calculates_stats(self, redis_cli_fixtures):
        """Test calculation of summary statistics."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert "total_keys" in stats
        assert stats["total_keys"] > 0
        assert "total_databases" in stats
        assert stats["total_databases"] >= 3
        assert "keys_found" in stats
        assert stats["keys_found"] > 0
        assert "config_entries" in stats
        assert stats["config_entries"] > 0

    def test_extracts_target(self, redis_cli_fixtures):
        """Test extraction of target host:port."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        target = result["target"]
        assert ":" in target
        # Should extract from first line comment or default
        assert target == "10.10.11.123:6379" or target == "unknown:6379"

    def test_parses_memory_info(self, redis_cli_fixtures):
        """Test parsing of memory information section."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        memory_info = result["memory_info"]
        assert "used_memory" in memory_info
        assert "used_memory_human" in memory_info

    def test_parses_stats_info(self, redis_cli_fixtures):
        """Test parsing of stats information section."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        stats_info = result["stats_info"]
        assert "total_connections_received" in stats_info
        assert "total_commands_processed" in stats_info

    def test_parses_replication_info(self, redis_cli_fixtures):
        """Test parsing of replication information section."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        replication_info = result["replication_info"]
        assert "role" in replication_info
        assert replication_info["role"] == "master"

    def test_output_is_valid_json(self, redis_cli_fixtures):
        """Test that parser output is valid JSON."""
        result = parse_redis_cli.parse_redis_cli(redis_cli_fixtures / "sample_basic.txt")

        # Should be able to serialize and deserialize
        json_str = json.dumps(result)
        parsed = json.loads(json_str)
        assert parsed["type"] == "redis-cli"

    def test_handles_missing_sections_gracefully(self, tmp_path):
        """Test parser handles minimal Redis output without errors."""
        minimal_output = """# Server
redis_version:6.0.0
tcp_port:6379
"""
        test_file = tmp_path / "minimal.txt"
        test_file.write_text(minimal_output)

        result = parse_redis_cli.parse_redis_cli(test_file)

        assert result["type"] == "redis-cli"
        assert result["server_info"]["redis_version"] == "6.0.0"
        assert result["keys"] == []
        assert result["databases"] == {}
        assert result["config"] == {}

    def test_cli_pretty_flag(self, redis_cli_fixtures, capsys):
        """Test that --pretty flag produces formatted output."""
        import sys
        from unittest.mock import patch

        test_args = [
            "parse-redis-cli.py",
            str(redis_cli_fixtures / "sample_basic.txt"),
            "--pretty"
        ]

        with patch.object(sys, 'argv', test_args):
            exit_code = parse_redis_cli.main()

        assert exit_code == 0

        captured = capsys.readouterr()
        output = captured.out

        # Pretty printed JSON should have indentation
        assert "  " in output  # Contains indentation
        parsed = json.loads(output)
        assert parsed["type"] == "redis-cli"

    def test_cli_without_pretty_flag(self, redis_cli_fixtures, capsys):
        """Test that output without --pretty is compact."""
        import sys
        from unittest.mock import patch

        test_args = [
            "parse-redis-cli.py",
            str(redis_cli_fixtures / "sample_basic.txt")
        ]

        with patch.object(sys, 'argv', test_args):
            exit_code = parse_redis_cli.main()

        assert exit_code == 0

        captured = capsys.readouterr()
        output = captured.out

        # Non-pretty output should be single line (or minimal lines)
        parsed = json.loads(output)
        assert parsed["type"] == "redis-cli"

    def test_cli_file_not_found(self, capsys):
        """Test CLI handles non-existent file gracefully."""
        import sys
        from unittest.mock import patch

        test_args = [
            "parse-redis-cli.py",
            "/nonexistent/file.txt"
        ]

        with patch.object(sys, 'argv', test_args):
            exit_code = parse_redis_cli.main()

        assert exit_code == 1

        captured = capsys.readouterr()
        output = captured.out
        assert "error" in output.lower()
