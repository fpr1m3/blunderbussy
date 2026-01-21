"""Unit tests for parse-showmount.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-showmount.py"
spec = importlib.util.spec_from_file_location("parse_showmount", PARSER_PATH)
parse_showmount = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_showmount)


class TestParseShowmount:
    """Tests for showmount output parsing."""

    def test_parses_basic_sample(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        assert result["type"] == "showmount"
        assert result["target"] == "10.10.10.1"
        assert result["stats"]["total_exports"] == 4

    def test_extracts_exports(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        exports = result["exports"]
        paths = [e["path"] for e in exports]

        assert "/home" in paths
        assert "/var/backups" in paths
        assert "/srv/nfs" in paths
        assert "/data" in paths

    def test_identifies_world_readable_wildcard(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        home_export = next(e for e in result["exports"] if e["path"] == "/home")
        assert home_export["world_readable"] is True
        assert "*" in home_export["allowed_hosts"]

    def test_identifies_world_readable_everyone(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        srv_export = next(e for e in result["exports"] if e["path"] == "/srv/nfs")
        assert srv_export["world_readable"] is True

    def test_identifies_restricted_export(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        backups_export = next(e for e in result["exports"] if e["path"] == "/var/backups")
        assert backups_export["world_readable"] is False
        assert "192.168.1.0/24" in backups_export["allowed_hosts"]

    def test_parses_comma_separated_hosts(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        data_export = next(e for e in result["exports"] if e["path"] == "/data")
        assert "server1.local" in data_export["allowed_hosts"]
        assert "server2.local" in data_export["allowed_hosts"]

    def test_stats_world_readable_list(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        world_readable = result["stats"]["world_readable"]
        assert "/home" in world_readable
        assert "/srv/nfs" in world_readable
        assert "/var/backups" not in world_readable

    def test_identifies_sensitive_paths(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        sensitive = result["stats"]["sensitive_paths"]
        assert "/home" in sensitive
        assert "/var/backups" in sensitive

    def test_generates_interesting_findings(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]
        # Should flag world-readable exports
        assert any("World-readable" in i for i in interesting)
        # Should flag sensitive paths
        assert any("Sensitive" in i or "/home" in i for i in interesting)

    def test_parses_minimal_sample(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_minimal.txt")

        assert result["type"] == "showmount"
        assert result["target"] == "nfs.example.com"
        assert result["stats"]["total_exports"] == 1
        assert result["exports"][0]["path"] == "/exports"
        assert result["exports"][0]["world_readable"] is False

    def test_output_has_required_fields(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        required_fields = ["type", "target", "exports", "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert "total_exports" in stats
        assert "world_readable" in stats
        assert "sensitive_paths" in stats
        assert "interesting" in stats

    def test_export_structure(self, showmount_fixtures):
        result = parse_showmount.parse_showmount(showmount_fixtures / "sample_basic.txt")

        for export in result["exports"]:
            assert "path" in export
            assert "allowed_hosts" in export
            assert "world_readable" in export


class TestWorldReadableDetection:
    """Tests for world-readable detection logic."""

    def test_wildcard_is_world_readable(self):
        assert parse_showmount.is_world_readable(["*"]) is True

    def test_everyone_is_world_readable(self):
        assert parse_showmount.is_world_readable(["(everyone)"]) is True
        assert parse_showmount.is_world_readable(["everyone"]) is True

    def test_specific_host_not_world_readable(self):
        assert parse_showmount.is_world_readable(["192.168.1.0/24"]) is False
        assert parse_showmount.is_world_readable(["server.local"]) is False

    def test_empty_host_is_world_readable(self):
        assert parse_showmount.is_world_readable([""]) is True


class TestSensitivePathDetection:
    """Tests for sensitive path detection logic."""

    def test_home_is_sensitive(self):
        assert parse_showmount.is_sensitive_path("/home") is True

    def test_root_is_sensitive(self):
        assert parse_showmount.is_sensitive_path("/root") is True

    def test_etc_is_sensitive(self):
        assert parse_showmount.is_sensitive_path("/etc") is True

    def test_var_backups_is_sensitive(self):
        assert parse_showmount.is_sensitive_path("/var/backups") is True

    def test_subpath_of_sensitive_is_sensitive(self):
        assert parse_showmount.is_sensitive_path("/home/user") is True
        assert parse_showmount.is_sensitive_path("/etc/passwd") is True

    def test_random_path_not_sensitive(self):
        assert parse_showmount.is_sensitive_path("/exports") is False
        assert parse_showmount.is_sensitive_path("/public") is False
