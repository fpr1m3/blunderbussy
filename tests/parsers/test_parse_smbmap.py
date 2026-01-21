"""Unit tests for parse-smbmap.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-smbmap.py"
spec = importlib.util.spec_from_file_location("parse_smbmap", PARSER_PATH)
parse_smbmap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_smbmap)


class TestParseTarget:
    """Tests for target extraction."""

    def test_extracts_ip_from_status_line(self):
        lines = ["[+] IP: 10.10.10.3:445	Name: lame.htb"]
        assert parse_smbmap.parse_target(lines) == "10.10.10.3"

    def test_extracts_from_host_format(self):
        lines = ["Host: 10.10.10.40"]
        assert parse_smbmap.parse_target(lines) == "10.10.10.40"

    def test_returns_none_when_no_target(self):
        lines = ["no target here"]
        assert parse_smbmap.parse_target(lines) is None


class TestParseHostname:
    """Tests for hostname extraction."""

    def test_extracts_hostname(self):
        lines = ["[+] IP: 10.10.10.3:445	Name: lame.htb"]
        assert parse_smbmap.parse_hostname(lines) == "lame.htb"

    def test_returns_none_when_no_hostname(self):
        lines = ["no hostname"]
        assert parse_smbmap.parse_hostname(lines) is None


class TestParseShares:
    """Tests for share enumeration extraction."""

    def test_extracts_shares_with_permissions(self):
        lines = [
            "Disk                      Permissions Comment",
            "----                      ----------- -------",
            "tmp             Disk      READ, WRITE    temp share",
            "admin$          Disk      NO ACCESS      Admin",
        ]
        result = parse_smbmap.parse_shares(lines)

        assert len(result) == 2
        assert result[0]["name"] == "tmp"
        assert result[0]["readable"] is True
        assert result[0]["writable"] is True
        assert result[1]["name"] == "admin$"
        assert result[1]["readable"] is False

    def test_handles_read_only_share(self):
        lines = [
            "Disk      Permissions",
            "Users           Disk      READ           User profiles",
        ]
        result = parse_smbmap.parse_shares(lines)

        assert len(result) == 1
        assert result[0]["readable"] is True
        assert result[0]["writable"] is False


class TestParseFileListing:
    """Tests for recursive file listing extraction."""

    def test_extracts_file_listings(self):
        lines = [
            "./Share",
            "dr--r--r--                0 Tue Jan 14 09:15:00 2026	Documents",
            "fr--r--r--             1024 Tue Jan 14 09:15:00 2026	readme.txt",
        ]
        result = parse_smbmap.parse_file_listing(lines)

        assert "Share" in result
        assert len(result["Share"]) == 2
        dirs = [f for f in result["Share"] if f["type"] == "directory"]
        files = [f for f in result["Share"] if f["type"] == "file"]
        assert len(dirs) == 1
        assert len(files) == 1

    def test_extracts_nested_paths(self):
        lines = [
            "./C$/Users",
            "dr--r--r--                0 Fri Jul 21 02:56:23 2017	Administrator",
            "./C$/Users/Administrator/Desktop",
            "fr--r--r--               34 Thu Nov 23 12:47:03 2023	root.txt",
        ]
        result = parse_smbmap.parse_file_listing(lines)

        assert "C$" in result
        # Should have files from both paths
        assert any(f["name"] == "Administrator" for f in result["C$"])
        assert any(f["name"] == "root.txt" for f in result["C$"])

    def test_skips_dot_entries(self):
        lines = [
            "./Share",
            "dr--r--r--                0 Tue Jan 14 09:15:00 2026	.",
            "dr--r--r--                0 Tue Jan 14 09:15:00 2026	..",
            "fr--r--r--             1024 Tue Jan 14 09:15:00 2026	file.txt",
        ]
        result = parse_smbmap.parse_file_listing(lines)

        names = [f["name"] for f in result["Share"]]
        assert "." not in names
        assert ".." not in names


class TestIdentifyInterestingFiles:
    """Tests for interesting file identification."""

    def test_identifies_sensitive_files(self):
        file_listings = {
            "Share": [
                {"path": "/", "name": "passwords.xlsx", "type": "file", "size": 1024},
                {"path": "/", "name": "id_rsa.bak", "type": "file", "size": 2048},
                {"path": "/", "name": "readme.txt", "type": "file", "size": 512},
            ]
        }
        result = parse_smbmap.identify_interesting_files(file_listings)

        assert any("password" in f.lower() for f in result)
        assert any("id_rsa" in f.lower() for f in result)

    def test_identifies_flag_files(self):
        file_listings = {
            "C$": [
                {"path": "/Users/Admin/Desktop", "name": "root.txt", "type": "file", "size": 34},
                {"path": "/Users/User/Desktop", "name": "user.txt", "type": "file", "size": 34},
            ]
        }
        result = parse_smbmap.identify_interesting_files(file_listings)

        assert any("root.txt" in f for f in result)
        assert any("user.txt" in f for f in result)


class TestParseSmbmap:
    """Integration tests for full parser."""

    def test_parses_basic_sample(self, smbmap_fixtures):
        result = parse_smbmap.parse_smbmap(smbmap_fixtures / "sample_basic.txt")

        assert result["type"] == "smbmap"
        assert result["target"] == "10.10.10.3"
        assert result["hostname"] == "lame.htb"
        assert result["stats"]["shares_found"] == 5
        assert result["stats"]["readable_shares"] >= 1
        assert result["stats"]["writable_shares"] >= 1

    def test_parses_recursive_sample(self, smbmap_fixtures):
        result = parse_smbmap.parse_smbmap(smbmap_fixtures / "sample_recursive.txt")

        assert result["type"] == "smbmap"
        assert result["stats"]["files_listed"] > 0
        # Should find interesting files like root.txt, passwords.xlsx
        interesting = result["stats"]["interesting_files"]
        assert len(interesting) > 0

    def test_identifies_writable_shares(self, smbmap_fixtures):
        result = parse_smbmap.parse_smbmap(smbmap_fixtures / "sample_basic.txt")

        writable_shares = [s for s in result["shares"] if s.get("writable")]
        assert len(writable_shares) >= 1
        assert any(s["name"] == "tmp" for s in writable_shares)

    def test_interesting_findings_summary(self, smbmap_fixtures):
        result = parse_smbmap.parse_smbmap(smbmap_fixtures / "sample_recursive.txt")

        interesting = result["stats"]["interesting"]
        # Should mention writable shares
        assert any("writable" in i.lower() for i in interesting)

    def test_output_has_required_fields(self, smbmap_fixtures):
        result = parse_smbmap.parse_smbmap(smbmap_fixtures / "sample_basic.txt")

        required_fields = ["type", "target", "hostname", "shares", "file_listings",
                          "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, smbmap_fixtures):
        result = parse_smbmap.parse_smbmap(smbmap_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert "shares_found" in stats
        assert "readable_shares" in stats
        assert "writable_shares" in stats
        assert "files_listed" in stats
        assert "interesting_files" in stats
        assert "interesting" in stats


class TestAuthSample:
    """Tests for authenticated scan output."""

    def test_parses_auth_sample(self, smbmap_fixtures):
        auth_file = smbmap_fixtures / "sample_auth.txt"
        if auth_file.exists():
            result = parse_smbmap.parse_smbmap(auth_file)
            assert result["type"] == "smbmap"
            # Auth scans typically have more access
            assert result["stats"]["shares_found"] >= 0
