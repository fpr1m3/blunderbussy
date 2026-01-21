"""Unit tests for parse-onesixtyone.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-onesixtyone.py"
spec = importlib.util.spec_from_file_location("parse_onesixtyone", PARSER_PATH)
parse_onesixtyone = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_onesixtyone)


class TestParseOnesixtyone:
    """Tests for onesixtyone output parsing."""

    def test_parses_basic_sample(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_basic.txt")

        assert result["type"] == "onesixtyone"
        assert result["stats"]["hosts_found"] == 5
        assert len(result["findings"]) == 5

    def test_extracts_ip_community_description(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_basic.txt")

        # Check first finding
        first = result["findings"][0]
        assert first["ip"] == "10.10.10.1"
        assert first["community"] == "public"
        assert "Linux host" in first["description"]

    def test_counts_community_strings(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_basic.txt")

        communities = result["stats"]["communities"]
        assert communities["public"] == 3
        assert communities["private"] == 1
        assert communities["community"] == 1

    def test_identifies_default_communities(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]
        # Should flag hosts responding to default community strings
        assert any("public" in i for i in interesting)
        assert any("private" in i for i in interesting)

    def test_identifies_cisco_devices(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]
        assert any("Cisco" in i for i in interesting)

    def test_identifies_linux_systems(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]
        assert any("Linux" in i for i in interesting)

    def test_parses_minimal_sample(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_minimal.txt")

        assert result["type"] == "onesixtyone"
        assert result["stats"]["hosts_found"] == 1
        assert len(result["findings"]) == 1
        assert result["findings"][0]["ip"] == "192.168.1.100"

    def test_output_has_required_fields(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_basic.txt")

        required_fields = ["type", "findings", "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert "hosts_found" in stats
        assert "communities" in stats
        assert "interesting" in stats

    def test_finding_structure(self, onesixtyone_fixtures):
        result = parse_onesixtyone.parse_onesixtyone(onesixtyone_fixtures / "sample_basic.txt")

        for finding in result["findings"]:
            assert "ip" in finding
            assert "community" in finding
            assert "description" in finding


class TestDefaultCommunities:
    """Tests for default community string detection."""

    def test_recognizes_common_defaults(self):
        defaults = parse_onesixtyone.DEFAULT_COMMUNITIES
        assert "public" in defaults
        assert "private" in defaults
        assert "community" in defaults
        assert "admin" in defaults
        assert "cisco" in defaults
