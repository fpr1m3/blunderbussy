"""Unit tests for parse-feroxbuster.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-feroxbuster.py"
spec = importlib.util.spec_from_file_location("parse_feroxbuster", PARSER_PATH)
parse_feroxbuster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_feroxbuster)


class TestParseFeroxbusterLine:
    """Tests for individual line parsing."""

    def test_parses_full_format_line(self):
        line = "200      GET      12l       25w      321c http://10.10.10.15/"
        result = parse_feroxbuster.parse_feroxbuster_line(line)

        assert result["status"] == 200
        assert result["method"] == "GET"
        assert result["lines"] == 12
        assert result["words"] == 25
        assert result["size"] == 321
        assert result["url"] == "http://10.10.10.15/"
        assert result["path"] == "/"

    def test_parses_simple_format_line(self):
        line = "200 1024 http://target/admin"
        result = parse_feroxbuster.parse_feroxbuster_line(line)

        assert result["status"] == 200
        assert result["size"] == 1024
        assert result["path"] == "/admin"

    def test_parses_json_format(self):
        line = '{"url":"http://10.10.10.15/test","status":200,"content_length":512,"method":"GET"}'
        result = parse_feroxbuster.parse_feroxbuster_line(line)

        assert result["status"] == 200
        assert result["size"] == 512
        assert result["path"] == "/test"

    def test_skips_empty_lines(self):
        assert parse_feroxbuster.parse_feroxbuster_line("") is None
        assert parse_feroxbuster.parse_feroxbuster_line("   ") is None

    def test_skips_progress_indicators(self):
        assert parse_feroxbuster.parse_feroxbuster_line("[##########] - 2m") is None
        assert parse_feroxbuster.parse_feroxbuster_line("───────────────") is None

    def test_skips_comments(self):
        assert parse_feroxbuster.parse_feroxbuster_line("# comment") is None


class TestExtractTarget:
    """Tests for target URL extraction."""

    def test_extracts_from_header(self):
        lines = ["Target Url            │ http://10.10.10.15", "other"]
        assert parse_feroxbuster.extract_target(lines) == "http://10.10.10.15"

    def test_extracts_from_findings(self):
        lines = ["200 GET 10l 20w 300c http://10.10.10.15/index.html"]
        assert parse_feroxbuster.extract_target(lines) == "http://10.10.10.15"

    def test_returns_none_when_no_target(self):
        lines = ["no target here"]
        assert parse_feroxbuster.extract_target(lines) is None


class TestExtractConfig:
    """Tests for scan configuration extraction."""

    def test_extracts_threads(self):
        lines = ["Threads                   │ 50"]
        config = parse_feroxbuster.extract_config(lines)
        assert config["threads"] == 50

    def test_extracts_wordlist(self):
        lines = ["Wordlist                  │ /usr/share/seclists/common.txt"]
        config = parse_feroxbuster.extract_config(lines)
        assert "common.txt" in config["wordlist"]

    def test_extracts_status_codes(self):
        lines = ["Status Codes              │ [200, 301, 403]"]
        config = parse_feroxbuster.extract_config(lines)
        assert config["status_codes"] == [200, 301, 403]


class TestParseFeroxbuster:
    """Integration tests for full parser."""

    def test_parses_basic_sample(self, feroxbuster_fixtures):
        result = parse_feroxbuster.parse_feroxbuster(feroxbuster_fixtures / "sample_basic.txt")

        assert result["type"] == "feroxbuster"
        assert result["target"] == "http://10.10.10.15"
        assert result["stats"]["total_found"] > 0
        assert "200" in result["stats"]["status_codes"]

    def test_parses_json_sample(self, feroxbuster_fixtures):
        result = parse_feroxbuster.parse_feroxbuster(feroxbuster_fixtures / "sample_json.jsonl")

        assert result["type"] == "feroxbuster"
        assert result["stats"]["total_found"] > 0
        # JSON format should parse URLs correctly
        urls = [f["url"] for f in result["findings"]]
        assert any("10.10.10.15" in url for url in urls)

    def test_identifies_interesting_paths(self, feroxbuster_fixtures):
        result = parse_feroxbuster.parse_feroxbuster(feroxbuster_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]
        # Should identify admin, backup, .git as interesting
        assert any("admin" in p for p in interesting)
        assert any("backup" in p for p in interesting)
        assert any(".git" in p for p in interesting)

    def test_categorizes_directories_and_files(self, feroxbuster_fixtures):
        result = parse_feroxbuster.parse_feroxbuster(feroxbuster_fixtures / "sample_basic.txt")

        assert len(result["stats"]["directories"]) > 0
        assert len(result["stats"]["files"]) > 0

    def test_deduplicates_findings(self, feroxbuster_fixtures):
        result = parse_feroxbuster.parse_feroxbuster(feroxbuster_fixtures / "sample_basic.txt")

        urls = [f["url"] for f in result["findings"]]
        assert len(urls) == len(set(urls)), "Duplicate URLs found"

    def test_output_has_required_fields(self, feroxbuster_fixtures):
        result = parse_feroxbuster.parse_feroxbuster(feroxbuster_fixtures / "sample_basic.txt")

        required_fields = ["type", "target", "config", "findings", "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, feroxbuster_fixtures):
        result = parse_feroxbuster.parse_feroxbuster(feroxbuster_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert "total_found" in stats
        assert "status_codes" in stats
        assert "interesting" in stats
        assert "directories" in stats
        assert "files" in stats
