"""Unit tests for parse-ffuf.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-ffuf.py"
spec = importlib.util.spec_from_file_location("parse_ffuf", PARSER_PATH)
parse_ffuf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_ffuf)


class TestParseFfufResult:
    """Tests for individual result parsing."""

    def test_parses_basic_result(self):
        result = {
            "input": {"FUZZ": "admin"},
            "url": "http://example.com/admin",
            "status": 200,
            "length": 1234,
            "words": 100,
            "lines": 50,
            "content-type": "text/html",
            "duration": 123456789,
            "host": "example.com",
            "position": 1
        }
        parsed = parse_ffuf.parse_ffuf_result(result)

        assert parsed["input"] == "admin"
        assert parsed["url"] == "http://example.com/admin"
        assert parsed["status"] == 200
        assert parsed["size"] == 1234
        assert parsed["words"] == 100
        assert parsed["lines"] == 50
        assert parsed["content_type"] == "text/html"
        assert parsed["host"] == "example.com"
        assert parsed["position"] == 1

    def test_parses_result_with_redirect(self):
        result = {
            "input": {"FUZZ": "api"},
            "url": "http://example.com/api",
            "status": 301,
            "length": 0,
            "redirectlocation": "http://example.com/api/",
            "duration": 67890123
        }
        parsed = parse_ffuf.parse_ffuf_result(result)

        assert parsed["status"] == 301
        assert parsed["redirect_location"] == "http://example.com/api/"

    def test_handles_missing_fields(self):
        result = {
            "url": "http://example.com/test",
            "status": 200
        }
        parsed = parse_ffuf.parse_ffuf_result(result)

        assert parsed["url"] == "http://example.com/test"
        assert parsed["status"] == 200
        assert parsed["size"] == 0
        assert parsed["words"] == 0
        assert parsed["lines"] == 0
        assert parsed["input"] == ""

    def test_duration_conversion_nanoseconds(self):
        """Test that nanosecond durations are converted to seconds."""
        result = {
            "url": "http://example.com/test",
            "status": 200,
            "duration": 1234567890  # More than 1000, treated as nanoseconds
        }
        parsed = parse_ffuf.parse_ffuf_result(result)

        # Should be converted from nanoseconds to seconds
        assert parsed["duration"] == pytest.approx(1.23456789, rel=1e-6)


class TestExtractConfig:
    """Tests for configuration extraction."""

    def test_extracts_from_commandline(self):
        data = {
            "commandline": "ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/common.txt -t 40 -X POST"
        }
        config = parse_ffuf.extract_config(data)

        assert config["commandline"] == data["commandline"]
        assert config["wordlist"] == "/usr/share/wordlists/common.txt"
        assert config["threads"] == 40
        assert config["method"] == "POST"

    def test_extracts_from_config_section(self):
        data = {
            "commandline": "ffuf -u http://example.com/FUZZ",
            "config": {
                "method": "GET",
                "threads": 50,
                "timeout": 10,
                "match_status": [200, 301, 403],
                "filter_size": [0]
            }
        }
        config = parse_ffuf.extract_config(data)

        assert config["method"] == "GET"
        assert config["threads"] == 50
        assert config["timeout"] == 10
        assert config["matchers"]["status"] == [200, 301, 403]
        assert config["filters"]["size"] == [0]

    def test_defaults_to_get_method(self):
        data = {
            "commandline": "ffuf -u http://example.com/FUZZ -w wordlist.txt"
        }
        config = parse_ffuf.extract_config(data)

        assert config["method"] == "GET"


class TestExtractTarget:
    """Tests for target URL extraction."""

    def test_extracts_from_commandline(self):
        data = {
            "commandline": "ffuf -u http://example.com/FUZZ -w wordlist.txt"
        }
        target = parse_ffuf.extract_target(data)

        assert target == "http://example.com/FUZZ"

    def test_extracts_from_config(self):
        data = {
            "commandline": "",
            "config": {
                "url": "http://target.com/FUZZ"
            }
        }
        target = parse_ffuf.extract_target(data)

        assert target == "http://target.com/FUZZ"

    def test_extracts_from_first_result(self):
        data = {
            "commandline": "",
            "results": [
                {"url": "http://found.com/admin"}
            ]
        }
        target = parse_ffuf.extract_target(data)

        assert target == "http://found.com/FUZZ"

    def test_returns_none_when_no_target(self):
        data = {"commandline": ""}
        target = parse_ffuf.extract_target(data)

        assert target is None


class TestIdentifyInteresting:
    """Tests for interesting findings identification."""

    def test_identifies_admin_paths(self):
        findings = [
            {"input": "admin", "url": "http://example.com/admin", "status": 200}
        ]
        interesting = parse_ffuf.identify_interesting(findings)

        assert len(interesting) > 0
        assert any(i["input"] == "admin" for i in interesting)
        assert any("admin" in i.get("reason", "") for i in interesting)

    def test_identifies_backup_paths(self):
        findings = [
            {"input": "backup", "url": "http://example.com/backup", "status": 200}
        ]
        interesting = parse_ffuf.identify_interesting(findings)

        assert len(interesting) > 0
        assert any("backup" in i.get("reason", "") for i in interesting)

    def test_identifies_protected_resources(self):
        findings = [
            {"input": "secret", "url": "http://example.com/secret", "status": 401},
            {"input": "private", "url": "http://example.com/private", "status": 403}
        ]
        interesting = parse_ffuf.identify_interesting(findings)

        # Should have entries for both pattern match and protected resource
        assert len(interesting) >= 2
        assert any("protected resource" in i.get("reason", "") or "401" in str(i.get("reason", "")) for i in interesting)

    def test_identifies_config_patterns(self):
        findings = [
            {"input": ".env", "url": "http://example.com/.env", "status": 200},
            {"input": "config", "url": "http://example.com/config", "status": 200}
        ]
        interesting = parse_ffuf.identify_interesting(findings)

        assert len(interesting) >= 2

    def test_empty_findings_returns_empty(self):
        interesting = parse_ffuf.identify_interesting([])

        assert interesting == []


class TestParseFfuf:
    """Integration tests for full parser."""

    def test_parses_basic_sample(self, ffuf_fixtures):
        result = parse_ffuf.parse_ffuf(ffuf_fixtures / "sample_basic.json")

        assert result["type"] == "ffuf"
        assert result["target"] == "http://example.com/FUZZ"
        assert result["stats"]["total_found"] == 4
        assert "200" in result["stats"]["status_codes"]

    def test_extracts_config_correctly(self, ffuf_fixtures):
        result = parse_ffuf.parse_ffuf(ffuf_fixtures / "sample_basic.json")

        assert result["config"]["method"] == "GET"
        assert result["config"]["threads"] == 40

    def test_identifies_interesting_findings(self, ffuf_fixtures):
        result = parse_ffuf.parse_ffuf(ffuf_fixtures / "sample_basic.json")

        interesting = result["stats"]["interesting"]
        # Should identify admin, backup, and api as interesting
        interesting_inputs = [i.get("input", "") for i in interesting]
        assert any("admin" in str(inp).lower() for inp in interesting_inputs)
        assert any("backup" in str(inp).lower() for inp in interesting_inputs)

    def test_status_code_counting(self, ffuf_fixtures):
        result = parse_ffuf.parse_ffuf(ffuf_fixtures / "sample_basic.json")

        status_codes = result["stats"]["status_codes"]
        assert status_codes["200"] == 2  # admin and robots.txt
        assert status_codes["403"] == 1  # backup
        assert status_codes["301"] == 1  # api

    def test_findings_have_required_fields(self, ffuf_fixtures):
        result = parse_ffuf.parse_ffuf(ffuf_fixtures / "sample_basic.json")

        for finding in result["findings"]:
            assert "input" in finding
            assert "url" in finding
            assert "status" in finding
            assert "size" in finding

    def test_output_has_required_fields(self, ffuf_fixtures):
        result = parse_ffuf.parse_ffuf(ffuf_fixtures / "sample_basic.json")

        required_fields = ["type", "target", "config", "findings", "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, ffuf_fixtures):
        result = parse_ffuf.parse_ffuf(ffuf_fixtures / "sample_basic.json")

        stats = result["stats"]
        assert "total_found" in stats
        assert "status_codes" in stats
        assert "interesting" in stats


class TestEmptyAndMinimalInputs:
    """Tests for edge cases with empty or minimal inputs."""

    def test_empty_results_array(self, tmp_path):
        """Test handling of empty results array."""
        content = '{"commandline": "ffuf -u http://test.com/FUZZ", "results": []}'
        test_file = tmp_path / "empty.json"
        test_file.write_text(content)

        result = parse_ffuf.parse_ffuf(test_file)

        assert result["type"] == "ffuf"
        assert result["stats"]["total_found"] == 0
        assert result["findings"] == []
        assert result["stats"]["status_codes"] == {}

    def test_minimal_json_structure(self, tmp_path):
        """Test with minimal valid JSON."""
        content = '{"results": []}'
        test_file = tmp_path / "minimal.json"
        test_file.write_text(content)

        result = parse_ffuf.parse_ffuf(test_file)

        assert result["type"] == "ffuf"
        assert result["target"] is None

    def test_single_result(self, tmp_path):
        """Test with single result entry."""
        content = '''{
            "commandline": "ffuf -u http://test.com/FUZZ",
            "results": [{"input": {"FUZZ": "test"}, "url": "http://test.com/test", "status": 200, "length": 100}]
        }'''
        test_file = tmp_path / "single.json"
        test_file.write_text(content)

        result = parse_ffuf.parse_ffuf(test_file)

        assert result["stats"]["total_found"] == 1
        assert len(result["findings"]) == 1
        assert result["findings"][0]["input"] == "test"
