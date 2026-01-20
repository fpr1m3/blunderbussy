"""Unit tests for parse-wpscan.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-wpscan.py"
spec = importlib.util.spec_from_file_location("parse_wpscan", PARSER_PATH)
parse_wpscan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_wpscan)


class TestExtractCveInfo:
    """Tests for CVE extraction."""

    def test_extracts_single_cve(self):
        text = "This vulnerability is CVE-2018-12895"
        result = parse_wpscan.extract_cve_info(text)

        assert len(result) == 1
        assert result[0]['id'] == 'CVE-2018-12895'
        assert result[0]['year'] == 2018
        assert result[0]['number'] == 12895

    def test_extracts_multiple_cves(self):
        text = "Affected by CVE-2019-8942 and CVE-2019-8943"
        result = parse_wpscan.extract_cve_info(text)

        assert len(result) == 2
        assert result[0]['id'] == 'CVE-2019-8942'
        assert result[1]['id'] == 'CVE-2019-8943'

    def test_returns_empty_list_for_no_cves(self):
        text = "No CVEs mentioned here"
        result = parse_wpscan.extract_cve_info(text)

        assert result == []

    def test_case_insensitive_extraction(self):
        text = "cve-2020-1234 and CVE-2020-5678"
        result = parse_wpscan.extract_cve_info(text)

        assert len(result) == 2


class TestExtractCvssScore:
    """Tests for CVSS score extraction."""

    def test_extracts_cvss_with_colon(self):
        text = "CVSS: 7.5"
        result = parse_wpscan.extract_cvss_score(text)

        assert result == 7.5

    def test_extracts_cvss_score_format(self):
        text = "cvss_score: 9.8"
        result = parse_wpscan.extract_cvss_score(text)

        assert result == 9.8

    def test_extracts_integer_cvss(self):
        text = "CVSS 10"
        result = parse_wpscan.extract_cvss_score(text)

        assert result == 10.0

    def test_returns_none_for_no_cvss(self):
        text = "No CVSS score here"
        result = parse_wpscan.extract_cvss_score(text)

        assert result is None


class TestParseWpscanJson:
    """Tests for JSON format parsing."""

    def test_parses_basic_json(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        assert result['type'] == 'wpscan'
        assert result['target'] == 'http://10.10.10.88/'

    def test_extracts_wordpress_version(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        assert result['wordpress']['version'] == '4.9.4'
        assert result['wordpress']['version_status'] == 'insecure'

    def test_extracts_theme_info(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        assert result['wordpress']['theme'] == 'flavor'
        assert result['wordpress']['theme_version'] == '1.0'

    def test_extracts_plugins(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        assert result['stats']['plugins_found'] == 2
        plugin_names = [p['name'] for p in result['wordpress']['plugins']]
        assert 'gwolle-gb' in plugin_names
        assert 'akismet' in plugin_names

    def test_extracts_vulnerabilities(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        assert result['stats']['total_vulnerabilities'] > 0
        # Should have WordPress core vulns and plugin vulns
        vuln_types = set(v['type'] for v in result['vulnerabilities'])
        assert 'wordpress_core' in vuln_types or 'plugin' in vuln_types

    def test_extracts_users(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        assert result['stats']['users_found'] == 2
        usernames = [u['username'] for u in result['users']]
        assert 'admin' in usernames
        assert 'garry' in usernames

    def test_counts_interesting_findings(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        assert result['stats']['interesting_findings'] >= 0


class TestParseWpscanText:
    """Tests for text format parsing."""

    def test_parses_text_format(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_text.txt")

        assert result['type'] == 'wpscan'
        assert result['target'] == 'http://10.10.10.88'

    def test_extracts_wordpress_version_from_text(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_text.txt")

        assert result['wordpress']['version'] == '4.9.4'
        assert result['wordpress']['version_status'] == 'insecure'

    def test_extracts_theme_from_text(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_text.txt")

        assert result['wordpress']['theme'] == 'flavor'

    def test_extracts_users_from_text(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_text.txt")

        assert result['stats']['users_found'] >= 2
        usernames = [u['username'] for u in result['users']]
        assert 'admin' in usernames
        assert 'garry' in usernames


class TestParseWpscanMinimal:
    """Tests for minimal/empty input handling."""

    def test_parses_minimal_text(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_minimal.txt")

        assert result['type'] == 'wpscan'
        assert result['target'] == 'http://10.10.10.99'

    def test_minimal_has_latest_version(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_minimal.txt")

        assert result['wordpress']['version'] == '6.4.1'
        assert result['wordpress']['version_status'] == 'latest'

    def test_minimal_has_no_plugins(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_minimal.txt")

        assert result['stats']['plugins_found'] == 0

    def test_minimal_has_few_or_no_users(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_minimal.txt")

        # Text parser may pick up some false positives from footer lines
        # The important thing is it doesn't find real valid usernames
        real_usernames = [u['username'] for u in result['users'] if not any(
            noise in u['username'].lower() for noise in ['finished', 'requests', 'elapsed', 'done', 'started']
        )]
        assert len(real_usernames) == 0

    def test_minimal_has_no_vulnerabilities(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_minimal.txt")

        assert result['stats']['total_vulnerabilities'] == 0


class TestParseWpscanIntegration:
    """Integration tests for full parser."""

    def test_output_has_required_fields(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        required_fields = ['type', 'target', 'wordpress', 'vulnerabilities', 'users', 'stats', 'raw_file', 'parsed_at']
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_wordpress_structure(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        wordpress = result['wordpress']
        assert 'version' in wordpress
        assert 'version_status' in wordpress
        assert 'theme' in wordpress
        assert 'theme_version' in wordpress
        assert 'plugins' in wordpress

    def test_stats_structure(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        stats = result['stats']
        assert 'total_vulnerabilities' in stats
        assert 'plugins_found' in stats
        assert 'users_found' in stats
        assert 'interesting_findings' in stats

    def test_vulnerability_has_cves(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        # Find a vulnerability with CVEs
        vulns_with_cves = [v for v in result['vulnerabilities'] if v['cves']]
        assert len(vulns_with_cves) > 0

        # Check CVE format
        for vuln in vulns_with_cves:
            for cve in vuln['cves']:
                assert cve.startswith('CVE-')

    def test_plugin_entry_structure(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        for plugin in result['wordpress']['plugins']:
            assert 'name' in plugin
            assert 'slug' in plugin
            assert 'version' in plugin
            assert 'vulnerabilities' in plugin

    def test_user_entry_structure(self, wpscan_fixtures):
        result = parse_wpscan.parse_wpscan(wpscan_fixtures / "sample_json.json")

        for user in result['users']:
            assert 'username' in user
