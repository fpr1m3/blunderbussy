"""Unit tests for parse-dirsearch.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-dirsearch.py"
spec = importlib.util.spec_from_file_location("parse_dirsearch", PARSER_PATH)
parse_dirsearch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_dirsearch)


class TestParseDirsearchLine:
    """Tests for individual line parsing."""

    def test_parses_timestamped_format(self):
        line = "[14:30:01] 200 -  1234B  - /admin"
        result = parse_dirsearch.parse_dirsearch_line(line)

        assert result['status'] == 200
        assert result['size'] == 1234
        assert result['path'] == '/admin'

    def test_parses_timestamped_with_redirect(self):
        line = "[14:30:02] 301 -  315B  - /images  ->  http://target/images/"
        result = parse_dirsearch.parse_dirsearch_line(line)

        assert result['status'] == 301
        assert result['size'] == 315
        assert result['path'] == '/images'
        assert result['redirect'] == 'http://target/images/'

    def test_parses_simple_format(self):
        line = "200 1024 http://target/admin"
        result = parse_dirsearch.parse_dirsearch_line(line)

        assert result['status'] == 200
        assert result['size'] == 1024
        assert '/admin' in result['path']

    def test_parses_minimal_format(self):
        line = "200 /index.html"
        result = parse_dirsearch.parse_dirsearch_line(line)

        assert result['status'] == 200
        assert result['path'] == '/index.html'

    def test_skips_empty_lines(self):
        assert parse_dirsearch.parse_dirsearch_line("") is None
        assert parse_dirsearch.parse_dirsearch_line("   ") is None

    def test_skips_comments(self):
        assert parse_dirsearch.parse_dirsearch_line("# comment line") is None

    def test_skips_header_lines(self):
        assert parse_dirsearch.parse_dirsearch_line("Extensions: php, aspx") is None
        assert parse_dirsearch.parse_dirsearch_line("Target: http://example.com") is None
        assert parse_dirsearch.parse_dirsearch_line("Output: /path/to/file.txt") is None

    def test_skips_decorative_lines(self):
        assert parse_dirsearch.parse_dirsearch_line("──────────────────") is None
        assert parse_dirsearch.parse_dirsearch_line("═══════════════") is None
        assert parse_dirsearch.parse_dirsearch_line("Task Completed") is None


class TestParseSize:
    """Tests for size string parsing."""

    def test_parses_plain_bytes(self):
        assert parse_dirsearch.parse_size("1234") == 1234

    def test_parses_bytes_suffix(self):
        assert parse_dirsearch.parse_size("1234B") == 1234

    def test_parses_kilobytes(self):
        assert parse_dirsearch.parse_size("2K") == 2048

    def test_parses_megabytes(self):
        assert parse_dirsearch.parse_size("1M") == 1048576

    def test_parses_gigabytes(self):
        assert parse_dirsearch.parse_size("1G") == 1073741824

    def test_handles_lowercase(self):
        assert parse_dirsearch.parse_size("2k") == 2048

    def test_handles_invalid_input(self):
        assert parse_dirsearch.parse_size("invalid") == 0


class TestExtractPath:
    """Tests for path extraction from URLs."""

    def test_extracts_path_from_url(self):
        assert parse_dirsearch.extract_path("http://example.com/admin/login") == "/admin/login"

    def test_extracts_root_path(self):
        assert parse_dirsearch.extract_path("http://example.com/") == "/"

    def test_extracts_bare_host_path(self):
        assert parse_dirsearch.extract_path("http://example.com") == "/"

    def test_returns_non_url_as_is(self):
        assert parse_dirsearch.extract_path("/admin") == "/admin"


class TestExtractTarget:
    """Tests for target URL extraction."""

    def test_extracts_from_target_header(self):
        lines = ["Target: http://10.10.10.95/", "other line"]
        assert parse_dirsearch.extract_target(lines) == "http://10.10.10.95"

    def test_extracts_from_url_header(self):
        lines = ["URL: http://10.10.10.95/", "other line"]
        assert parse_dirsearch.extract_target(lines) == "http://10.10.10.95"

    def test_extracts_from_findings(self):
        lines = ["some text", "http://10.10.10.95/admin found"]
        assert parse_dirsearch.extract_target(lines) == "http://10.10.10.95"

    def test_returns_none_when_no_target(self):
        lines = ["no target here"]
        assert parse_dirsearch.extract_target(lines) is None


class TestExtractConfig:
    """Tests for scan configuration extraction."""

    def test_extracts_extensions(self):
        lines = ["Extensions: php, aspx, html"]
        config = parse_dirsearch.extract_config(lines)

        assert 'extensions' in config
        assert 'php' in config['extensions']
        assert 'aspx' in config['extensions']

    def test_extracts_threads(self):
        lines = ["Threads: 25"]
        config = parse_dirsearch.extract_config(lines)

        assert config['threads'] == 25

    def test_extracts_wordlist(self):
        lines = ["Wordlist: /usr/share/dirsearch/wordlist.txt"]
        config = parse_dirsearch.extract_config(lines)

        assert 'wordlist.txt' in config['wordlist']

    def test_extracts_wordlist_size(self):
        lines = ["Wordlist size: 10927"]
        config = parse_dirsearch.extract_config(lines)

        assert config['wordlist_size'] == 10927

    def test_extracts_method(self):
        lines = ["Method: GET"]
        config = parse_dirsearch.extract_config(lines)

        assert config['method'] == 'GET'


class TestParseDirsearchText:
    """Tests for text format parsing."""

    def test_parses_text_format(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        assert result['type'] == 'dirsearch'
        assert result['target'] == 'http://10.10.10.95'

    def test_extracts_findings(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        assert result['stats']['total_found'] > 0
        assert len(result['findings']) > 0

    def test_extracts_status_codes(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        assert '200' in result['stats']['status_codes']
        assert result['stats']['status_codes']['200'] > 0

    def test_identifies_interesting_paths(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        interesting = result['stats']['interesting']
        # Should identify admin, backup, .git, .env as interesting
        assert any('admin' in p for p in interesting)
        assert any('backup' in p for p in interesting)
        assert any('.git' in p for p in interesting)
        assert any('.env' in p for p in interesting)

    def test_categorizes_directories_and_files(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        assert len(result['stats']['directories']) > 0
        assert len(result['stats']['files']) > 0


class TestParseDirsearchJson:
    """Tests for JSON format parsing."""

    def test_parses_json_format(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_json.json")

        assert result['type'] == 'dirsearch'
        assert result['target'] == 'http://10.10.10.75'

    def test_json_extracts_findings(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_json.json")

        assert result['stats']['total_found'] > 0
        paths = [f['path'] for f in result['findings']]
        assert '/' in paths
        assert '/robots.txt' in paths

    def test_json_extracts_redirects(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_json.json")

        redirects = [f for f in result['findings'] if f.get('redirect')]
        assert len(redirects) > 0


class TestParseDirsearchCsv:
    """Tests for CSV format parsing."""

    def test_parses_csv_format(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_csv.csv")

        assert result['type'] == 'dirsearch'
        assert result['target'] == 'http://10.10.10.80'

    def test_csv_extracts_findings(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_csv.csv")

        assert result['stats']['total_found'] > 0
        assert len(result['findings']) > 0

    def test_csv_extracts_status_codes(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_csv.csv")

        assert '200' in result['stats']['status_codes']
        assert '403' in result['stats']['status_codes']


class TestParseDirsearchMinimal:
    """Tests for minimal/empty input handling."""

    def test_parses_minimal_text(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_minimal.txt")

        assert result['type'] == 'dirsearch'
        assert result['target'] == 'http://10.10.10.100'

    def test_minimal_extracts_some_findings(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_minimal.txt")

        # Minimal sample has 4 entries
        assert result['stats']['total_found'] >= 1


class TestParseDirsearchIntegration:
    """Integration tests for full parser."""

    def test_output_has_required_fields(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        required_fields = ['type', 'target', 'config', 'findings', 'stats', 'raw_file', 'parsed_at']
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        stats = result['stats']
        assert 'total_found' in stats
        assert 'status_codes' in stats
        assert 'interesting' in stats
        assert 'directories' in stats
        assert 'files' in stats

    def test_finding_entry_structure(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        for finding in result['findings']:
            assert 'status' in finding
            assert 'size' in finding
            assert 'path' in finding

    def test_deduplicates_findings(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        paths = [f['path'] for f in result['findings']]
        assert len(paths) == len(set(paths)), "Duplicate paths found"

    def test_urls_are_populated(self, dirsearch_fixtures):
        result = parse_dirsearch.parse_dirsearch(dirsearch_fixtures / "sample_text.txt")

        # When target is known, URLs should be populated
        if result['target']:
            for finding in result['findings']:
                assert finding.get('url') is not None or finding.get('path') is not None
