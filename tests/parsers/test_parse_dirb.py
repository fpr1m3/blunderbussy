"""
Unit tests for parse-dirb.py parser.
"""

import importlib.util
from pathlib import Path
import pytest


# Load the parser module dynamically
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-dirb.py"
spec = importlib.util.spec_from_file_location("parse_dirb", PARSER_PATH)
parse_dirb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_dirb)


@pytest.fixture
def dirb_fixtures():
    """Provide path to dirb test fixtures directory."""
    return Path(__file__).parent.parent / "fixtures" / "dirb"


class TestParseDirb:
    """Test suite for DIRB parser."""

    def test_parses_basic_output(self, dirb_fixtures):
        """Test parsing basic DIRB output file."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        # Check basic structure
        assert result["type"] == "dirb"
        assert result["target"] == "http://10.10.10.15/"
        assert "parsed_at" in result
        assert "raw_file" in result

    def test_parses_configuration(self, dirb_fixtures):
        """Test parsing configuration section."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        assert "config" in result
        assert result["config"]["wordlist"] == "/usr/share/dirb/wordlists/common.txt"
        assert result["config"]["start_time"] == "Mon Jan 20 10:00:00 2026"

    def test_parses_findings(self, dirb_fixtures):
        """Test parsing findings from output."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        assert "findings" in result
        assert len(result["findings"]) > 0

        # Check that all findings have required fields
        for finding in result["findings"]:
            assert "url" in finding
            assert "path" in finding
            assert "is_directory" in finding

    def test_parses_status_codes_and_sizes(self, dirb_fixtures):
        """Test parsing status codes and sizes from findings."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        # Find a specific finding
        admin_finding = next(
            (f for f in result["findings"] if "/admin" in f["path"]),
            None
        )
        assert admin_finding is not None
        assert admin_finding["status"] == 301
        assert admin_finding["size"] == 312

    def test_identifies_directories(self, dirb_fixtures):
        """Test directory identification."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        # Check directories in stats
        assert "directories" in result["stats"]
        assert "/images/" in result["stats"]["directories"]
        assert "/admin" in result["stats"]["directories"]  # 301 redirects are directories

        # Check is_directory flag on findings
        images_finding = next(
            (f for f in result["findings"] if f["path"] == "/images/"),
            None
        )
        assert images_finding is not None
        assert images_finding["is_directory"] is True

        # Check 301 redirects are marked as directories
        admin_finding = next(
            (f for f in result["findings"] if f["path"] == "/admin"),
            None
        )
        assert admin_finding is not None
        assert admin_finding["is_directory"] is True

    def test_calculates_statistics(self, dirb_fixtures):
        """Test statistics calculation."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert stats["total_found"] > 0
        assert "status_codes" in stats
        assert "directories" in stats
        assert "files" in stats
        assert "interesting" in stats

    def test_identifies_interesting_paths(self, dirb_fixtures):
        """Test interesting path detection."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]
        # Should flag admin, backup, and .git as interesting
        assert any("admin" in path for path in interesting)
        assert any("backup" in path for path in interesting)
        assert any(".git" in path for path in interesting)

    def test_status_code_aggregation(self, dirb_fixtures):
        """Test status code counting."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        status_codes = result["stats"]["status_codes"]
        assert "200" in status_codes
        assert "301" in status_codes
        assert "403" in status_codes

        # Based on sample_basic.txt:
        # 200: index.html, .git/HEAD, logo.png = 3
        # 301: admin = 1
        # 403: backup = 1
        assert status_codes["200"] == 3
        assert status_codes["301"] == 1
        assert status_codes["403"] == 1

    def test_separates_files_and_directories(self, dirb_fixtures):
        """Test separation of files vs directories."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        files = result["stats"]["files"]
        directories = result["stats"]["directories"]

        # Files should include index.html, .git/HEAD, logo.png, backup
        assert any("index.html" in f for f in files)
        assert any(".git/HEAD" in f for f in files)
        assert any("logo.png" in f for f in files)
        assert any("backup" in f for f in files)

        # Directories should include /images/ and /admin (301 redirect)
        assert any("images" in d for d in directories)
        assert any("admin" in d for d in directories)

    def test_is_interesting_function(self):
        """Test the is_interesting helper function."""
        assert parse_dirb.is_interesting("/admin/login.php") is True
        assert parse_dirb.is_interesting("/.git/config") is True
        assert parse_dirb.is_interesting("/backup/database.sql") is True
        assert parse_dirb.is_interesting("/api/v1/users") is True
        assert parse_dirb.is_interesting("/uploads/") is True
        assert parse_dirb.is_interesting("/test/debug.php") is True

        # Non-interesting paths
        assert parse_dirb.is_interesting("/index.html") is False
        assert parse_dirb.is_interesting("/about.html") is False
        assert parse_dirb.is_interesting("/contact.php") is False

    def test_handles_path_extraction(self, dirb_fixtures):
        """Test path extraction from URLs."""
        result = parse_dirb.parse_dirb(dirb_fixtures / "sample_basic.txt")

        # Verify paths are correctly extracted
        paths = [f["path"] for f in result["findings"]]
        assert "/admin" in paths
        assert "/index.html" in paths
        assert "/backup" in paths
        assert "/.git/HEAD" in paths
