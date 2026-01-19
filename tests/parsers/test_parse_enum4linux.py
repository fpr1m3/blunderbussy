"""Unit tests for parse-enum4linux.py parser."""
import importlib.util
import sys
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-enum4linux.py"
spec = importlib.util.spec_from_file_location("parse_enum4linux", PARSER_PATH)
parse_enum4linux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_enum4linux)


class TestParseTarget:
    """Tests for target extraction."""

    def test_extracts_target_from_target_line(self):
        lines = ["Target ........... 10.10.10.3", "other line"]
        assert parse_enum4linux.parse_target(lines) == "10.10.10.3"

    def test_extracts_target_from_starting_line(self):
        lines = ["Starting enum4linux v0.9.1 on 10.10.10.3", "other"]
        assert parse_enum4linux.parse_target(lines) == "10.10.10.3"

    def test_returns_none_when_no_target(self):
        lines = ["no target here", "or here"]
        assert parse_enum4linux.parse_target(lines) is None


class TestParseOsInfo:
    """Tests for OS information extraction."""

    def test_extracts_native_os(self):
        lines = [
            "OS information on 10.10.10.3",
            "Native OS: Unix",
            "Native LAN Manager: Samba 3.0.20-Debian",
        ]
        result = parse_enum4linux.parse_os_info(lines)
        assert result["native_os"] == "Unix"
        assert result["native_lanman"] == "Samba 3.0.20-Debian"

    def test_handles_missing_os_info(self):
        lines = ["no os info here"]
        result = parse_enum4linux.parse_os_info(lines)
        assert result["native_os"] is None


class TestParseShares:
    """Tests for share enumeration extraction."""

    def test_extracts_shares_from_table(self):
        lines = [
            "Share Enumeration on 10.10.10.3",
            "Sharename       Type      Comment",
            "---------       ----      -------",
            "	print$          Disk      Printer Drivers",
            "	tmp             Disk      oh nance!",
            "	IPC$            IPC       IPC Service",
        ]
        result = parse_enum4linux.parse_shares(lines)
        assert len(result) == 3
        assert result[0]["name"] == "print$"
        assert result[0]["type"] == "Disk"
        assert result[1]["name"] == "tmp"

    def test_extracts_shares_with_unc_path(self):
        lines = [
            "Share Enumeration",
            "\\\\10.10.10.3\\tmp	Disk	temp share",
        ]
        result = parse_enum4linux.parse_shares(lines)
        assert len(result) == 1
        assert result[0]["name"] == "tmp"


class TestParseUsers:
    """Tests for user enumeration extraction."""

    def test_extracts_users_from_rid_format(self):
        lines = [
            "Users on 10.10.10.3",
            "user:[games] rid:[0x3f2]",
            "user:[nobody] rid:[0x1f5]",
            "user:[root] rid:[0x3e8]",
        ]
        result = parse_enum4linux.parse_users(lines)
        assert len(result) == 3
        usernames = [u["username"] for u in result]
        assert "games" in usernames
        assert "root" in usernames

    def test_deduplicates_users(self):
        lines = [
            "Users on 10.10.10.3",
            "user:[admin] rid:[0x1f4]",
            "user:[admin] rid:[0x1f4]",
        ]
        result = parse_enum4linux.parse_users(lines)
        assert len(result) == 1


class TestParseGroups:
    """Tests for group enumeration extraction."""

    def test_extracts_groups(self):
        lines = [
            "Group enum on 10.10.10.3",
            "group:[Administrators] rid:[0x220]",
            "group:[Users] rid:[0x221]",
        ]
        result = parse_enum4linux.parse_groups(lines)
        total_groups = sum(len(g) for g in result.values())
        assert total_groups == 2


class TestParsePasswordPolicy:
    """Tests for password policy extraction."""

    def test_extracts_password_policy(self):
        lines = [
            "Password Policy Information",
            "[+] Minimum password length: 5",
            "[+] Password history length: None",
            "[+] Account Lockout Threshold: None",
        ]
        result = parse_enum4linux.parse_password_policy(lines)
        assert result["min_length"] == 5

    def test_handles_missing_policy(self):
        lines = ["no policy info"]
        result = parse_enum4linux.parse_password_policy(lines)
        assert result == {}


class TestParseEnum4linux:
    """Integration tests for full parser."""

    def test_parses_basic_sample(self, enum4linux_fixtures):
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_basic.txt")

        assert result["type"] == "enum4linux"
        assert result["target"] == "10.10.10.3"
        assert result["os_info"]["native_os"] == "Unix"
        assert result["os_info"]["native_lanman"] == "Samba 3.0.20-Debian"
        assert result["stats"]["shares_found"] == 5
        assert result["stats"]["users_found"] == 29
        assert result["password_policy"]["min_length"] == 5

    def test_parses_minimal_sample(self, enum4linux_fixtures):
        """Test parsing output when enumeration failed."""
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_minimal.txt")

        assert result["type"] == "enum4linux"
        assert result["target"] == "10.10.10.100"
        assert result["stats"]["shares_found"] == 0
        assert result["stats"]["users_found"] == 0

    def test_identifies_interesting_findings(self, enum4linux_fixtures):
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]
        assert any("users" in i.lower() for i in interesting)
        assert any("password" in i.lower() or "root" in i.lower() for i in interesting)

    def test_output_has_required_fields(self, enum4linux_fixtures):
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_basic.txt")

        required_fields = ["type", "target", "os_info", "shares", "users", "groups",
                          "password_policy", "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"


class TestIsEnum4linuxNg:
    """Tests for format detection."""

    def test_detects_ng_format(self):
        lines = ["ENUM4LINUX - next generation (v1.3.7)", "other line"]
        assert parse_enum4linux.is_enum4linux_ng(lines) is True

    def test_detects_classic_format(self):
        lines = ["Starting enum4linux v0.9.1", "other line"]
        assert parse_enum4linux.is_enum4linux_ng(lines) is False


class TestEnum4linuxNgFormat:
    """Tests for enum4linux-ng specific parsing."""

    def test_parses_ng_sample(self, enum4linux_fixtures):
        """Test parsing enum4linux-ng output."""
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_enum4linux_ng.txt")

        assert result["type"] == "enum4linux"
        assert result["target"] == "10.10.10.3"
        assert result["stats"]["shares_found"] == 5
        assert result["stats"]["users_found"] == 29
        assert result["stats"]["groups_found"] == 6

    def test_ng_extracts_os_info(self, enum4linux_fixtures):
        """Test OS info extraction from ng format."""
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_enum4linux_ng.txt")

        assert result["os_info"]["native_os"] == "Unix"
        assert "Samba 3.0.20-Debian" in result["os_info"]["native_lanman"]
        assert result["os_info"]["workgroup"] == "WORKGROUP"

    def test_ng_extracts_shares_yaml_format(self, enum4linux_fixtures):
        """Test share extraction from ng YAML format."""
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_enum4linux_ng.txt")

        shares = result["shares"]
        share_names = [s["name"] for s in shares]
        assert "print$" in share_names
        assert "tmp" in share_names
        assert "IPC$" in share_names

        # Check types and comments
        tmp_share = next(s for s in shares if s["name"] == "tmp")
        assert tmp_share["type"] == "Disk"
        assert tmp_share["comment"] == "oh nance!"

    def test_ng_extracts_users_yaml_format(self, enum4linux_fixtures):
        """Test user extraction from ng YAML format."""
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_enum4linux_ng.txt")

        users = result["users"]
        usernames = [u["username"] for u in users]
        assert "root" in usernames
        assert "games" in usernames
        assert "msfadmin" in usernames

        # Check that users have rid field
        root_user = next(u for u in users if u["username"] == "root")
        assert "rid" in root_user

    def test_ng_extracts_groups_yaml_format(self, enum4linux_fixtures):
        """Test group extraction from ng YAML format."""
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_enum4linux_ng.txt")

        groups = result["groups"]
        # All groups in ng sample are domain groups
        domain_group_names = [g["name"] for g in groups["domain"]]
        assert "Administrators" in domain_group_names
        assert "Users" in domain_group_names

    def test_ng_extracts_password_policy(self, enum4linux_fixtures):
        """Test password policy extraction from ng format."""
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_enum4linux_ng.txt")

        assert result["password_policy"]["min_length"] == 5

    def test_ng_output_has_required_fields(self, enum4linux_fixtures):
        """Test that ng output has all required fields."""
        result = parse_enum4linux.parse_enum4linux(enum4linux_fixtures / "sample_enum4linux_ng.txt")

        required_fields = ["type", "target", "os_info", "shares", "users", "groups",
                          "password_policy", "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
