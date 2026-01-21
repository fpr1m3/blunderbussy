"""Unit tests for parse-rpcdump.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-rpcdump.py"
spec = importlib.util.spec_from_file_location("parse_rpcdump", PARSER_PATH)
parse_rpcdump = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_rpcdump)


class TestParseBinding:
    """Tests for individual binding parsing."""

    def test_parses_named_pipe_binding(self):
        binding = r"ncacn_np:\\10.10.10.100[\pipe\samr]"
        result = parse_rpcdump.parse_binding(binding)

        assert result["type"] == "ncacn_np"
        assert result["address"] == "10.10.10.100"
        assert result["endpoint"] == r"\pipe\samr"

    def test_parses_tcp_binding(self):
        binding = "ncacn_ip_tcp:10.10.10.100[49664]"
        result = parse_rpcdump.parse_binding(binding)

        assert result["type"] == "ncacn_ip_tcp"
        assert result["address"] == "10.10.10.100"
        assert result["port"] == 49664

    def test_parses_local_rpc_binding(self):
        binding = "ncalrpc:[LRPC-1234abcd]"
        result = parse_rpcdump.parse_binding(binding)

        assert result["type"] == "ncalrpc"
        assert result["endpoint"] == "LRPC-1234abcd"

    def test_parses_http_binding(self):
        binding = "ncacn_http:10.10.10.100:80"
        result = parse_rpcdump.parse_binding(binding)

        assert result["type"] == "ncacn_http"
        assert result["address"] == "10.10.10.100"
        assert result["port"] == 80

    def test_returns_none_for_empty_binding(self):
        assert parse_rpcdump.parse_binding("") is None
        assert parse_rpcdump.parse_binding("   ") is None


class TestExtractProtocolName:
    """Tests for protocol name extraction."""

    def test_extracts_full_protocol_line(self):
        line = "Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol"
        protocol, name = parse_rpcdump.extract_protocol_name(line)

        assert protocol == "MS-SAMR"
        assert name == "Security Account Manager (SAM) Remote Protocol"

    def test_extracts_protocol_without_brackets(self):
        line = "Protocol: Generic RPC Service"
        protocol, name = parse_rpcdump.extract_protocol_name(line)

        assert protocol is None
        assert name == "Generic RPC Service"

    def test_handles_malformed_protocol_line(self):
        line = "Protocol:"
        protocol, name = parse_rpcdump.extract_protocol_name(line)

        assert protocol is None
        # Should handle gracefully


class TestExtractTarget:
    """Tests for target extraction."""

    def test_extracts_from_header(self):
        lines = ["Impacket v0.10.0", "[*] Retrieving endpoint list from 10.10.10.100"]
        assert parse_rpcdump.extract_target(lines) == "10.10.10.100"

    def test_extracts_from_bindings(self):
        lines = ["ncacn_ip_tcp:192.168.1.50[49664]"]
        assert parse_rpcdump.extract_target(lines) == "192.168.1.50"

    def test_returns_none_when_no_target(self):
        lines = ["no target here"]
        assert parse_rpcdump.extract_target(lines) is None


class TestClassifyProtocolRisk:
    """Tests for protocol risk classification."""

    def test_identifies_samr_risks(self):
        notes = parse_rpcdump.classify_protocol_risk("MS-SAMR", "Security Account Manager")

        assert any("user enumeration" in note for note in notes)
        assert any("password policy" in note for note in notes)

    def test_identifies_scmr_risks(self):
        notes = parse_rpcdump.classify_protocol_risk("MS-SCMR", "Service Control Manager")

        assert any("service control" in note for note in notes)
        assert any("service manipulation" in note for note in notes)

    def test_identifies_drsr_risks(self):
        notes = parse_rpcdump.classify_protocol_risk("MS-DRSR", "Directory Replication")

        assert any("DCSync" in note for note in notes)
        assert any("AD replication" in note for note in notes)

    def test_identifies_rprn_risks(self):
        notes = parse_rpcdump.classify_protocol_risk("MS-RPRN", "Print System")

        assert any("PrintNightmare" in note or "printer" in note for note in notes)

    def test_identifies_efsr_risks(self):
        notes = parse_rpcdump.classify_protocol_risk("MS-EFSR", "Encryption File System")

        assert any("PetitPotam" in note for note in notes)

    def test_returns_empty_for_safe_protocol(self):
        notes = parse_rpcdump.classify_protocol_risk("UNKNOWN", "Generic Service")

        assert len(notes) == 0


class TestParseRpcdump:
    """Integration tests for full parser."""

    def test_parses_basic_sample(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        assert result["type"] == "rpcdump"
        assert result["target"] == "10.10.10.100"
        assert len(result["endpoints"]) > 0

    def test_parses_all_endpoints(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        # Should find 7 endpoints in the fixture
        assert result["stats"]["total_endpoints"] == 7

    def test_parses_endpoint_details(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        # Check first endpoint (MS-SAMR)
        samr = [e for e in result["endpoints"] if e["protocol"] == "MS-SAMR"][0]
        assert samr["protocol_name"] == "Security Account Manager (SAM) Remote Protocol"
        assert samr["provider"] == "samr.dll"
        assert samr["uuid"] == "12345778-1234-ABCD-EF00-0123456789AB"
        assert samr["version"] == "1.0"
        assert len(samr["bindings"]) == 2

    def test_parses_bindings_correctly(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        samr = [e for e in result["endpoints"] if e["protocol"] == "MS-SAMR"][0]
        bindings = samr["bindings"]

        # First binding should be named pipe
        np_binding = [b for b in bindings if b["type"] == "ncacn_np"][0]
        assert np_binding["address"] == "10.10.10.100"
        assert r"\pipe\samr" in np_binding["endpoint"]

        # Second binding should be TCP
        tcp_binding = [b for b in bindings if b["type"] == "ncacn_ip_tcp"][0]
        assert tcp_binding["address"] == "10.10.10.100"
        assert tcp_binding["port"] == 49664

    def test_identifies_protocols_found(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        protocols = result["stats"]["protocols_found"]
        assert "MS-SAMR" in protocols
        assert "MS-SCMR" in protocols
        assert "MS-DRSR" in protocols
        assert "MS-RPRN" in protocols
        assert "MS-WKST" in protocols
        assert "MS-TSCH" in protocols

    def test_identifies_interesting_protocols(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        interesting = result["stats"]["interesting"]

        # Should flag SAMR
        assert any("SAMR" in note and "user enumeration" in note for note in interesting)

        # Should flag SCMR
        assert any("SCMR" in note and "service control" in note for note in interesting)

        # Should flag DRSR
        assert any("DRSR" in note and "DCSync" in note for note in interesting)

        # Should flag RPRN
        assert any("RPRN" in note for note in interesting)

    def test_output_has_required_fields(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        required_fields = ["type", "target", "endpoints", "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert "total_endpoints" in stats
        assert "protocols_found" in stats
        assert "interesting" in stats
        assert isinstance(stats["total_endpoints"], int)
        assert isinstance(stats["protocols_found"], list)
        assert isinstance(stats["interesting"], list)

    def test_endpoint_structure(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        endpoint = result["endpoints"][0]
        required_endpoint_fields = ["protocol", "protocol_name", "provider", "uuid", "version", "bindings"]
        for field in required_endpoint_fields:
            assert field in endpoint, f"Missing endpoint field: {field}"

    def test_handles_local_rpc_bindings(self, rpcdump_fixtures):
        result = parse_rpcdump.parse_rpcdump(rpcdump_fixtures / "sample_basic.txt")

        # Find endpoint with local RPC binding
        endpoints_with_lrpc = [
            e for e in result["endpoints"]
            if any(b["type"] == "ncalrpc" for b in e["bindings"])
        ]

        assert len(endpoints_with_lrpc) > 0
        lrpc_binding = [b for b in endpoints_with_lrpc[0]["bindings"] if b["type"] == "ncalrpc"][0]
        assert "endpoint" in lrpc_binding
