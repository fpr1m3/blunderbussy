"""Unit tests for parse-dnsrecon.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-dnsrecon.py"
spec = importlib.util.spec_from_file_location("parse_dnsrecon", PARSER_PATH)
parse_dnsrecon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_dnsrecon)


class TestParseJsonRecord:
    """Tests for individual JSON record parsing."""

    def test_parses_a_record(self):
        record = {"type": "A", "name": "example.com", "address": "93.184.216.34"}
        parsed = parse_dnsrecon.parse_json_record(record)

        assert parsed["type"] == "A"
        assert parsed["name"] == "example.com"
        assert parsed["address"] == "93.184.216.34"

    def test_parses_aaaa_record(self):
        record = {"type": "AAAA", "name": "example.com", "address": "2606:2800:220:1:248:1893:25c8:1946"}
        parsed = parse_dnsrecon.parse_json_record(record)

        assert parsed["type"] == "AAAA"
        assert parsed["address"] == "2606:2800:220:1:248:1893:25c8:1946"

    def test_parses_mx_record(self):
        record = {"type": "MX", "name": "example.com", "exchange": "mail.example.com", "priority": 10}
        parsed = parse_dnsrecon.parse_json_record(record)

        assert parsed["type"] == "MX"
        assert parsed["exchange"] == "mail.example.com"
        assert parsed["priority"] == 10

    def test_parses_ns_record(self):
        record = {"type": "NS", "name": "example.com", "target": "ns1.example.com"}
        parsed = parse_dnsrecon.parse_json_record(record)

        assert parsed["type"] == "NS"
        assert parsed["target"] == "ns1.example.com"

    def test_parses_txt_record(self):
        record = {"type": "TXT", "name": "example.com", "strings": "v=spf1 include:_spf.google.com ~all"}
        parsed = parse_dnsrecon.parse_json_record(record)

        assert parsed["type"] == "TXT"
        assert parsed["text"] == "v=spf1 include:_spf.google.com ~all"

    def test_parses_soa_record(self):
        record = {
            "type": "SOA",
            "mname": "ns1.example.com",
            "rname": "admin.example.com",
            "serial": 2024011501,
            "refresh": 7200,
            "retry": 3600,
            "expire": 1209600,
            "minimum": 86400
        }
        parsed = parse_dnsrecon.parse_json_record(record)

        assert parsed["type"] == "SOA"
        assert parsed["mname"] == "ns1.example.com"
        assert parsed["rname"] == "admin.example.com"
        assert parsed["serial"] == 2024011501

    def test_parses_cname_record(self):
        record = {"type": "CNAME", "name": "www.example.com", "target": "example.com"}
        parsed = parse_dnsrecon.parse_json_record(record)

        assert parsed["type"] == "CNAME"
        assert parsed["target"] == "example.com"

    def test_parses_srv_record(self):
        record = {"type": "SRV", "name": "_sip._tcp.example.com", "target": "sip.example.com", "port": 5060, "priority": 10, "weight": 5}
        parsed = parse_dnsrecon.parse_json_record(record)

        assert parsed["type"] == "SRV"
        assert parsed["target"] == "sip.example.com"
        assert parsed["port"] == 5060


class TestParseTextLine:
    """Tests for text line parsing."""

    def test_parses_a_record_line(self):
        line = "[*]      A example.com 93.184.216.34"
        parsed = parse_dnsrecon.parse_text_line(line)

        assert parsed["type"] == "A"
        assert parsed["name"] == "example.com"
        assert parsed["address"] == "93.184.216.34"

    def test_parses_mx_record_line(self):
        line = "[*]      MX example.com 10 mail.example.com"
        parsed = parse_dnsrecon.parse_text_line(line)

        assert parsed["type"] == "MX"
        assert parsed["priority"] == 10
        assert parsed["exchange"] == "mail.example.com"

    def test_parses_ns_record_line(self):
        line = "[*]      NS ns1.example.com"
        parsed = parse_dnsrecon.parse_text_line(line)

        assert parsed["type"] == "NS"

    def test_parses_txt_record_line(self):
        line = '[*]      TXT example.com "v=spf1 include:_spf.google.com ~all"'
        parsed = parse_dnsrecon.parse_text_line(line)

        assert parsed["type"] == "TXT"
        assert "spf1" in parsed["text"]

    def test_detects_zone_transfer_success(self):
        line = "[*] Zone Transfer was successful!!"
        parsed = parse_dnsrecon.parse_text_line(line)

        assert parsed["type"] == "ZONE_TRANSFER"
        assert parsed["vulnerable"] is True

    def test_detects_zone_transfer_failure(self):
        line = "[*] Zone Transfer for ns1.example.com failed"
        parsed = parse_dnsrecon.parse_text_line(line)

        assert parsed["type"] == "ZONE_TRANSFER"
        assert parsed["vulnerable"] is False

    def test_skips_empty_lines(self):
        assert parse_dnsrecon.parse_text_line("") is None
        assert parse_dnsrecon.parse_text_line("   ") is None

    def test_skips_header_lines(self):
        assert parse_dnsrecon.parse_text_line("[*] Performing General Enumeration of Domain: example.com") is None


class TestExtractTarget:
    """Tests for target domain extraction."""

    def test_extracts_from_json_records(self):
        records = [
            {"type": "A", "name": "www.example.com", "address": "93.184.216.34"}
        ]
        target = parse_dnsrecon.extract_target_from_json(records)

        assert target == "example.com"

    def test_extracts_from_text_lines(self):
        lines = [
            "[*] Performing General Enumeration of Domain: example.com",
            "[*]      A example.com 93.184.216.34"
        ]
        target = parse_dnsrecon.extract_target_from_text(lines)

        assert target == "example.com"

    def test_returns_none_for_empty_json(self):
        target = parse_dnsrecon.extract_target_from_json([])

        assert target is None


class TestDetectFormat:
    """Tests for format detection."""

    def test_detects_json_array(self):
        content = '[{"type": "A"}]'
        assert parse_dnsrecon.detect_format(content) == "json"

    def test_detects_json_object(self):
        content = '{"records": []}'
        assert parse_dnsrecon.detect_format(content) == "json"

    def test_detects_text_format(self):
        content = "[*] Performing General Enumeration"
        assert parse_dnsrecon.detect_format(content) == "text"

    def test_invalid_json_returns_text(self):
        content = '[{"broken json'
        assert parse_dnsrecon.detect_format(content) == "text"


class TestIdentifyInteresting:
    """Tests for interesting findings identification."""

    def test_identifies_zone_transfer_vulnerability(self):
        result = {
            "zone_transfer": {"vulnerable": True, "servers": ["ns1.example.com"]},
            "records": {},
            "subdomains": []
        }
        interesting = parse_dnsrecon.identify_interesting(result)

        assert len(interesting) > 0
        zone_transfer_findings = [i for i in interesting if i["type"] == "zone_transfer"]
        assert len(zone_transfer_findings) == 1
        assert zone_transfer_findings[0]["severity"] == "high"

    def test_identifies_spf_record(self):
        result = {
            "zone_transfer": {"vulnerable": False, "servers": []},
            "records": {"TXT": [{"text": "v=spf1 include:_spf.google.com ~all"}]},
            "subdomains": []
        }
        interesting = parse_dnsrecon.identify_interesting(result)

        spf_findings = [i for i in interesting if i["type"] == "spf_record"]
        assert len(spf_findings) == 1

    def test_identifies_dmarc_record(self):
        result = {
            "zone_transfer": {"vulnerable": False, "servers": []},
            "records": {"TXT": [{"text": "v=DMARC1; p=reject;"}]},
            "subdomains": []
        }
        interesting = parse_dnsrecon.identify_interesting(result)

        dmarc_findings = [i for i in interesting if i["type"] == "dmarc_record"]
        assert len(dmarc_findings) == 1

    def test_identifies_verification_records(self):
        result = {
            "zone_transfer": {"vulnerable": False, "servers": []},
            "records": {"TXT": [{"text": "google-site-verification=abc123"}]},
            "subdomains": []
        }
        interesting = parse_dnsrecon.identify_interesting(result)

        verification_findings = [i for i in interesting if i["type"] == "verification_record"]
        assert len(verification_findings) == 1

    def test_identifies_multiple_mx_records(self):
        result = {
            "zone_transfer": {"vulnerable": False, "servers": []},
            "records": {"MX": [{"exchange": "mail1.example.com"}, {"exchange": "mail2.example.com"}]},
            "subdomains": []
        }
        interesting = parse_dnsrecon.identify_interesting(result)

        mx_findings = [i for i in interesting if i["type"] == "multiple_mx"]
        assert len(mx_findings) == 1

    def test_identifies_interesting_subdomains(self):
        result = {
            "zone_transfer": {"vulnerable": False, "servers": []},
            "records": {},
            "subdomains": ["admin.example.com", "dev.example.com", "staging.example.com"]
        }
        interesting = parse_dnsrecon.identify_interesting(result)

        subdomain_findings = [i for i in interesting if i["type"] == "interesting_subdomain"]
        assert len(subdomain_findings) >= 3


class TestParseDnsreconJson:
    """Integration tests for JSON format parsing."""

    def test_parses_json_sample(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        assert result["type"] == "dnsrecon"
        assert result["target"] == "example.com"
        assert result["stats"]["total_records"] > 0

    def test_extracts_a_records(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        a_records = result["records"]["A"]
        assert len(a_records) >= 2
        assert any(r["address"] == "93.184.216.34" for r in a_records)

    def test_extracts_mx_records(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        mx_records = result["records"]["MX"]
        assert len(mx_records) == 2

    def test_extracts_txt_records(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        txt_records = result["records"]["TXT"]
        assert len(txt_records) >= 1

    def test_identifies_subdomains(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        subdomains = result["subdomains"]
        # Should identify www.example.com and admin.example.com as subdomains
        assert "www.example.com" in subdomains or "admin.example.com" in subdomains

    def test_identifies_interesting_findings(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        interesting = result["stats"]["interesting"]
        # Should find SPF and DMARC records
        interesting_types = [i["type"] for i in interesting]
        assert "spf_record" in interesting_types or "multiple_mx" in interesting_types


class TestParseDnsreconText:
    """Integration tests for text format parsing."""

    def test_parses_text_sample(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_text.txt")

        assert result["type"] == "dnsrecon"
        assert result["target"] == "example.com"
        assert result["stats"]["total_records"] > 0

    def test_extracts_a_records_from_text(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_text.txt")

        a_records = result["records"]["A"]
        assert len(a_records) >= 2

    def test_detects_zone_transfer_vulnerability(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_text.txt")

        assert result["zone_transfer"]["vulnerable"] is True

    def test_identifies_subdomains_from_text(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_text.txt")

        subdomains = result["subdomains"]
        # Should find dev.example.com and staging.example.com
        assert any("dev" in s for s in subdomains) or any("staging" in s for s in subdomains)


class TestOutputStructure:
    """Tests for output structure validation."""

    def test_output_has_required_fields(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        required_fields = ["type", "target", "records", "subdomains", "zone_transfer", "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_records_have_all_types(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        expected_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR"]
        for rtype in expected_types:
            assert rtype in result["records"], f"Missing record type: {rtype}"

    def test_stats_structure(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        stats = result["stats"]
        assert "total_records" in stats
        assert "record_types" in stats
        assert "interesting" in stats

    def test_zone_transfer_structure(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        zone_transfer = result["zone_transfer"]
        assert "vulnerable" in zone_transfer
        assert "servers" in zone_transfer


class TestEmptyAndMinimalInputs:
    """Tests for edge cases with empty or minimal inputs."""

    def test_empty_json_array(self, tmp_path):
        """Test handling of empty JSON array."""
        test_file = tmp_path / "empty.json"
        test_file.write_text("[]")

        result = parse_dnsrecon.parse_dnsrecon(test_file)

        assert result["type"] == "dnsrecon"
        assert result["stats"]["total_records"] == 0
        assert result["target"] is None

    def test_empty_text_file(self, tmp_path):
        """Test handling of empty text file."""
        test_file = tmp_path / "empty.txt"
        test_file.write_text("")

        result = parse_dnsrecon.parse_dnsrecon(test_file)

        assert result["type"] == "dnsrecon"
        assert result["stats"]["total_records"] == 0

    def test_single_record_json(self, tmp_path):
        """Test with single record."""
        content = '[{"type": "A", "name": "test.com", "address": "1.2.3.4"}]'
        test_file = tmp_path / "single.json"
        test_file.write_text(content)

        result = parse_dnsrecon.parse_dnsrecon(test_file)

        assert result["stats"]["total_records"] == 1
        assert len(result["records"]["A"]) == 1

    def test_text_with_only_headers(self, tmp_path):
        """Test text file with only header lines."""
        content = "[*] Performing General Enumeration of Domain: test.com\n[*] DNSSEC is not configured\n"
        test_file = tmp_path / "headers_only.txt"
        test_file.write_text(content)

        result = parse_dnsrecon.parse_dnsrecon(test_file)

        assert result["type"] == "dnsrecon"
        assert result["stats"]["total_records"] == 0


class TestRecordTypeCounting:
    """Tests for record type counting in stats."""

    def test_counts_record_types_correctly(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        record_types = result["stats"]["record_types"]
        # Verify counts match actual records
        for rtype, count in record_types.items():
            assert len(result["records"][rtype]) == count

    def test_total_records_matches_sum(self, dnsrecon_fixtures):
        result = parse_dnsrecon.parse_dnsrecon(dnsrecon_fixtures / "sample_json.json")

        total_from_types = sum(result["stats"]["record_types"].values())
        assert result["stats"]["total_records"] == total_from_types
