"""Unit tests for parse-dig.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-dig.py"
spec = importlib.util.spec_from_file_location("parse_dig", PARSER_PATH)
parse_dig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_dig)


@pytest.fixture
def dig_fixtures():
    """Return path to dig test fixtures."""
    return Path(__file__).parent.parent / "fixtures" / "dig"


class TestParseHeader:
    """Tests for header parsing."""

    def test_extracts_status(self):
        lines = [";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345"]
        result = parse_dig.parse_header(lines)
        assert result["status"] == "NOERROR"

    def test_extracts_id(self):
        lines = [";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345"]
        result = parse_dig.parse_header(lines)
        assert result["id"] == 12345

    def test_extracts_flags(self):
        lines = [";; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1"]
        result = parse_dig.parse_header(lines)
        assert "qr" in result["flags"]
        assert "rd" in result["flags"]
        assert "ra" in result["flags"]

    def test_extracts_counts(self):
        lines = [";; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1"]
        result = parse_dig.parse_header(lines)
        assert result["query_count"] == 1
        assert result["answer_count"] == 5
        assert result["authority_count"] == 0
        assert result["additional_count"] == 1


class TestParseQuestion:
    """Tests for question section parsing."""

    def test_extracts_question(self):
        lines = [
            ";; QUESTION SECTION:",
            ";example.com.                   IN      ANY"
        ]
        result = parse_dig.parse_question(lines)
        assert result is not None
        assert result["name"] == "example.com"
        assert result["query_type"] == "ANY"

    def test_handles_a_query(self):
        lines = [";google.com.                   IN      A"]
        result = parse_dig.parse_question(lines)
        assert result["name"] == "google.com"
        assert result["query_type"] == "A"


class TestParseRecordLine:
    """Tests for individual record parsing."""

    def test_parses_a_record(self):
        line = "example.com.            300     IN      A       93.184.216.34"
        result = parse_dig.parse_record_line(line)
        assert result is not None
        assert result["name"] == "example.com"
        assert result["ttl"] == 300
        assert result["type"] == "A"
        assert result["value"] == "93.184.216.34"

    def test_parses_aaaa_record(self):
        line = "example.com.            300     IN      AAAA    2606:2800:220:1:248:1893:25c8:1946"
        result = parse_dig.parse_record_line(line)
        assert result is not None
        assert result["type"] == "AAAA"
        assert result["value"] == "2606:2800:220:1:248:1893:25c8:1946"

    def test_parses_mx_record(self):
        line = "example.com.            300     IN      MX      10 mail.example.com."
        result = parse_dig.parse_record_line(line)
        assert result is not None
        assert result["type"] == "MX"
        assert result["priority"] == 10
        assert result["value"] == "mail.example.com"

    def test_parses_ns_record(self):
        line = "example.com.            300     IN      NS      ns1.example.com."
        result = parse_dig.parse_record_line(line)
        assert result is not None
        assert result["type"] == "NS"
        assert result["value"] == "ns1.example.com"

    def test_parses_txt_record(self):
        line = 'example.com.            300     IN      TXT     "v=spf1 include:_spf.example.com ~all"'
        result = parse_dig.parse_record_line(line)
        assert result is not None
        assert result["type"] == "TXT"
        assert "v=spf1" in result["value"]

    def test_parses_cname_record(self):
        line = "www.example.com.        300     IN      CNAME   example.com."
        result = parse_dig.parse_record_line(line)
        assert result is not None
        assert result["type"] == "CNAME"
        assert result["value"] == "example.com"

    def test_parses_soa_record(self):
        line = "example.com.            3600    IN      SOA     ns1.example.com. admin.example.com. 2026012001 7200 3600 1209600 86400"
        result = parse_dig.parse_record_line(line)
        assert result is not None
        assert result["type"] == "SOA"
        assert result["mname"] == "ns1.example.com"
        assert result["rname"] == "admin.example.com"
        assert result["serial"] == 2026012001
        assert result["refresh"] == 7200

    def test_skips_empty_lines(self):
        result = parse_dig.parse_record_line("")
        assert result is None

    def test_skips_comment_lines(self):
        result = parse_dig.parse_record_line(";; ANSWER SECTION:")
        assert result is None


class TestParseRecords:
    """Tests for section record parsing."""

    def test_extracts_answer_section(self):
        lines = [
            ";; ANSWER SECTION:",
            "example.com.            300     IN      A       93.184.216.34",
            "example.com.            300     IN      NS      ns1.example.com.",
            ";; AUTHORITY SECTION:"
        ]
        result = parse_dig.parse_records(lines, "ANSWER")
        assert len(result) == 2
        assert result[0]["type"] == "A"
        assert result[1]["type"] == "NS"

    def test_stops_at_next_section(self):
        lines = [
            ";; ANSWER SECTION:",
            "example.com.            300     IN      A       93.184.216.34",
            ";; AUTHORITY SECTION:",
            "example.com.            300     IN      NS      ns1.example.com."
        ]
        result = parse_dig.parse_records(lines, "ANSWER")
        assert len(result) == 1
        assert result[0]["type"] == "A"


class TestParseStats:
    """Tests for statistics parsing."""

    def test_extracts_query_time(self):
        lines = [";; Query time: 50 msec"]
        result = parse_dig.parse_stats(lines)
        assert result["query_time_ms"] == 50

    def test_extracts_server(self):
        lines = [";; SERVER: 192.168.1.1#53(192.168.1.1)"]
        result = parse_dig.parse_stats(lines)
        assert result["server"] == "192.168.1.1"
        assert result["server_port"] == 53

    def test_extracts_server_with_custom_port(self):
        lines = [";; SERVER: 8.8.8.8#5353(8.8.8.8)"]
        result = parse_dig.parse_stats(lines)
        assert result["server"] == "8.8.8.8"
        assert result["server_port"] == 5353

    def test_extracts_msg_size(self):
        lines = [";; MSG SIZE  rcvd: 256"]
        result = parse_dig.parse_stats(lines)
        assert result["msg_size"] == 256

    def test_extracts_when(self):
        lines = [";; WHEN: Mon Jan 20 10:00:00 PST 2026"]
        result = parse_dig.parse_stats(lines)
        assert "Jan 20" in result["when"]


class TestExtractTarget:
    """Tests for target extraction."""

    def test_extracts_from_header(self):
        lines = ["; <<>> DiG 9.16.1-Ubuntu <<>> example.com ANY"]
        result = parse_dig.extract_target_from_header(lines)
        assert result == "example.com"

    def test_handles_trailing_dot(self):
        lines = ["; <<>> DiG 9.16.1-Ubuntu <<>> example.com. A"]
        result = parse_dig.extract_target_from_header(lines)
        assert result == "example.com"


class TestParseDig:
    """Integration tests for full parser."""

    def test_parses_basic_sample(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        assert result["type"] == "dig"
        assert result["target"] == "example.com"
        assert result["query_type"] == "ANY"
        assert result["status"] == "NOERROR"
        assert result["server"] == "192.168.1.1"

    def test_extracts_all_record_types(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        records = result["records"]
        assert "A" in records
        assert "AAAA" in records
        assert "NS" in records
        assert "MX" in records
        assert "TXT" in records
        assert "SOA" in records

    def test_counts_records_correctly(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert stats["total_records"] == 8
        assert stats["record_types"]["A"] == 1
        assert stats["record_types"]["NS"] == 2
        assert stats["record_types"]["MX"] == 2

    def test_parses_flags(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        assert "qr" in result["flags"]
        assert "rd" in result["flags"]
        assert "ra" in result["flags"]

    def test_parses_query_stats(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert stats["query_time_ms"] == 50
        assert stats["msg_size"] == 256

    def test_output_has_required_fields(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        required_fields = ["type", "target", "query_type", "server", "status",
                          "flags", "records", "stats", "raw_file", "parsed_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        stats = result["stats"]
        assert "total_records" in stats
        assert "record_types" in stats
        assert "query_time_ms" in stats
        assert "msg_size" in stats
        assert "answer_count" in stats
        assert "authority_count" in stats
        assert "additional_count" in stats

    def test_mx_records_have_priority(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        mx_records = result["records"]["MX"]
        assert len(mx_records) >= 2
        assert all("priority" in mx for mx in mx_records)
        assert any(mx["priority"] == 10 for mx in mx_records)
        assert any(mx["priority"] == 20 for mx in mx_records)

    def test_soa_record_parsed(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        soa_records = result["records"]["SOA"]
        assert len(soa_records) == 1
        soa = soa_records[0]
        assert "mname" in soa
        assert "rname" in soa
        assert "serial" in soa
        assert soa["mname"] == "ns1.example.com"

    def test_ipv6_address_parsed(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        aaaa_records = result["records"]["AAAA"]
        assert len(aaaa_records) == 1
        assert "2606:2800:220:1:248:1893:25c8:1946" in aaaa_records[0]["value"]

    def test_txt_record_content(self, dig_fixtures):
        result = parse_dig.parse_dig(dig_fixtures / "sample_basic.txt")

        txt_records = result["records"]["TXT"]
        assert len(txt_records) >= 1
        # Should have SPF record
        assert any("spf" in txt["value"].lower() for txt in txt_records)
