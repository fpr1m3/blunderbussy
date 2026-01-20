"""Unit tests for parse-sslscan.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-sslscan.py"
spec = importlib.util.spec_from_file_location("parse_sslscan", PARSER_PATH)
parse_sslscan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_sslscan)


class TestClassifyCipherStrength:
    """Tests for cipher strength classification."""

    def test_weak_cipher_rc4(self):
        assert parse_sslscan.classify_cipher_strength("RC4-SHA", 128) == 'weak'

    def test_weak_cipher_des(self):
        assert parse_sslscan.classify_cipher_strength("DES-CBC-SHA", 56) == 'weak'

    def test_weak_cipher_3des(self):
        assert parse_sslscan.classify_cipher_strength("DES-CBC3-SHA", 112) == 'weak'

    def test_weak_cipher_export(self):
        assert parse_sslscan.classify_cipher_strength("EXP-RC4-MD5", 40) == 'weak'

    def test_weak_cipher_null(self):
        assert parse_sslscan.classify_cipher_strength("NULL-SHA256", 0) == 'weak'

    def test_weak_cipher_low_bits(self):
        assert parse_sslscan.classify_cipher_strength("SOME-CIPHER", 64) == 'weak'

    def test_medium_cipher_sha1(self):
        assert parse_sslscan.classify_cipher_strength("ECDHE-RSA-AES128-SHA1", 128) == 'medium'

    def test_medium_cipher_128_bits(self):
        assert parse_sslscan.classify_cipher_strength("AES128-GCM-SHA256", 128) == 'medium'

    def test_strong_cipher_gcm_256(self):
        assert parse_sslscan.classify_cipher_strength("ECDHE-RSA-AES256-GCM-SHA384", 256) == 'strong'

    def test_strong_cipher_chacha(self):
        assert parse_sslscan.classify_cipher_strength("TLS_CHACHA20_POLY1305_SHA256", 256) == 'strong'


class TestIsXmlFile:
    """Tests for XML file detection."""

    def test_detects_xml_with_declaration(self, tmp_path):
        xml_file = tmp_path / "test.xml"
        xml_file.write_text('<?xml version="1.0"?>\n<root/>')
        assert parse_sslscan.is_xml_file(xml_file) is True

    def test_detects_xml_with_root_element(self, tmp_path):
        xml_file = tmp_path / "test.xml"
        xml_file.write_text('<document>\n<data/>\n</document>')
        assert parse_sslscan.is_xml_file(xml_file) is True

    def test_detects_text_format(self, tmp_path):
        text_file = tmp_path / "test.txt"
        text_file.write_text('Version: 2.0.15\nTesting SSL server...')
        assert parse_sslscan.is_xml_file(text_file) is False


class TestIdentifyIssues:
    """Tests for security issue identification."""

    def test_identifies_sslv2_enabled(self):
        result = {
            'protocols': {'sslv2': True, 'sslv3': False, 'tlsv1_0': False, 'tlsv1_1': False, 'tlsv1_2': True, 'tlsv1_3': False},
            'stats': {'weak_ciphers': []},
            'certificate': None,
            'vulnerabilities': {}
        }
        issues = parse_sslscan.identify_issues(result)
        assert any('SSLv2' in issue for issue in issues)

    def test_identifies_sslv3_enabled(self):
        result = {
            'protocols': {'sslv2': False, 'sslv3': True, 'tlsv1_0': False, 'tlsv1_1': False, 'tlsv1_2': True, 'tlsv1_3': False},
            'stats': {'weak_ciphers': []},
            'certificate': None,
            'vulnerabilities': {}
        }
        issues = parse_sslscan.identify_issues(result)
        assert any('SSLv3' in issue for issue in issues)

    def test_identifies_deprecated_tls10(self):
        result = {
            'protocols': {'sslv2': False, 'sslv3': False, 'tlsv1_0': True, 'tlsv1_1': False, 'tlsv1_2': True, 'tlsv1_3': False},
            'stats': {'weak_ciphers': []},
            'certificate': None,
            'vulnerabilities': {}
        }
        issues = parse_sslscan.identify_issues(result)
        assert any('TLSv1.0' in issue for issue in issues)

    def test_identifies_weak_ciphers(self):
        result = {
            'protocols': {'sslv2': False, 'sslv3': False, 'tlsv1_0': False, 'tlsv1_1': False, 'tlsv1_2': True, 'tlsv1_3': True},
            'stats': {'weak_ciphers': ['RC4-SHA', 'DES-CBC-SHA']},
            'certificate': None,
            'vulnerabilities': {}
        }
        issues = parse_sslscan.identify_issues(result)
        assert any('Weak ciphers' in issue for issue in issues)

    def test_identifies_expired_certificate(self):
        result = {
            'protocols': {'sslv2': False, 'sslv3': False, 'tlsv1_0': False, 'tlsv1_1': False, 'tlsv1_2': True, 'tlsv1_3': True},
            'stats': {'weak_ciphers': []},
            'certificate': {'expired': True, 'self_signed': False, 'key_bits': 2048, 'signature_algorithm': 'sha256'},
            'vulnerabilities': {}
        }
        issues = parse_sslscan.identify_issues(result)
        assert any('expired' in issue for issue in issues)

    def test_identifies_self_signed_certificate(self):
        result = {
            'protocols': {'sslv2': False, 'sslv3': False, 'tlsv1_0': False, 'tlsv1_1': False, 'tlsv1_2': True, 'tlsv1_3': True},
            'stats': {'weak_ciphers': []},
            'certificate': {'expired': False, 'self_signed': True, 'key_bits': 2048, 'signature_algorithm': 'sha256'},
            'vulnerabilities': {}
        }
        issues = parse_sslscan.identify_issues(result)
        assert any('self-signed' in issue for issue in issues)

    def test_identifies_weak_key_size(self):
        result = {
            'protocols': {'sslv2': False, 'sslv3': False, 'tlsv1_0': False, 'tlsv1_1': False, 'tlsv1_2': True, 'tlsv1_3': True},
            'stats': {'weak_ciphers': []},
            'certificate': {'expired': False, 'self_signed': False, 'key_bits': 1024, 'signature_algorithm': 'sha256'},
            'vulnerabilities': {}
        }
        issues = parse_sslscan.identify_issues(result)
        assert any('1024 bits' in issue for issue in issues)

    def test_identifies_heartbleed_vulnerability(self):
        result = {
            'protocols': {'sslv2': False, 'sslv3': False, 'tlsv1_0': False, 'tlsv1_1': False, 'tlsv1_2': True, 'tlsv1_3': True},
            'stats': {'weak_ciphers': []},
            'certificate': None,
            'vulnerabilities': {'heartbleed': True, 'ccs_injection': False}
        }
        issues = parse_sslscan.identify_issues(result)
        assert any('Heartbleed' in issue for issue in issues)


class TestParseSslscanText:
    """Tests for text format parsing."""

    def test_parses_text_sample(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_text(sslscan_fixtures / "sample_text.txt")

        assert result['type'] == 'sslscan'
        assert result['target'] == '10.10.10.5:443'

    def test_parses_protocols_text(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_text(sslscan_fixtures / "sample_text.txt")

        assert result['protocols']['sslv2'] is False
        assert result['protocols']['sslv3'] is False
        assert result['protocols']['tlsv1_0'] is False
        assert result['protocols']['tlsv1_1'] is False
        assert result['protocols']['tlsv1_2'] is True
        assert result['protocols']['tlsv1_3'] is True

    def test_parses_ciphers_text(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_text(sslscan_fixtures / "sample_text.txt")

        assert len(result['ciphers']) > 0
        cipher_names = [c['name'] for c in result['ciphers']]
        assert 'TLS_AES_256_GCM_SHA384' in cipher_names

    def test_parses_certificate_text(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_text(sslscan_fixtures / "sample_text.txt")

        assert result['certificate'] is not None
        assert 'example.com' in result['certificate']['subject']
        assert result['certificate']['key_bits'] == 2048
        assert 'sha256' in result['certificate']['signature_algorithm'].lower()

    def test_parses_san_entries(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_text(sslscan_fixtures / "sample_text.txt")

        assert 'example.com' in result['certificate']['san']
        assert 'www.example.com' in result['certificate']['san']

    def test_parses_heartbleed_not_vulnerable(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_text(sslscan_fixtures / "sample_text.txt")

        assert result['vulnerabilities']['heartbleed'] is False


class TestParseSslscanVulnerable:
    """Tests for parsing vulnerable configurations."""

    def test_parses_vulnerable_sample(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert result['type'] == 'sslscan'
        assert result['target'] == '10.10.10.100:443'

    def test_detects_deprecated_protocols(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert result['protocols']['sslv3'] is True
        assert result['protocols']['tlsv1_0'] is True
        assert result['protocols']['tlsv1_1'] is True
        assert result['protocols']['tlsv1_3'] is False

    def test_detects_weak_ciphers(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert len(result['stats']['weak_ciphers']) > 0
        weak_ciphers = result['stats']['weak_ciphers']
        # Should detect RC4, DES, and EXPORT ciphers as weak
        assert any('RC4' in c for c in weak_ciphers) or any('DES' in c for c in weak_ciphers)

    def test_detects_heartbleed(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert result['vulnerabilities']['heartbleed'] is True

    def test_detects_ccs_injection(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert result['vulnerabilities']['ccs_injection'] is True

    def test_detects_compression_crime(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert result['vulnerabilities']['crime'] is True

    def test_detects_expired_certificate(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert result['certificate']['expired'] is True

    def test_detects_self_signed(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert result['certificate']['self_signed'] is True

    def test_detects_weak_key(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert result['certificate']['key_bits'] == 1024

    def test_detects_sha1_signature(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert 'sha1' in result['certificate']['signature_algorithm'].lower()

    def test_issues_populated(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_vulnerable.txt")

        assert len(result['stats']['issues']) > 0
        # Should have multiple issues for this vulnerable config
        assert len(result['stats']['issues']) >= 5


class TestParseSslscanXml:
    """Tests for XML format parsing."""

    def test_parses_xml_sample(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_xml(sslscan_fixtures / "sample_xml.xml")

        assert result['type'] == 'sslscan'
        assert result['target'] == '10.10.10.5:443'

    def test_parses_protocols_xml(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_xml(sslscan_fixtures / "sample_xml.xml")

        assert result['protocols']['sslv2'] is False
        assert result['protocols']['sslv3'] is False
        assert result['protocols']['tlsv1_0'] is False
        assert result['protocols']['tlsv1_1'] is False
        assert result['protocols']['tlsv1_2'] is True
        assert result['protocols']['tlsv1_3'] is True

    def test_parses_ciphers_xml(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_xml(sslscan_fixtures / "sample_xml.xml")

        # Should only include accepted ciphers, not rejected
        assert len(result['ciphers']) > 0
        cipher_names = [c['name'] for c in result['ciphers']]
        assert 'TLS_AES_256_GCM_SHA384' in cipher_names
        # Rejected cipher should not be included
        assert 'DES-CBC-SHA' not in cipher_names

    def test_parses_certificate_xml(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_xml(sslscan_fixtures / "sample_xml.xml")

        assert result['certificate'] is not None
        assert 'example.com' in result['certificate']['subject']
        assert result['certificate']['key_bits'] == 2048
        assert result['certificate']['expired'] is False
        assert result['certificate']['self_signed'] is False

    def test_parses_san_xml(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_xml(sslscan_fixtures / "sample_xml.xml")

        assert 'DNS:example.com' in result['certificate']['san']
        assert 'DNS:www.example.com' in result['certificate']['san']

    def test_parses_heartbleed_xml(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan_xml(sslscan_fixtures / "sample_xml.xml")

        assert result['vulnerabilities']['heartbleed'] is False


class TestParseSslscan:
    """Integration tests for the main parse_sslscan function."""

    def test_auto_detects_text_format(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_text.txt")

        assert result['type'] == 'sslscan'
        assert result['target'] == '10.10.10.5:443'

    def test_auto_detects_xml_format(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_xml.xml")

        assert result['type'] == 'sslscan'
        assert result['target'] == '10.10.10.5:443'

    def test_output_has_required_fields(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_text.txt")

        required_fields = ['type', 'target', 'protocols', 'ciphers', 'certificate',
                          'vulnerabilities', 'stats', 'raw_file', 'parsed_at']
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_text.txt")

        assert 'weak_ciphers' in result['stats']
        assert 'issues' in result['stats']
        assert isinstance(result['stats']['weak_ciphers'], list)
        assert isinstance(result['stats']['issues'], list)

    def test_vulnerabilities_structure(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_text.txt")

        vuln_keys = ['heartbleed', 'ccs_injection', 'beast', 'poodle', 'sweet32',
                    'ticketbleed', 'robot', 'drown', 'crime', 'breach', 'logjam', 'freak']
        for key in vuln_keys:
            assert key in result['vulnerabilities'], f"Missing vulnerability key: {key}"

    def test_cipher_strength_classification(self, sslscan_fixtures):
        result = parse_sslscan.parse_sslscan(sslscan_fixtures / "sample_text.txt")

        for cipher in result['ciphers']:
            assert 'strength' in cipher
            assert cipher['strength'] in ['weak', 'medium', 'strong']


class TestEmptyAndMinimalInput:
    """Tests for edge cases with empty or minimal input."""

    def test_empty_file(self, tmp_path):
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")

        result = parse_sslscan.parse_sslscan_text(empty_file)

        assert result['type'] == 'sslscan'
        assert result['target'] is None
        assert len(result['ciphers']) == 0
        assert result['certificate'] is None

    def test_minimal_text_file(self, tmp_path):
        minimal_file = tmp_path / "minimal.txt"
        minimal_file.write_text("Connected to 10.10.10.1\n")

        result = parse_sslscan.parse_sslscan_text(minimal_file)

        assert result['type'] == 'sslscan'
        assert result['target'] == '10.10.10.1'

    def test_file_with_only_comments(self, tmp_path):
        comment_file = tmp_path / "comments.txt"
        comment_file.write_text("# This is a comment\n# Another comment\n")

        result = parse_sslscan.parse_sslscan_text(comment_file)

        assert result['type'] == 'sslscan'
        assert len(result['ciphers']) == 0
