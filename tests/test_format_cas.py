"""Tests for CAS formatter vulnerability severity filtering."""
import sys
from pathlib import Path

import pytest

# Add enrichment directory to path for import
enrichment_dir = Path(__file__).parent.parent / "infrastructure" / "enrichment"
sys.path.insert(0, str(enrichment_dir))

# Import using importlib to handle hyphenated filename
from importlib.util import spec_from_loader, module_from_spec
from importlib.machinery import SourceFileLoader

loader = SourceFileLoader("format_cas", str(enrichment_dir / "format-cas.py"))
spec = spec_from_loader("format_cas", loader)
format_cas = module_from_spec(spec)
loader.exec_module(format_cas)

CASFormatter = format_cas.CASFormatter


@pytest.fixture
def formatter():
    return CASFormatter()


@pytest.fixture
def mixed_severity_vulns():
    """Test data with vulnerabilities of all severity levels."""
    return {
        "target": "test-target",
        "session_id": "test_session",
        "scan_type": "test",
        "data": {
            "vulnerabilities": [
                {"template_id": "v1", "template_name": "Critical SQL Injection", "severity": "critical", "host": "10.0.0.1"},
                {"template_id": "v2", "template_name": "High XSS", "severity": "high", "host": "10.0.0.1"},
                {"template_id": "v3", "template_name": "Medium CSRF", "severity": "medium", "host": "10.0.0.1"},
                {"template_id": "v4", "template_name": "Low Info Disclosure", "severity": "low", "host": "10.0.0.1"},
                {"template_id": "v5", "template_name": "Info Header", "severity": "info", "host": "10.0.0.1"},
            ]
        }
    }


class TestVulnerabilitySeverityFiltering:
    """Tests for vulnerability severity filtering in CAS output."""

    def test_critical_high_go_to_vulnerabilities(self, formatter, mixed_severity_vulns):
        """Critical and high severity vulns should be in main vulnerabilities list."""
        cas = formatter.format_cas(mixed_severity_vulns)

        assert len(cas["vulnerabilities"]) == 2
        severities = {v["severity"] for v in cas["vulnerabilities"]}
        assert severities == {"critical", "high"}

    def test_medium_low_info_go_to_low_priority(self, formatter, mixed_severity_vulns):
        """Medium, low, and info severity vulns should be in low_priority_vulns."""
        cas = formatter.format_cas(mixed_severity_vulns)

        assert len(cas["low_priority_vulns"]) == 3
        severities = {v["severity"] for v in cas["low_priority_vulns"]}
        assert severities == {"medium", "low", "info"}

    def test_summary_counts_are_correct(self, formatter, mixed_severity_vulns):
        """Summary should have correct counts for both categories."""
        cas = formatter.format_cas(mixed_severity_vulns)

        assert cas["summary"]["critical_findings"] == 2
        assert cas["summary"]["low_priority_vulns_count"] == 3
        assert cas["summary"]["vulnerabilities_found"] == 5


class TestCASMerge:
    """Tests for CAS document merging with severity-filtered vulnerabilities.

    Note: low_priority_vulns are externalized to last_resort.yaml, so they
    are not merged - only the new data's low_priority_vulns are kept for
    re-externalization by write_cas().
    """

    def test_merge_combines_vulnerabilities(self, formatter):
        """Merging should combine high-priority vulnerabilities from both documents."""
        existing = {
            "generated_at": "2026-01-18T00:00:00",
            "target": {"scan_types": ["nmap"]},
            "vulnerabilities": [
                {"id": "existing1", "host": "10.0.0.1", "matched_at": "/path1", "severity": "critical"}
            ],
            "hosts": [],
            "web_services": [],
            "subdomains": [],
            "directories": [],
            "nikto_findings": [],
            "smb_shares": [],
            "smb_enum": {},
            "key_findings": [],
            "summary": {}
        }

        new = {
            "generated_at": "2026-01-19T00:00:00",
            "target": {"scan_types": ["nuclei"]},
            "vulnerabilities": [
                {"id": "new1", "host": "10.0.0.2", "matched_at": "/new", "severity": "high"}
            ],
            "low_priority_vulns": [
                {"id": "new2", "host": "10.0.0.2", "matched_at": "/new2", "severity": "medium"}
            ],
            "hosts": [],
            "web_services": [],
            "subdomains": [],
            "directories": [],
            "nikto_findings": [],
            "smb_shares": [],
            "smb_enum": {},
            "key_findings": [],
            "summary": {"exploitable_cves": 0}
        }

        merged = formatter._merge_cas(existing, new)

        # High-priority vulns are merged from both docs
        assert len(merged["vulnerabilities"]) == 2
        # Low-priority vulns come only from new (externalized)
        assert len(merged["low_priority_vulns"]) == 1

    def test_merge_updates_summary_counts(self, formatter):
        """Merged summary should reflect combined high-priority and new low-priority counts."""
        existing = {
            "generated_at": "2026-01-18T00:00:00",
            "target": {"scan_types": ["nmap"]},
            "vulnerabilities": [{"id": "v1", "host": "h1", "matched_at": "/p1"}],
            "hosts": [],
            "web_services": [],
            "subdomains": [],
            "directories": [],
            "nikto_findings": [],
            "smb_shares": [],
            "smb_enum": {},
            "key_findings": [],
            "summary": {}
        }

        new = {
            "generated_at": "2026-01-19T00:00:00",
            "target": {"scan_types": ["nuclei"]},
            "vulnerabilities": [{"id": "v3", "host": "h2", "matched_at": "/p3"}],
            "low_priority_vulns": [{"id": "v4", "host": "h2", "matched_at": "/p4"}],
            "hosts": [],
            "web_services": [],
            "subdomains": [],
            "directories": [],
            "nikto_findings": [],
            "smb_shares": [],
            "smb_enum": {},
            "key_findings": [],
            "summary": {"exploitable_cves": 0}
        }

        merged = formatter._merge_cas(existing, new)

        # 2 high-priority vulns merged
        assert merged["summary"]["critical_findings"] == 2
        # 1 low-priority from new data (externalized)
        assert merged["summary"]["low_priority_vulns_count"] == 1
        # Total = 2 high + 1 low = 3
        assert merged["summary"]["vulnerabilities_found"] == 3


# Import new functions for Faraday detection tests
detect_data_source = format_cas.detect_data_source
process_faraday_data = format_cas.process_faraday_data


class TestFaradayDataSourceDetection:
    """Tests for Faraday data source detection."""

    def test_detect_faraday_from_source_field(self):
        """Data with source starting with 'faraday:' should be detected as Faraday."""
        data = {"source": "faraday:workspace_123", "hosts": []}
        assert detect_data_source(data) == "faraday"

    def test_detect_faraday_from_scan_type(self):
        """Data with scan_type 'faraday' should be detected as Faraday."""
        data = {"scan_type": "faraday", "hosts": []}
        assert detect_data_source(data) == "faraday"

    def test_detect_legacy_without_faraday_markers(self):
        """Data without Faraday markers should be detected as legacy."""
        data = {"scan_type": "nmap", "hosts": []}
        assert detect_data_source(data) == "legacy"

    def test_detect_legacy_empty_data(self):
        """Empty data should be detected as legacy."""
        data = {}
        assert detect_data_source(data) == "legacy"

    def test_detect_legacy_with_non_faraday_source(self):
        """Data with different source should be legacy."""
        data = {"source": "autorecon", "hosts": []}
        assert detect_data_source(data) == "legacy"


class TestFaradayProcessorRouting:
    """Tests for routing to appropriate processor based on data source."""

    def test_format_cas_routes_faraday_data(self, formatter):
        """format_cas should route Faraday data to process_faraday_data."""
        faraday_data = {
            "source": "faraday:test_workspace",
            "target": "192.168.1.0/24",
            "session_id": "sess_123"
        }
        cas = formatter.format_cas(faraday_data)

        assert cas["cas_version"] == "1.2"
        # Source is in target dict, not top-level
        assert cas["target"]["source"] == "faraday:test_workspace"
        assert cas["target"]["identifier"] == "192.168.1.0/24"
        assert cas["target"]["session_id"] == "sess_123"

    def test_format_cas_routes_legacy_data(self, formatter, mixed_severity_vulns):
        """format_cas should route legacy data to _process_legacy_data."""
        cas = formatter.format_cas(mixed_severity_vulns)

        assert cas["cas_version"] == "1.1"
        assert "source" not in cas or cas.get("source") != "faraday"

    def test_faraday_processor_stub_returns_empty_structure(self):
        """process_faraday_data should return valid empty CAS structure."""
        faraday_data = {
            "source": "faraday:workspace",
            "target": "test-target",
            "session_id": "test-session"
        }
        cas = process_faraday_data(faraday_data)

        # Verify structure
        assert "cas_version" in cas
        assert "generated_at" in cas
        assert "target" in cas
        assert "summary" in cas
        assert "hosts" in cas
        assert "vulnerabilities" in cas

        # Verify empty arrays
        assert cas["hosts"] == []
        assert cas["vulnerabilities"] == []
        assert cas["web_services"] == []

        # Verify summary counts are zero
        assert cas["summary"]["hosts_discovered"] == 0
        assert cas["summary"]["vulnerabilities_found"] == 0
