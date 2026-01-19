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
    """Tests for CAS document merging with severity-filtered vulnerabilities."""

    def test_merge_preserves_both_vulnerability_lists(self, formatter):
        """Merging should combine vulnerabilities from both documents."""
        existing = {
            "generated_at": "2026-01-18T00:00:00",
            "target": {"scan_types": ["nmap"]},
            "vulnerabilities": [
                {"id": "existing1", "host": "10.0.0.1", "matched_at": "/path1", "severity": "critical"}
            ],
            "low_priority_vulns": [
                {"id": "existing2", "host": "10.0.0.1", "matched_at": "/path2", "severity": "info"}
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

        assert len(merged["vulnerabilities"]) == 2
        assert len(merged["low_priority_vulns"]) == 2

    def test_merge_updates_summary_counts(self, formatter):
        """Merged summary should reflect combined counts."""
        existing = {
            "generated_at": "2026-01-18T00:00:00",
            "target": {"scan_types": ["nmap"]},
            "vulnerabilities": [{"id": "v1", "host": "h1", "matched_at": "/p1"}],
            "low_priority_vulns": [{"id": "v2", "host": "h1", "matched_at": "/p2"}],
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

        assert merged["summary"]["critical_findings"] == 2
        assert merged["summary"]["low_priority_vulns_count"] == 2
        assert merged["summary"]["vulnerabilities_found"] == 4
