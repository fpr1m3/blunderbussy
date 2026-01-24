#!/usr/bin/env python3
"""
Integration tests for Faraday -> CAS pipeline.

Tests the complete flow from Faraday API data through to CAS YAML generation
and PTT initialization.

Fixture data in tests/fixtures/faraday_responses/:
- hosts.json: Sample Faraday hosts with services
- vulnerabilities.json: Sample vulns with CVE refs and varying severities
- services.json: Mix of web and non-web services
- stats.json: Workspace statistics
"""

import json
import pytest
import yaml
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import patch, MagicMock
from datetime import datetime

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import functions to test from format-cas.py
from importlib.util import spec_from_loader, module_from_spec
from importlib.machinery import SourceFileLoader

# Load format-cas.py module (hyphenated name requires special loading)
format_cas_path = Path(__file__).parent.parent / 'format-cas.py'
spec = spec_from_loader('format_cas', SourceFileLoader('format_cas', str(format_cas_path)))
format_cas = module_from_spec(spec)
spec.loader.exec_module(format_cas)

# Extract functions from format_cas module
process_faraday_hosts = format_cas.process_faraday_hosts
process_faraday_vulnerabilities = format_cas.process_faraday_vulnerabilities
process_faraday_services = format_cas.process_faraday_services
generate_summary_from_faraday = format_cas.generate_summary_from_faraday
generate_fallback_guidance = format_cas.generate_fallback_guidance
generate_attack_guidance = format_cas.generate_attack_guidance
process_faraday_data = format_cas.process_faraday_data
detect_data_source = format_cas.detect_data_source
CASFormatter = format_cas.CASFormatter
calculate_host_priority = format_cas.calculate_host_priority
assess_exploitability = format_cas.assess_exploitability
estimate_cvss = format_cas.estimate_cvss


# ─────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def fixtures_dir():
    """Path to fixture data directory."""
    return Path(__file__).parent / 'fixtures' / 'faraday_responses'


@pytest.fixture
def sample_hosts(fixtures_dir):
    """Load sample hosts from fixture."""
    with open(fixtures_dir / 'hosts.json') as f:
        return json.load(f)


@pytest.fixture
def sample_vulnerabilities(fixtures_dir):
    """Load sample vulnerabilities from fixture."""
    with open(fixtures_dir / 'vulnerabilities.json') as f:
        return json.load(f)


@pytest.fixture
def sample_services(fixtures_dir):
    """Load sample services from fixture."""
    with open(fixtures_dir / 'services.json') as f:
        return json.load(f)


@pytest.fixture
def sample_stats(fixtures_dir):
    """Load sample stats from fixture."""
    with open(fixtures_dir / 'stats.json') as f:
        return json.load(f)


@pytest.fixture
def hosts_by_id(sample_hosts):
    """Build host lookup dictionary."""
    return {h['id']: h for h in sample_hosts}


@pytest.fixture
def services_by_id(sample_services):
    """Build service lookup dictionary."""
    return {s['id']: s for s in sample_services}


@pytest.fixture
def faraday_input_data(sample_hosts, sample_vulnerabilities, sample_services, sample_stats):
    """Build complete Faraday input data structure."""
    return {
        'target': '192.168.1.0/24',
        'session_id': 'test_session_20260123_120000',
        'scan_type': 'faraday',
        'data': {
            'hosts': sample_hosts,
            'vulnerabilities': sample_vulnerabilities,
            'services': sample_services,
            'stats': sample_stats
        },
        'source': 'faraday:test_workspace',
        'timestamp': '2026-01-23T12:00:00Z'
    }


# ─────────────────────────────────────────────────────────────────
# Data Mapping Tests
# ─────────────────────────────────────────────────────────────────

class TestProcessFaradayHostsBasic:
    """Test process_faraday_hosts with basic host data."""

    def test_basic_host_mapping(self, sample_hosts):
        """Host fields correctly mapped to CAS format."""
        cas_hosts = process_faraday_hosts(sample_hosts)

        assert len(cas_hosts) == 4

        # First host - web server
        web_host = cas_hosts[0]
        assert web_host['ip'] == '192.168.1.10'
        assert 'web.local' in web_host['hostnames']
        assert web_host['os'] == 'Ubuntu 20.04 LTS'
        assert web_host['mac'] == '00:11:22:33:44:55'
        assert web_host['vuln_count'] == 5

    def test_empty_hosts_list(self):
        """Empty hosts list returns empty result."""
        cas_hosts = process_faraday_hosts([])
        assert cas_hosts == []

    def test_host_with_null_fields(self, sample_hosts):
        """Hosts with null fields handled gracefully."""
        cas_hosts = process_faraday_hosts(sample_hosts)

        # Fourth host has null os, mac, and empty hostnames
        null_host = cas_hosts[3]
        assert null_host['ip'] == '192.168.1.40'
        assert null_host['hostnames'] == []
        assert null_host['os'] is None
        assert null_host['mac'] is None

    def test_priority_score_calculated(self, sample_hosts):
        """Priority scores calculated for each host."""
        cas_hosts = process_faraday_hosts(sample_hosts)

        for host in cas_hosts:
            assert 'priority_score' in host
            assert 0.0 <= host['priority_score'] <= 10.0


class TestProcessFaradayHostsWithServices:
    """Test process_faraday_hosts service mapping."""

    def test_services_mapped_to_ports(self, sample_hosts):
        """Host services converted to ports array."""
        cas_hosts = process_faraday_hosts(sample_hosts)

        web_host = cas_hosts[0]
        assert len(web_host['ports']) == 3

        # Check SSH port mapping
        ssh_port = next(p for p in web_host['ports'] if p['port'] == 22)
        assert ssh_port['protocol'] == 'tcp'
        assert ssh_port['service'] == 'ssh'
        assert ssh_port['version'] == 'OpenSSH 8.2p1'
        assert ssh_port['state'] == 'open'

    def test_host_without_services(self, sample_hosts):
        """Host with no services has empty ports array."""
        cas_hosts = process_faraday_hosts(sample_hosts)

        empty_host = cas_hosts[3]
        assert empty_host['ports'] == []

    def test_critical_services_increase_priority(self, sample_hosts):
        """Hosts with critical services get higher priority scores."""
        cas_hosts = process_faraday_hosts(sample_hosts)

        # DB host has smb, mssql, rdp - all critical services
        db_host = next(h for h in cas_hosts if h['ip'] == '192.168.1.20')

        # Legacy host has telnet (very critical) and ftp
        legacy_host = next(h for h in cas_hosts if h['ip'] == '192.168.1.30')

        # Both should have elevated priority scores
        assert db_host['priority_score'] > 0
        assert legacy_host['priority_score'] > 0


class TestProcessFaradayVulnerabilitiesWithCVEs:
    """Test process_faraday_vulnerabilities CVE extraction."""

    def test_cves_extracted_from_refs(self, sample_vulnerabilities, hosts_by_id, services_by_id):
        """CVE identifiers extracted from refs array."""
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )

        # First vuln has single CVE
        sql_vuln = next(v for v in cas_vulns if 'SQL Injection' in v['name'])
        assert 'CVE-2023-12345' in sql_vuln['cves']

        # RCE vuln has multiple CVEs
        rce_vuln = next(v for v in cas_vulns if 'Deserialization' in v['name'])
        assert len(rce_vuln['cves']) == 3
        assert 'CVE-2024-5678' in rce_vuln['cves']

    def test_non_cve_refs_preserved(self, sample_vulnerabilities, hosts_by_id, services_by_id):
        """Non-CVE references preserved separately."""
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )

        sql_vuln = next(v for v in cas_vulns if 'SQL Injection' in v['name'])
        # OWASP and CWE refs should be in references, not cves
        assert any('owasp' in ref.lower() for ref in sql_vuln['references'])

    def test_vuln_without_cves(self, sample_vulnerabilities, hosts_by_id, services_by_id):
        """Vulnerability without CVEs has empty cves list."""
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )

        telnet_vuln = next(v for v in cas_vulns if 'Telnet' in v['name'])
        assert telnet_vuln['cves'] == []

    def test_severity_normalized(self, sample_vulnerabilities, hosts_by_id, services_by_id):
        """Severity values normalized to lowercase."""
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )

        severities = [v['severity'] for v in cas_vulns]
        assert all(s == s.lower() for s in severities)

    def test_vulns_sorted_by_severity(self, sample_vulnerabilities, hosts_by_id, services_by_id):
        """Vulnerabilities sorted by severity (critical first)."""
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        for i in range(len(cas_vulns) - 1):
            current_order = severity_order.get(cas_vulns[i]['severity'], 5)
            next_order = severity_order.get(cas_vulns[i + 1]['severity'], 5)
            assert current_order <= next_order

    def test_host_ip_resolved(self, sample_vulnerabilities, hosts_by_id, services_by_id):
        """Vulnerability host IP resolved from host_id lookup."""
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )

        sql_vuln = next(v for v in cas_vulns if 'SQL Injection' in v['name'])
        assert sql_vuln['host'] == '192.168.1.10'

    def test_service_details_resolved(self, sample_vulnerabilities, hosts_by_id, services_by_id):
        """Vulnerability service name and port resolved from service_id."""
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )

        sql_vuln = next(v for v in cas_vulns if 'SQL Injection' in v['name'])
        assert sql_vuln['port'] == 80
        assert sql_vuln['service'] == 'http'

    def test_exploitability_assessed(self, sample_vulnerabilities, hosts_by_id, services_by_id):
        """Exploitability field populated for each vulnerability."""
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )

        for vuln in cas_vulns:
            assert 'exploitability' in vuln
            assert vuln['exploitability'] in ('high', 'medium', 'low', 'none')

    def test_cvss_estimated_from_severity(self, sample_vulnerabilities, hosts_by_id, services_by_id):
        """CVSS score estimated from severity level."""
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )

        critical_vuln = next(v for v in cas_vulns if v['severity'] == 'critical')
        assert critical_vuln['cvss'] == 9.5

        low_vuln = next(v for v in cas_vulns if v['severity'] == 'low')
        assert low_vuln['cvss'] == 2.5


class TestProcessFaradayServicesWebOnly:
    """Test process_faraday_services web filtering."""

    def test_only_web_services_included(self, sample_services, hosts_by_id):
        """Only HTTP/HTTPS services included in web_services."""
        web_services = process_faraday_services(sample_services, hosts_by_id)

        # From fixture: http (80), https (443), http-proxy (8080)
        assert len(web_services) == 3

        service_names = {s['protocol'] for s in web_services}
        assert 'http' in service_names or 'https' in service_names

    def test_non_web_services_excluded(self, sample_services, hosts_by_id):
        """Non-web services (ssh, ftp, mysql, etc.) excluded."""
        web_services = process_faraday_services(sample_services, hosts_by_id)

        ports = [s['port'] for s in web_services]
        # SSH (22), FTP (21), MySQL (3306), MSSQL (1433) should not be included
        assert 22 not in ports
        assert 21 not in ports
        assert 3306 not in ports
        assert 1433 not in ports

    def test_url_constructed_correctly(self, sample_services, hosts_by_id):
        """URL constructed with correct protocol and port."""
        web_services = process_faraday_services(sample_services, hosts_by_id)

        http_svc = next(s for s in web_services if s['port'] == 80)
        assert http_svc['url'] == 'http://192.168.1.10:80'

        https_svc = next(s for s in web_services if s['port'] == 443)
        assert https_svc['url'] == 'https://192.168.1.10:443'

    def test_https_detected_by_service_name(self, sample_services, hosts_by_id):
        """HTTPS detected from service name."""
        web_services = process_faraday_services(sample_services, hosts_by_id)

        https_svc = next(s for s in web_services if s['port'] == 443)
        assert https_svc['protocol'] == 'https'

    def test_server_version_included(self, sample_services, hosts_by_id):
        """Server version info included in output."""
        web_services = process_faraday_services(sample_services, hosts_by_id)

        http_svc = next(s for s in web_services if s['port'] == 80)
        assert http_svc['server'] == 'nginx 1.18.0'


class TestGenerateSummaryFromStats:
    """Test generate_summary_from_faraday stats conversion."""

    def test_summary_structure(self, sample_stats):
        """Summary has correct structure."""
        result = generate_summary_from_faraday(sample_stats, web_services_count=3)

        assert 'summary' in result
        assert 'severity_breakdown' in result

        summary = result['summary']
        assert 'hosts_discovered' in summary
        assert 'services_found' in summary
        assert 'vulnerabilities_found' in summary
        assert 'critical_findings' in summary
        assert 'web_services_found' in summary
        assert 'attack_surface' in summary

    def test_counts_mapped_correctly(self, sample_stats):
        """Stats counts mapped to summary fields."""
        result = generate_summary_from_faraday(sample_stats, web_services_count=3)

        summary = result['summary']
        assert summary['hosts_discovered'] == 4
        assert summary['services_found'] == 10
        assert summary['vulnerabilities_found'] == 10
        assert summary['web_services_found'] == 3

    def test_critical_findings_sum(self, sample_stats):
        """Critical findings equals critical + high severity vulns."""
        result = generate_summary_from_faraday(sample_stats, web_services_count=3)

        # From fixture: critical=4, high=2
        assert result['summary']['critical_findings'] == 6

    def test_severity_breakdown_preserved(self, sample_stats):
        """Severity breakdown preserved in output."""
        result = generate_summary_from_faraday(sample_stats, web_services_count=3)

        breakdown = result['severity_breakdown']
        assert breakdown['critical'] == 4
        assert breakdown['high'] == 2
        assert breakdown['medium'] == 2
        assert breakdown['low'] == 1
        assert breakdown['informational'] == 1

    def test_attack_surface_assessed(self, sample_stats):
        """Attack surface level assessed based on findings."""
        result = generate_summary_from_faraday(sample_stats, web_services_count=3)

        # With 4 critical + 2 high = 6 critical findings, should be 'critical'
        assert result['summary']['attack_surface'] == 'critical'

    def test_empty_stats_handled(self):
        """Empty stats produce valid summary with zeros."""
        result = generate_summary_from_faraday({}, web_services_count=0)

        assert result['summary']['hosts_discovered'] == 0
        assert result['summary']['critical_findings'] == 0
        assert result['summary']['attack_surface'] == 'low'


# ─────────────────────────────────────────────────────────────────
# Attack Guidance Tests
# ─────────────────────────────────────────────────────────────────

class TestGenerateFallbackGuidance:
    """Test heuristic-based attack guidance generation."""

    def test_fallback_guidance_structure(self, sample_hosts, sample_vulnerabilities, sample_services, hosts_by_id, services_by_id):
        """Fallback guidance has expected structure."""
        cas_hosts = process_faraday_hosts(sample_hosts)
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )
        cas_web = process_faraday_services(sample_services, hosts_by_id)

        result = generate_fallback_guidance(cas_hosts, cas_vulns, cas_web)

        assert 'attack_guidance' in result
        guidance = result['attack_guidance']
        assert 'priority_targets' in guidance
        assert 'quick_wins' in guidance
        assert 'recommended_commands' in guidance
        assert guidance['_source'] == 'heuristic'

    def test_priority_targets_sorted_by_score(self, sample_hosts, sample_vulnerabilities, sample_services, hosts_by_id, services_by_id):
        """Priority targets sorted by score descending."""
        cas_hosts = process_faraday_hosts(sample_hosts)
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )
        cas_web = process_faraday_services(sample_services, hosts_by_id)

        result = generate_fallback_guidance(cas_hosts, cas_vulns, cas_web)
        targets = result['attack_guidance']['priority_targets']

        for i in range(len(targets) - 1):
            assert targets[i]['score'] >= targets[i + 1]['score']

    def test_quick_wins_from_critical_vulns(self, sample_hosts, sample_vulnerabilities, sample_services, hosts_by_id, services_by_id):
        """Quick wins generated from critical/high vulnerabilities."""
        cas_hosts = process_faraday_hosts(sample_hosts)
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )
        cas_web = process_faraday_services(sample_services, hosts_by_id)

        result = generate_fallback_guidance(cas_hosts, cas_vulns, cas_web)
        quick_wins = result['attack_guidance']['quick_wins']

        # Should have quick wins from critical/high vulns
        assert len(quick_wins) > 0
        for qw in quick_wins:
            assert 'target' in qw
            assert 'action' in qw


class TestAttackGuidanceIncludesSourceFlag:
    """Test attack guidance source flag handling."""

    def test_fallback_has_heuristic_source(self, sample_hosts, sample_vulnerabilities, sample_services, hosts_by_id, services_by_id):
        """Fallback guidance marked as heuristic source."""
        cas_hosts = process_faraday_hosts(sample_hosts)
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )
        cas_web = process_faraday_services(sample_services, hosts_by_id)

        result = generate_fallback_guidance(cas_hosts, cas_vulns, cas_web)

        assert result['attack_guidance']['_source'] == 'heuristic'
        assert '_note' in result['attack_guidance']

    @patch('subprocess.run')
    def test_gemini_success_has_gemini_source(self, mock_run, sample_hosts, sample_vulnerabilities, sample_services, hosts_by_id, services_by_id):
        """Successful Gemini call marked as gemini source."""
        # Mock successful Gemini response
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"priority_targets": [], "quick_wins": []}'
        )

        cas_hosts = process_faraday_hosts(sample_hosts)
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )
        cas_web = process_faraday_services(sample_services, hosts_by_id)

        result = generate_attack_guidance(cas_hosts, cas_vulns, cas_web)

        assert result['attack_guidance']['_source'] == 'gemini'

    @patch('subprocess.run')
    def test_gemini_failure_falls_back_to_heuristic(self, mock_run, sample_hosts, sample_vulnerabilities, sample_services, hosts_by_id, services_by_id):
        """Failed Gemini call falls back to heuristic."""
        mock_run.return_value = MagicMock(returncode=1)

        cas_hosts = process_faraday_hosts(sample_hosts)
        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, hosts_by_id, services_by_id
        )
        cas_web = process_faraday_services(sample_services, hosts_by_id)

        result = generate_attack_guidance(cas_hosts, cas_vulns, cas_web)

        assert result['attack_guidance']['_source'] == 'heuristic'


# ─────────────────────────────────────────────────────────────────
# Integration Tests
# ─────────────────────────────────────────────────────────────────

class TestFullFaradayToCASConversion:
    """Test complete Faraday data to CAS conversion."""

    def test_full_conversion(self, faraday_input_data):
        """Complete conversion produces valid CAS document."""
        cas_doc = process_faraday_data(faraday_input_data)

        # Verify top-level structure
        assert 'cas_version' in cas_doc
        assert 'generated_at' in cas_doc
        assert 'target' in cas_doc
        assert 'summary' in cas_doc
        assert 'hosts' in cas_doc
        assert 'vulnerabilities' in cas_doc
        assert 'web_services' in cas_doc
        assert 'attack_guidance' in cas_doc
        assert 'faraday_meta' in cas_doc

    def test_target_info_preserved(self, faraday_input_data):
        """Target information preserved in CAS document."""
        cas_doc = process_faraday_data(faraday_input_data)

        assert cas_doc['target']['identifier'] == '192.168.1.0/24'
        assert cas_doc['target']['session_id'] == 'test_session_20260123_120000'
        assert 'faraday' in cas_doc['target']['scan_types']

    def test_faraday_meta_included(self, faraday_input_data):
        """Faraday metadata included in CAS document."""
        cas_doc = process_faraday_data(faraday_input_data)

        assert cas_doc['faraday_meta']['workspace'] == 'test_workspace'
        assert cas_doc['faraday_meta']['imported_at'] == '2026-01-23T12:00:00Z'

    def test_hosts_processed(self, faraday_input_data):
        """Hosts correctly processed in full conversion."""
        cas_doc = process_faraday_data(faraday_input_data)

        assert len(cas_doc['hosts']) == 4
        assert all('ip' in h for h in cas_doc['hosts'])
        assert all('priority_score' in h for h in cas_doc['hosts'])

    def test_vulns_split_by_severity(self, faraday_input_data):
        """Vulnerabilities split into high-priority and low-priority lists."""
        cas_doc = process_faraday_data(faraday_input_data)

        # High priority (critical/high) go to vulnerabilities
        high_priority = cas_doc['vulnerabilities']
        low_priority = cas_doc['low_priority_vulns']

        for v in high_priority:
            assert v['severity'] in ('critical', 'high')

        for v in low_priority:
            assert v['severity'] in ('medium', 'low', 'info')

    def test_key_findings_extracted(self, faraday_input_data):
        """Key findings extracted from critical vulnerabilities."""
        cas_doc = process_faraday_data(faraday_input_data)

        assert 'key_findings' in cas_doc
        assert len(cas_doc['key_findings']) > 0


class TestCASYamlValidStructure:
    """Test CAS YAML output validity."""

    def test_cas_yaml_serializable(self, faraday_input_data):
        """CAS document can be serialized to valid YAML."""
        cas_doc = process_faraday_data(faraday_input_data)

        # Should not raise
        yaml_str = yaml.dump(cas_doc, default_flow_style=False)
        assert yaml_str is not None
        assert len(yaml_str) > 0

    def test_cas_yaml_roundtrip(self, faraday_input_data):
        """CAS document survives YAML roundtrip."""
        cas_doc = process_faraday_data(faraday_input_data)

        yaml_str = yaml.dump(cas_doc, default_flow_style=False)
        restored = yaml.safe_load(yaml_str)

        assert restored['cas_version'] == cas_doc['cas_version']
        assert len(restored['hosts']) == len(cas_doc['hosts'])
        assert len(restored['vulnerabilities']) == len(cas_doc['vulnerabilities'])

    def test_cas_written_to_file(self, faraday_input_data):
        """CAS document can be written to file."""
        formatter = CASFormatter()
        cas_doc = formatter.format_cas(faraday_input_data)

        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / 'context.yaml'
            formatter.write_cas(cas_doc, output_path)

            assert output_path.exists()
            with open(output_path) as f:
                loaded = yaml.safe_load(f)
            assert loaded['cas_version'] == cas_doc['cas_version']


class TestPTTGenerationFromFaradayCAS:
    """Test PTT generation from Faraday-sourced CAS."""

    def test_detect_faraday_source(self, faraday_input_data):
        """Faraday data source correctly detected."""
        assert detect_data_source(faraday_input_data) == 'faraday'

    def test_detect_legacy_source(self):
        """Legacy data source correctly detected."""
        legacy_data = {
            'target': 'test',
            'data': {'hosts': []}
        }
        assert detect_data_source(legacy_data) == 'legacy'

    def test_faraday_meta_enables_ptt_detection(self, faraday_input_data):
        """faraday_meta section present for PTT source detection."""
        cas_doc = process_faraday_data(faraday_input_data)

        # PTT init-ptt.py uses faraday_meta presence to detect source
        assert 'faraday_meta' in cas_doc
        assert 'workspace' in cas_doc['faraday_meta']

    def test_cas_format_version(self, faraday_input_data):
        """CAS version is 1.2 for Faraday-sourced data."""
        cas_doc = process_faraday_data(faraday_input_data)
        assert cas_doc['cas_version'] == '1.2'


# ─────────────────────────────────────────────────────────────────
# Edge Cases
# ─────────────────────────────────────────────────────────────────

class TestEmptyWorkspaceData:
    """Test handling of empty workspace data."""

    def test_empty_hosts_list(self):
        """Empty hosts list handled gracefully."""
        cas_hosts = process_faraday_hosts([])
        assert cas_hosts == []

    def test_empty_vulns_list(self):
        """Empty vulnerabilities list handled gracefully."""
        cas_vulns = process_faraday_vulnerabilities([], {}, {})
        assert cas_vulns == []

    def test_empty_services_list(self):
        """Empty services list handled gracefully."""
        web_services = process_faraday_services([], {})
        assert web_services == []

    def test_empty_workspace_full_conversion(self):
        """Empty workspace produces valid CAS document."""
        empty_input = {
            'target': 'empty_target',
            'session_id': 'empty_session',
            'scan_type': 'faraday',
            'data': {
                'hosts': [],
                'vulnerabilities': [],
                'services': [],
                'stats': {}
            },
            'source': 'faraday:empty',
            'timestamp': '2026-01-23T12:00:00Z'
        }

        cas_doc = process_faraday_data(empty_input)

        assert cas_doc['hosts'] == []
        assert cas_doc['vulnerabilities'] == []
        assert cas_doc['web_services'] == []
        assert cas_doc['summary']['hosts_discovered'] == 0


class TestMissingHostReferences:
    """Test handling of vulnerabilities referencing missing hosts."""

    def test_vuln_with_missing_host_id(self, sample_vulnerabilities, services_by_id):
        """Vulnerability with missing host_id handled gracefully."""
        # Empty hosts dict
        empty_hosts = {}

        cas_vulns = process_faraday_vulnerabilities(
            sample_vulnerabilities, empty_hosts, services_by_id
        )

        # Should still process, but host field will be empty/None
        assert len(cas_vulns) > 0
        # Host IP comes from lookup - will be None if not found
        for vuln in cas_vulns:
            assert 'host' in vuln  # Field exists, may be None

    def test_service_with_missing_host_id(self, sample_services):
        """Service with missing host in lookup handled gracefully."""
        empty_hosts = {}

        web_services = process_faraday_services(sample_services, empty_hosts)

        # Should still process with 'unknown' as host
        for svc in web_services:
            assert 'host' in svc
            assert svc['host'] == 'unknown'


class TestVulnsWithoutServices:
    """Test handling of vulnerabilities without service associations."""

    def test_vuln_with_null_service_id(self, hosts_by_id, services_by_id):
        """Vulnerability with null service_id handled gracefully."""
        vulns_without_service = [{
            "id": 9999,
            "name": "Host-Level Vulnerability",
            "severity": "medium",
            "desc": "A vulnerability without service association.",
            "refs": ["CVE-2020-1234"],
            "confirmed": False,
            "tool": "nessus",
            "host_id": 1,
            "service_id": None
        }]

        cas_vulns = process_faraday_vulnerabilities(
            vulns_without_service, hosts_by_id, services_by_id
        )

        assert len(cas_vulns) == 1
        vuln = cas_vulns[0]
        assert vuln['port'] is None
        assert vuln['service'] is None
        assert vuln['host'] == '192.168.1.10'  # Host still resolved

    def test_vuln_with_invalid_service_id(self, hosts_by_id, services_by_id):
        """Vulnerability with non-existent service_id handled gracefully."""
        vulns_bad_service = [{
            "id": 9998,
            "name": "Bad Service Reference",
            "severity": "low",
            "desc": "References a non-existent service.",
            "refs": [],
            "confirmed": False,
            "tool": "test",
            "host_id": 1,
            "service_id": 99999  # Does not exist
        }]

        cas_vulns = process_faraday_vulnerabilities(
            vulns_bad_service, hosts_by_id, services_by_id
        )

        assert len(cas_vulns) == 1
        vuln = cas_vulns[0]
        assert vuln['port'] is None
        assert vuln['service'] is None


# ─────────────────────────────────────────────────────────────────
# Helper Function Tests
# ─────────────────────────────────────────────────────────────────

class TestEstimateCVSS:
    """Test CVSS score estimation from severity."""

    def test_critical_severity(self):
        assert estimate_cvss('critical') == 9.5
        assert estimate_cvss('CRITICAL') == 9.5

    def test_high_severity(self):
        assert estimate_cvss('high') == 7.5
        assert estimate_cvss('High') == 7.5

    def test_medium_severity(self):
        assert estimate_cvss('medium') == 5.0

    def test_low_severity(self):
        assert estimate_cvss('low') == 2.5

    def test_info_severity(self):
        assert estimate_cvss('info') == 0.0
        assert estimate_cvss('informational') == 0.0

    def test_null_severity(self):
        assert estimate_cvss(None) == 0.0

    def test_unknown_severity(self):
        assert estimate_cvss('unknown') == 0.0


class TestAssessExploitability:
    """Test exploitability assessment logic."""

    def test_high_exploitability_with_cves_and_confirmed(self):
        """Critical confirmed vuln with CVEs is highly exploitable."""
        vuln = {
            'severity': 'critical',
            'confirmed': True,
            'tool': 'metasploit'
        }
        cves = ['CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-9012']

        result = assess_exploitability(vuln, cves)
        assert result == 'high'

    def test_medium_exploitability(self):
        """High severity vuln with single CVE is medium exploitable."""
        vuln = {
            'severity': 'high',
            'confirmed': False,
            'tool': 'nmap'
        }
        cves = ['CVE-2024-1111']

        result = assess_exploitability(vuln, cves)
        assert result == 'medium'

    def test_low_exploitability(self):
        """Medium severity unconfirmed vuln is low exploitable."""
        vuln = {
            'severity': 'medium',
            'confirmed': False,
            'tool': 'nikto'
        }
        cves = []

        result = assess_exploitability(vuln, cves)
        assert result == 'low'

    def test_none_exploitability(self):
        """Info severity vuln with no indicators is not exploitable."""
        vuln = {
            'severity': 'info',
            'confirmed': False,
            'tool': 'nmap'
        }
        cves = []

        result = assess_exploitability(vuln, cves)
        assert result == 'none'


class TestCalculateHostPriority:
    """Test host priority score calculation."""

    def test_high_priority_host(self):
        """Host with many vulns and critical services gets high priority."""
        host = {
            'vuln_count': 10,
            'os': 'Windows Server 2008',
            'ports': [
                {'port': 445, 'service': 'smb', 'state': 'open'},
                {'port': 3389, 'service': 'rdp', 'state': 'open'},
                {'port': 23, 'service': 'telnet', 'state': 'open'},
            ]
        }

        score = calculate_host_priority(host)
        assert score >= 7.0  # High priority

    def test_low_priority_host(self):
        """Host with no vulns and basic services gets low priority."""
        host = {
            'vuln_count': 0,
            'os': 'Ubuntu 22.04',
            'ports': [
                {'port': 80, 'service': 'http', 'state': 'open'},
            ]
        }

        score = calculate_host_priority(host)
        assert score <= 3.0  # Low priority

    def test_legacy_os_increases_priority(self):
        """Legacy OS increases priority score."""
        modern_host = {
            'vuln_count': 0,
            'os': 'Ubuntu 22.04',
            'ports': []
        }

        legacy_host = {
            'vuln_count': 0,
            'os': 'Windows XP SP3',
            'ports': []
        }

        modern_score = calculate_host_priority(modern_host)
        legacy_score = calculate_host_priority(legacy_host)

        assert legacy_score > modern_score

    def test_score_bounds(self):
        """Priority score stays within 0.0-10.0 bounds."""
        extreme_host = {
            'vuln_count': 1000,
            'os': 'Windows XP',
            'ports': [{'port': p, 'service': 'unknown', 'state': 'open'} for p in range(100)]
        }

        score = calculate_host_priority(extreme_host)
        assert 0.0 <= score <= 10.0
