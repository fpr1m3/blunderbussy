#!/usr/bin/env python3
"""
Unit tests for FaradayClient.

Uses responses library to mock HTTP calls - no real Faraday server needed.
"""

import pytest
import responses
from pathlib import Path
from tempfile import NamedTemporaryFile

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from faraday_client import FaradayClient, FaradayConfig, CONTENT_TYPES


@pytest.fixture
def config():
    """Standard test configuration."""
    return FaradayConfig(
        url='http://faraday-test:5985',
        username='testuser',
        password='testpass',
        verify_ssl=False,
        timeout=5
    )


@pytest.fixture
def client(config):
    """Unauthenticated client."""
    return FaradayClient(config)


@pytest.fixture
def auth_client(config):
    """Pre-authenticated client with mocked login."""
    client = FaradayClient(config)
    client._authenticated = True
    client._csrf_token = 'test-csrf-token'
    client.session.headers['X-CSRF-Token'] = 'test-csrf-token'
    return client


# ─────────────────────────────────────────────────────────────────
# Authentication Tests
# ─────────────────────────────────────────────────────────────────

class TestAuthentication:
    """Test authenticate() method."""

    @responses.activate
    def test_authenticate_success(self, client, config):
        """Successful authentication returns True and sets state."""
        responses.add(
            responses.POST,
            f'{config.url}/_api/login',
            json={'status': 'ok'},
            status=200,
            headers={'Set-Cookie': 'csrf_access_token=abc123'}
        )

        result = client.authenticate()

        assert result is True
        assert client.authenticated is True

    @responses.activate
    def test_authenticate_bad_credentials(self, client, config):
        """Invalid credentials return False."""
        responses.add(
            responses.POST,
            f'{config.url}/_api/login',
            json={'error': 'Invalid credentials'},
            status=401
        )

        result = client.authenticate()

        assert result is False
        assert client.authenticated is False

    @responses.activate
    def test_authenticate_connection_error(self, client, config):
        """Connection error raises exception."""
        responses.add(
            responses.POST,
            f'{config.url}/_api/login',
            body=ConnectionError('Connection refused')
        )

        with pytest.raises(ConnectionError):
            client.authenticate()

    @responses.activate
    def test_authenticate_csrf_from_response_body(self, client, config):
        """CSRF token extracted from response body if not in cookie."""
        responses.add(
            responses.POST,
            f'{config.url}/_api/login',
            json={'status': 'ok', 'csrf_token': 'body-csrf-token'},
            status=200
        )

        result = client.authenticate()

        assert result is True
        assert client._csrf_token == 'body-csrf-token'


# ─────────────────────────────────────────────────────────────────
# Upload Tests
# ─────────────────────────────────────────────────────────────────

class TestUploadReport:
    """Test upload_report() method."""

    @responses.activate
    def test_upload_report_success(self, auth_client, config):
        """Successful upload returns command details."""
        responses.add(
            responses.POST,
            f'{config.url}/_api/v3/ws/testworkspace/upload_report/',
            json={
                'command_id': 42,
                'vulns_count': 5,
                'hosts_count': 3
            },
            status=201
        )

        with NamedTemporaryFile(suffix='.xml', delete=False) as f:
            f.write(b'<nmap>test</nmap>')
            temp_path = Path(f.name)

        try:
            result = auth_client.upload_report('testworkspace', temp_path)

            assert result['command_id'] == 42
            assert result['vulnerabilities'] == 5
            assert result['hosts'] == 3
        finally:
            temp_path.unlink()

    def test_upload_report_file_not_found(self, auth_client):
        """Non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            auth_client.upload_report('workspace', Path('/nonexistent/file.xml'))

    @responses.activate
    def test_upload_report_workspace_not_found(self, auth_client, config):
        """Missing workspace raises ValueError."""
        responses.add(
            responses.POST,
            f'{config.url}/_api/v3/ws/missing/upload_report/',
            json={'error': 'Not found'},
            status=404
        )

        with NamedTemporaryFile(suffix='.xml', delete=False) as f:
            f.write(b'<test/>')
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match='Workspace not found'):
                auth_client.upload_report('missing', temp_path)
        finally:
            temp_path.unlink()

    def test_upload_content_type_detection(self):
        """Content types correctly detected from extension."""
        assert CONTENT_TYPES['.xml'] == 'application/xml'
        assert CONTENT_TYPES['.json'] == 'application/json'
        assert CONTENT_TYPES['.jsonl'] == 'application/x-ndjson'
        assert CONTENT_TYPES['.txt'] == 'text/plain'
        assert CONTENT_TYPES['.html'] == 'text/html'

    def test_upload_requires_auth(self, client):
        """Upload without auth raises RuntimeError."""
        with pytest.raises(RuntimeError, match='Not authenticated'):
            client.upload_report('workspace', Path('/tmp/test.xml'))


# ─────────────────────────────────────────────────────────────────
# Host Query Tests
# ─────────────────────────────────────────────────────────────────

class TestGetHosts:
    """Test get_hosts() method."""

    @responses.activate
    def test_get_hosts_empty_workspace(self, auth_client, config):
        """Empty workspace returns empty list."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/empty/hosts/',
            json={'rows': []},
            status=200
        )

        result = auth_client.get_hosts('empty')

        assert result == []

    @responses.activate
    def test_get_hosts_with_data(self, auth_client, config):
        """Hosts returned with normalized structure."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/hosts/',
            json={
                'rows': [
                    {
                        'id': 1,
                        'ip': '192.168.1.1',
                        'hostnames': ['host1.local'],
                        'os': 'Linux',
                        'services': [{'port': 22}],
                        'vulnerability_count': 3
                    },
                    {
                        '_id': 2,  # Alternate ID field
                        'ip': '192.168.1.2',
                        'hostnames': [],
                        'os': 'Windows',
                        'vuln_count': 1  # Alternate count field
                    }
                ]
            },
            status=200
        )

        result = auth_client.get_hosts('test')

        assert len(result) == 2
        assert result[0]['id'] == 1
        assert result[0]['ip'] == '192.168.1.1'
        assert result[0]['vuln_count'] == 3
        assert result[1]['id'] == 2
        assert result[1]['vuln_count'] == 1

    @responses.activate
    def test_get_hosts_pagination(self, auth_client, config):
        """Pagination parameters passed correctly."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/hosts/',
            json={'rows': []},
            status=200
        )

        auth_client.get_hosts('test', limit=50, offset=100)

        assert 'limit=50' in responses.calls[0].request.url
        assert 'offset=100' in responses.calls[0].request.url

    def test_get_hosts_requires_auth(self, client):
        """get_hosts without auth raises RuntimeError."""
        with pytest.raises(RuntimeError, match='Not authenticated'):
            client.get_hosts('workspace')


# ─────────────────────────────────────────────────────────────────
# Vulnerability Query Tests
# ─────────────────────────────────────────────────────────────────

class TestGetVulnerabilities:
    """Test get_vulnerabilities() method."""

    @responses.activate
    def test_get_vulnerabilities_severity_filter(self, auth_client, config):
        """Severity filter applied correctly."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/vulns/',
            json={
                'rows': [
                    {
                        'id': 1,
                        'name': 'SQL Injection',
                        'severity': 'critical',
                        'desc': 'SQLi found',
                        'refs': ['https://owasp.org'],
                        'cve': ['CVE-2024-1234'],
                        'confirmed': True
                    }
                ]
            },
            status=200
        )

        result = auth_client.get_vulnerabilities(
            'test',
            severity=['critical', 'high']
        )

        assert 'severity=critical%2Chigh' in responses.calls[0].request.url
        assert len(result) == 1
        assert result[0]['severity'] == 'critical'
        assert result[0]['cve'] == ['CVE-2024-1234']

    @responses.activate
    def test_get_vulnerabilities_confirmed_filter(self, auth_client, config):
        """Confirmed filter applied correctly."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/vulns/',
            json={'rows': []},
            status=200
        )

        auth_client.get_vulnerabilities('test', confirmed=True)

        assert 'confirmed=true' in responses.calls[0].request.url

    @responses.activate
    def test_get_vulnerabilities_normalizes_fields(self, auth_client, config):
        """Alternative field names normalized."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/vulns/',
            json={
                'rows': [
                    {
                        '_id': 99,
                        'name': 'XSS',
                        'severity': 'medium',
                        'description': 'XSS via desc alternative',  # Not 'desc'
                        'parent': 5  # Alternative to host_id
                    }
                ]
            },
            status=200
        )

        result = auth_client.get_vulnerabilities('test')

        assert result[0]['id'] == 99
        assert result[0]['desc'] == 'XSS via desc alternative'
        assert result[0]['host_id'] == 5


# ─────────────────────────────────────────────────────────────────
# Service Query Tests
# ─────────────────────────────────────────────────────────────────

class TestGetServices:
    """Test get_services() method."""

    @responses.activate
    def test_get_services_host_filter(self, auth_client, config):
        """Host filter applied correctly."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/services/',
            json={
                'rows': [
                    {
                        'id': 1,
                        'name': 'ssh',
                        'port': 22,
                        'protocol': 'tcp',
                        'version': 'OpenSSH 8.9',
                        'host_id': 5,
                        'status': 'open'
                    }
                ]
            },
            status=200
        )

        result = auth_client.get_services('test', host_id=5)

        assert 'host_id=5' in responses.calls[0].request.url
        assert len(result) == 1
        assert result[0]['port'] == 22
        assert result[0]['name'] == 'ssh'

    @responses.activate
    def test_get_services_default_status(self, auth_client, config):
        """Missing status defaults to 'open'."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/services/',
            json={
                'rows': [
                    {'id': 1, 'name': 'http', 'port': 80, 'protocol': 'tcp'}
                ]
            },
            status=200
        )

        result = auth_client.get_services('test')

        assert result[0]['status'] == 'open'


# ─────────────────────────────────────────────────────────────────
# Workspace Tests
# ─────────────────────────────────────────────────────────────────

class TestWorkspaceManagement:
    """Test workspace management methods."""

    @responses.activate
    def test_create_workspace_success(self, auth_client, config):
        """Successful workspace creation returns details."""
        responses.add(
            responses.POST,
            f'{config.url}/_api/v3/ws/',
            json={'name': 'newworkspace', 'id': 42},
            status=201
        )

        result = auth_client.create_workspace('newworkspace', 'Test workspace')

        assert result['name'] == 'newworkspace'

    @responses.activate
    def test_create_workspace_already_exists(self, auth_client, config):
        """Duplicate workspace raises ValueError."""
        responses.add(
            responses.POST,
            f'{config.url}/_api/v3/ws/',
            json={'error': 'Workspace exists'},
            status=409
        )

        with pytest.raises(ValueError, match='already exists'):
            auth_client.create_workspace('existing')

    @responses.activate
    def test_create_workspace_invalid_name(self, auth_client, config):
        """Invalid name raises ValueError."""
        responses.add(
            responses.POST,
            f'{config.url}/_api/v3/ws/',
            json={'error': 'Invalid name'},
            status=400
        )

        with pytest.raises(ValueError, match='Invalid workspace name'):
            auth_client.create_workspace('invalid name!')

    @responses.activate
    def test_workspace_exists_true(self, auth_client, config):
        """Existing workspace returns True."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/existing/',
            json={'name': 'existing'},
            status=200
        )

        assert auth_client.workspace_exists('existing') is True

    @responses.activate
    def test_workspace_exists_false(self, auth_client, config):
        """Missing workspace returns False."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/missing/',
            json={'error': 'Not found'},
            status=404
        )

        assert auth_client.workspace_exists('missing') is False

    @responses.activate
    def test_get_workspace_stats(self, auth_client, config):
        """Workspace stats returned with normalized structure."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/',
            json={
                'name': 'test',
                'stats': {
                    'hosts': 10,
                    'services': 50,
                    'total_vulns': 25,
                    'critical_vulns': 2,
                    'high_vulns': 5,
                    'med_vulns': 10,
                    'low_vulns': 5,
                    'info_vulns': 3
                },
                'update_date': '2024-01-15T10:30:00'
            },
            status=200
        )

        result = auth_client.get_workspace_stats('test')

        assert result['hosts_count'] == 10
        assert result['services_count'] == 50
        assert result['vulns_count'] == 25
        assert result['vulns_by_severity']['critical'] == 2
        assert result['vulns_by_severity']['high'] == 5
        assert result['last_activity'] == '2024-01-15T10:30:00'

    @responses.activate
    def test_get_workspace_stats_alternate_fields(self, auth_client, config):
        """Alternate field names handled correctly."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/',
            json={
                'name': 'test',
                'hosts_count': 5,
                'services_count': 20,
                'vuln_count': 8,
                'last_activity': '2024-01-10'
            },
            status=200
        )

        result = auth_client.get_workspace_stats('test')

        assert result['hosts_count'] == 5
        assert result['vulns_count'] == 8


# ─────────────────────────────────────────────────────────────────
# Edge Cases
# ─────────────────────────────────────────────────────────────────

class TestEdgeCases:
    """Edge case and error handling tests."""

    def test_require_auth_raises_when_not_authenticated(self, client):
        """_require_auth raises when not authenticated."""
        with pytest.raises(RuntimeError, match='Not authenticated'):
            client._require_auth()

    @responses.activate
    def test_authenticated_property(self, client, config):
        """authenticated property reflects state correctly."""
        assert client.authenticated is False

        responses.add(
            responses.POST,
            f'{config.url}/_api/login',
            json={'status': 'ok'},
            status=200
        )
        client.authenticate()

        assert client.authenticated is True

    @responses.activate
    def test_list_response_format(self, auth_client, config):
        """Handle APIs that return list directly instead of {'rows': [...]}."""
        responses.add(
            responses.GET,
            f'{config.url}/_api/v3/ws/test/hosts/',
            json=[
                {'id': 1, 'ip': '10.0.0.1'}
            ],
            status=200
        )

        result = auth_client.get_hosts('test')

        assert len(result) == 1
        assert result[0]['ip'] == '10.0.0.1'
