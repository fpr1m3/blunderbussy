#!/usr/bin/env python3
"""
Faraday API Client
==================
REST client for Faraday vulnerability management platform.
Replaces manual parser execution with Faraday's 80+ built-in plugins.

Usage:
    config = FaradayConfig(
        url='http://faraday:5985',
        username='faraday',
        password='changeme'
    )
    client = FaradayClient(config)
    client.authenticate()
    client.upload_report('workspace', Path('/path/to/nmap.xml'))
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log
)

logger = logging.getLogger('faraday-client')


# Content types for upload_report
CONTENT_TYPES: Dict[str, str] = {
    '.xml': 'application/xml',
    '.json': 'application/json',
    '.jsonl': 'application/x-ndjson',
    '.txt': 'text/plain',
    '.html': 'text/html',
}


@dataclass
class FaradayConfig:
    """Faraday connection configuration."""
    url: str
    username: str
    password: str
    verify_ssl: bool = True
    timeout: int = 30


class FaradayClient:
    """
    REST API client for Faraday vulnerability management platform.

    Handles authentication, session management, and API calls for:
    - Uploading scan reports (auto-parsed by Faraday's plugin system)
    - Querying hosts, services, and vulnerabilities
    - Managing workspaces

    Attributes:
        config: FaradayConfig with connection details
        session: requests.Session for persistent connections
    """

    def __init__(self, config: FaradayConfig):
        """
        Initialize the Faraday client.

        Args:
            config: FaradayConfig with url, username, password
        """
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self._csrf_token: Optional[str] = None
        self._authenticated = False

        logger.debug(f"FaradayClient initialized for {config.url}")

    def _require_auth(self) -> None:
        """Raise RuntimeError if not authenticated."""
        if not self._authenticated:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout)),
        before_sleep=before_sleep_log(logger, logging.WARNING)
    )
    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> requests.Response:
        """
        Make HTTP request with automatic retry on transient failures.

        Retries up to 3 times with exponential backoff (2s, 4s, 8s) on:
        - Connection errors
        - Timeouts

        Does NOT retry on 4xx client errors.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (e.g., '/_api/v3/ws/')
            **kwargs: Passed to requests

        Returns:
            requests.Response object
        """
        url = f"{self.config.url}{endpoint}"
        kwargs.setdefault('timeout', self.config.timeout)

        response = self.session.request(method, url, **kwargs)
        return response

    @property
    def authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self._authenticated

    # ─────────────────────────────────────────────────────────────────
    # Authentication (blunderbussy-eh7)
    # ─────────────────────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """
        Authenticate with Faraday server and obtain CSRF token.

        Returns:
            bool: True if authentication successful, False otherwise.

        Raises:
            requests.RequestException: On network errors.
        """
        url = f"{self.config.url}/_api/login"
        payload = {
            "email": self.config.username,
            "password": self.config.password
        }

        try:
            response = self.session.post(
                url,
                json=payload,
                timeout=self.config.timeout
            )

            if response.status_code == 401:
                logger.warning("Authentication failed: invalid credentials")
                self._authenticated = False
                return False

            response.raise_for_status()

            # Extract CSRF token from cookies (Flask-JWT-Extended pattern)
            csrf_token = self.session.cookies.get('csrf_access_token')
            if csrf_token:
                self._csrf_token = csrf_token
                self.session.headers['X-CSRF-Token'] = csrf_token
                logger.debug("CSRF token extracted from cookies")
            else:
                # Fallback: check response JSON
                try:
                    data = response.json()
                    if 'csrf_token' in data:
                        self._csrf_token = data['csrf_token']
                        self.session.headers['X-CSRF-Token'] = data['csrf_token']
                        logger.debug("CSRF token extracted from response body")
                except ValueError:
                    pass

            self._authenticated = True
            logger.info(f"Authenticated with Faraday at {self.config.url}")
            return True

        except requests.Timeout:
            logger.error(f"Authentication timeout after {self.config.timeout}s")
            raise
        except requests.ConnectionError as e:
            logger.error(f"Connection error during authentication: {e}")
            raise
        except requests.HTTPError as e:
            logger.error(f"HTTP error during authentication: {e}")
            self._authenticated = False
            return False

    # ─────────────────────────────────────────────────────────────────
    # Report Upload (blunderbussy-3yr)
    # ─────────────────────────────────────────────────────────────────

    def upload_report(
        self,
        workspace: str,
        file_path: Path,
        ignore_info: bool = False,
        dns_resolution: bool = True
    ) -> Dict[str, Any]:
        """
        Upload a scan report to Faraday for automatic parsing.

        Faraday auto-detects tool format via its plugin system.
        Supported: nmap, nuclei, nikto, whatweb, httpx, burp, nessus, etc.

        Args:
            workspace: Target workspace name
            file_path: Path to scan report file
            ignore_info: Skip informational findings
            dns_resolution: Resolve hostnames to IPs

        Returns:
            dict with keys:
                - command_id: Processing command ID
                - vulnerabilities: Count of vulns imported
                - hosts: Count of hosts discovered

        Raises:
            FileNotFoundError: If file_path doesn't exist
            ValueError: If workspace doesn't exist
            RuntimeError: If upload fails
        """
        self._require_auth()

        if not file_path.exists():
            raise FileNotFoundError(f"Report file not found: {file_path}")

        # Detect content type from extension
        content_type = CONTENT_TYPES.get(file_path.suffix.lower(), 'application/octet-stream')

        url = f"{self.config.url}/_api/v3/ws/{workspace}/upload_report/"

        with open(file_path, 'rb') as f:
            files = {
                'file': (file_path.name, f, content_type)
            }
            data = {
                'ignore_info': str(ignore_info).lower(),
                'resolve_hostname': str(dns_resolution).lower()
            }

            response = self.session.post(
                url,
                files=files,
                data=data,
                timeout=self.config.timeout * 2  # Uploads may take longer
            )

        if response.status_code == 404:
            raise ValueError(f"Workspace not found: {workspace}")

        if response.status_code not in (200, 201):
            raise RuntimeError(f"Upload failed: {response.status_code} {response.text}")

        result = response.json()
        logger.info(f"Uploaded {file_path.name} to {workspace}: {result}")

        return {
            'command_id': result.get('command_id'),
            'vulnerabilities': result.get('vulns_count', 0),
            'hosts': result.get('hosts_count', 0)
        }

    # ─────────────────────────────────────────────────────────────────
    # Host Queries (blunderbussy-1g3)
    # ─────────────────────────────────────────────────────────────────

    def get_hosts(
        self,
        workspace: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get all hosts in a workspace.

        Args:
            workspace: Workspace name
            limit: Maximum hosts to return
            offset: Pagination offset

        Returns:
            List of host dictionaries with keys:
                - id: Host ID
                - ip: IP address
                - hostnames: List of hostnames
                - os: Detected OS
                - services: List of service dicts
                - vuln_count: Vulnerability count
        """
        self._require_auth()

        url = f"{self.config.url}/_api/v3/ws/{workspace}/hosts/"
        params = {'limit': limit, 'offset': offset}

        response = self.session.get(url, params=params, timeout=self.config.timeout)
        response.raise_for_status()

        data = response.json()
        rows = data.get('rows', data) if isinstance(data, dict) else data

        return [
            {
                'id': h.get('id') or h.get('_id'),
                'ip': h.get('ip'),
                'hostnames': h.get('hostnames', []),
                'os': h.get('os'),
                'services': h.get('services', []),
                'vuln_count': h.get('vulnerability_count', h.get('vuln_count', 0))
            }
            for h in rows
        ]

    # ─────────────────────────────────────────────────────────────────
    # Vulnerability Queries (blunderbussy-cdm)
    # ─────────────────────────────────────────────────────────────────

    def get_vulnerabilities(
        self,
        workspace: str,
        severity: Optional[List[str]] = None,
        confirmed: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities in a workspace.

        Args:
            workspace: Workspace name
            severity: Filter by severity ['critical', 'high', 'medium', 'low', 'info']
            confirmed: Filter by confirmed status
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of vulnerability dictionaries with keys:
                - id: Vuln ID
                - name: Vulnerability name
                - severity: Severity level
                - desc: Description
                - resolution: Remediation steps
                - refs: Reference URLs
                - cve: CVE IDs (if applicable)
                - host_id: Associated host
                - service_id: Associated service
                - confirmed: Confirmation status
        """
        self._require_auth()

        url = f"{self.config.url}/_api/v3/ws/{workspace}/vulns/"
        params: Dict[str, Any] = {'limit': limit, 'offset': offset}

        if severity:
            params['severity'] = ','.join(severity)
        if confirmed is not None:
            params['confirmed'] = str(confirmed).lower()

        response = self.session.get(url, params=params, timeout=self.config.timeout)
        response.raise_for_status()

        data = response.json()
        rows = data.get('rows', data) if isinstance(data, dict) else data

        return [
            {
                'id': v.get('id') or v.get('_id'),
                'name': v.get('name'),
                'severity': v.get('severity'),
                'desc': v.get('desc') or v.get('description'),
                'resolution': v.get('resolution'),
                'refs': v.get('refs', []),
                'cve': v.get('cve', []),
                'host_id': v.get('host_id') or v.get('parent'),
                'service_id': v.get('service_id'),
                'confirmed': v.get('confirmed', False)
            }
            for v in rows
        ]

    # ─────────────────────────────────────────────────────────────────
    # Service Queries (blunderbussy-xzw)
    # ─────────────────────────────────────────────────────────────────

    def get_services(
        self,
        workspace: str,
        host_id: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get services in a workspace, optionally filtered by host.

        Args:
            workspace: Workspace name
            host_id: Optional host ID to filter by
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of service dictionaries with keys:
                - id: Service ID
                - name: Service name (http, ssh, etc.)
                - port: Port number
                - protocol: tcp/udp
                - version: Version string
                - host_id: Associated host
                - status: open/closed/filtered
        """
        self._require_auth()

        url = f"{self.config.url}/_api/v3/ws/{workspace}/services/"
        params: Dict[str, Any] = {'limit': limit, 'offset': offset}

        if host_id is not None:
            params['host_id'] = host_id

        response = self.session.get(url, params=params, timeout=self.config.timeout)
        response.raise_for_status()

        data = response.json()
        rows = data.get('rows', data) if isinstance(data, dict) else data

        return [
            {
                'id': s.get('id') or s.get('_id'),
                'name': s.get('name'),
                'port': s.get('port'),
                'protocol': s.get('protocol'),
                'version': s.get('version'),
                'host_id': s.get('host_id') or s.get('parent'),
                'status': s.get('status', 'open')
            }
            for s in rows
        ]

    # ─────────────────────────────────────────────────────────────────
    # Workspace Management (blunderbussy-c3c, blunderbussy-ibv, blunderbussy-514)
    # ─────────────────────────────────────────────────────────────────

    def workspace_exists(self, name: str) -> bool:
        """
        Check if a workspace exists.

        Args:
            name: Workspace name

        Returns:
            bool: True if workspace exists
        """
        self._require_auth()

        url = f"{self.config.url}/_api/v3/ws/{name}/"
        response = self.session.get(url, timeout=self.config.timeout)

        if response.status_code == 404:
            return False

        response.raise_for_status()
        return True

    def create_workspace(
        self,
        name: str,
        description: str = ''
    ) -> Dict[str, Any]:
        """
        Create a new workspace.

        Args:
            name: Workspace name (alphanumeric, underscores)
            description: Optional description

        Returns:
            dict with created workspace details

        Raises:
            ValueError: If workspace name invalid or exists
        """
        self._require_auth()

        url = f"{self.config.url}/_api/v3/ws/"
        payload = {
            'name': name,
            'description': description
        }

        response = self.session.post(
            url,
            json=payload,
            timeout=self.config.timeout
        )

        if response.status_code == 409:
            raise ValueError(f"Workspace already exists: {name}")

        if response.status_code == 400:
            raise ValueError(f"Invalid workspace name: {name}")

        response.raise_for_status()

        result = response.json()
        logger.info(f"Created workspace: {name}")
        return result

    def get_workspace_stats(self, workspace: str) -> Dict[str, Any]:
        """
        Get summary statistics for a workspace.

        Args:
            workspace: Workspace name

        Returns:
            dict with keys:
                - hosts_count: Total hosts
                - services_count: Total services
                - vulns_count: Total vulnerabilities
                - vulns_by_severity: {critical: N, high: N, ...}
                - last_activity: Timestamp of last change
        """
        self._require_auth()

        url = f"{self.config.url}/_api/v3/ws/{workspace}/"
        response = self.session.get(url, timeout=self.config.timeout)
        response.raise_for_status()

        data = response.json()

        return {
            'hosts_count': data.get('stats', {}).get('hosts', data.get('hosts_count', 0)),
            'services_count': data.get('stats', {}).get('services', data.get('services_count', 0)),
            'vulns_count': data.get('stats', {}).get('total_vulns', data.get('vuln_count', 0)),
            'vulns_by_severity': {
                'critical': data.get('stats', {}).get('critical_vulns', 0),
                'high': data.get('stats', {}).get('high_vulns', 0),
                'medium': data.get('stats', {}).get('med_vulns', 0),
                'low': data.get('stats', {}).get('low_vulns', 0),
                'info': data.get('stats', {}).get('info_vulns', 0),
            },
            'last_activity': data.get('update_date') or data.get('last_activity')
        }
