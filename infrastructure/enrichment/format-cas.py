#!/usr/bin/env python3
"""
Agent Opulence - CAS (Context-Aware Summary) Formatter
======================================================
Formats enriched scan data into CAS YAML for agent consumption.

Usage: format-cas.py <output_path>
Input: JSON from stdin with enriched data
Output: CAS YAML file at output_path

CAS Schema:
- Hierarchical YAML structure
- Token-optimized for LLM context windows
- Includes attack priority guidance
- References raw artifacts

Reference: schemas/CAS_SCHEMA.md
"""

import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import yaml


# Web service names that should be included in web_services mapping
WEB_SERVICE_NAMES = {'http', 'https', 'http-proxy', 'https-proxy', 'http-alt'}


def format_facts_for_prompt(
    hosts: List[Dict],
    vulns: List[Dict],
    web_services: List[Dict]
) -> str:
    """Format CAS facts as YAML for the Gemini prompt.

    Limits data to maintain token efficiency while providing
    enough context for meaningful guidance generation.

    Args:
        hosts: List of CAS-formatted host dictionaries
        vulns: List of CAS-formatted vulnerability dictionaries
        web_services: List of CAS-formatted web service dictionaries

    Returns:
        YAML string suitable for prompt injection
    """
    facts = {
        'hosts': hosts[:10],  # Limit for token efficiency
        'vulnerabilities': vulns[:20],
        'web_services': web_services[:10]
    }
    return yaml.dump(facts, default_flow_style=False)


def generate_fallback_guidance(
    hosts: List[Dict],
    vulns: List[Dict],
    web_services: List[Dict]
) -> Dict:
    """Generate basic heuristic-based attack guidance when Gemini is unavailable.

    Provides severity-ranked targets and basic prioritization without
    AI-powered analysis. Flags output as heuristic-based so Dame knows
    the guidance is less sophisticated.

    Args:
        hosts: List of CAS-formatted host dictionaries
        vulns: List of CAS-formatted vulnerability dictionaries
        web_services: List of CAS-formatted web service dictionaries

    Returns:
        Dict with attack_guidance section containing heuristic-based recommendations
    """
    # Sort hosts by priority_score (descending)
    priority_targets = sorted(
        [{'host': h.get('ip'), 'score': h.get('priority_score', 0) or 0} for h in hosts],
        key=lambda x: x['score'] or 0,
        reverse=True
    )[:5]

    # Extract high-severity vulnerabilities as quick wins
    quick_wins = []
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    sorted_vulns = sorted(
        vulns,
        key=lambda v: severity_order.get(v.get('severity', 'info'), 5)
    )

    for vuln in sorted_vulns[:3]:
        if vuln.get('severity') in ('critical', 'high'):
            quick_wins.append({
                'target': f"{vuln.get('host', 'unknown')}:{vuln.get('port', '')}",
                'action': f"Investigate {vuln.get('name', 'vulnerability')}",
                'difficulty': 'medium',
                'expected_outcome': 'Potential exploitation'
            })

    return {
        'attack_guidance': {
            'priority_targets': priority_targets,
            'quick_wins': quick_wins,
            'recommended_commands': [],
            '_source': 'heuristic',
            '_note': 'AI guidance unavailable - basic severity ranking only'
        }
    }


def generate_attack_guidance(
    hosts: List[Dict],
    vulns: List[Dict],
    web_services: List[Dict]
) -> Dict:
    """Generate attack guidance via Gemini CLI.

    Calls gemini-cli non-interactively with CAS facts formatted as YAML.
    The prompt template at /app/prompts/attack_guidance.md instructs Gemini
    to analyze the reconnaissance data and output structured JSON with
    prioritized attack recommendations.

    Falls back to heuristic-based guidance if Gemini is unavailable or fails.

    Args:
        hosts: List of CAS-formatted host dictionaries
        vulns: List of CAS-formatted vulnerability dictionaries
        web_services: List of CAS-formatted web service dictionaries

    Returns:
        Dict with attack_guidance section containing AI or heuristic recommendations
    """
    # Build context from facts
    facts_yaml = format_facts_for_prompt(hosts, vulns, web_services)

    # Non-interactive gemini-cli call
    try:
        result = subprocess.run(
            ['gemini', '-p', '/app/prompts/attack_guidance.md', '--output-format', 'json'],
            input=facts_yaml,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            return generate_fallback_guidance(hosts, vulns, web_services)

        guidance = json.loads(result.stdout)
        guidance['_source'] = 'gemini'
        return {'attack_guidance': guidance}

    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return generate_fallback_guidance(hosts, vulns, web_services)


def estimate_cvss(severity: Optional[str]) -> float:
    """Estimate CVSS score from severity level.

    Args:
        severity: Severity string (critical, high, medium, low, info)

    Returns:
        Estimated CVSS score (0.0-10.0)
    """
    severity_cvss_map = {
        'critical': 9.5,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5,
        'info': 0.0,
        'informational': 0.0
    }
    if not severity:
        return 0.0
    return severity_cvss_map.get(severity.lower(), 0.0)


def assess_exploitability(vuln: Dict, cves: List[str]) -> str:
    """Assess exploitability of a vulnerability.

    Considers:
    - Presence of known CVEs (increases exploitability)
    - Confirmed status (indicates exploitability verified)
    - Severity level (critical/high more likely exploitable)
    - Tool that found it (certain tools indicate exploitability)

    Args:
        vuln: Faraday vulnerability dictionary
        cves: List of CVE identifiers extracted from refs

    Returns:
        Exploitability assessment: 'high', 'medium', 'low', or 'none'
    """
    score = 0

    # CVEs indicate known vulnerabilities with potential exploits
    if cves:
        score += 2
        # Multiple CVEs suggest well-documented vulnerability
        if len(cves) >= 3:
            score += 1

    # Confirmed vulnerabilities are more likely exploitable
    if vuln.get('confirmed', False):
        score += 2

    # Severity influences exploitability
    severity = vuln.get('severity', '').lower()
    if severity == 'critical':
        score += 3
    elif severity == 'high':
        score += 2
    elif severity == 'medium':
        score += 1

    # Certain tools indicate higher exploitability
    tool = vuln.get('tool', '').lower()
    high_confidence_tools = ['metasploit', 'exploit-db', 'nuclei', 'nessus']
    if any(t in tool for t in high_confidence_tools):
        score += 1

    # Map score to exploitability level
    if score >= 6:
        return 'high'
    elif score >= 3:
        return 'medium'
    elif score >= 1:
        return 'low'
    else:
        return 'none'


def process_faraday_vulnerabilities(
    vulns: List[Dict],
    hosts: Dict[int, Dict],
    services: Dict[int, Dict]
) -> List[Dict]:
    """Convert Faraday vulnerabilities to CAS format.

    Args:
        vulns: List of Faraday vulnerability dictionaries
        hosts: Lookup dict mapping host_id to host details
        services: Lookup dict mapping service_id to service details

    Returns:
        List of CAS-formatted vulnerability dictionaries sorted by severity
    """
    cas_vulns = []

    for vuln in vulns:
        # Extract CVEs from refs (strings starting with "CVE-")
        refs = vuln.get('refs', []) or []
        cves = [ref for ref in refs if isinstance(ref, str) and ref.startswith('CVE-')]
        other_refs = [ref for ref in refs if isinstance(ref, str) and not ref.startswith('CVE-')]

        # Look up host/service details
        host_id = vuln.get('host_id')
        service_id = vuln.get('service_id')
        host = hosts.get(host_id, {}) if host_id is not None else {}
        service = services.get(service_id, {}) if service_id is not None else {}

        # Get severity and normalize
        severity = vuln.get('severity', 'info')
        if severity:
            severity = severity.lower()
        else:
            severity = 'info'

        cas_vuln = {
            'name': vuln.get('name'),
            'severity': severity,
            'cvss': estimate_cvss(severity),
            'cves': cves,
            'description': vuln.get('desc'),
            'remediation': vuln.get('resolution'),
            'references': other_refs,
            'host': host.get('ip'),
            'port': service.get('port'),
            'service': service.get('name'),
            'confirmed': vuln.get('confirmed', False),
            'tool': vuln.get('tool'),
            'exploitability': assess_exploitability(vuln, cves)
        }

        cas_vulns.append(cas_vuln)

    # Sort by severity (critical > high > medium > low > info)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'informational': 5}
    cas_vulns.sort(key=lambda v: severity_order.get(v.get('severity', 'info'), 6))

    return cas_vulns


def detect_data_source(data: Dict) -> str:
    """Detect whether data came from custom parsers or Faraday.

    Args:
        data: Input data dictionary to analyze

    Returns:
        'faraday' if data originated from Faraday API
        'legacy' if data came from custom parsers (nmap, nuclei, etc.)
    """
    # Check for explicit Faraday source marker
    if data.get('source', '').startswith('faraday:'):
        return 'faraday'

    # Check for Faraday scan type
    if data.get('scan_type') == 'faraday':
        return 'faraday'

    return 'legacy'


# Critical services that increase priority score
CRITICAL_SERVICES = {
    'ssh': 2.0,      # Remote access - high value target
    'rdp': 2.5,      # Remote desktop - very high value
    'smb': 2.0,      # File sharing - lateral movement potential
    'ms-wbt-server': 2.5,  # RDP alternative name
    'microsoft-ds': 2.0,   # SMB alternative name
    'netbios-ssn': 1.5,    # NetBIOS session
    'http': 1.0,     # Web service
    'https': 1.0,    # Secure web
    'mysql': 1.5,    # Database
    'postgresql': 1.5,
    'mssql': 2.0,    # MS SQL - often misconfigured
    'oracle': 1.5,
    'ftp': 1.5,      # File transfer - often anonymous
    'telnet': 2.5,   # Plaintext remote access - critical
    'vnc': 2.0,      # Remote desktop
    'ldap': 1.5,     # Directory services
    'kerberos': 1.5, # Authentication
    'dns': 1.0,      # DNS
    'smtp': 1.0,     # Mail
    'snmp': 1.5,     # Often default community strings
    'nfs': 1.5,      # Network file system
    'rpc': 1.0,      # RPC services
}

# OS patterns that suggest older/vulnerable systems
LEGACY_OS_PATTERNS = [
    ('windows xp', 3.0),
    ('windows 2003', 2.5),
    ('windows 2000', 3.0),
    ('windows 7', 1.5),
    ('windows 2008', 2.0),
    ('windows server 2008', 2.0),
    ('windows vista', 2.0),
    ('ubuntu 14', 1.5),
    ('ubuntu 12', 2.0),
    ('centos 5', 2.5),
    ('centos 6', 2.0),
    ('debian 7', 2.0),
    ('debian 8', 1.5),
    ('linux 2.', 2.0),  # Old kernel
    ('linux 3.', 1.0),  # Older kernel
]


def calculate_host_priority(host: Dict) -> float:
    """Calculate priority score for a host based on attack potential.

    The priority score ranges from 0.0 to 10.0, where higher scores
    indicate higher priority targets for assessment.

    Factors considered:
    - Number of vulnerabilities (higher = more priority)
    - Critical services exposed (ssh, smb, rdp, databases)
    - OS type and age (legacy systems get higher priority)
    - Number of open ports (attack surface)

    Args:
        host: CAS-formatted host dictionary with:
            - vuln_count: Number of vulnerabilities
            - ports: List of port dictionaries
            - os: Operating system string

    Returns:
        float: Priority score from 0.0 to 10.0
    """
    import math
    score = 0.0

    # Factor 1: Vulnerability count (max 3.0 points)
    vuln_count = host.get('vuln_count', 0)
    if vuln_count > 0:
        # Logarithmic scaling: 1 vuln = 1.0, 5 vulns = 2.0, 10+ = 3.0
        vuln_score = min(3.0, 1.0 + math.log10(vuln_count + 1))
        score += vuln_score

    # Factor 2: Critical services (max 3.0 points)
    ports = host.get('ports', [])
    service_score = 0.0
    for port in ports:
        service_name = (port.get('service') or '').lower()
        if service_name in CRITICAL_SERVICES:
            service_score += CRITICAL_SERVICES[service_name]
    # Cap service score at 3.0
    score += min(3.0, service_score)

    # Factor 3: OS age/vulnerability (max 2.0 points)
    os_string = (host.get('os') or '').lower()
    os_score = 0.0
    for pattern, weight in LEGACY_OS_PATTERNS:
        if pattern in os_string:
            os_score = max(os_score, weight)
            break
    score += min(2.0, os_score)

    # Factor 4: Attack surface - number of open ports (max 2.0 points)
    open_ports = sum(1 for p in ports if p.get('state') == 'open')
    if open_ports > 0:
        # More ports = larger attack surface
        # 1-5 ports: 0.5, 6-10: 1.0, 11-20: 1.5, 20+: 2.0
        if open_ports <= 5:
            surface_score = 0.5
        elif open_ports <= 10:
            surface_score = 1.0
        elif open_ports <= 20:
            surface_score = 1.5
        else:
            surface_score = 2.0
        score += surface_score

    # Ensure score is within bounds
    return round(min(10.0, max(0.0, score)), 1)


def process_faraday_hosts(hosts: List[Dict]) -> List[Dict]:
    """Convert Faraday hosts to CAS format.

    Maps Faraday API host format to the CAS schema format used by
    Agent Opulence for attack planning and prioritization.

    Args:
        hosts: List of Faraday host dictionaries with keys:
            - id: Host ID (from Faraday)
            - ip: IP address
            - hostnames: List of hostname strings
            - os: Operating system string
            - mac: MAC address (optional)
            - services: List of service dicts
            - vulnerability_count or vuln_count: Number of vulns
            - credentials: List of credentials (optional)
            - notes: Notes string (optional)

    Returns:
        List of CAS-formatted host dictionaries with keys:
            - ip: IP address
            - hostnames: List of hostnames
            - os: Operating system
            - mac: MAC address
            - ports: List of port dicts (converted from services)
            - vuln_count: Vulnerability count
            - priority_score: Calculated attack priority (0.0-10.0)
    """
    cas_hosts = []

    for host in hosts:
        # Build base CAS host structure
        cas_host = {
            'ip': host.get('ip') or '',
            'hostnames': host.get('hostnames') or [],
            'os': host.get('os') or None,
            'mac': host.get('mac') or None,
            'ports': [],
            'vuln_count': host.get('vulnerability_count', host.get('vuln_count', 0)),
        }

        # Map Faraday services to CAS ports format
        for svc in host.get('services', []):
            port_entry = {
                'port': svc.get('port'),
                'protocol': svc.get('protocol', 'tcp'),
                'service': svc.get('name') or '',
                'version': svc.get('version') or None,
                'state': svc.get('status', 'open'),
            }
            cas_host['ports'].append(port_entry)

        # Calculate priority score based on host characteristics
        cas_host['priority_score'] = calculate_host_priority(cas_host)

        cas_hosts.append(cas_host)

    return cas_hosts


def process_faraday_services(
    services: List[Dict],
    hosts: Dict[int, Dict]
) -> List[Dict]:
    """Convert Faraday services to CAS web_services format.

    Filters to web services only (http, https, http-proxy, https-proxy, http-alt)
    and constructs properly formatted web service entries.

    Args:
        services: List of Faraday service dictionaries with keys:
            - id, name, port, protocol, version, status, host_id, summary
        hosts: Dictionary mapping host_id to host data (must include 'ip' key)

    Returns:
        List of CAS web_services entries with keys:
            - url, host, port, protocol, server, title, technologies, status_code
    """
    web_services = []

    for svc in services:
        # Only include web services
        if svc.get('name', '').lower() not in WEB_SERVICE_NAMES:
            continue

        host_id = svc.get('host_id')
        host = hosts.get(host_id, {}) if host_id is not None else {}
        ip = host.get('ip', 'unknown')
        port = svc.get('port')

        # Determine protocol - HTTPS if service name indicates SSL or port is 443
        is_ssl = svc.get('name', '').lower() in {'https', 'https-proxy'} or port == 443
        protocol = 'https' if is_ssl else 'http'

        web_svc = {
            'url': f'{protocol}://{ip}:{port}',
            'host': ip,
            'port': port,
            'protocol': protocol,
            'server': svc.get('version'),
            'title': '',
            'technologies': [],
            'status_code': None
        }

        web_services.append(web_svc)

    return web_services


def process_faraday_data(input_data: Dict) -> Dict:
    """
    Process Faraday-sourced data into CAS format.

    Args:
        input_data: Dict containing:
            - target: Target identifier
            - session_id: Session identifier
            - data: Dict with hosts, vulnerabilities, services, stats
            - source: 'faraday:{workspace}'
            - timestamp: ISO timestamp

    Returns:
        Complete CAS document dict
    """
    data = input_data.get('data', {})

    # Build lookup dicts for cross-referencing
    hosts_raw = data.get('hosts', [])
    vulns_raw = data.get('vulnerabilities', [])
    services_raw = data.get('services', [])
    stats = data.get('stats', {})

    hosts_by_id = {h.get('id'): h for h in hosts_raw if h.get('id') is not None}
    services_by_id = {s.get('id'): s for s in services_raw if s.get('id') is not None}

    # Process each data type using the mapper functions
    cas_hosts = process_faraday_hosts(hosts_raw)
    cas_vulns = process_faraday_vulnerabilities(vulns_raw, hosts_by_id, services_by_id)
    cas_web_services = process_faraday_services(services_raw, hosts_by_id)

    # Generate summary
    summary_data = generate_summary_from_faraday(stats, len(cas_web_services))

    # Generate attack guidance
    guidance = generate_attack_guidance(cas_hosts, cas_vulns, cas_web_services)

    # Helper to extract key findings
    def extract_key_findings(vulns, hosts):
        findings = []
        for vuln in vulns[:5]:
            if vuln.get('severity') in ('critical', 'high'):
                findings.append({
                    'type': 'vulnerability',
                    'severity': vuln.get('severity'),
                    'summary': vuln.get('name', '')[:100],
                    'host': vuln.get('host'),
                    'exploitable': vuln.get('exploitability') == 'high'
                })
        return findings

    # Separate vulns by severity for CAS structure
    critical_high_vulns = [v for v in cas_vulns if v.get('severity') in ['critical', 'high']]
    low_info_vulns = [v for v in cas_vulns if v.get('severity') in ['medium', 'low', 'info']]

    # Build final CAS document
    cas_doc = {
        'cas_version': '1.2',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'target': {
            'identifier': input_data.get('target'),
            'session_id': input_data.get('session_id'),
            'scan_types': ['faraday'],
            'source': input_data.get('source')
        },
        **summary_data,
        'key_findings': extract_key_findings(cas_vulns, cas_hosts),
        **guidance,
        'hosts': cas_hosts,
        'vulnerabilities': critical_high_vulns,
        'web_services': cas_web_services,
        'low_priority_vulns': low_info_vulns,
        'faraday_meta': {
            'workspace': input_data.get('source', '').replace('faraday:', ''),
            'imported_at': input_data.get('timestamp')
        }
    }

    return cas_doc


def assess_attack_surface(hosts: int, services: int, critical_vulns: int) -> str:
    """Assess overall attack surface based on discovered assets and vulnerabilities.

    Args:
        hosts: Number of discovered hosts
        services: Number of discovered services
        critical_vulns: Number of critical findings (critical + high severity)

    Returns:
        Attack surface level: 'critical', 'high', 'medium', or 'low'
    """
    if critical_vulns >= 5 or (services > 50 and critical_vulns > 0):
        return 'critical'
    elif critical_vulns >= 2 or services > 30:
        return 'high'
    elif critical_vulns >= 1 or services > 15:
        return 'medium'
    else:
        return 'low'


def generate_summary_from_faraday(stats: Dict, web_services_count: int) -> Dict:
    """Generate CAS summary section from Faraday workspace stats.

    Args:
        stats: Faraday workspace statistics containing:
            - hosts_count: Number of discovered hosts
            - services_count: Number of discovered services
            - vulns_count: Total vulnerability count
            - vulns_by_severity: Dict with critical/high/medium/low/info counts
            - last_activity: ISO timestamp of last activity
        web_services_count: Number of web services discovered

    Returns:
        Dict with 'summary' and 'severity_breakdown' sections for CAS document
    """
    vulns_by_severity = stats.get('vulns_by_severity', {})
    critical_findings = (
        vulns_by_severity.get('critical', 0) +
        vulns_by_severity.get('high', 0)
    )

    # Assess attack surface based on findings
    attack_surface = assess_attack_surface(
        hosts=stats.get('hosts_count', 0),
        services=stats.get('services_count', 0),
        critical_vulns=critical_findings
    )

    return {
        'summary': {
            'hosts_discovered': stats.get('hosts_count', 0),
            'services_found': stats.get('services_count', 0),
            'vulnerabilities_found': stats.get('vulns_count', 0),
            'critical_findings': critical_findings,
            'web_services_found': web_services_count,
            'attack_surface': attack_surface,
            'scan_timestamp': stats.get('last_activity')
        },
        'severity_breakdown': {
            'critical': vulns_by_severity.get('critical', 0),
            'high': vulns_by_severity.get('high', 0),
            'medium': vulns_by_severity.get('medium', 0),
            'low': vulns_by_severity.get('low', 0),
            'informational': vulns_by_severity.get('info', 0)
        }
    }


class CASFormatter:
    """Formats enriched data into CAS YAML documents."""

    def __init__(self):
        self.max_items_per_section = 20
        self.max_description_length = 200

    def _truncate(self, text: str, max_len: int = 200) -> str:
        """Truncate text to max length."""
        if not text:
            return ''
        text = str(text)
        if len(text) <= max_len:
            return text
        return text[:max_len - 3] + '...'

    def _format_host_summary(self, host: Dict) -> Dict:
        """Format a host into CAS summary format."""
        summary = {
            'ip': host.get('ip', ''),
            'hostname': host.get('hostname', ''),
            'status': host.get('status', 'unknown'),
            'os': None,
            'ports': [],
            'priority': host.get('enrichment_summary', {}).get('max_priority', 5),
            'vulns': host.get('enrichment_summary', {}).get('vulns_found', [])[:5]
        }

        # OS detection
        os_info = host.get('os')
        if os_info and os_info.get('matches'):
            best_match = os_info['matches'][0]
            summary['os'] = {
                'name': best_match.get('name', ''),
                'accuracy': best_match.get('accuracy', 0)
            }

        # Port summaries
        for port in host.get('ports', [])[:self.max_items_per_section]:
            port_summary = {
                'port': port.get('port'),
                'proto': port.get('protocol', 'tcp'),
                'service': port.get('service', ''),
                'version': self._truncate(port.get('version_string', ''), 50),
                'state': port.get('state', 'open')
            }

            # Include enrichment if available
            enrichment = port.get('enrichment', {})
            if enrichment:
                port_summary['priority'] = enrichment.get('priority_score', 5)
                port_summary['vulns'] = enrichment.get('known_vulns', [])[:3]
                port_summary['vectors'] = enrichment.get('attack_vectors', [])[:3]

            summary['ports'].append(port_summary)

        return summary

    def _format_vulnerability_summary(self, vuln: Dict) -> Dict:
        """Format a vulnerability into CAS summary format.

        Handles multiple source formats:
        - Nuclei: template_id, template_name, host, matched_at, cves
        - Nikto: osvdb, path, description, severity
        """
        # Detect source type
        is_nikto = 'description' in vuln and 'path' in vuln
        is_nuclei = 'template_id' in vuln or 'template_name' in vuln

        if is_nikto:
            return {
                'id': vuln.get('osvdb', ''),
                'name': self._truncate(vuln.get('description', ''), 80),
                'severity': vuln.get('severity', 'info'),
                'host': vuln.get('target', ''),  # From parser metadata
                'matched_at': vuln.get('path', ''),
                'cves': [],
                'cvss': 0,
                'exploitable': False,
                'source': 'nikto'
            }
        else:  # Nuclei or unknown
            return {
                'id': vuln.get('template_id', ''),
                'name': self._truncate(vuln.get('template_name', ''), 80),
                'severity': vuln.get('severity', 'unknown'),
                'host': vuln.get('host', ''),
                'matched_at': vuln.get('matched_at', ''),
                'cves': vuln.get('cves', [])[:3],
                'cvss': vuln.get('cvss_score', 0),
                'exploitable': bool(vuln.get('cve_enriched', {}).values() and
                                   any(e.get('exploit_available') for e in vuln.get('cve_enriched', {}).values())),
                'source': 'nuclei'
            }

    def _format_web_service_summary(self, service: Dict) -> Dict:
        """Format a web service into CAS summary format."""
        enrichment = service.get('enrichment', {})

        return {
            'url': service.get('url', ''),
            'status': service.get('status_code', 0),
            'title': self._truncate(service.get('title', ''), 60),
            'server': service.get('webserver', ''),
            'tech': service.get('technologies', [])[:5],
            'tls': bool(service.get('tls')),
            'cdn': service.get('cdn', {}).get('name') if service.get('cdn', {}).get('detected') else None,
            'waf': service.get('waf', {}).get('name') if service.get('waf', {}).get('detected') else None,
            'attack_surface': enrichment.get('attack_surface_score', 0),
            'issues': len(enrichment.get('security_issues', []))
        }

    def _format_subdomain_summary(self, subdomain: Dict) -> Dict:
        """Format a subdomain into CAS summary format."""
        domain_info = subdomain.get('domain_info', {})

        return {
            'host': subdomain.get('host', ''),
            'sources': subdomain.get('sources', [])[:3],
            'patterns': domain_info.get('patterns', [])[:3],
            'env': domain_info.get('environment', '')
        }

    def _format_smb_share(self, share: Dict) -> Dict:
        """Format an SMB share into CAS summary format."""
        return {
            'name': share.get('name', ''),
            'type': share.get('type', 'Disk'),
            'readable': share.get('readable', share.get('accessible', False)),
            'writable': share.get('writable', False),
            'permissions': share.get('permissions', ''),
            'comment': self._truncate(share.get('comment', ''), 80)
        }

    def _format_smb_enum_summary(self, enum_data: List[Dict]) -> Dict:
        """Format enum4linux/SMB enumeration data into CAS summary."""
        summary = {
            'users': [],
            'groups': [],
            'password_policy': {},
            'os_info': {},
            'sessions': []
        }

        for data in enum_data:
            # Merge users
            for user in data.get('users', []):
                user_summary = {
                    'username': user.get('username', ''),
                    'type': user.get('type', ''),
                    'sid': user.get('sid', '')
                }
                if user_summary not in summary['users']:
                    summary['users'].append(user_summary)

            # Merge groups
            for category, groups in data.get('groups', {}).items():
                for group in groups:
                    group_summary = {
                        'name': group.get('name', ''),
                        'category': category,
                        'rid': group.get('rid', '')
                    }
                    if group_summary not in summary['groups']:
                        summary['groups'].append(group_summary)

            # Take most recent password policy
            if data.get('password_policy'):
                summary['password_policy'] = data['password_policy']

            # Merge OS info
            if data.get('os_info'):
                summary['os_info'].update(data['os_info'])

            # Merge sessions
            for session in data.get('sessions', []):
                if session not in summary['sessions']:
                    summary['sessions'].append(session)

        # Truncate lists
        summary['users'] = summary['users'][:self.max_items_per_section]
        summary['groups'] = summary['groups'][:self.max_items_per_section]

        return summary

    def _format_autorecon_meta(self, data: Dict) -> Dict:
        """Format AutoRecon metadata into CAS format."""
        return {
            'scan_types': data.get('scan_types', []),
            'total_scan_files': len(data.get('raw_files', [])),
            'source': 'autorecon'
        }

    def _generate_attack_guidance(self, data: Dict) -> Dict:
        """Generate attack guidance from enriched data and manual commands."""
        guidance = {
            'priority_targets': [],
            'quick_wins': [],
            'recommended_next': [],
            'recommended_commands': [],
            'tools_to_run': set()
        }

        # From manual commands (AutoRecon _manual_commands.txt)
        # These are the primary source for attack recommendations
        if 'recommendations' in data and data['recommendations']:
            for rec in data['recommendations'][:15]:
                cmd_entry = {
                    'service': rec.get('service', ''),
                    'port': rec.get('port', 0),
                    'tool': rec.get('tool', ''),
                    'category': rec.get('category', ''),
                    'command': rec.get('command', ''),
                    'priority': rec.get('priority', 5)
                }
                guidance['recommended_commands'].append(cmd_entry)

                # Add high-priority commands to quick_wins
                if rec.get('priority', 5) <= 2:
                    tool = rec.get('tool', 'command')
                    service = rec.get('service', 'service')
                    guidance['quick_wins'].append(
                        f"{tool} {rec.get('category', '')} on {service}:{rec.get('port', '')}"
                    )

        # From host enrichment
        if 'attack_plan' in data:
            plan = data['attack_plan']
            for target in plan.get('priority_targets', [])[:5]:
                guidance['priority_targets'].append({
                    'target': target.get('target', ''),
                    'priority': target.get('priority', 5),
                    'reason': target.get('reason', '')
                })
            guidance['quick_wins'].extend(plan.get('recommended_first_steps', [])[:5])

        # From web enrichment
        if 'web_attack_plan' in data:
            web_plan = data['web_attack_plan']
            for target in web_plan.get('priority_targets', [])[:3]:
                if target not in guidance['priority_targets']:
                    guidance['priority_targets'].append({
                        'target': target.get('url', ''),
                        'priority': 7,
                        'reason': target.get('reason', '')
                    })
            for cmd in web_plan.get('vulnerability_scan_commands', [])[:5]:
                guidance['tools_to_run'].add(cmd)

        # From CVE enrichment
        if 'exploit_available' in data:
            for cve in data['exploit_available'][:3]:
                guidance['quick_wins'].append(f"Exploit available for {cve}")

        if 'cisa_kev_cves' in data:
            for cve in data['cisa_kev_cves'][:3]:
                guidance['quick_wins'].append(f"CISA KEV: {cve} - known exploited")

        # Convert set to list
        guidance['tools_to_run'] = list(guidance['tools_to_run'])[:10]

        # Generate recommended next steps
        guidance['recommended_next'] = self._generate_next_steps(data)

        # Sort recommended_commands by priority
        guidance['recommended_commands'].sort(key=lambda x: x.get('priority', 5))

        return guidance

    def _generate_next_steps(self, data: Dict) -> List[str]:
        """Generate recommended next steps based on findings."""
        steps = []

        # Check what data we have
        has_hosts = 'hosts' in data and data['hosts']
        has_vulns = 'vulnerabilities' in data and data['vulnerabilities']
        has_web = 'web_services' in data and data['web_services']
        has_subdomains = 'subdomains' in data and data['subdomains']

        if has_hosts:
            steps.append("Review high-priority services for exploitation")
            steps.append("Run targeted nuclei scans on discovered services")

        if has_vulns:
            critical_count = len([v for v in data['vulnerabilities'] if v.get('severity') == 'critical'])
            if critical_count > 0:
                steps.append(f"Investigate {critical_count} CRITICAL vulnerabilities")

        if has_web:
            steps.append("Test web applications for authentication bypass")
            steps.append("Check exposed admin panels and APIs")

        if has_subdomains:
            interesting = data.get('interesting', {})
            if interesting.get('development_environments'):
                steps.append("Focus on development/staging environments")
            if interesting.get('api_endpoints'):
                steps.append("Enumerate and test API endpoints")

        # Default steps if nothing specific
        if not steps:
            steps = [
                "Complete reconnaissance phase",
                "Run service-specific vulnerability scans",
                "Attempt default credential access"
            ]

        return steps[:5]

    def _build_key_findings(self, data: Dict) -> List[Dict]:
        """Extract key findings for executive summary."""
        findings = []

        # Critical vulnerabilities
        if 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                if vuln.get('severity') in ['critical', 'high']:
                    # Handle both nikto and nuclei formats
                    if 'description' in vuln:  # Nikto
                        summary = self._truncate(vuln.get('description', 'Unknown vulnerability'), 100)
                    else:  # Nuclei
                        summary = f"{vuln.get('template_name', 'Unknown')} at {vuln.get('host', 'unknown')}"

                    findings.append({
                        'type': 'vulnerability',
                        'severity': vuln.get('severity'),
                        'summary': summary,
                        'cves': vuln.get('cves', [])[:2]
                    })

        # Exploitable CVEs
        if 'exploit_available' in data:
            for cve in data['exploit_available'][:5]:
                cve_detail = data.get('cve_details', {}).get(cve, {})
                findings.append({
                    'type': 'exploitable_cve',
                    'severity': 'high',
                    'summary': f"Exploit available: {cve}",
                    'cvss': cve_detail.get('cvss_v3_score', 0)
                })

        # High-value services
        if 'hosts' in data:
            for host in data['hosts']:
                for port in host.get('ports', []):
                    enrichment = port.get('enrichment', {})
                    if enrichment.get('priority_score', 0) >= 8:
                        findings.append({
                            'type': 'high_value_service',
                            'severity': 'medium',
                            'summary': f"{port.get('service', 'unknown')} on {host.get('ip', '')}:{port.get('port', '')}",
                            'vectors': enrichment.get('attack_vectors', [])[:2]
                        })

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 5))

        return findings[:15]

    def format_cas(self, input_data: Dict) -> Dict:
        """Format enriched data into CAS structure.

        Routes to appropriate processor based on data source:
        - Faraday data: process_faraday_data() for API-sourced data
        - Legacy data: _process_legacy_data() for custom parser data
        """
        # Detect data source and route to appropriate processor
        source = detect_data_source(input_data)

        if source == 'faraday':
            return process_faraday_data(input_data)

        # Legacy processing continues below
        return self._process_legacy_data(input_data)

    def _process_legacy_data(self, input_data: Dict) -> Dict:
        """Process legacy parser data into CAS structure.

        Handles data from custom parsers: nmap, nuclei, nikto, etc.
        """
        # Extract metadata
        target = input_data.get('target', 'unknown')
        session_id = input_data.get('session_id', '')
        scan_type = input_data.get('scan_type', 'unknown')
        timestamp = input_data.get('timestamp', datetime.utcnow().isoformat())
        data = input_data.get('data', input_data)

        # Build CAS document
        cas = {
            'cas_version': '1.1',
            'generated_at': datetime.utcnow().isoformat(),
            'target': {
                'identifier': target,
                'session_id': session_id,
                'scan_types': [scan_type] if scan_type else []
            },
            'summary': {
                'hosts_discovered': len(data.get('hosts', [])),
                'vulnerabilities_found': len(data.get('vulnerabilities', [])),
                'web_services_found': len(data.get('web_services', [])),
                'subdomains_found': len(data.get('subdomains', [])),
                'directories_found': 0,
                'smb_shares_found': len(data.get('smb_shares', [])),
                'smb_users_found': 0,
                'critical_findings': 0,
                'low_priority_vulns_count': 0,
                'exploitable_cves': len(data.get('exploit_available', []))
            },
            'key_findings': [],
            'attack_guidance': {},
            'hosts': [],
            'vulnerabilities': [],
            'web_services': [],
            'subdomains': [],
            'directories': [],
            'nikto_findings': [],
            'smb_shares': [],
            'smb_enum': {},
            'ssh_info': [],
            'technologies': [],
            'autorecon_meta': {},
            'enrichment_metadata': {},
            'raw_artifacts': [],
            'low_priority_vulns': []  # medium/low/info - available on request
        }

        # Process hosts - deduplicate by IP
        if 'hosts' in data:
            seen_ips = set()
            for host in data['hosts'][:self.max_items_per_section]:
                ip = host.get('ip', '')
                if ip and ip not in seen_ips:
                    cas['hosts'].append(self._format_host_summary(host))
                    seen_ips.add(ip)

        # Process vulnerabilities - split by severity
        # critical/high go to main vulnerabilities list (immediate attention)
        # medium/low/info go to low_priority_vulns (available on request)
        HIGH_PRIORITY_SEVERITIES = {'critical', 'high'}
        if 'vulnerabilities' in data:
            critical_count = 0
            low_priority_count = 0
            for vuln in data['vulnerabilities'][:self.max_items_per_section * 2]:  # Allow more since we're splitting
                formatted = self._format_vulnerability_summary(vuln)
                if formatted['severity'] in HIGH_PRIORITY_SEVERITIES:
                    cas['vulnerabilities'].append(formatted)
                    critical_count += 1
                else:
                    cas['low_priority_vulns'].append(formatted)
                    low_priority_count += 1
            cas['summary']['critical_findings'] = critical_count
            cas['summary']['low_priority_vulns_count'] = low_priority_count

        # Process web services
        if 'web_services' in data:
            for service in data['web_services'][:self.max_items_per_section]:
                cas['web_services'].append(self._format_web_service_summary(service))

        # Process subdomains
        if 'subdomains' in data:
            for subdomain in data['subdomains'][:self.max_items_per_section]:
                cas['subdomains'].append(self._format_subdomain_summary(subdomain))

        # Process directories (gobuster/feroxbuster findings)
        # Handle both direct findings (gobuster) and merged directories (autorecon)
        directories_data = data.get('directories', [])
        if not directories_data and 'findings' in data and data.get('type') in ('gobuster', 'feroxbuster'):
            directories_data = data['findings']

        for finding in directories_data[:self.max_items_per_section]:
            cas['directories'].append({
                'path': finding.get('path', ''),
                'status': finding.get('status', 0),
                'size': finding.get('size', 0),
                'redirect': finding.get('redirect'),
                'interesting': finding.get('path', '') in data.get('stats', {}).get('interesting', [])
            })
        cas['summary']['directories_found'] = len(directories_data)

        # Process nikto findings
        if 'findings' in data and data.get('type') == 'nikto':
            for finding in data['findings'][:self.max_items_per_section]:
                cas['nikto_findings'].append({
                    'path': finding.get('path', ''),
                    'osvdb': finding.get('osvdb'),
                    'severity': finding.get('severity', 'info'),
                    'description': self._truncate(finding.get('description', ''), 150)
                })

        # Process SMB shares (from smbmap/enum4linux)
        if 'smb_shares' in data:
            for share in data['smb_shares'][:self.max_items_per_section]:
                cas['smb_shares'].append(self._format_smb_share(share))

        # Process SMB enumeration data (from enum4linux)
        if 'smb_enum' in data and data['smb_enum']:
            cas['smb_enum'] = self._format_smb_enum_summary(data['smb_enum'])
            # Update summary with user count
            cas['summary']['smb_users_found'] = len(cas['smb_enum'].get('users', []))

        # Process SSH info (from nmap SSH scripts)
        if 'ssh_info' in data and data['ssh_info']:
            for ssh in data['ssh_info'][:self.max_items_per_section]:
                cas['ssh_info'].append({
                    'host': ssh.get('host', ''),
                    'port': ssh.get('port', 22),
                    'auth_methods': ssh.get('auth_methods', []),
                    'host_keys': ssh.get('host_keys', [])[:3],  # Limit keys
                    'banner': ssh.get('banner', '')
                })

        # Process technologies (from whatweb)
        if 'technologies' in data and data['technologies']:
            for tech in data['technologies'][:self.max_items_per_section]:
                cas['technologies'].append({
                    'name': tech.get('name', ''),
                    'version': tech.get('version'),
                    'category': tech.get('category', '')
                })

        # Process AutoRecon metadata
        if data.get('type') == 'autorecon':
            cas['autorecon_meta'] = self._format_autorecon_meta(data)
            # Update scan types from AutoRecon
            if 'scan_types' in data:
                cas['target']['scan_types'] = data['scan_types']

        # Generate key findings
        cas['key_findings'] = self._build_key_findings(data)

        # Generate attack guidance
        cas['attack_guidance'] = self._generate_attack_guidance(data)

        # Include enrichment metadata
        if 'enrichment' in data:
            cas['enrichment_metadata'] = {
                'cve_enrichment': data['enrichment'].get('cve', {}),
                'service_enrichment': data['enrichment'].get('services', {}),
                'web_enrichment': data['enrichment'].get('web', {})
            }

        # Track raw artifacts
        if 'raw_file' in data:
            cas['raw_artifacts'].append(data['raw_file'])
        if input_data.get('source_file'):
            cas['raw_artifacts'].append(input_data['source_file'])

        return cas

    def write_cas(self, cas_data: Dict, output_path: Path):
        """Write CAS document to YAML file."""
        # Custom YAML representer for cleaner output
        def str_representer(dumper, data):
            if '\n' in data:
                return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
            return dumper.represent_scalar('tag:yaml.org,2002:str', data)

        yaml.add_representer(str, str_representer)

        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Check if file exists and merge
        if output_path.exists():
            try:
                with open(output_path, 'r') as f:
                    existing = yaml.safe_load(f) or {}
                cas_data = self._merge_cas(existing, cas_data)
            except Exception:
                pass

        # Write YAML
        with open(output_path, 'w') as f:
            yaml.dump(cas_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    def _merge_cas(self, existing: Dict, new: Dict) -> Dict:
        """Merge new CAS data into existing document."""
        # Update timestamp
        existing['generated_at'] = new['generated_at']

        # Merge scan types
        existing_types = set(existing.get('target', {}).get('scan_types', []))
        new_types = set(new.get('target', {}).get('scan_types', []))
        existing.setdefault('target', {})['scan_types'] = list(existing_types | new_types)

        # Merge lists (deduplicate by key fields)
        for field in ['hosts', 'vulnerabilities', 'low_priority_vulns', 'web_services', 'subdomains', 'directories', 'nikto_findings', 'smb_shares', 'ssh_info', 'technologies']:
            existing_items = existing.get(field, [])
            new_items = new.get(field, [])

            # Create lookup for existing items
            if field == 'hosts':
                key_func = lambda x: x.get('ip', '')
            elif field in ('vulnerabilities', 'low_priority_vulns'):
                key_func = lambda x: f"{x.get('id', '')}_{x.get('host', '')}_{x.get('matched_at', '')}"
            elif field == 'web_services':
                key_func = lambda x: x.get('url', '')
            elif field == 'directories':
                key_func = lambda x: x.get('path', '')
            elif field == 'nikto_findings':
                key_func = lambda x: f"{x.get('path', '')}_{x.get('osvdb', '')}"
            elif field == 'smb_shares':
                key_func = lambda x: x.get('name', '')
            elif field == 'ssh_info':
                key_func = lambda x: f"{x.get('host', '')}:{x.get('port', 22)}"
            elif field == 'technologies':
                key_func = lambda x: x.get('name', '')
            else:
                key_func = lambda x: x.get('host', '')

            existing_keys = {key_func(item) for item in existing_items}

            # Add new items that don't exist
            for item in new_items:
                if key_func(item) not in existing_keys:
                    existing_items.append(item)

            existing[field] = existing_items

        # Merge SMB enumeration data
        if new.get('smb_enum'):
            existing_smb = existing.get('smb_enum', {})
            new_smb = new.get('smb_enum', {})

            # Merge users
            existing_users = existing_smb.get('users', [])
            for user in new_smb.get('users', []):
                if user not in existing_users:
                    existing_users.append(user)
            existing_smb['users'] = existing_users

            # Merge groups
            existing_groups = existing_smb.get('groups', [])
            for group in new_smb.get('groups', []):
                if group not in existing_groups:
                    existing_groups.append(group)
            existing_smb['groups'] = existing_groups

            # Update password policy (take newest)
            if new_smb.get('password_policy'):
                existing_smb['password_policy'] = new_smb['password_policy']

            # Merge OS info
            if new_smb.get('os_info'):
                existing_smb.setdefault('os_info', {}).update(new_smb['os_info'])

            existing['smb_enum'] = existing_smb

        # Merge AutoRecon metadata
        if new.get('autorecon_meta'):
            existing['autorecon_meta'] = new['autorecon_meta']

        # Update summary
        high_priority_count = len(existing.get('vulnerabilities', []))
        low_priority_count = len(existing.get('low_priority_vulns', []))
        existing['summary'] = {
            'hosts_discovered': len(existing.get('hosts', [])),
            'vulnerabilities_found': high_priority_count + low_priority_count,  # Total count
            'web_services_found': len(existing.get('web_services', [])),
            'subdomains_found': len(existing.get('subdomains', [])),
            'directories_found': len(existing.get('directories', [])),
            'smb_shares_found': len(existing.get('smb_shares', [])),
            'smb_users_found': len(existing.get('smb_enum', {}).get('users', [])),
            'critical_findings': high_priority_count,  # Critical/high only
            'low_priority_vulns_count': low_priority_count,  # Medium/low/info
            'exploitable_cves': new['summary'].get('exploitable_cves', 0)
        }

        # Merge key findings (keep unique)
        existing_findings = existing.get('key_findings', [])
        new_findings = new.get('key_findings', [])
        finding_summaries = {f.get('summary', '') for f in existing_findings}

        for finding in new_findings:
            if finding.get('summary', '') not in finding_summaries:
                existing_findings.append(finding)

        existing['key_findings'] = existing_findings[:15]

        # Update attack guidance
        existing['attack_guidance'] = new.get('attack_guidance', {})

        # Merge enrichment metadata
        existing['enrichment_metadata'] = new.get('enrichment_metadata', {})

        # Merge raw artifacts
        existing_artifacts = set(existing.get('raw_artifacts', []))
        new_artifacts = set(new.get('raw_artifacts', []))
        existing['raw_artifacts'] = list(existing_artifacts | new_artifacts)

        return existing


def main():
    parser = argparse.ArgumentParser(description='Format enriched data as CAS YAML')
    parser.add_argument('output', type=Path, help='Output path for CAS YAML')
    args = parser.parse_args()

    # Read input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    # Format and write CAS
    formatter = CASFormatter()
    cas_data = formatter.format_cas(input_data)
    formatter.write_cas(cas_data, args.output)

    print(f"CAS document written to: {args.output}")


if __name__ == '__main__':
    main()
