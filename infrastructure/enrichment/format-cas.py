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
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import yaml


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
        """Format a vulnerability into CAS summary format."""
        return {
            'id': vuln.get('template_id', ''),
            'name': self._truncate(vuln.get('template_name', ''), 80),
            'severity': vuln.get('severity', 'unknown'),
            'host': vuln.get('host', ''),
            'matched_at': vuln.get('matched_at', ''),
            'cves': vuln.get('cves', [])[:3],
            'cvss': vuln.get('cvss_score', 0),
            'exploitable': bool(vuln.get('cve_enriched', {}).values() and
                               any(e.get('exploit_available') for e in vuln.get('cve_enriched', {}).values()))
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

    def _generate_attack_guidance(self, data: Dict) -> Dict:
        """Generate attack guidance from enriched data."""
        guidance = {
            'priority_targets': [],
            'quick_wins': [],
            'recommended_next': [],
            'tools_to_run': set()
        }

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
                    findings.append({
                        'type': 'vulnerability',
                        'severity': vuln.get('severity'),
                        'summary': f"{vuln.get('template_name', 'Unknown')} at {vuln.get('host', 'unknown')}",
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
        """Format enriched data into CAS structure."""
        # Extract metadata
        target = input_data.get('target', 'unknown')
        session_id = input_data.get('session_id', '')
        scan_type = input_data.get('scan_type', 'unknown')
        timestamp = input_data.get('timestamp', datetime.utcnow().isoformat())
        data = input_data.get('data', input_data)

        # Build CAS document
        cas = {
            'cas_version': '1.0',
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
                'critical_findings': 0,
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
            'enrichment_metadata': {},
            'raw_artifacts': []
        }

        # Process hosts
        if 'hosts' in data:
            for host in data['hosts'][:self.max_items_per_section]:
                cas['hosts'].append(self._format_host_summary(host))

        # Process vulnerabilities
        if 'vulnerabilities' in data:
            critical_count = 0
            for vuln in data['vulnerabilities'][:self.max_items_per_section]:
                formatted = self._format_vulnerability_summary(vuln)
                cas['vulnerabilities'].append(formatted)
                if formatted['severity'] in ['critical', 'high']:
                    critical_count += 1
            cas['summary']['critical_findings'] = critical_count

        # Process web services
        if 'web_services' in data:
            for service in data['web_services'][:self.max_items_per_section]:
                cas['web_services'].append(self._format_web_service_summary(service))

        # Process subdomains
        if 'subdomains' in data:
            for subdomain in data['subdomains'][:self.max_items_per_section]:
                cas['subdomains'].append(self._format_subdomain_summary(subdomain))

        # Process directories (gobuster findings)
        if 'findings' in data and data.get('type') == 'gobuster':
            for finding in data['findings'][:self.max_items_per_section]:
                cas['directories'].append({
                    'path': finding.get('path', ''),
                    'status': finding.get('status', 0),
                    'size': finding.get('size', 0),
                    'redirect': finding.get('redirect')
                })
            cas['summary']['directories_found'] = len(data['findings'])

        # Process nikto findings
        if 'findings' in data and data.get('type') == 'nikto':
            for finding in data['findings'][:self.max_items_per_section]:
                cas['nikto_findings'].append({
                    'path': finding.get('path', ''),
                    'osvdb': finding.get('osvdb'),
                    'severity': finding.get('severity', 'info'),
                    'description': self._truncate(finding.get('description', ''), 150)
                })

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
        for field in ['hosts', 'vulnerabilities', 'web_services', 'subdomains', 'directories', 'nikto_findings']:
            existing_items = existing.get(field, [])
            new_items = new.get(field, [])

            # Create lookup for existing items
            if field == 'hosts':
                key_func = lambda x: x.get('ip', '')
            elif field == 'vulnerabilities':
                key_func = lambda x: f"{x.get('id', '')}_{x.get('host', '')}"
            elif field == 'web_services':
                key_func = lambda x: x.get('url', '')
            elif field == 'directories':
                key_func = lambda x: x.get('path', '')
            elif field == 'nikto_findings':
                key_func = lambda x: f"{x.get('path', '')}_{x.get('osvdb', '')}"
            else:
                key_func = lambda x: x.get('host', '')

            existing_keys = {key_func(item) for item in existing_items}

            # Add new items that don't exist
            for item in new_items:
                if key_func(item) not in existing_keys:
                    existing_items.append(item)

            existing[field] = existing_items

        # Update summary
        existing['summary'] = {
            'hosts_discovered': len(existing.get('hosts', [])),
            'vulnerabilities_found': len(existing.get('vulnerabilities', [])),
            'web_services_found': len(existing.get('web_services', [])),
            'subdomains_found': len(existing.get('subdomains', [])),
            'directories_found': len(existing.get('directories', [])),
            'critical_findings': new['summary'].get('critical_findings', 0),
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
