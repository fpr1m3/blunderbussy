#!/usr/bin/env python3
"""
Agent Opulence - Manifest Update Script
=======================================
Updates the global manifest with new scan findings and key findings extraction.

Usage: update-manifest.py
Input: JSON from stdin with scan metadata and enriched data
Output: Updated manifest at /artifacts/manifest.yaml

Manifest Schema:
- Session tracking
- Target inventory
- Key findings aggregation
- Scan history
- Attack progress tracking

Reference: schemas/MANIFEST_SCHEMA.md
"""

import sys
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import yaml
import fcntl


# Configuration
MANIFEST_PATH = Path(os.environ.get('MANIFEST_PATH', '/artifacts/manifest.yaml'))
LOCK_PATH = Path('/artifacts/.manifest.lock')


class ManifestManager:
    """Manages the global manifest document."""

    def __init__(self, manifest_path: Path = MANIFEST_PATH):
        self.manifest_path = manifest_path
        self.lock_path = LOCK_PATH

    def _acquire_lock(self):
        """Acquire file lock for manifest updates."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_file = open(self.lock_path, 'w')
        fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX)

    def _release_lock(self):
        """Release file lock."""
        if hasattr(self, 'lock_file'):
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            self.lock_file.close()

    def _load_manifest(self) -> Dict:
        """Load existing manifest or create new one."""
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path, 'r') as f:
                    manifest = yaml.safe_load(f) or {}
                    return manifest
            except Exception:
                pass

        # Default manifest structure
        return {
            'manifest_version': '1.0',
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'sessions': {},
            'targets': {},
            'key_findings': [],
            'scan_history': [],
            'attack_progress': {
                'phase': 'reconnaissance',
                'completed_steps': [],
                'next_steps': []
            },
            'statistics': {
                'total_scans': 0,
                'total_targets': 0,
                'total_hosts': 0,
                'total_vulnerabilities': 0,
                'critical_findings': 0,
                'exploitable_cves': 0
            }
        }

    def _save_manifest(self, manifest: Dict):
        """Save manifest to disk."""
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.manifest_path, 'w') as f:
            yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    def _extract_key_findings(self, enriched_data: Dict) -> List[Dict]:
        """Extract key findings from enriched data."""
        findings = []

        # Critical/High vulnerabilities
        if 'vulnerabilities' in enriched_data:
            for vuln in enriched_data['vulnerabilities']:
                if vuln.get('severity') in ['critical', 'high']:
                    findings.append({
                        'type': 'vulnerability',
                        'severity': vuln.get('severity'),
                        'id': vuln.get('template_id', ''),
                        'name': vuln.get('template_name', '')[:80],
                        'host': vuln.get('host', ''),
                        'cves': vuln.get('cves', [])[:3],
                        'discovered_at': datetime.utcnow().isoformat()
                    })

        # Exploitable CVEs
        if 'exploit_available' in enriched_data:
            for cve in enriched_data['exploit_available']:
                cve_detail = enriched_data.get('cve_details', {}).get(cve, {})
                findings.append({
                    'type': 'exploitable_cve',
                    'severity': 'high',
                    'cve_id': cve,
                    'cvss': cve_detail.get('cvss_v3_score', 0),
                    'in_kev': cve in enriched_data.get('cisa_kev_cves', []),
                    'exploit_sources': cve_detail.get('exploit_sources', [])[:3],
                    'discovered_at': datetime.utcnow().isoformat()
                })

        # High-value services
        if 'hosts' in enriched_data:
            for host in enriched_data['hosts']:
                for port in host.get('ports', []):
                    enrichment = port.get('enrichment', {})
                    if enrichment.get('priority_score', 0) >= 8:
                        findings.append({
                            'type': 'high_value_service',
                            'severity': 'medium',
                            'host': host.get('ip', ''),
                            'port': port.get('port'),
                            'service': port.get('service', ''),
                            'version': port.get('version_string', '')[:50],
                            'priority': enrichment.get('priority_score'),
                            'vulns': enrichment.get('known_vulns', [])[:3],
                            'discovered_at': datetime.utcnow().isoformat()
                        })

        # Interesting subdomains
        if 'interesting' in enriched_data:
            interesting = enriched_data['interesting']
            for category in ['development_environments', 'admin_panels', 'api_endpoints']:
                for host in interesting.get(category, [])[:5]:
                    findings.append({
                        'type': 'interesting_subdomain',
                        'severity': 'info',
                        'host': host,
                        'category': category,
                        'discovered_at': datetime.utcnow().isoformat()
                    })

        return findings

    def _update_target(self, manifest: Dict, target: str, enriched_data: Dict) -> Dict:
        """Update target entry in manifest."""
        targets = manifest.setdefault('targets', {})

        if target not in targets:
            targets[target] = {
                'first_seen': datetime.utcnow().isoformat(),
                'last_updated': datetime.utcnow().isoformat(),
                'scan_types': [],
                'hosts_count': 0,
                'vulns_count': 0,
                'web_services_count': 0,
                'cas_path': None,
                'status': 'active'
            }

        target_entry = targets[target]
        target_entry['last_updated'] = datetime.utcnow().isoformat()

        # Update counts
        if 'hosts' in enriched_data:
            target_entry['hosts_count'] = len(enriched_data['hosts'])

        if 'vulnerabilities' in enriched_data:
            target_entry['vulns_count'] = len(enriched_data['vulnerabilities'])

        if 'web_services' in enriched_data:
            target_entry['web_services_count'] = len(enriched_data['web_services'])

        return targets[target]

    def _update_session(self, manifest: Dict, session_id: str, target: str, scan_type: str) -> Dict:
        """Update or create session entry."""
        sessions = manifest.setdefault('sessions', {})

        if session_id not in sessions:
            sessions[session_id] = {
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat(),
                'target': target,
                'scans': [],
                'status': 'active',
                'phase': 'reconnaissance'
            }

        session = sessions[session_id]
        session['updated_at'] = datetime.utcnow().isoformat()

        # Add scan to session
        scan_entry = {
            'type': scan_type,
            'timestamp': datetime.utcnow().isoformat()
        }

        if scan_entry not in session['scans']:
            session['scans'].append(scan_entry)

        return session

    def _add_to_scan_history(self, manifest: Dict, target: str, scan_type: str, source_file: str):
        """Add entry to scan history."""
        history = manifest.setdefault('scan_history', [])

        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'target': target,
            'scan_type': scan_type,
            'source_file': source_file
        }

        # Add to beginning (most recent first)
        history.insert(0, entry)

        # Keep only last 100 entries
        manifest['scan_history'] = history[:100]

    def _update_statistics(self, manifest: Dict, enriched_data: Dict):
        """Update global statistics."""
        stats = manifest.setdefault('statistics', {
            'total_scans': 0,
            'total_targets': 0,
            'total_hosts': 0,
            'total_vulnerabilities': 0,
            'critical_findings': 0,
            'exploitable_cves': 0
        })

        stats['total_scans'] += 1
        stats['total_targets'] = len(manifest.get('targets', {}))

        # Update from enriched data
        if 'hosts' in enriched_data:
            stats['total_hosts'] = max(stats['total_hosts'], len(enriched_data['hosts']))

        if 'vulnerabilities' in enriched_data:
            vuln_count = len(enriched_data['vulnerabilities'])
            stats['total_vulnerabilities'] = max(stats['total_vulnerabilities'], vuln_count)

            critical = len([v for v in enriched_data['vulnerabilities'] if v.get('severity') == 'critical'])
            stats['critical_findings'] = max(stats['critical_findings'], critical)

        if 'exploit_available' in enriched_data:
            stats['exploitable_cves'] = max(stats['exploitable_cves'], len(enriched_data['exploit_available']))

    def _update_attack_progress(self, manifest: Dict, enriched_data: Dict):
        """Update attack progress based on findings."""
        progress = manifest.setdefault('attack_progress', {
            'phase': 'reconnaissance',
            'completed_steps': [],
            'next_steps': []
        })

        # Determine phase based on findings
        has_vulns = bool(enriched_data.get('vulnerabilities'))
        has_exploits = bool(enriched_data.get('exploit_available'))
        has_services = bool(enriched_data.get('hosts'))

        if has_exploits:
            progress['phase'] = 'exploitation'
        elif has_vulns:
            progress['phase'] = 'vulnerability_assessment'
        elif has_services:
            progress['phase'] = 'enumeration'
        else:
            progress['phase'] = 'reconnaissance'

        # Generate next steps from attack guidance
        if 'attack_plan' in enriched_data:
            progress['next_steps'] = enriched_data['attack_plan'].get('recommended_first_steps', [])[:5]
        elif 'web_attack_plan' in enriched_data:
            progress['next_steps'] = enriched_data['web_attack_plan'].get('vulnerability_scan_commands', [])[:5]

    def _merge_key_findings(self, manifest: Dict, new_findings: List[Dict]):
        """Merge new key findings, avoiding duplicates."""
        existing = manifest.setdefault('key_findings', [])

        # Create lookup for existing findings
        existing_keys = set()
        for finding in existing:
            if finding.get('type') == 'vulnerability':
                key = f"vuln_{finding.get('id')}_{finding.get('host')}"
            elif finding.get('type') == 'exploitable_cve':
                key = f"cve_{finding.get('cve_id')}"
            elif finding.get('type') == 'high_value_service':
                key = f"svc_{finding.get('host')}_{finding.get('port')}"
            else:
                key = f"{finding.get('type')}_{finding.get('host', '')}"
            existing_keys.add(key)

        # Add new findings
        for finding in new_findings:
            if finding.get('type') == 'vulnerability':
                key = f"vuln_{finding.get('id')}_{finding.get('host')}"
            elif finding.get('type') == 'exploitable_cve':
                key = f"cve_{finding.get('cve_id')}"
            elif finding.get('type') == 'high_value_service':
                key = f"svc_{finding.get('host')}_{finding.get('port')}"
            else:
                key = f"{finding.get('type')}_{finding.get('host', '')}"

            if key not in existing_keys:
                existing.append(finding)
                existing_keys.add(key)

        # Sort by severity and limit
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        existing.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 5))
        manifest['key_findings'] = existing[:50]

    def update(self, input_data: Dict) -> Dict:
        """Update manifest with new scan data."""
        target = input_data.get('target', 'unknown')
        session_id = input_data.get('session_id', '')
        scan_type = input_data.get('scan_type', 'unknown')
        cas_path = input_data.get('cas_path', '')
        enriched_data = input_data.get('enriched_data', {})
        timestamp = input_data.get('timestamp', datetime.utcnow().isoformat())

        try:
            self._acquire_lock()

            # Load existing manifest
            manifest = self._load_manifest()

            # Update target entry
            target_entry = self._update_target(manifest, target, enriched_data)
            target_entry['cas_path'] = cas_path

            # Update scan types for target
            if scan_type and scan_type not in target_entry['scan_types']:
                target_entry['scan_types'].append(scan_type)

            # Update session
            if session_id:
                self._update_session(manifest, session_id, target, scan_type)

            # Add to scan history
            source_file = input_data.get('source_file', '')
            self._add_to_scan_history(manifest, target, scan_type, source_file)

            # Extract and merge key findings
            new_findings = self._extract_key_findings(enriched_data)
            self._merge_key_findings(manifest, new_findings)

            # Update statistics
            self._update_statistics(manifest, enriched_data)

            # Update attack progress
            self._update_attack_progress(manifest, enriched_data)

            # Update timestamp
            manifest['updated_at'] = datetime.utcnow().isoformat()

            # Save manifest
            self._save_manifest(manifest)

            return manifest

        finally:
            self._release_lock()


def main():
    # Read input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    # Update manifest
    manager = ManifestManager()

    try:
        manifest = manager.update(input_data)
        print(f"Manifest updated: {manager.manifest_path}")

        # Output summary
        stats = manifest.get('statistics', {})
        print(f"  Targets: {stats.get('total_targets', 0)}")
        print(f"  Scans: {stats.get('total_scans', 0)}")
        print(f"  Key findings: {len(manifest.get('key_findings', []))}")

    except Exception as e:
        print(f"Error updating manifest: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
