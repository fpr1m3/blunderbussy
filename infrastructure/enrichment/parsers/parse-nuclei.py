#!/usr/bin/env python3
"""
Agent Opulence - Nuclei JSON Parser
===================================
Parses nuclei JSON/JSONL output into structured format for enrichment pipeline.

Usage: parse-nuclei.py <nuclei_json_file>
Output: JSON to stdout

Extracts:
- Vulnerabilities with template info
- CVE identifiers
- Severity ratings
- Matched locations
- Extracted data
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict


def parse_nuclei_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a single nuclei finding."""
    parsed = {
        'template_id': finding.get('template-id', finding.get('templateID', '')),
        'template_name': finding.get('info', {}).get('name', ''),
        'template_path': finding.get('template', finding.get('template-path', '')),
        'severity': finding.get('info', {}).get('severity', 'unknown').lower(),
        'type': finding.get('type', 'unknown'),
        'host': finding.get('host', ''),
        'matched_at': finding.get('matched-at', finding.get('matched', '')),
        'ip': finding.get('ip', ''),
        'timestamp': finding.get('timestamp', ''),
        'curl_command': finding.get('curl-command', ''),
        'matcher_name': finding.get('matcher-name', ''),
        'matcher_status': finding.get('matcher-status', True),
        'extracted_results': finding.get('extracted-results', []),
        'metadata': {},
        'cves': [],
        'cwe': [],
        'references': []
    }

    # Parse info block
    info = finding.get('info', {})

    # Extract CVEs
    classification = info.get('classification', {})
    if classification:
        cve_id = classification.get('cve-id', [])
        if cve_id:
            if isinstance(cve_id, list):
                parsed['cves'] = cve_id
            else:
                parsed['cves'] = [cve_id]

        cwe_id = classification.get('cwe-id', [])
        if cwe_id:
            if isinstance(cwe_id, list):
                parsed['cwe'] = cwe_id
            else:
                parsed['cwe'] = [cwe_id]

        parsed['cvss_metrics'] = classification.get('cvss-metrics', '')
        parsed['cvss_score'] = classification.get('cvss-score', 0)

    # Extract metadata
    metadata = info.get('metadata', {})
    if metadata:
        parsed['metadata'] = {
            'author': info.get('author', ''),
            'tags': info.get('tags', []),
            'description': info.get('description', ''),
            'remediation': info.get('remediation', ''),
            'impact': metadata.get('impact', ''),
            'verified': metadata.get('verified', False),
            'max_request': metadata.get('max-request', 0),
            'shodan_query': metadata.get('shodan-query', ''),
            'fofa_query': metadata.get('fofa-query', '')
        }

    # Extract references
    refs = info.get('reference', [])
    if refs:
        if isinstance(refs, list):
            parsed['references'] = refs
        else:
            parsed['references'] = [refs]

    # Parse request/response if available
    if 'request' in finding:
        parsed['request'] = finding['request']
    if 'response' in finding:
        # Truncate large responses
        response = finding['response']
        if len(response) > 5000:
            response = response[:5000] + '\n... [truncated]'
        parsed['response'] = response

    # Extract matcher data
    if 'matcher-status' in finding:
        parsed['matcher_status'] = finding['matcher-status']

    return parsed


def parse_nuclei_output(file_path: Path) -> Dict[str, Any]:
    """Parse nuclei JSON/JSONL output file."""
    findings = []

    # Read file content
    with open(file_path, 'r') as f:
        content = f.read().strip()

    # Determine format (JSON array, single object, or JSONL)
    if content.startswith('['):
        # JSON array format
        data = json.loads(content)
        for item in data:
            findings.append(parse_nuclei_finding(item))
    elif content.startswith('{') and '\n{' not in content:
        # Single JSON object (not JSONL)
        data = json.loads(content)
        findings.append(parse_nuclei_finding(data))
    else:
        # JSONL format (one JSON object per line)
        for line in content.split('\n'):
            line = line.strip()
            if line:
                try:
                    item = json.loads(line)
                    findings.append(parse_nuclei_finding(item))
                except json.JSONDecodeError:
                    continue

    # Build result structure
    result = {
        'type': 'nuclei',
        'version': 'nuclei',
        'vulnerabilities': findings,
        'stats': {
            'total': len(findings),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'unique_templates': set(),
            'unique_hosts': set(),
            'cves_found': set()
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Calculate stats
    for finding in findings:
        severity = finding['severity']
        result['stats']['by_severity'][severity] += 1
        result['stats']['by_type'][finding['type']] += 1
        result['stats']['unique_templates'].add(finding['template_id'])
        result['stats']['unique_hosts'].add(finding['host'])

        for cve in finding['cves']:
            result['stats']['cves_found'].add(cve)

    # Convert sets to lists for JSON serialization
    result['stats']['unique_templates'] = list(result['stats']['unique_templates'])
    result['stats']['unique_hosts'] = list(result['stats']['unique_hosts'])
    result['stats']['cves_found'] = list(result['stats']['cves_found'])
    result['stats']['by_severity'] = dict(result['stats']['by_severity'])
    result['stats']['by_type'] = dict(result['stats']['by_type'])

    # Organize by severity for quick access
    result['by_severity'] = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': [],
        'unknown': []
    }

    for finding in findings:
        severity = finding['severity']
        if severity in result['by_severity']:
            result['by_severity'][severity].append(finding)
        else:
            result['by_severity']['unknown'].append(finding)

    # Extract key findings (critical and high severity)
    result['key_findings'] = []
    for finding in findings:
        if finding['severity'] in ['critical', 'high']:
            key_finding = {
                'template_id': finding['template_id'],
                'template_name': finding['template_name'],
                'severity': finding['severity'],
                'host': finding['host'],
                'matched_at': finding['matched_at'],
                'cves': finding['cves'],
                'cvss_score': finding.get('cvss_score', 0)
            }
            result['key_findings'].append(key_finding)

    # Sort key findings by CVSS score
    result['key_findings'].sort(key=lambda x: x.get('cvss_score', 0), reverse=True)

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse nuclei JSON output')
    parser.add_argument('file', type=Path, help='Nuclei JSON/JSONL file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_nuclei_output(args.file)
        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except json.JSONDecodeError as e:
        print(json.dumps({'error': f'JSON parse error: {e}'}), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}'}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
