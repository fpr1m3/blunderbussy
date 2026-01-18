#!/usr/bin/env python3
"""
Agent Opulence - Nikto Output Parser
=====================================
Parses nikto web vulnerability scanner output into structured JSON.

Usage: parse-nikto.py <nikto_output_file>
Output: JSON to stdout

Supports:
- Text output (-Format txt)
- CSV output (-Format csv)
- XML output (-Format xml)
"""

import sys
import re
import csv
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

try:
    from defusedxml import ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


def detect_format(file_path: Path) -> str:
    """Detect nikto output format."""
    with open(file_path, 'r', errors='replace') as f:
        first_line = f.readline().strip()

    if first_line.startswith('<?xml'):
        return 'xml'
    elif '","' in first_line or first_line.startswith('"'):
        return 'csv'
    else:
        return 'txt'


def parse_txt_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a nikto text output line.

    Format: + OSVDB-XXXX: /path: Description
    Or:     + /path: Description
    """
    line = line.strip()
    if not line.startswith('+'):
        return None

    # Remove leading +
    line = line[1:].strip()

    finding = {
        'osvdb': None,
        'path': None,
        'method': None,
        'description': line,
        'severity': 'info'
    }

    # Extract OSVDB reference
    osvdb_match = re.match(r'(OSVDB-\d+):\s*(.+)', line)
    if osvdb_match:
        finding['osvdb'] = osvdb_match.group(1)
        line = osvdb_match.group(2)
        finding['description'] = line

    # Extract path
    path_match = re.match(r'(/\S*):?\s*(.+)', line)
    if path_match:
        finding['path'] = path_match.group(1)
        finding['description'] = path_match.group(2)

    # Determine severity from keywords
    desc_lower = finding['description'].lower()
    if any(word in desc_lower for word in ['critical', 'remote code', 'rce', 'command execution']):
        finding['severity'] = 'critical'
    elif any(word in desc_lower for word in ['vulnerability', 'exploit', 'injection', 'xss', 'sqli']):
        finding['severity'] = 'high'
    elif any(word in desc_lower for word in ['disclosure', 'leak', 'sensitive', 'password', 'backup']):
        finding['severity'] = 'medium'
    elif any(word in desc_lower for word in ['outdated', 'deprecated', 'warning']):
        finding['severity'] = 'low'

    return finding


def parse_txt(file_path: Path) -> Dict[str, Any]:
    """Parse nikto text output."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.strip().split('\n')

    result = {
        'type': 'nikto',
        'format': 'txt',
        'target': None,
        'port': None,
        'findings': [],
        'server_info': {},
        'stats': {
            'total_findings': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    for line in lines:
        line = line.strip()

        # Extract target info
        target_match = re.match(r'^\+\s*Target IP:\s*(.+)', line)
        if target_match:
            result['target'] = target_match.group(1).strip()
            continue

        target_match = re.match(r'^\+\s*Target Hostname:\s*(.+)', line)
        if target_match and not result['target']:
            result['target'] = target_match.group(1).strip()
            continue

        port_match = re.match(r'^\+\s*Target Port:\s*(\d+)', line)
        if port_match:
            result['port'] = int(port_match.group(1))
            continue

        # Extract server info
        server_match = re.match(r'^\+\s*Server:\s*(.+)', line)
        if server_match:
            result['server_info']['server'] = server_match.group(1).strip()
            continue

        # Parse findings
        if line.startswith('+') and ':' in line:
            finding = parse_txt_line(line)
            if finding and finding['description']:
                # Skip header lines
                if any(skip in finding['description'].lower() for skip in
                       ['target ip', 'target hostname', 'target port', 'start time', 'end time', 'host(s) tested']):
                    continue

                result['findings'].append(finding)
                result['stats']['total_findings'] += 1
                result['stats']['by_severity'][finding['severity']] += 1

    return result


def parse_csv(file_path: Path) -> Dict[str, Any]:
    """Parse nikto CSV output."""
    result = {
        'type': 'nikto',
        'format': 'csv',
        'target': None,
        'port': None,
        'findings': [],
        'server_info': {},
        'stats': {
            'total_findings': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    with open(file_path, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            finding = {
                'osvdb': row.get('OSVDB', row.get('osvdb')),
                'path': row.get('URI', row.get('uri', row.get('path'))),
                'method': row.get('Method', row.get('method')),
                'description': row.get('Description', row.get('description', row.get('msg', ''))),
                'severity': 'info'
            }

            # Determine severity
            desc_lower = finding['description'].lower()
            if any(word in desc_lower for word in ['critical', 'remote code', 'rce']):
                finding['severity'] = 'critical'
            elif any(word in desc_lower for word in ['vulnerability', 'exploit']):
                finding['severity'] = 'high'
            elif any(word in desc_lower for word in ['disclosure', 'leak']):
                finding['severity'] = 'medium'
            elif any(word in desc_lower for word in ['outdated', 'deprecated']):
                finding['severity'] = 'low'

            result['findings'].append(finding)
            result['stats']['total_findings'] += 1
            result['stats']['by_severity'][finding['severity']] += 1

            # Extract target from first row if available
            if not result['target']:
                result['target'] = row.get('Host', row.get('host', row.get('IP')))
                result['port'] = int(row.get('Port', row.get('port', 0)) or 0) or None

    return result


def parse_xml(file_path: Path) -> Dict[str, Any]:
    """Parse nikto XML output."""
    result = {
        'type': 'nikto',
        'format': 'xml',
        'target': None,
        'port': None,
        'findings': [],
        'server_info': {},
        'stats': {
            'total_findings': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    tree = ET.parse(str(file_path))
    root = tree.getroot()

    # Find scan target
    for scandetails in root.findall('.//scandetails'):
        result['target'] = scandetails.get('targetip') or scandetails.get('targethostname')
        result['port'] = int(scandetails.get('targetport', 0)) or None
        result['server_info']['server'] = scandetails.get('targetbanner')
        break

    # Parse items
    for item in root.findall('.//item'):
        finding = {
            'osvdb': item.get('osvdbid'),
            'path': item.findtext('uri'),
            'method': item.get('method'),
            'description': item.findtext('description', ''),
            'severity': 'info'
        }

        # Determine severity
        desc_lower = finding['description'].lower()
        if any(word in desc_lower for word in ['critical', 'remote code', 'rce']):
            finding['severity'] = 'critical'
        elif any(word in desc_lower for word in ['vulnerability', 'exploit']):
            finding['severity'] = 'high'
        elif any(word in desc_lower for word in ['disclosure', 'leak']):
            finding['severity'] = 'medium'
        elif any(word in desc_lower for word in ['outdated', 'deprecated']):
            finding['severity'] = 'low'

        result['findings'].append(finding)
        result['stats']['total_findings'] += 1
        result['stats']['by_severity'][finding['severity']] += 1

    return result


def parse_nikto(file_path: Path) -> Dict[str, Any]:
    """Parse nikto output file, auto-detecting format."""
    fmt = detect_format(file_path)

    if fmt == 'xml':
        return parse_xml(file_path)
    elif fmt == 'csv':
        return parse_csv(file_path)
    else:
        return parse_txt(file_path)


def main():
    parser = argparse.ArgumentParser(description='Parse nikto output')
    parser.add_argument('file', type=Path, help='Nikto output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_nikto(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
