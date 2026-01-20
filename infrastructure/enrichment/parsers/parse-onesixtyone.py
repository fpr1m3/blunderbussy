#!/usr/bin/env python3
"""
Agent Opulence - Onesixtyone Output Parser
==========================================
Parses onesixtyone SNMP community string scanner output into structured JSON.

Usage: parse-onesixtyone.py <onesixtyone_output_file>
Output: JSON to stdout

Onesixtyone scans for SNMP community strings:
- Identifies responding hosts
- Reveals community strings (public, private, etc.)
- Shows system descriptions
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime, timezone


# Common/default community strings that are security concerns
DEFAULT_COMMUNITIES = {
    'public', 'private', 'community', 'snmp', 'admin', 'manager',
    'default', 'password', 'secret', 'cisco', 'write', 'all',
    'system', 'security', 'monitor', 'agent', 'admin123'
}


def parse_onesixtyone(file_path: Path) -> Dict[str, Any]:
    """Parse onesixtyone output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    result = {
        'type': 'onesixtyone',
        'findings': [],
        'stats': {
            'hosts_found': 0,
            'communities': {},
            'interesting': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Parse output format: IP [community] description
    # Example: 10.10.10.1 [public] Linux host 5.4.0-kali3-amd64
    pattern = re.compile(r'^(\d+\.\d+\.\d+\.\d+)\s+\[([^\]]+)\]\s+(.*)$')

    seen_hosts = set()

    for line in content.strip().split('\n'):
        line = line.strip()
        if not line:
            continue

        match = pattern.match(line)
        if match:
            ip = match.group(1)
            community = match.group(2)
            description = match.group(3).strip()

            result['findings'].append({
                'ip': ip,
                'community': community,
                'description': description
            })

            seen_hosts.add(ip)

            # Track community string frequency
            if community in result['stats']['communities']:
                result['stats']['communities'][community] += 1
            else:
                result['stats']['communities'][community] = 1

    # Calculate stats
    result['stats']['hosts_found'] = len(seen_hosts)

    # Identify interesting/security-relevant findings
    interesting = []

    for finding in result['findings']:
        ip = finding['ip']
        community = finding['community']
        description = finding['description'].lower()

        # Flag default/weak community strings
        if community.lower() in DEFAULT_COMMUNITIES:
            interesting.append(f"{ip} responds to '{community}'")

        # Flag potentially sensitive devices
        if 'cisco' in description:
            interesting.append(f"{ip}: Cisco device detected")
        elif 'linux' in description:
            interesting.append(f"{ip}: Linux system detected")
        elif 'windows' in description:
            interesting.append(f"{ip}: Windows system detected")
        elif 'router' in description or 'switch' in description:
            interesting.append(f"{ip}: Network device detected")

    # Deduplicate interesting findings
    result['stats']['interesting'] = list(dict.fromkeys(interesting))

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse onesixtyone SNMP scanner output')
    parser.add_argument('file', type=Path, help='Onesixtyone output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_onesixtyone(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
