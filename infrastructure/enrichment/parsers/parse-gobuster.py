#!/usr/bin/env python3
"""
Agent Opulence - Gobuster Output Parser
========================================
Parses gobuster directory/vhost brute-force output into structured JSON.

Usage: parse-gobuster.py <gobuster_output_file>
Output: JSON to stdout

Supports:
- dir mode (directory brute-forcing)
- vhost mode (virtual host discovery)
- dns mode (DNS subdomain enumeration)
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def detect_mode(lines: List[str]) -> str:
    """Detect gobuster mode from output content."""
    for line in lines[:20]:
        if 'Gobuster v' in line:
            if 'dir' in line.lower():
                return 'dir'
            elif 'vhost' in line.lower():
                return 'vhost'
            elif 'dns' in line.lower():
                return 'dns'

    # Infer from content
    for line in lines:
        if line.startswith('/') and 'Status:' in line:
            return 'dir'
        elif 'Found:' in line and '.' in line:
            return 'vhost'

    return 'dir'  # Default


def parse_dir_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a gobuster dir mode line.

    Formats:
    - /path (Status: 200) [Size: 1234]
    - /path                 (Status: 200) [Size: 1234] [--> /redirect]
    """
    # Standard format with optional redirect
    match = re.match(
        r'^(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\](?:\s*\[--> ([^\]]+)\])?',
        line.strip()
    )

    if match:
        result = {
            'path': match.group(1),
            'status': int(match.group(2)),
            'size': int(match.group(3)),
        }
        if match.group(4):
            result['redirect'] = match.group(4)
        return result

    # Simpler format (older gobuster versions)
    match = re.match(r'^(/\S+)\s+\(Status:\s*(\d+)\)', line.strip())
    if match:
        return {
            'path': match.group(1),
            'status': int(match.group(2)),
            'size': 0
        }

    return None


def parse_vhost_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a gobuster vhost mode line.

    Format: Found: subdomain.example.com (Status: 200) [Size: 1234]
    """
    match = re.match(
        r'^Found:\s+(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]',
        line.strip()
    )

    if match:
        return {
            'vhost': match.group(1),
            'status': int(match.group(2)),
            'size': int(match.group(3))
        }

    return None


def parse_dns_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a gobuster dns mode line.

    Format: Found: subdomain.example.com
    """
    match = re.match(r'^Found:\s+(\S+)', line.strip())

    if match:
        return {
            'subdomain': match.group(1)
        }

    return None


def extract_target(lines: List[str]) -> Optional[str]:
    """Extract target URL/domain from gobuster output."""
    for line in lines[:30]:
        # Look for Url: or Target: in header
        match = re.search(r'(?:Url|Target):\s*(\S+)', line, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def extract_wordlist(lines: List[str]) -> Optional[str]:
    """Extract wordlist path from gobuster output."""
    for line in lines[:30]:
        match = re.search(r'Wordlist:\s*(\S+)', line)
        if match:
            return match.group(1)
    return None


def parse_gobuster(file_path: Path) -> Dict[str, Any]:
    """Parse gobuster output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.strip().split('\n')
    mode = detect_mode(lines)

    result = {
        'type': 'gobuster',
        'mode': mode,
        'target': extract_target(lines),
        'wordlist': extract_wordlist(lines),
        'findings': [],
        'stats': {
            'total_found': 0,
            'status_codes': {},
            'interesting': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Parse findings based on mode
    for line in lines:
        line = line.strip()
        if not line or line.startswith('=') or line.startswith('['):
            continue

        finding = None
        if mode == 'dir':
            finding = parse_dir_line(line)
        elif mode == 'vhost':
            finding = parse_vhost_line(line)
        elif mode == 'dns':
            finding = parse_dns_line(line)

        if finding:
            result['findings'].append(finding)
            result['stats']['total_found'] += 1

            # Track status codes for dir/vhost
            if 'status' in finding:
                status = str(finding['status'])
                result['stats']['status_codes'][status] = \
                    result['stats']['status_codes'].get(status, 0) + 1

    # Identify interesting findings
    interesting_patterns = [
        r'admin', r'backup', r'config', r'db', r'database',
        r'api', r'upload', r'private', r'secret', r'\.git',
        r'\.env', r'\.htaccess', r'wp-admin', r'phpmyadmin',
        r'shell', r'cmd', r'exec', r'console', r'debug'
    ]

    for finding in result['findings']:
        path = finding.get('path', finding.get('vhost', finding.get('subdomain', '')))
        for pattern in interesting_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                result['stats']['interesting'].append(path)
                break

    # Remove duplicates from interesting
    result['stats']['interesting'] = list(set(result['stats']['interesting']))

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse gobuster output')
    parser.add_argument('file', type=Path, help='Gobuster output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_gobuster(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
