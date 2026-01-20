#!/usr/bin/env python3
"""
Agent Opulence - Showmount Output Parser
========================================
Parses showmount NFS export listing output into structured JSON.

Usage: parse-showmount.py <showmount_output_file>
Output: JSON to stdout

Showmount lists NFS exports from a server:
- Export paths
- Allowed hosts/networks
- World-readable shares (security risk)
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


# Sensitive paths that should be flagged
SENSITIVE_PATHS = {
    '/home', '/root', '/etc', '/var', '/var/backups', '/var/log',
    '/tmp', '/opt', '/srv', '/backup', '/backups', '/data',
    '/usr/local', '/mnt', '/media', '/private'
}

# Patterns indicating world-readable access
WORLD_READABLE_PATTERNS = ['*', '(everyone)', 'everyone', '(all)', 'all']


def is_world_readable(allowed_hosts: List[str]) -> bool:
    """Check if the export is world-readable."""
    for host in allowed_hosts:
        host_lower = host.lower().strip()
        if host_lower in WORLD_READABLE_PATTERNS:
            return True
        # Also check for empty which sometimes means everyone
        if host_lower == '':
            return True
    return False


def is_sensitive_path(path: str) -> bool:
    """Check if the export path is sensitive."""
    path_lower = path.lower().rstrip('/')

    # Check exact matches
    if path_lower in SENSITIVE_PATHS:
        return True

    # Check if it's under a sensitive directory
    for sensitive in SENSITIVE_PATHS:
        if path_lower.startswith(sensitive + '/'):
            return True

    return False


def parse_showmount(file_path: Path) -> Dict[str, Any]:
    """Parse showmount output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    result = {
        'type': 'showmount',
        'target': None,
        'exports': [],
        'stats': {
            'total_exports': 0,
            'world_readable': [],
            'sensitive_paths': [],
            'interesting': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    lines = content.strip().split('\n')

    # Parse header to get target
    # Format: "Export list for 10.10.10.1:" or "Exports list for hostname:"
    for line in lines:
        match = re.match(r'^Export\s+list\s+for\s+([^:]+):', line, re.IGNORECASE)
        if match:
            result['target'] = match.group(1).strip()
            break

    # Parse exports
    # Format: /path    allowed_hosts
    # Examples:
    #   /home          *
    #   /var/backups   192.168.1.0/24
    #   /srv/nfs       (everyone)
    #   /data          host1.example.com,host2.example.com
    export_pattern = re.compile(r'^(/\S*)\s+(.+)$')

    for line in lines:
        line = line.strip()
        if not line or line.lower().startswith('export'):
            continue

        match = export_pattern.match(line)
        if match:
            path = match.group(1)
            hosts_str = match.group(2).strip()

            # Parse allowed hosts - can be comma or space separated
            allowed_hosts = []
            if ',' in hosts_str:
                allowed_hosts = [h.strip() for h in hosts_str.split(',')]
            else:
                allowed_hosts = hosts_str.split()

            # Clean up hosts
            allowed_hosts = [h for h in allowed_hosts if h]

            world_readable = is_world_readable(allowed_hosts)

            export_entry = {
                'path': path,
                'allowed_hosts': allowed_hosts,
                'world_readable': world_readable
            }

            result['exports'].append(export_entry)

            # Track world-readable exports
            if world_readable:
                result['stats']['world_readable'].append(path)

            # Track sensitive paths
            if is_sensitive_path(path):
                result['stats']['sensitive_paths'].append(path)

    # Calculate stats
    result['stats']['total_exports'] = len(result['exports'])

    # Generate interesting findings
    interesting = []

    for export in result['exports']:
        path = export['path']

        if export['world_readable']:
            interesting.append(f"World-readable export: {path}")

        if is_sensitive_path(path):
            if export['world_readable']:
                interesting.append(f"CRITICAL: Sensitive path {path} is world-readable!")
            else:
                interesting.append(f"Sensitive path exported: {path}")

    # Deduplicate
    result['stats']['interesting'] = list(dict.fromkeys(interesting))

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse showmount NFS export listing')
    parser.add_argument('file', type=Path, help='Showmount output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_showmount(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
