#!/usr/bin/env python3
"""
Agent Opulence - Smbmap Output Parser
=====================================
Parses smbmap SMB share enumeration output into structured JSON.

Usage: parse-smbmap.py <smbmap_output_file>
Output: JSON to stdout

Smbmap enumerates SMB shares and their permissions:
- Share names and types
- Read/Write permissions
- File listing (if requested)
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def parse_target(lines: List[str]) -> Optional[str]:
    """Extract target from smbmap output."""
    for line in lines[:20]:
        # Host line: [+] IP: 10.10.10.3:445  Name: lame.htb
        match = re.search(r'IP:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            return match.group(1)

        # Alternative format
        match = re.search(r'Host:\s*(\S+)', line)
        if match:
            return match.group(1)

    return None


def parse_hostname(lines: List[str]) -> Optional[str]:
    """Extract hostname from smbmap output."""
    for line in lines[:20]:
        match = re.search(r'Name:\s*(\S+)', line)
        if match:
            return match.group(1)
    return None


def parse_shares(lines: List[str]) -> List[Dict[str, Any]]:
    """Extract share information from smbmap output."""
    shares = []
    in_share_section = False

    for line in lines:
        # Detect share listing section
        if 'Disk' in line and ('READ' in line or 'WRITE' in line or 'NO ACCESS' in line):
            in_share_section = True

        # Share table header
        if '----' in line and 'Disk' in line:
            in_share_section = True
            continue

        if in_share_section:
            # Format: SHARENAME    Disk    READ, WRITE    Comment
            # Or: SHARENAME    Disk    NO ACCESS
            match = re.match(
                r'\s*(\S+)\s+(Disk|IPC|Printer)\s+(READ(?:,\s*WRITE)?|WRITE|NO ACCESS)\s*(.*)',
                line,
                re.IGNORECASE
            )
            if match:
                permissions = match.group(3).upper()
                shares.append({
                    'name': match.group(1),
                    'type': match.group(2),
                    'permissions': permissions,
                    'readable': 'READ' in permissions,
                    'writable': 'WRITE' in permissions,
                    'comment': match.group(4).strip() if match.group(4) else ''
                })
                continue

            # Simpler format with tabs
            match = re.match(r'\t(\S+)\t+(Disk|IPC|Printer)\t+(.*)', line, re.IGNORECASE)
            if match:
                perm_text = match.group(3).strip()
                permissions = perm_text.split()[0] if perm_text else 'NO ACCESS'
                shares.append({
                    'name': match.group(1),
                    'type': match.group(2),
                    'permissions': permissions.upper(),
                    'readable': 'READ' in permissions.upper(),
                    'writable': 'WRITE' in permissions.upper(),
                    'comment': ' '.join(perm_text.split()[1:]) if len(perm_text.split()) > 1 else ''
                })

    # Also look for verbose share output
    for line in lines:
        # [+] Finding open SMB ports....
        # [+] Guest session established on 10.10.10.3...
        # [+] SHARENAME    Disk    READ, WRITE

        match = re.search(r'\[\+\]\s+(\S+)\s+(Disk|IPC)\s+(READ|WRITE|NO ACCESS)', line, re.IGNORECASE)
        if match:
            share_name = match.group(1)
            # Check if already parsed
            if not any(s['name'] == share_name for s in shares):
                permissions = match.group(3).upper()
                shares.append({
                    'name': share_name,
                    'type': match.group(2),
                    'permissions': permissions,
                    'readable': 'READ' in permissions,
                    'writable': 'WRITE' in permissions,
                    'comment': ''
                })

    return shares


def parse_file_listing(lines: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Extract file listings if smbmap was run with -R or -r."""
    file_listings = {}
    current_share = None
    current_path = ''

    for line in lines:
        # Share/path header: ./sharename/path
        match = re.match(r'\./([^/]+)(/.*)?', line)
        if match:
            current_share = match.group(1)
            current_path = match.group(2) or '/'
            if current_share not in file_listings:
                file_listings[current_share] = []
            continue

        # Working on share header
        match = re.search(r'Working on it.*?(\S+)', line)
        if match:
            current_share = match.group(1)
            if current_share not in file_listings:
                file_listings[current_share] = []
            continue

        # File/directory entry
        # Format: dr--r--r-- 0 Wed Apr 22 14:50:29 2020    $Recycle.Bin
        #     or: fr--r--r-- 4284 Wed Oct 3 10:16:24 2018  ActivityLog.xsl
        # smbmap uses: d=directory, f=file, r=read, w=write, x=execute, -=none
        # Time field (HH:MM:SS) is optional for compatibility
        if current_share:
            match = re.match(
                r'\s*([dfrwx-]{10})\s+(\d+)\s+\w+\s+\w+\s+\d+\s+(?:[\d:]+\s+)?\d{4}\s+(.+)',
                line
            )
            if match:
                perms = match.group(1)
                size = int(match.group(2))
                name = match.group(3).strip()

                if name not in ['.', '..']:
                    file_listings[current_share].append({
                        'path': current_path,
                        'name': name,
                        'type': 'directory' if perms.startswith('d') else 'file',
                        'permissions': perms,
                        'size': size
                    })

    return file_listings


def identify_interesting_files(file_listings: Dict[str, List[Dict[str, Any]]]) -> List[str]:
    """Identify potentially interesting files from listings."""
    interesting = []

    interesting_patterns = [
        r'\.txt$', r'\.xml$', r'\.conf$', r'\.config$', r'\.ini$',
        r'\.bak$', r'\.backup$', r'\.old$', r'\.sql$', r'\.db$',
        r'password', r'passwd', r'credential', r'secret', r'key',
        r'\.pem$', r'\.key$', r'\.crt$', r'\.p12$', r'\.pfx$',
        r'id_rsa', r'id_dsa', r'\.ssh', r'authorized_keys',
        r'web\.config', r'wp-config', r'\.htpasswd', r'\.htaccess',
        r'wp-login', r'admin', r'flag', r'user\.txt', r'root\.txt'
    ]

    for share, files in file_listings.items():
        for file_info in files:
            name = file_info['name'].lower()
            full_path = f"//{share}{file_info['path']}/{file_info['name']}"

            for pattern in interesting_patterns:
                if re.search(pattern, name, re.IGNORECASE):
                    interesting.append(full_path)
                    break

    return interesting


def parse_smbmap(file_path: Path) -> Dict[str, Any]:
    """Parse smbmap output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.strip().split('\n')

    shares = parse_shares(lines)
    file_listings = parse_file_listing(lines)

    result = {
        'type': 'smbmap',
        'target': parse_target(lines),
        'hostname': parse_hostname(lines),
        'shares': shares,
        'file_listings': file_listings,
        'stats': {
            'shares_found': len(shares),
            'readable_shares': 0,
            'writable_shares': 0,
            'files_listed': 0,
            'interesting_files': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Calculate stats
    for share in shares:
        if share.get('readable'):
            result['stats']['readable_shares'] += 1
        if share.get('writable'):
            result['stats']['writable_shares'] += 1

    for share, files in file_listings.items():
        result['stats']['files_listed'] += len(files)

    # Identify interesting files
    result['stats']['interesting_files'] = identify_interesting_files(file_listings)

    # Add interesting findings summary
    interesting = []

    # Writable shares
    for share in shares:
        if share.get('writable'):
            interesting.append(f"Writable share: {share['name']}")

    # Readable non-default shares
    for share in shares:
        if share.get('readable') and share['name'].lower() not in ['ipc$', 'print$']:
            interesting.append(f"Readable share: {share['name']}")

    # Interesting files
    for file_path in result['stats']['interesting_files'][:10]:
        interesting.append(f"Interesting file: {file_path}")

    result['stats']['interesting'] = interesting

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse smbmap output')
    parser.add_argument('file', type=Path, help='Smbmap output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_smbmap(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
