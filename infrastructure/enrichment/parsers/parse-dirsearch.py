#!/usr/bin/env python3
"""
Agent Opulence - Dirsearch Output Parser
=========================================
Parses dirsearch directory brute-force output into structured JSON.

Usage: parse-dirsearch.py <dirsearch_output_file>
Output: JSON to stdout

Dirsearch is a web path scanner that outputs in various formats:
- Plain text (default)
- JSON (--format json)
- CSV (--format csv)
- Markdown (--format md)
"""

import sys
import re
import json
import csv
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from io import StringIO


def parse_dirsearch_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a dirsearch text output line.

    Formats:
    - [HH:MM:SS] 200 -  1234B  - /path
    - [HH:MM:SS] 301 -  234B  - /path  ->  http://target/newpath
    - 200    1234    http://target/path
    """
    line = line.strip()

    # Skip empty lines, comments, headers
    if not line or line.startswith('#') or line.startswith('Extensions:'):
        return None
    if 'Target:' in line or 'Output:' in line or 'Error Log:' in line:
        return None
    if '──' in line or '═' in line or 'Task Completed' in line:
        return None

    # Format with timestamp: [HH:MM:SS] STATUS - SIZE - PATH [-> REDIRECT]
    match = re.match(
        r'\[[\d:]+\]\s+(\d{3})\s+-\s+(\d+[BKMG]?)\s+-\s+(\S+)(?:\s+->\s+(\S+))?',
        line
    )
    if match:
        size_str = match.group(2)
        size = parse_size(size_str)
        path = match.group(3)
        redirect = match.group(4)

        return {
            'status': int(match.group(1)),
            'size': size,
            'path': path,
            'url': None,  # Will be filled in later if target is known
            'redirect': redirect
        }

    # Format without timestamp: STATUS SIZE PATH or STATUS - SIZE - PATH
    match = re.match(r'^(\d{3})\s+[-]?\s*(\d+[BKMG]?)\s+[-]?\s*(\S+)', line)
    if match:
        size_str = match.group(2)
        size = parse_size(size_str)
        path = match.group(3)

        return {
            'status': int(match.group(1)),
            'size': size,
            'path': path if not path.startswith('http') else extract_path(path),
            'url': path if path.startswith('http') else None,
            'redirect': None
        }

    # Simple format: STATUS PATH (some minimal outputs)
    match = re.match(r'^(\d{3})\s+(/\S+)', line)
    if match:
        return {
            'status': int(match.group(1)),
            'size': 0,
            'path': match.group(2),
            'url': None,
            'redirect': None
        }

    return None


def parse_size(size_str: str) -> int:
    """Convert size string (e.g., '1234B', '5K', '2M') to bytes."""
    size_str = size_str.upper().strip()

    # Already a plain number
    if size_str.isdigit():
        return int(size_str)

    # Has suffix
    match = re.match(r'^(\d+(?:\.\d+)?)\s*([BKMG]?)$', size_str)
    if match:
        value = float(match.group(1))
        suffix = match.group(2)
        multipliers = {'B': 1, 'K': 1024, 'M': 1024*1024, 'G': 1024*1024*1024, '': 1}
        return int(value * multipliers.get(suffix, 1))

    return 0


def extract_path(url: str) -> str:
    """Extract path from full URL."""
    if '://' in url:
        parts = url.split('/', 3)
        if len(parts) > 3:
            return '/' + parts[3]
        return '/'
    return url


def extract_target(lines: List[str]) -> Optional[str]:
    """Extract target URL from dirsearch output."""
    for line in lines[:30]:
        # Target: http://example.com/
        match = re.search(r'Target:\s*(https?://\S+)', line, re.IGNORECASE)
        if match:
            return match.group(1).rstrip('/')

        # URL: http://example.com/
        match = re.search(r'URL:\s*(https?://\S+)', line, re.IGNORECASE)
        if match:
            return match.group(1).rstrip('/')

    # Try to extract from findings
    for line in lines:
        if line.startswith('http'):
            match = re.search(r'(https?://[^/\s]+)', line)
            if match:
                return match.group(1)

    return None


def extract_config(lines: List[str]) -> Dict[str, Any]:
    """Extract scan configuration from dirsearch header."""
    config = {}

    for line in lines[:50]:
        # Extensions
        match = re.search(r'Extensions:\s*(.+)', line, re.IGNORECASE)
        if match:
            exts = [e.strip() for e in match.group(1).split(',')]
            config['extensions'] = [e.lstrip('.') for e in exts if e]

        # Threads
        match = re.search(r'Threads:\s*(\d+)', line, re.IGNORECASE)
        if match:
            config['threads'] = int(match.group(1))

        # Wordlist
        match = re.search(r'Wordlist(?:\s+size)?:\s*(\S+)', line, re.IGNORECASE)
        if match:
            val = match.group(1)
            if val.isdigit():
                config['wordlist_size'] = int(val)
            else:
                config['wordlist'] = val

        # HTTP Method
        match = re.search(r'Method:\s*(\S+)', line, re.IGNORECASE)
        if match:
            config['method'] = match.group(1)

    return config


def parse_dirsearch_json(data: Any) -> Dict[str, Any]:
    """Parse dirsearch JSON output format."""
    result = {
        'type': 'dirsearch',
        'target': None,
        'config': {},
        'findings': [],
        'stats': {
            'total_found': 0,
            'status_codes': {},
            'interesting': [],
            'directories': [],
            'files': []
        }
    }

    # dirsearch JSON can be a dict with URL keys or a list
    if isinstance(data, dict):
        # Format: {"http://target": [{"status": 200, "path": "/..."}, ...]}
        for target_url, findings in data.items():
            if target_url.startswith('http'):
                result['target'] = target_url.rstrip('/')
                if isinstance(findings, list):
                    for finding in findings:
                        if isinstance(finding, dict):
                            entry = {
                                'status': finding.get('status', 0),
                                'size': finding.get('content-length', finding.get('size', 0)),
                                'path': finding.get('path', ''),
                                'url': finding.get('url', f"{target_url}{finding.get('path', '')}"),
                                'redirect': finding.get('redirect', finding.get('location'))
                            }
                            result['findings'].append(entry)
                break

        # Alternative format: {"results": [...], "target": "..."}
        if 'results' in data:
            result['target'] = data.get('target', data.get('url', '')).rstrip('/')
            for finding in data['results']:
                if isinstance(finding, dict):
                    entry = {
                        'status': finding.get('status', 0),
                        'size': finding.get('content-length', finding.get('size', 0)),
                        'path': finding.get('path', ''),
                        'url': finding.get('url', ''),
                        'redirect': finding.get('redirect', finding.get('location'))
                    }
                    result['findings'].append(entry)

    elif isinstance(data, list):
        # Plain list of findings
        for finding in data:
            if isinstance(finding, dict):
                entry = {
                    'status': finding.get('status', 0),
                    'size': finding.get('content-length', finding.get('size', 0)),
                    'path': finding.get('path', ''),
                    'url': finding.get('url', ''),
                    'redirect': finding.get('redirect', finding.get('location'))
                }
                if not result['target'] and entry['url']:
                    match = re.match(r'(https?://[^/]+)', entry['url'])
                    if match:
                        result['target'] = match.group(1)
                result['findings'].append(entry)

    return result


def parse_dirsearch_csv(content: str) -> Dict[str, Any]:
    """Parse dirsearch CSV output format."""
    result = {
        'type': 'dirsearch',
        'target': None,
        'config': {},
        'findings': [],
        'stats': {
            'total_found': 0,
            'status_codes': {},
            'interesting': [],
            'directories': [],
            'files': []
        }
    }

    reader = csv.DictReader(StringIO(content))
    for row in reader:
        # Handle various CSV column names
        status = row.get('status', row.get('Status', row.get('status_code', '0')))
        size = row.get('content-length', row.get('size', row.get('Size', '0')))
        path = row.get('path', row.get('Path', row.get('url', '')))
        redirect = row.get('redirect', row.get('location', row.get('Location')))

        try:
            status_int = int(status)
        except (ValueError, TypeError):
            status_int = 0

        try:
            size_int = int(size)
        except (ValueError, TypeError):
            size_int = 0

        entry = {
            'status': status_int,
            'size': size_int,
            'path': extract_path(path) if path.startswith('http') else path,
            'url': path if path.startswith('http') else None,
            'redirect': redirect
        }

        if not result['target'] and entry.get('url'):
            match = re.match(r'(https?://[^/]+)', entry['url'])
            if match:
                result['target'] = match.group(1)

        result['findings'].append(entry)

    return result


def parse_dirsearch(file_path: Path) -> Dict[str, Any]:
    """Parse dirsearch output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.strip().split('\n')

    # Try to detect format and parse accordingly
    result = None

    # Try JSON first
    try:
        data = json.loads(content)
        result = parse_dirsearch_json(data)
    except json.JSONDecodeError:
        pass

    # Try CSV if it looks like CSV
    if result is None and lines and ',' in lines[0]:
        # Check for CSV headers
        first_line = lines[0].lower()
        if any(h in first_line for h in ['status', 'path', 'url', 'content-length']):
            try:
                result = parse_dirsearch_csv(content)
            except Exception:
                pass

    # Fall back to text parsing
    if result is None:
        result = {
            'type': 'dirsearch',
            'target': extract_target(lines),
            'config': extract_config(lines),
            'findings': [],
            'stats': {
                'total_found': 0,
                'status_codes': {},
                'interesting': [],
                'directories': [],
                'files': []
            }
        }

        # Parse text findings
        seen_paths = set()
        for line in lines:
            finding = parse_dirsearch_line(line)
            if finding:
                path_key = finding.get('path') or finding.get('url')
                if path_key and path_key not in seen_paths:
                    seen_paths.add(path_key)
                    # Set URL if we have target
                    if result['target'] and not finding.get('url'):
                        finding['url'] = f"{result['target']}{finding['path']}"
                    result['findings'].append(finding)

    # Calculate stats
    for finding in result['findings']:
        result['stats']['total_found'] += 1

        # Track status codes
        status = str(finding.get('status', 0))
        result['stats']['status_codes'][status] = \
            result['stats']['status_codes'].get(status, 0) + 1

        # Classify as directory or file
        path = finding.get('path', '')
        if path.endswith('/'):
            result['stats']['directories'].append(path)
        elif '.' in path.split('/')[-1]:
            result['stats']['files'].append(path)
        else:
            result['stats']['directories'].append(path)

    # Identify interesting findings
    interesting_patterns = [
        r'admin', r'backup', r'config', r'db', r'database',
        r'api', r'upload', r'private', r'secret', r'\.git',
        r'\.env', r'\.htaccess', r'wp-admin', r'phpmyadmin',
        r'shell', r'cmd', r'exec', r'console', r'debug',
        r'test', r'dev', r'stage', r'login', r'auth',
        r'cgi-bin', r'includes', r'scripts', r'tmp', r'temp',
        r'\.bak', r'\.old', r'\.swp', r'\.sql', r'\.tar',
        r'\.zip', r'\.gz', r'robots\.txt', r'sitemap',
        r'phpinfo', r'info\.php', r'server-status'
    ]

    for finding in result['findings']:
        path = finding.get('path', finding.get('url', ''))
        for pattern in interesting_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                if path not in result['stats']['interesting']:
                    result['stats']['interesting'].append(path)
                break

    result['raw_file'] = str(file_path)
    result['parsed_at'] = datetime.now(timezone.utc).isoformat()

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse dirsearch output')
    parser.add_argument('file', type=Path, help='Dirsearch output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_dirsearch(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
