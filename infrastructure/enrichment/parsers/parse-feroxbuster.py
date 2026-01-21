#!/usr/bin/env python3
"""
Agent Opulence - Feroxbuster Output Parser
==========================================
Parses feroxbuster directory brute-force output into structured JSON.

Usage: parse-feroxbuster.py <feroxbuster_output_file>
Output: JSON to stdout

Feroxbuster is a fast, recursive content discovery tool written in Rust.
Output format differs from gobuster:
- Status code first, then size, then URL
- May include response time and other metadata
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def parse_feroxbuster_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a feroxbuster output line.

    Formats:
    - 200      GET      123l      456w      7890c http://target/path
    - 200        0l        0w        0c http://target/path
    - Status and size patterns: STATUS METHOD LINESl WORDSw BYTESc URL
    - Simpler format: STATUS SIZE URL
    """
    line = line.strip()

    # Skip empty lines, comments, progress indicators
    if not line or line.startswith('#') or line.startswith('[') or '─' in line:
        return None

    # Full format with method and line/word/char counts
    # Example: 200      GET      123l      456w      7890c http://target/path
    match = re.match(
        r'^(\d{3})\s+(\w+)\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(\S+)',
        line
    )
    if match:
        url = match.group(6)
        # Extract path from URL
        path = '/' + '/'.join(url.split('/')[3:]) if '://' in url else url

        return {
            'status': int(match.group(1)),
            'method': match.group(2),
            'lines': int(match.group(3)),
            'words': int(match.group(4)),
            'size': int(match.group(5)),
            'url': url,
            'path': path
        }

    # Simpler format: STATUS SIZE URL (some feroxbuster versions)
    match = re.match(r'^(\d{3})\s+(\d+)\s+(\S+)', line)
    if match:
        url = match.group(3)
        path = '/' + '/'.join(url.split('/')[3:]) if '://' in url else url

        return {
            'status': int(match.group(1)),
            'size': int(match.group(2)),
            'url': url,
            'path': path
        }

    # JSON output format (if feroxbuster was run with --json)
    if line.startswith('{'):
        try:
            data = json.loads(line)
            if 'url' in data:
                url = data.get('url', '')
                path = '/' + '/'.join(url.split('/')[3:]) if '://' in url else url
                return {
                    'status': data.get('status', 0),
                    'size': data.get('content_length', data.get('length', 0)),
                    'url': url,
                    'path': path,
                    'method': data.get('method', 'GET'),
                    'lines': data.get('line_count', 0),
                    'words': data.get('word_count', 0)
                }
        except json.JSONDecodeError:
            pass

    return None


def extract_target(lines: List[str]) -> Optional[str]:
    """Extract target URL from feroxbuster output."""
    for line in lines[:50]:
        # Look for target in header
        match = re.search(r'Target Url:\s*(\S+)', line, re.IGNORECASE)
        if match:
            return match.group(1)

        # Look for URLs in findings
        if 'http' in line.lower():
            match = re.search(r'(https?://[^/\s]+)', line)
            if match:
                return match.group(1)

    return None


def extract_config(lines: List[str]) -> Dict[str, Any]:
    """Extract scan configuration from feroxbuster header."""
    config = {}

    for line in lines[:50]:
        # Threads (handles both "Threads: 50" and "Threads │ 50" formats)
        match = re.search(r'Threads\s*[│:]\s*(\d+)', line)
        if match:
            config['threads'] = int(match.group(1))

        # Wordlist
        match = re.search(r'Wordlist\s*[│:]\s*(\S+)', line)
        if match:
            config['wordlist'] = match.group(1)

        # Status codes
        match = re.search(r'Status Codes\s*[│:]\s*\[([^\]]+)\]', line)
        if match:
            config['status_codes'] = [int(c.strip()) for c in match.group(1).split(',')]

        # Timeout
        match = re.search(r'Timeout\s*\(secs\)\s*[│:]\s*(\d+)', line)
        if match:
            config['timeout'] = int(match.group(1))

    return config


def parse_feroxbuster(file_path: Path) -> Dict[str, Any]:
    """Parse feroxbuster output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.strip().split('\n')

    result = {
        'type': 'feroxbuster',
        'target': extract_target(lines),
        'config': extract_config(lines),
        'findings': [],
        'stats': {
            'total_found': 0,
            'status_codes': {},
            'interesting': [],
            'directories': [],
            'files': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Parse findings
    seen_urls = set()
    for line in lines:
        finding = parse_feroxbuster_line(line)
        if finding and finding.get('url') not in seen_urls:
            seen_urls.add(finding.get('url'))
            result['findings'].append(finding)
            result['stats']['total_found'] += 1

            # Track status codes
            status = str(finding['status'])
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
        # Admin and management
        r'admin', r'manager', r'dashboard', r'panel', r'control',
        r'wp-admin', r'phpmyadmin', r'adminer', r'cpanel',
        # Backup and archives (CRITICAL for source code leaks)
        r'backup', r'\.bak', r'\.old', r'\.orig', r'\.save',
        r'\.tar', r'\.tar\.gz', r'\.tgz', r'\.zip', r'\.rar', r'\.7z',
        r'\.sql', r'\.dump', r'\.gz', r'\.bz2',
        # Source code indicators
        r'source', r'src', r'code', r'\.git', r'\.svn', r'\.hg',
        r'\.gitignore', r'\.dockerignore', r'Dockerfile',
        r'package\.json', r'composer\.json', r'requirements\.txt',
        r'Gemfile', r'Cargo\.toml', r'go\.mod', r'pom\.xml',
        # Config and secrets
        r'config', r'conf', r'settings', r'\.env', r'\.ini', r'\.cfg',
        r'\.htaccess', r'\.htpasswd', r'web\.config', r'\.yml', r'\.yaml',
        r'credentials', r'secrets', r'keys', r'tokens', r'password',
        # Database
        r'db', r'database', r'mysql', r'postgres', r'mongo', r'redis',
        r'sqlite', r'\.db', r'\.sqlite', r'\.mdb',
        # API and services
        r'api', r'graphql', r'swagger', r'openapi', r'v1', r'v2',
        r'rest', r'soap', r'wsdl', r'webhook',
        # Upload and file handling
        r'upload', r'uploads', r'files', r'media', r'assets', r'storage',
        r'attachments', r'documents', r'downloads',
        # Private and restricted
        r'private', r'internal', r'secret', r'hidden', r'\.hidden',
        r'restricted', r'confidential', r'sensitive',
        # Shell and execution
        r'shell', r'cmd', r'exec', r'command', r'terminal', r'ssh',
        r'console', r'debug', r'trace', r'log', r'logs',
        # Development and testing
        r'test', r'tests', r'dev', r'devel', r'develop', r'development',
        r'stage', r'staging', r'uat', r'qa', r'sandbox', r'demo',
        # Authentication
        r'login', r'logout', r'auth', r'oauth', r'sso', r'saml',
        r'register', r'signup', r'reset', r'forgot', r'session',
        # Server and infra
        r'cgi-bin', r'cgi', r'fcgi', r'includes', r'inc',
        r'scripts', r'bin', r'lib', r'vendor', r'node_modules',
        r'tmp', r'temp', r'cache', r'var', r'proc',
        # CMS and frameworks
        r'wordpress', r'wp-content', r'wp-includes', r'drupal',
        r'joomla', r'magento', r'laravel', r'symfony',
        # Documentation (may leak internal info)
        r'readme', r'changelog', r'todo', r'notes', r'docs'
    ]

    for finding in result['findings']:
        path = finding.get('path', finding.get('url', ''))
        for pattern in interesting_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                if path not in result['stats']['interesting']:
                    result['stats']['interesting'].append(path)
                break

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse feroxbuster output')
    parser.add_argument('file', type=Path, help='Feroxbuster output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_feroxbuster(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
