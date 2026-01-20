#!/usr/bin/env python3
"""
Agent Opulence - FFUF JSON Parser
=================================
Parses FFUF web fuzzer JSON output into structured format for enrichment pipeline.

Usage: parse-ffuf.py <ffuf_json_file>
Output: JSON to stdout

FFUF is a fast web fuzzer that can output results in JSON format.
This parser handles the standard FFUF JSON output structure.

Extracts:
- All discovered endpoints
- Status codes and response metrics
- Configuration details
- Interesting findings based on patterns
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def parse_ffuf_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a single FFUF result entry."""
    return {
        'input': result.get('input', {}).get('FUZZ', result.get('input', '')),
        'url': result.get('url', ''),
        'status': result.get('status', 0),
        'size': result.get('length', result.get('content-length', 0)),
        'words': result.get('words', 0),
        'lines': result.get('lines', 0),
        'content_type': result.get('content-type', result.get('contentType', '')),
        'duration': result.get('duration', 0) / 1_000_000_000 if result.get('duration', 0) > 1000 else result.get('duration', 0),  # Convert ns to seconds if needed
        'redirect_location': result.get('redirectlocation', ''),
        'host': result.get('host', ''),
        'position': result.get('position', 0)
    }


def extract_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract scan configuration from FFUF JSON."""
    config = {}

    # From commandline
    commandline = data.get('commandline', '')
    config['commandline'] = commandline

    # Parse common options from commandline
    if '-w ' in commandline:
        parts = commandline.split('-w ')
        if len(parts) > 1:
            wordlist = parts[1].split()[0] if parts[1].split() else ''
            config['wordlist'] = wordlist

    if '-t ' in commandline:
        parts = commandline.split('-t ')
        if len(parts) > 1:
            try:
                config['threads'] = int(parts[1].split()[0])
            except (ValueError, IndexError):
                pass

    if '-X ' in commandline:
        parts = commandline.split('-X ')
        if len(parts) > 1:
            config['method'] = parts[1].split()[0]
    else:
        config['method'] = 'GET'

    # From config section if available
    ffuf_config = data.get('config', {})
    if ffuf_config:
        config['method'] = ffuf_config.get('method', config.get('method', 'GET'))
        config['threads'] = ffuf_config.get('threads', config.get('threads', 0))
        config['timeout'] = ffuf_config.get('timeout', 0)
        config['delay'] = ffuf_config.get('delay', '')
        config['matchers'] = {
            'status': ffuf_config.get('match_status', []),
            'size': ffuf_config.get('match_size', []),
            'words': ffuf_config.get('match_words', []),
            'lines': ffuf_config.get('match_lines', [])
        }
        config['filters'] = {
            'status': ffuf_config.get('filter_status', []),
            'size': ffuf_config.get('filter_size', []),
            'words': ffuf_config.get('filter_words', []),
            'lines': ffuf_config.get('filter_lines', [])
        }

    return config


def extract_target(data: Dict[str, Any]) -> Optional[str]:
    """Extract target URL from FFUF JSON."""
    # Try commandline first
    commandline = data.get('commandline', '')
    if '-u ' in commandline:
        parts = commandline.split('-u ')
        if len(parts) > 1:
            url = parts[1].split()[0] if parts[1].split() else ''
            return url

    # Try config
    config = data.get('config', {})
    if config:
        url = config.get('url', '')
        if url:
            return url

    # Try first result
    results = data.get('results', [])
    if results:
        url = results[0].get('url', '')
        if url:
            # Extract base URL pattern
            return url.rsplit('/', 1)[0] + '/FUZZ' if '/' in url else url

    return None


def identify_interesting(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify interesting findings based on patterns."""
    interesting = []

    interesting_patterns = [
        'admin', 'backup', 'config', 'db', 'database',
        'api', 'upload', 'private', 'secret', '.git',
        '.env', '.htaccess', 'wp-admin', 'phpmyadmin',
        'shell', 'cmd', 'exec', 'console', 'debug',
        'test', 'dev', 'stage', 'login', 'auth',
        'cgi-bin', 'includes', 'scripts', 'tmp', 'temp',
        'flag', 'password', 'credential', 'key', 'token'
    ]

    # Status codes that are typically interesting
    interesting_statuses = [200, 201, 301, 302, 401, 403, 500]

    for finding in findings:
        url = finding.get('url', '').lower()
        input_val = str(finding.get('input', '')).lower()
        status = finding.get('status', 0)

        # Check for interesting patterns
        for pattern in interesting_patterns:
            if pattern in url or pattern in input_val:
                interesting.append({
                    'input': finding.get('input'),
                    'url': finding.get('url'),
                    'status': status,
                    'reason': f'matches pattern: {pattern}'
                })
                break

        # 401/403 might indicate protected resources
        if status in [401, 403]:
            if finding not in [i for i in interesting if i.get('url') == finding.get('url')]:
                interesting.append({
                    'input': finding.get('input'),
                    'url': finding.get('url'),
                    'status': status,
                    'reason': f'protected resource (HTTP {status})'
                })

    return interesting


def parse_ffuf(file_path: Path) -> Dict[str, Any]:
    """Parse FFUF JSON output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    # Parse JSON
    data = json.loads(content)

    result = {
        'type': 'ffuf',
        'target': extract_target(data),
        'config': extract_config(data),
        'findings': [],
        'stats': {
            'total_found': 0,
            'status_codes': {},
            'interesting': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Parse results
    results = data.get('results', [])
    for item in results:
        finding = parse_ffuf_result(item)
        result['findings'].append(finding)
        result['stats']['total_found'] += 1

        # Track status codes
        status = str(finding['status'])
        result['stats']['status_codes'][status] = \
            result['stats']['status_codes'].get(status, 0) + 1

    # Identify interesting findings
    result['stats']['interesting'] = identify_interesting(result['findings'])

    # Add time statistics if available
    if 'time' in data:
        result['timing'] = {
            'start': data.get('time', ''),
            'duration': data.get('duration', 0)
        }

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse FFUF JSON output')
    parser.add_argument('file', type=Path, help='FFUF JSON file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_ffuf(args.file)
        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except json.JSONDecodeError as e:
        print(json.dumps({'error': f'JSON parse error: {e}'}), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({'error': str(e), 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
