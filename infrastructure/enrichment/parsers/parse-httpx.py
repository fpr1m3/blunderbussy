#!/usr/bin/env python3
"""
Agent Opulence - HTTPX JSON Parser
==================================
Parses httpx JSON/JSONL output into structured format for enrichment pipeline.

Usage: parse-httpx.py <httpx_json_file>
Output: JSON to stdout

Extracts:
- Web services discovery
- Technology detection
- SSL/TLS information
- HTTP headers and responses
- CDN/WAF detection
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict
from urllib.parse import urlparse


def parse_httpx_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a single httpx result."""
    parsed = {
        'url': result.get('url', ''),
        'input': result.get('input', ''),
        'host': result.get('host', ''),
        'port': result.get('port', 0),
        'scheme': result.get('scheme', 'http'),
        'path': result.get('path', '/'),
        'status_code': result.get('status_code', result.get('status-code', 0)),
        'content_length': result.get('content_length', result.get('content-length', 0)),
        'content_type': result.get('content_type', result.get('content-type', '')),
        'title': result.get('title', ''),
        'webserver': result.get('webserver', ''),
        'technologies': result.get('tech', result.get('technologies', [])),
        'final_url': result.get('final_url', result.get('final-url', '')),
        'response_time': result.get('response_time', result.get('time', '')),
        'failed': result.get('failed', False),
        'lines': result.get('lines', 0),
        'words': result.get('words', 0),
        'a_records': result.get('a', []),
        'cname_records': result.get('cname', []),
        'cdn': {
            'detected': False,
            'name': None,
            'type': None
        },
        'waf': {
            'detected': False,
            'name': None
        },
        'tls': None,
        'headers': {},
        'hashes': {},
        'method': result.get('method', 'GET'),
        'body_preview': result.get('body_preview', ''),
        'favicon': result.get('favicon', ''),
        'favicon_hash': result.get('favicon_hash', result.get('favicon-mmh3', ''))
    }

    # Parse URL for additional info
    if parsed['url']:
        parsed_url = urlparse(parsed['url'])
        if not parsed['host']:
            parsed['host'] = parsed_url.hostname or ''
        if not parsed['port']:
            parsed['port'] = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        if not parsed['scheme']:
            parsed['scheme'] = parsed_url.scheme or 'http'

    # Parse CDN detection
    cdn_name = result.get('cdn_name', result.get('cdn-name', ''))
    cdn_type = result.get('cdn_type', result.get('cdn-type', ''))
    if cdn_name or cdn_type:
        parsed['cdn'] = {
            'detected': True,
            'name': cdn_name,
            'type': cdn_type
        }

    # Parse WAF detection
    waf = result.get('waf', '')
    if waf:
        parsed['waf'] = {
            'detected': True,
            'name': waf
        }

    # Parse TLS/SSL info
    tls = result.get('tls', result.get('tls-grab', {}))
    if tls:
        parsed['tls'] = {
            'version': tls.get('version', ''),
            'cipher': tls.get('cipher', ''),
            'issuer': tls.get('issuer_cn', tls.get('issuer', '')),
            'subject': tls.get('subject_cn', tls.get('subject', '')),
            'not_before': tls.get('not_before', ''),
            'not_after': tls.get('not_after', ''),
            'serial': tls.get('serial', ''),
            'fingerprint_sha256': tls.get('fingerprint_sha256', ''),
            'san': tls.get('san', []),
            'expired': tls.get('expired', False),
            'self_signed': tls.get('self_signed', False),
            'mismatched': tls.get('mismatched', False)
        }

    # Parse headers
    headers = result.get('header', result.get('headers', {}))
    if headers:
        if isinstance(headers, dict):
            parsed['headers'] = headers
        elif isinstance(headers, str):
            # Parse header string
            parsed['headers'] = {}
            for line in headers.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    parsed['headers'][key.strip().lower()] = value.strip()

    # Parse hashes
    parsed['hashes'] = {
        'body_md5': result.get('body_md5', result.get('body-md5', '')),
        'body_sha256': result.get('body_sha256', result.get('body-sha256', '')),
        'header_md5': result.get('header_md5', result.get('header-md5', '')),
        'body_mmh3': result.get('body_mmh3', '')
    }

    # Parse additional fields
    parsed['jarm'] = result.get('jarm', '')
    parsed['asn'] = result.get('asn', '')
    parsed['asn_org'] = result.get('asn_org', result.get('as_org', ''))

    # Detect interesting headers
    parsed['security_headers'] = {
        'csp': parsed['headers'].get('content-security-policy', ''),
        'xss_protection': parsed['headers'].get('x-xss-protection', ''),
        'frame_options': parsed['headers'].get('x-frame-options', ''),
        'content_type_options': parsed['headers'].get('x-content-type-options', ''),
        'hsts': parsed['headers'].get('strict-transport-security', ''),
        'referrer_policy': parsed['headers'].get('referrer-policy', '')
    }

    # Check for interesting headers
    parsed['interesting_headers'] = []
    interesting = ['x-powered-by', 'server', 'x-aspnet-version', 'x-runtime',
                   'x-generator', 'x-drupal-cache', 'x-varnish', 'via',
                   'x-amz-cf-id', 'x-cache', 'x-served-by']
    for header in interesting:
        if header in parsed['headers']:
            parsed['interesting_headers'].append({
                'name': header,
                'value': parsed['headers'][header]
            })

    return parsed


def parse_httpx_output(file_path: Path) -> Dict[str, Any]:
    """Parse httpx JSON/JSONL output file."""
    web_services = []

    # Read file content
    with open(file_path, 'r') as f:
        content = f.read().strip()

    # Determine format (JSON array, single object, or JSONL)
    if content.startswith('['):
        # JSON array format
        data = json.loads(content)
        for item in data:
            web_services.append(parse_httpx_result(item))
    elif content.startswith('{') and '\n{' not in content:
        # Single JSON object (not JSONL)
        data = json.loads(content)
        web_services.append(parse_httpx_result(data))
    else:
        # JSONL format (one JSON object per line)
        for line in content.split('\n'):
            line = line.strip()
            if line:
                try:
                    item = json.loads(line)
                    web_services.append(parse_httpx_result(item))
                except json.JSONDecodeError:
                    continue

    # Build result structure
    result = {
        'type': 'httpx',
        'version': 'httpx',
        'web_services': web_services,
        'stats': {
            'total': len(web_services),
            'by_status_code': defaultdict(int),
            'by_technology': defaultdict(int),
            'unique_hosts': set(),
            'with_tls': 0,
            'with_cdn': 0,
            'with_waf': 0,
            'status_groups': {
                '2xx': 0,
                '3xx': 0,
                '4xx': 0,
                '5xx': 0
            }
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Calculate stats
    for service in web_services:
        status = service['status_code']
        result['stats']['by_status_code'][str(status)] += 1

        # Status code groups
        if 200 <= status < 300:
            result['stats']['status_groups']['2xx'] += 1
        elif 300 <= status < 400:
            result['stats']['status_groups']['3xx'] += 1
        elif 400 <= status < 500:
            result['stats']['status_groups']['4xx'] += 1
        elif 500 <= status < 600:
            result['stats']['status_groups']['5xx'] += 1

        for tech in service['technologies']:
            result['stats']['by_technology'][tech] += 1

        result['stats']['unique_hosts'].add(service['host'])

        if service['tls']:
            result['stats']['with_tls'] += 1
        if service['cdn']['detected']:
            result['stats']['with_cdn'] += 1
        if service['waf']['detected']:
            result['stats']['with_waf'] += 1

    # Convert sets to lists for JSON serialization
    result['stats']['unique_hosts'] = list(result['stats']['unique_hosts'])
    result['stats']['by_status_code'] = dict(result['stats']['by_status_code'])
    result['stats']['by_technology'] = dict(result['stats']['by_technology'])

    # Organize by technology for analysis
    result['by_technology'] = defaultdict(list)
    for service in web_services:
        for tech in service['technologies']:
            result['by_technology'][tech].append({
                'url': service['url'],
                'host': service['host'],
                'status_code': service['status_code'],
                'title': service['title']
            })
    result['by_technology'] = dict(result['by_technology'])

    # Extract interesting findings
    result['interesting'] = {
        'with_vulnerabilities': [],  # Placeholder for enrichment
        'missing_security_headers': [],
        'self_signed_certs': [],
        'expired_certs': [],
        'cdn_hosts': [],
        'waf_hosts': []
    }

    for service in web_services:
        # Check for missing security headers
        sec_headers = service['security_headers']
        missing = []
        if not sec_headers['csp']:
            missing.append('Content-Security-Policy')
        if not sec_headers['frame_options']:
            missing.append('X-Frame-Options')
        if not sec_headers['content_type_options']:
            missing.append('X-Content-Type-Options')
        if service['scheme'] == 'https' and not sec_headers['hsts']:
            missing.append('Strict-Transport-Security')

        if missing:
            result['interesting']['missing_security_headers'].append({
                'url': service['url'],
                'missing': missing
            })

        # Check TLS issues
        if service['tls']:
            if service['tls'].get('self_signed'):
                result['interesting']['self_signed_certs'].append({
                    'url': service['url'],
                    'issuer': service['tls']['issuer']
                })
            if service['tls'].get('expired'):
                result['interesting']['expired_certs'].append({
                    'url': service['url'],
                    'not_after': service['tls']['not_after']
                })

        # CDN and WAF hosts
        if service['cdn']['detected']:
            result['interesting']['cdn_hosts'].append({
                'url': service['url'],
                'cdn': service['cdn']['name']
            })
        if service['waf']['detected']:
            result['interesting']['waf_hosts'].append({
                'url': service['url'],
                'waf': service['waf']['name']
            })

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse httpx JSON output')
    parser.add_argument('file', type=Path, help='HTTPX JSON/JSONL file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_httpx_output(args.file)
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
