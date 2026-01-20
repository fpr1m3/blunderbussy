#!/usr/bin/env python3
"""
Agent Opulence - DNSRecon Output Parser
=======================================
Parses DNSRecon DNS enumeration output into structured JSON.

Usage: parse-dnsrecon.py <dnsrecon_output_file>
Output: JSON to stdout

DNSRecon performs various DNS enumeration techniques including:
- Standard record enumeration (A, AAAA, MX, NS, TXT, SOA, etc.)
- Zone transfer attempts
- Subdomain brute-forcing
- Reverse lookups

Supports both JSON and text output formats.

Extracts:
- All DNS record types
- Discovered subdomains
- Zone transfer vulnerability status
- Interesting findings
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict


def parse_json_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a single DNSRecon JSON record."""
    record_type = record.get('type', '').upper()

    parsed = {
        'type': record_type,
        'name': record.get('name', record.get('mname', '')),
        'raw': record
    }

    # Type-specific parsing
    if record_type == 'A':
        parsed['address'] = record.get('address', '')
    elif record_type == 'AAAA':
        parsed['address'] = record.get('address', '')
    elif record_type == 'MX':
        parsed['exchange'] = record.get('exchange', record.get('address', ''))
        parsed['priority'] = record.get('priority', record.get('preference', 0))
    elif record_type == 'NS':
        parsed['target'] = record.get('target', record.get('address', ''))
    elif record_type == 'TXT':
        parsed['text'] = record.get('strings', record.get('text', record.get('string', '')))
    elif record_type == 'SOA':
        parsed['mname'] = record.get('mname', '')
        parsed['rname'] = record.get('rname', '')
        parsed['serial'] = record.get('serial', 0)
        parsed['refresh'] = record.get('refresh', 0)
        parsed['retry'] = record.get('retry', 0)
        parsed['expire'] = record.get('expire', 0)
        parsed['minimum'] = record.get('minimum', 0)
    elif record_type == 'CNAME':
        parsed['target'] = record.get('target', record.get('address', ''))
    elif record_type == 'SRV':
        parsed['target'] = record.get('target', '')
        parsed['port'] = record.get('port', 0)
        parsed['priority'] = record.get('priority', 0)
        parsed['weight'] = record.get('weight', 0)
    elif record_type == 'PTR':
        parsed['target'] = record.get('target', record.get('address', ''))

    return parsed


def parse_text_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single DNSRecon text output line."""
    line = line.strip()

    # Skip empty lines and headers
    if not line or line.startswith('[*]') and 'Performing' in line:
        return None

    # Check for zone transfer status FIRST (before record parsing)
    # [*] Zone Transfer was successful!!
    if 'Zone Transfer' in line and 'successful' in line.lower():
        return {'type': 'ZONE_TRANSFER', 'vulnerable': True, 'line': line}

    # Failed zone transfer
    if 'Zone Transfer' in line and ('failed' in line.lower() or 'not' in line.lower()):
        return {'type': 'ZONE_TRANSFER', 'vulnerable': False, 'line': line}

    # Parse different record formats
    # Format: [*]      TYPE recordname IP/value (with variable whitespace)
    # Example: [*]      A example.com 93.184.216.34

    match = re.match(r'^\[\*\]\s+(\w+)\s+(\S+)(?:\s+(.+))?$', line)
    if match:
        record_type = match.group(1).upper()
        name = match.group(2)
        value = match.group(3).strip() if match.group(3) else ''

        record = {
            'type': record_type,
            'name': name
        }

        if record_type in ['A', 'AAAA']:
            record['address'] = value
        elif record_type == 'MX':
            # MX record: priority exchange
            parts = value.split()
            if len(parts) >= 2:
                try:
                    record['priority'] = int(parts[0])
                    record['exchange'] = parts[1]
                except ValueError:
                    record['exchange'] = value
            else:
                record['exchange'] = value
        elif record_type == 'NS':
            # NS records may have target in 'name' field if no value
            record['target'] = value if value else name
            if not value:
                record['name'] = ''  # Clear name if it was actually the target
        elif record_type == 'TXT':
            record['text'] = value.strip('"')
        elif record_type == 'CNAME':
            record['target'] = value
        elif record_type == 'SOA':
            # SOA format varies, store raw
            record['raw_value'] = value
        elif record_type == 'SRV':
            # SRV: priority weight port target
            parts = value.split()
            if len(parts) >= 4:
                try:
                    record['priority'] = int(parts[0])
                    record['weight'] = int(parts[1])
                    record['port'] = int(parts[2])
                    record['target'] = parts[3]
                except ValueError:
                    record['target'] = value
            else:
                record['target'] = value
        elif record_type == 'PTR':
            record['target'] = value

        return record

    return None


def extract_target_from_json(data: List[Dict[str, Any]]) -> Optional[str]:
    """Extract target domain from DNSRecon JSON data."""
    for record in data:
        name = record.get('name', record.get('mname', ''))
        if name and '.' in name:
            # Return the root domain
            parts = name.split('.')
            if len(parts) >= 2:
                # Get last two parts (domain.tld)
                return '.'.join(parts[-2:]) if parts[-1] else '.'.join(parts[-3:-1])
    return None


def extract_target_from_text(lines: List[str]) -> Optional[str]:
    """Extract target domain from DNSRecon text output."""
    for line in lines[:20]:
        # Look for target specification
        match = re.search(r'(?:Testing|Enumerating|Target)\s+(?:NS|Servers for|domain)?\s*:?\s*(\S+)', line, re.IGNORECASE)
        if match:
            domain = match.group(1).strip('.')
            if '.' in domain:
                return domain

        # Look for domain in records
        match = re.search(r'\[\*\]\s+\w+\s+(\S+\.\S+)', line)
        if match:
            name = match.group(1)
            parts = name.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:]) if parts[-1] else name

    return None


def detect_format(content: str) -> str:
    """Detect if content is JSON or text format."""
    content = content.strip()
    if content.startswith('[') or content.startswith('{'):
        try:
            json.loads(content)
            return 'json'
        except json.JSONDecodeError:
            pass
    return 'text'


def parse_dnsrecon_json(content: str) -> Dict[str, Any]:
    """Parse DNSRecon JSON format output."""
    data = json.loads(content)

    # Handle both array and object formats
    if isinstance(data, dict):
        records = data.get('records', data.get('results', [data]))
    else:
        records = data

    result = {
        'type': 'dnsrecon',
        'target': extract_target_from_json(records),
        'records': defaultdict(list),
        'subdomains': set(),
        'zone_transfer': {
            'vulnerable': False,
            'servers': []
        },
        'stats': {
            'total_records': 0,
            'record_types': defaultdict(int),
            'interesting': []
        }
    }

    target_domain = result['target']

    for record in records:
        parsed = parse_json_record(record)
        record_type = parsed['type']

        if record_type == 'ZONE_TRANSFER' or record_type == 'info':
            # Handle zone transfer info
            if 'Zone Transfer' in str(record):
                if record.get('zone_transfer') == 'success':
                    result['zone_transfer']['vulnerable'] = True
            continue

        # Add to appropriate record type
        if record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR']:
            result['records'][record_type].append(parsed)
            result['stats']['total_records'] += 1
            result['stats']['record_types'][record_type] += 1

            # Extract subdomains
            name = parsed.get('name', '')
            if name and target_domain and name.endswith(target_domain) and name != target_domain:
                result['subdomains'].add(name)

    return result


def parse_dnsrecon_text(content: str) -> Dict[str, Any]:
    """Parse DNSRecon text format output."""
    lines = content.strip().split('\n')

    result = {
        'type': 'dnsrecon',
        'target': extract_target_from_text(lines),
        'records': defaultdict(list),
        'subdomains': set(),
        'zone_transfer': {
            'vulnerable': False,
            'servers': []
        },
        'stats': {
            'total_records': 0,
            'record_types': defaultdict(int),
            'interesting': []
        }
    }

    target_domain = result['target']

    for line in lines:
        parsed = parse_text_line(line)
        if not parsed:
            continue

        record_type = parsed.get('type', '')

        # Handle zone transfer status
        if record_type == 'ZONE_TRANSFER':
            if parsed.get('vulnerable'):
                result['zone_transfer']['vulnerable'] = True
                # Try to extract server from line
                match = re.search(r'(\S+\.\S+)', parsed.get('line', ''))
                if match:
                    result['zone_transfer']['servers'].append(match.group(1))
            continue

        # Add to appropriate record type
        if record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR']:
            result['records'][record_type].append(parsed)
            result['stats']['total_records'] += 1
            result['stats']['record_types'][record_type] += 1

            # Extract subdomains
            name = parsed.get('name', '')
            if name and target_domain and name.endswith(target_domain) and name != target_domain:
                result['subdomains'].add(name)

    return result


def identify_interesting(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Identify interesting DNS findings."""
    interesting = []

    # Zone transfer vulnerability is critical
    if result['zone_transfer']['vulnerable']:
        interesting.append({
            'type': 'zone_transfer',
            'severity': 'high',
            'description': 'Zone transfer is allowed',
            'servers': result['zone_transfer']['servers']
        })

    # Check for interesting TXT records
    for txt in result['records'].get('TXT', []):
        text = str(txt.get('text', '')).lower()

        # SPF records
        if 'v=spf' in text:
            interesting.append({
                'type': 'spf_record',
                'severity': 'info',
                'description': 'SPF record found',
                'value': txt.get('text', '')
            })

        # DMARC
        if 'v=dmarc' in text:
            interesting.append({
                'type': 'dmarc_record',
                'severity': 'info',
                'description': 'DMARC record found',
                'value': txt.get('text', '')
            })

        # DKIM
        if 'v=dkim' in text:
            interesting.append({
                'type': 'dkim_record',
                'severity': 'info',
                'description': 'DKIM record found',
                'value': txt.get('text', '')
            })

        # Verification records (might leak info)
        verification_services = ['google-site-verification', 'facebook-domain-verification',
                                  'ms=', 'docusign', 'adobe-idp-site-verification']
        for svc in verification_services:
            if svc in text:
                interesting.append({
                    'type': 'verification_record',
                    'severity': 'info',
                    'description': f'Third-party verification record found',
                    'value': txt.get('text', '')
                })
                break

    # Multiple MX records might indicate mail infrastructure
    mx_records = result['records'].get('MX', [])
    if len(mx_records) > 1:
        interesting.append({
            'type': 'multiple_mx',
            'severity': 'info',
            'description': f'Multiple MX records found ({len(mx_records)})',
            'records': [mx.get('exchange', '') for mx in mx_records]
        })

    # Subdomains are always interesting
    subdomains = list(result.get('subdomains', []))
    if subdomains:
        # Look for interesting subdomain patterns
        interesting_subdomain_patterns = [
            'admin', 'dev', 'test', 'stage', 'staging', 'uat', 'api',
            'internal', 'intranet', 'vpn', 'remote', 'mail', 'webmail',
            'ftp', 'ssh', 'git', 'jenkins', 'ci', 'cd', 'backup'
        ]

        for subdomain in subdomains:
            for pattern in interesting_subdomain_patterns:
                if pattern in subdomain.lower():
                    interesting.append({
                        'type': 'interesting_subdomain',
                        'severity': 'info',
                        'description': f'Potentially sensitive subdomain found',
                        'subdomain': subdomain,
                        'pattern': pattern
                    })
                    break

    return interesting


def parse_dnsrecon(file_path: Path) -> Dict[str, Any]:
    """Parse DNSRecon output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    # Detect format and parse accordingly
    fmt = detect_format(content)

    if fmt == 'json':
        result = parse_dnsrecon_json(content)
    else:
        result = parse_dnsrecon_text(content)

    # Convert defaultdicts and sets for JSON serialization
    result['records'] = {k: list(v) for k, v in result['records'].items()}
    result['subdomains'] = sorted(list(result['subdomains']))
    result['stats']['record_types'] = dict(result['stats']['record_types'])

    # Add interesting findings
    result['stats']['interesting'] = identify_interesting(result)

    # Add metadata
    result['raw_file'] = str(file_path)
    result['parsed_at'] = datetime.now(timezone.utc).isoformat()

    # Ensure all record types exist (even if empty)
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR']:
        if rtype not in result['records']:
            result['records'][rtype] = []

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse DNSRecon output')
    parser.add_argument('file', type=Path, help='DNSRecon output file (JSON or text)')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_dnsrecon(args.file)
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
