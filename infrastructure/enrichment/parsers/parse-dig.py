#!/usr/bin/env python3
"""
Agent Opulence - dig Output Parser
===================================
Parses dig DNS query output into structured JSON.

Usage: parse-dig.py <dig_output_file>
Output: JSON to stdout

dig performs DNS lookups and displays the answers returned from the name server(s).
This parser extracts DNS records from dig's detailed output format.

Extracts:
- Query parameters (target, query type, server)
- Status and flags
- DNS records by type (A, AAAA, MX, NS, TXT, CNAME, SOA, etc.)
- Query statistics (time, message size)
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict


def parse_header(lines: List[str]) -> Dict[str, Any]:
    """Parse the dig header section."""
    header = {
        'status': None,
        'id': None,
        'flags': [],
        'query_count': 0,
        'answer_count': 0,
        'authority_count': 0,
        'additional_count': 0
    }

    for line in lines:
        # Parse header line: opcode: QUERY, status: NOERROR, id: 12345
        if '->>HEADER<<-' in line:
            # Extract status
            status_match = re.search(r'status:\s+(\w+)', line)
            if status_match:
                header['status'] = status_match.group(1)

            # Extract id
            id_match = re.search(r'id:\s+(\d+)', line)
            if id_match:
                header['id'] = int(id_match.group(1))

        # Parse flags line: flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1
        if line.strip().startswith(';; flags:') or (';; flags' in line and 'QUERY:' in line):
            # Extract flags
            flags_match = re.search(r'flags:\s+([^;]+)', line)
            if flags_match:
                flags_str = flags_match.group(1).strip()
                header['flags'] = flags_str.split()

            # Extract counts
            query_match = re.search(r'QUERY:\s+(\d+)', line)
            answer_match = re.search(r'ANSWER:\s+(\d+)', line)
            authority_match = re.search(r'AUTHORITY:\s+(\d+)', line)
            additional_match = re.search(r'ADDITIONAL:\s+(\d+)', line)

            if query_match:
                header['query_count'] = int(query_match.group(1))
            if answer_match:
                header['answer_count'] = int(answer_match.group(1))
            if authority_match:
                header['authority_count'] = int(authority_match.group(1))
            if additional_match:
                header['additional_count'] = int(additional_match.group(1))

    return header


def parse_question(lines: List[str]) -> Optional[Dict[str, str]]:
    """Parse the QUESTION SECTION."""
    for line in lines:
        # Format: ;example.com.                   IN      ANY
        if line.startswith(';') and not line.startswith(';;'):
            match = re.match(r';(\S+)\.\s+IN\s+(\w+)', line)
            if match:
                return {
                    'name': match.group(1),
                    'query_type': match.group(2)
                }
    return None


def parse_record_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single DNS record line from the ANSWER section."""
    # Skip empty lines and comments
    if not line.strip() or line.strip().startswith(';'):
        return None

    # Standard format: name.  TTL  IN  TYPE  [priority]  value
    # Example: example.com.            300     IN      A       93.184.216.34
    # Example: example.com.            300     IN      MX      10 mail.example.com.

    parts = line.split()
    if len(parts) < 5:
        return None

    try:
        name = parts[0].rstrip('.')
        ttl = int(parts[1])
        record_class = parts[2]  # Usually "IN"
        record_type = parts[3].upper()

        if record_class != 'IN':
            # Some formats omit the class, try parsing differently
            # name.  TTL  TYPE  value
            if len(parts) >= 4:
                ttl = int(parts[1])
                record_type = parts[2].upper()
                value_parts = parts[3:]
            else:
                return None
        else:
            value_parts = parts[4:]

        record = {
            'name': name,
            'ttl': ttl,
            'type': record_type
        }

        # Type-specific parsing
        if record_type in ['A', 'AAAA']:
            record['value'] = value_parts[0] if value_parts else ''

        elif record_type == 'MX':
            if len(value_parts) >= 2:
                record['priority'] = int(value_parts[0])
                record['value'] = value_parts[1].rstrip('.')
            else:
                record['value'] = ' '.join(value_parts)

        elif record_type in ['NS', 'CNAME', 'PTR']:
            record['value'] = value_parts[0].rstrip('.') if value_parts else ''

        elif record_type == 'TXT':
            # TXT records are quoted strings, may span multiple parts
            txt_value = ' '.join(value_parts)
            # Remove surrounding quotes
            record['value'] = txt_value.strip('"')

        elif record_type == 'SOA':
            # SOA: mname rname serial refresh retry expire minimum
            if len(value_parts) >= 7:
                record['mname'] = value_parts[0].rstrip('.')
                record['rname'] = value_parts[1].rstrip('.')
                record['serial'] = int(value_parts[2])
                record['refresh'] = int(value_parts[3])
                record['retry'] = int(value_parts[4])
                record['expire'] = int(value_parts[5])
                record['minimum'] = int(value_parts[6])
            else:
                record['value'] = ' '.join(value_parts)

        elif record_type == 'SRV':
            # SRV: priority weight port target
            if len(value_parts) >= 4:
                record['priority'] = int(value_parts[0])
                record['weight'] = int(value_parts[1])
                record['port'] = int(value_parts[2])
                record['value'] = value_parts[3].rstrip('.')
            else:
                record['value'] = ' '.join(value_parts)

        else:
            # Generic handling for other record types
            record['value'] = ' '.join(value_parts)

        return record

    except (ValueError, IndexError):
        return None


def parse_records(lines: List[str], section_name: str) -> List[Dict[str, Any]]:
    """Parse records from a specific section (ANSWER, AUTHORITY, ADDITIONAL)."""
    records = []
    in_section = False

    for line in lines:
        # Check for section header
        if f';; {section_name} SECTION:' in line:
            in_section = True
            continue

        # Stop at next section
        if in_section and line.startswith(';;') and 'SECTION:' in line:
            break

        # Parse record if in section
        if in_section:
            record = parse_record_line(line)
            if record:
                records.append(record)

    return records


def parse_stats(lines: List[str]) -> Dict[str, Any]:
    """Parse query statistics from the footer."""
    stats = {
        'query_time_ms': None,
        'server': None,
        'server_port': 53,
        'when': None,
        'msg_size': None
    }

    for line in lines:
        # Query time: 50 msec
        if line.startswith(';; Query time:'):
            match = re.search(r'(\d+)\s+msec', line)
            if match:
                stats['query_time_ms'] = int(match.group(1))

        # SERVER: 192.168.1.1#53(192.168.1.1)
        elif line.startswith(';; SERVER:'):
            match = re.search(r'SERVER:\s+([^#\s]+)(?:#(\d+))?', line)
            if match:
                stats['server'] = match.group(1)
                if match.group(2):
                    stats['server_port'] = int(match.group(2))

        # WHEN: Mon Jan 20 10:00:00 PST 2026
        elif line.startswith(';; WHEN:'):
            stats['when'] = line.split('WHEN:', 1)[1].strip()

        # MSG SIZE  rcvd: 256
        elif line.startswith(';; MSG SIZE'):
            match = re.search(r'rcvd:\s+(\d+)', line)
            if match:
                stats['msg_size'] = int(match.group(1))

    return stats


def extract_target_from_header(lines: List[str]) -> Optional[str]:
    """Extract target domain from dig command header."""
    for line in lines[:10]:
        # ; <<>> DiG 9.16.1-Ubuntu <<>> example.com ANY
        if '<<>>' in line and 'DiG' in line:
            # Extract domain (usually second to last or third to last element)
            parts = line.split()
            for part in reversed(parts):
                # Look for domain-like string (contains dots, not a flag)
                if '.' in part and not part.startswith('-') and not part.startswith(';'):
                    return part.rstrip('.')
    return None


def parse_dig(file_path: Path) -> Dict[str, Any]:
    """Parse dig output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.split('\n')

    # Parse components
    header = parse_header(lines)
    question = parse_question(lines)
    answer_records = parse_records(lines, 'ANSWER')
    authority_records = parse_records(lines, 'AUTHORITY')
    additional_records = parse_records(lines, 'ADDITIONAL')
    stats = parse_stats(lines)

    # Determine target and query type
    target = None
    query_type = None

    if question:
        target = question['name']
        query_type = question['query_type']
    else:
        # Try to extract from header
        target = extract_target_from_header(lines)
        # Try to infer query type from records
        if answer_records:
            query_type = answer_records[0]['type']

    # Organize records by type
    records_by_type = defaultdict(list)
    all_records = answer_records + authority_records + additional_records

    for record in all_records:
        record_type = record.get('type', 'UNKNOWN')
        records_by_type[record_type].append(record)

    # Count record types
    record_type_counts = {k: len(v) for k, v in records_by_type.items()}

    # Build result
    result = {
        'type': 'dig',
        'target': target,
        'query_type': query_type,
        'server': stats.get('server'),
        'server_port': stats.get('server_port', 53),
        'status': header.get('status'),
        'flags': header.get('flags', []),
        'records': dict(records_by_type),
        'stats': {
            'total_records': len(answer_records),
            'record_types': record_type_counts,
            'query_time_ms': stats.get('query_time_ms'),
            'msg_size': stats.get('msg_size'),
            'answer_count': header.get('answer_count', 0),
            'authority_count': header.get('authority_count', 0),
            'additional_count': header.get('additional_count', 0)
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse dig output')
    parser.add_argument('file', type=Path, help='dig output file')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_dig(args.file)
        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': str(e), 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
