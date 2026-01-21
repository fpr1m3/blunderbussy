#!/usr/bin/env python3
"""
Agent Opulence - Impacket rpcdump Output Parser
================================================
Parses Impacket rpcdump RPC endpoint enumeration output into structured JSON.

Usage: parse-rpcdump.py <rpcdump_output_file>
Output: JSON to stdout

Impacket's rpcdump.py enumerates RPC endpoints on remote systems, revealing
exposed services and protocols that can be used for lateral movement,
privilege escalation, and exploitation.
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def parse_binding(binding_line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single RPC binding line.

    Formats:
    - ncacn_np:\\\\10.10.10.100[\\pipe\\samr]
    - ncacn_ip_tcp:10.10.10.100[49664]
    - ncalrpc:[LRPC-1234abcd]
    """
    binding_line = binding_line.strip()

    # Named pipe binding: ncacn_np:\\server[\pipe\name]
    match = re.match(r'ncacn_np:\\\\([^\\]+)\[(.+)\]', binding_line)
    if match:
        return {
            'type': 'ncacn_np',
            'address': match.group(1),
            'endpoint': match.group(2)
        }

    # TCP/IP binding: ncacn_ip_tcp:host[port]
    match = re.match(r'ncacn_ip_tcp:([^:\[]+)\[(\d+)\]', binding_line)
    if match:
        return {
            'type': 'ncacn_ip_tcp',
            'address': match.group(1),
            'port': int(match.group(2))
        }

    # Local RPC: ncalrpc:[endpoint]
    match = re.match(r'ncalrpc:\[(.+)\]', binding_line)
    if match:
        return {
            'type': 'ncalrpc',
            'endpoint': match.group(1)
        }

    # HTTP/HTTPS bindings: ncacn_http:host:port
    match = re.match(r'ncacn_http:([^:]+):(\d+)', binding_line)
    if match:
        return {
            'type': 'ncacn_http',
            'address': match.group(1),
            'port': int(match.group(2))
        }

    # Fallback: return raw binding
    if binding_line:
        return {
            'type': 'unknown',
            'raw': binding_line
        }

    return None


def extract_protocol_name(protocol_line: str) -> tuple[Optional[str], Optional[str]]:
    """
    Extract protocol short name and full name.

    Example: "Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol"
    Returns: ("MS-SAMR", "Security Account Manager (SAM) Remote Protocol")
    """
    match = re.match(r'Protocol:\s*\[([^\]]+)\]:\s*(.+)', protocol_line.strip())
    if match:
        return match.group(1), match.group(2)

    # Fallback: no brackets
    match = re.match(r'Protocol:\s*(.+)', protocol_line.strip())
    if match:
        full_name = match.group(1).strip()
        return None, full_name

    return None, None


def extract_target(lines: List[str]) -> Optional[str]:
    """Extract target IP/hostname from rpcdump output."""
    for line in lines[:20]:
        # Look for "Retrieving endpoint list from X"
        match = re.search(r'Retrieving endpoint list from\s+(\S+)', line, re.IGNORECASE)
        if match:
            return match.group(1)

        # Look for IP addresses in bindings
        match = re.search(r'(?:ncacn_\w+:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if match:
            return match.group(1)

    return None


def classify_protocol_risk(protocol: str, protocol_name: str) -> List[str]:
    """
    Identify security-relevant protocols and their implications.

    Returns list of security notes for the protocol.
    """
    notes = []

    protocol_upper = protocol.upper() if protocol else ""
    name_upper = protocol_name.upper() if protocol_name else ""

    # Critical protocols for exploitation
    if 'MS-SAMR' in protocol_upper or 'SAMR' in name_upper:
        notes.append("MS-SAMR exposed - potential user enumeration")
        notes.append("SAMR allows password policy queries")

    if 'MS-SCMR' in protocol_upper or 'SERVICE CONTROL' in name_upper:
        notes.append("MS-SCMR exposed - service control")
        notes.append("SCMR allows remote service manipulation")

    if 'MS-DRSR' in protocol_upper or 'DIRECTORY REPLICATION' in name_upper:
        notes.append("MS-DRSR exposed - AD replication service")
        notes.append("DRSR vulnerable to DCSync attacks")

    if 'MS-RPRN' in protocol_upper or 'PRINT' in name_upper:
        notes.append("MS-RPRN exposed - printer exploitation")
        notes.append("RPRN vulnerable to PrintNightmare and coercion attacks")

    if 'MS-EFSR' in protocol_upper or 'EFS' in name_upper:
        notes.append("MS-EFSR exposed - encryption file system")
        notes.append("EFSR vulnerable to PetitPotam coerced authentication")

    if 'MS-WKST' in protocol_upper or 'WORKSTATION' in name_upper:
        notes.append("MS-WKST exposed - workstation service")
        notes.append("WKST allows system information enumeration")

    if 'MS-EVEN' in protocol_upper or 'EVENT LOG' in name_upper:
        notes.append("MS-EVEN exposed - event log access")
        notes.append("EVEN allows security event log reading")

    if 'MS-TSCH' in protocol_upper or 'TASK SCHEDULER' in name_upper:
        notes.append("MS-TSCH exposed - task scheduler")
        notes.append("TSCH allows scheduled task manipulation for persistence")

    if 'MS-DCOM' in protocol_upper or 'DCOM' in name_upper:
        notes.append("MS-DCOM exposed - distributed COM")
        notes.append("DCOM can be used for lateral movement")

    if 'MS-WMI' in protocol_upper or 'WMI' in name_upper:
        notes.append("MS-WMI exposed - Windows Management Instrumentation")
        notes.append("WMI enables remote command execution")

    return notes


def parse_rpcdump(file_path: Path) -> Dict[str, Any]:
    """Parse rpcdump output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.strip().split('\n')

    result = {
        'type': 'rpcdump',
        'target': extract_target(lines),
        'endpoints': [],
        'stats': {
            'total_endpoints': 0,
            'protocols_found': [],
            'interesting': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # State machine for parsing
    current_endpoint = None
    in_bindings = False

    for line in lines:
        line = line.strip()

        # Skip empty lines
        if not line:
            if current_endpoint and in_bindings:
                # End of bindings section
                in_bindings = False
            continue

        # Skip header lines
        if line.startswith('Impacket') or line.startswith('[*]') or line.startswith('[+]'):
            continue

        # New protocol entry
        if line.startswith('Protocol:'):
            # Save previous endpoint
            if current_endpoint:
                result['endpoints'].append(current_endpoint)

            protocol, protocol_name = extract_protocol_name(line)
            current_endpoint = {
                'protocol': protocol,
                'protocol_name': protocol_name,
                'provider': None,
                'uuid': None,
                'version': None,
                'bindings': []
            }
            in_bindings = False

        # Provider
        elif line.startswith('Provider:') and current_endpoint:
            current_endpoint['provider'] = line.split(':', 1)[1].strip()

        # UUID and version
        elif line.startswith('UUID') and current_endpoint:
            # Format: UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0
            match = re.search(r'UUID\s*:\s*([0-9A-Fa-f-]+)\s+v?([\d.]+)', line)
            if match:
                current_endpoint['uuid'] = match.group(1)
                current_endpoint['version'] = match.group(2)

        # Bindings section
        elif line.startswith('Bindings:'):
            in_bindings = True

        # Binding entry (indented lines after "Bindings:")
        elif in_bindings and current_endpoint:
            binding = parse_binding(line)
            if binding:
                current_endpoint['bindings'].append(binding)

    # Save last endpoint
    if current_endpoint:
        result['endpoints'].append(current_endpoint)

    # Calculate statistics
    result['stats']['total_endpoints'] = len(result['endpoints'])

    for endpoint in result['endpoints']:
        protocol = endpoint.get('protocol', '')
        protocol_name = endpoint.get('protocol_name', '')

        if protocol and protocol not in result['stats']['protocols_found']:
            result['stats']['protocols_found'].append(protocol)

        # Identify interesting/risky protocols
        notes = classify_protocol_risk(protocol, protocol_name)
        for note in notes:
            if note not in result['stats']['interesting']:
                result['stats']['interesting'].append(note)

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse Impacket rpcdump output')
    parser.add_argument('file', type=Path, help='rpcdump output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_rpcdump(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
