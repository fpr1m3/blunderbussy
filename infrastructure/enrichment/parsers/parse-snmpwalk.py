#!/usr/bin/env python3
"""
Agent Opulence - SNMPWalk Output Parser
=======================================
Parses snmpwalk output into structured JSON for enrichment pipeline.

Usage: parse-snmpwalk.py <snmpwalk_output_file>
Output: JSON to stdout

SNMPWalk enumerates SNMP MIB data from network devices:
- System information (sysDescr, sysName, sysLocation, etc.)
- Network interfaces and configuration
- Running processes
- User accounts
- Storage/disk information
- Installed software
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone


# Common OID mappings for human-readable names
OID_NAMES = {
    # System MIB (1.3.6.1.2.1.1)
    '1.3.6.1.2.1.1.1': 'sysDescr',
    '1.3.6.1.2.1.1.2': 'sysObjectID',
    '1.3.6.1.2.1.1.3': 'sysUpTime',
    '1.3.6.1.2.1.1.4': 'sysContact',
    '1.3.6.1.2.1.1.5': 'sysName',
    '1.3.6.1.2.1.1.6': 'sysLocation',
    '1.3.6.1.2.1.1.7': 'sysServices',

    # Interface MIB (1.3.6.1.2.1.2)
    '1.3.6.1.2.1.2.1': 'ifNumber',
    '1.3.6.1.2.1.2.2.1.1': 'ifIndex',
    '1.3.6.1.2.1.2.2.1.2': 'ifDescr',
    '1.3.6.1.2.1.2.2.1.3': 'ifType',
    '1.3.6.1.2.1.2.2.1.4': 'ifMtu',
    '1.3.6.1.2.1.2.2.1.5': 'ifSpeed',
    '1.3.6.1.2.1.2.2.1.6': 'ifPhysAddress',
    '1.3.6.1.2.1.2.2.1.7': 'ifAdminStatus',
    '1.3.6.1.2.1.2.2.1.8': 'ifOperStatus',

    # IP MIB (1.3.6.1.2.1.4)
    '1.3.6.1.2.1.4.20.1.1': 'ipAdEntAddr',
    '1.3.6.1.2.1.4.20.1.2': 'ipAdEntIfIndex',
    '1.3.6.1.2.1.4.20.1.3': 'ipAdEntNetMask',

    # TCP MIB (1.3.6.1.2.1.6)
    '1.3.6.1.2.1.6.13.1.1': 'tcpConnState',
    '1.3.6.1.2.1.6.13.1.2': 'tcpConnLocalAddress',
    '1.3.6.1.2.1.6.13.1.3': 'tcpConnLocalPort',
    '1.3.6.1.2.1.6.13.1.4': 'tcpConnRemAddress',
    '1.3.6.1.2.1.6.13.1.5': 'tcpConnRemPort',

    # UDP MIB (1.3.6.1.2.1.7)
    '1.3.6.1.2.1.7.5.1.1': 'udpLocalAddress',
    '1.3.6.1.2.1.7.5.1.2': 'udpLocalPort',

    # Host Resources MIB (1.3.6.1.2.1.25)
    '1.3.6.1.2.1.25.1.1': 'hrSystemUptime',
    '1.3.6.1.2.1.25.1.2': 'hrSystemDate',
    '1.3.6.1.2.1.25.1.4': 'hrSystemInitialLoadDevice',
    '1.3.6.1.2.1.25.1.5': 'hrSystemInitialLoadParameters',
    '1.3.6.1.2.1.25.1.6': 'hrSystemNumUsers',
    '1.3.6.1.2.1.25.1.7': 'hrSystemProcesses',
    '1.3.6.1.2.1.25.2.2': 'hrMemorySize',

    # Storage (1.3.6.1.2.1.25.2.3)
    '1.3.6.1.2.1.25.2.3.1.1': 'hrStorageIndex',
    '1.3.6.1.2.1.25.2.3.1.2': 'hrStorageType',
    '1.3.6.1.2.1.25.2.3.1.3': 'hrStorageDescr',
    '1.3.6.1.2.1.25.2.3.1.4': 'hrStorageAllocationUnits',
    '1.3.6.1.2.1.25.2.3.1.5': 'hrStorageSize',
    '1.3.6.1.2.1.25.2.3.1.6': 'hrStorageUsed',

    # Device MIB (1.3.6.1.2.1.25.3)
    '1.3.6.1.2.1.25.3.2.1.1': 'hrDeviceIndex',
    '1.3.6.1.2.1.25.3.2.1.2': 'hrDeviceType',
    '1.3.6.1.2.1.25.3.2.1.3': 'hrDeviceDescr',

    # Processes (1.3.6.1.2.1.25.4)
    '1.3.6.1.2.1.25.4.2.1.1': 'hrSWRunIndex',
    '1.3.6.1.2.1.25.4.2.1.2': 'hrSWRunName',
    '1.3.6.1.2.1.25.4.2.1.4': 'hrSWRunPath',
    '1.3.6.1.2.1.25.4.2.1.5': 'hrSWRunParameters',
    '1.3.6.1.2.1.25.4.2.1.6': 'hrSWRunType',
    '1.3.6.1.2.1.25.4.2.1.7': 'hrSWRunStatus',

    # Installed Software (1.3.6.1.2.1.25.6)
    '1.3.6.1.2.1.25.6.3.1.1': 'hrSWInstalledIndex',
    '1.3.6.1.2.1.25.6.3.1.2': 'hrSWInstalledName',
    '1.3.6.1.2.1.25.6.3.1.3': 'hrSWInstalledID',
    '1.3.6.1.2.1.25.6.3.1.4': 'hrSWInstalledType',
    '1.3.6.1.2.1.25.6.3.1.5': 'hrSWInstalledDate',

    # SNMP MIB (1.3.6.1.2.1.11)
    '1.3.6.1.2.1.11.1': 'snmpInPkts',
    '1.3.6.1.2.1.11.2': 'snmpOutPkts',

    # Cisco specific
    '1.3.6.1.4.1.9.2.1.1': 'locIfDescr',
    '1.3.6.1.4.1.9.9.23.1.2.1.1.6': 'cdpCacheDeviceId',

    # NET-SNMP specific
    '1.3.6.1.4.1.8072.1.3.2.2.1.2': 'nsExtendOutput1Line',
    '1.3.6.1.4.1.8072.1.3.2.3.1.1': 'nsExtendCommand',
    '1.3.6.1.4.1.8072.1.3.2.3.1.2': 'nsExtendArgs',
}

# Interesting OIDs for security purposes
INTERESTING_OIDS = {
    'hrSWRunName', 'hrSWRunPath', 'hrSWRunParameters',  # Running processes
    'hrSWInstalledName',  # Installed software
    'sysDescr', 'sysName', 'sysContact', 'sysLocation',  # System info
    'ifDescr', 'ifPhysAddress', 'ipAdEntAddr',  # Network info
    'nsExtendCommand', 'nsExtendArgs', 'nsExtendOutput1Line',  # NET-SNMP extensions
}


def get_oid_name(oid: str) -> str:
    """Get human-readable name for an OID."""
    # Try exact match first
    if oid in OID_NAMES:
        return OID_NAMES[oid]

    # Try to find base OID match
    for base_oid, name in OID_NAMES.items():
        if oid.startswith(base_oid + '.'):
            return name

    # Extract last component for unknown OIDs
    parts = oid.split('.')
    if len(parts) > 0:
        return f"oid-{parts[-1]}"

    return 'unknown'


def parse_snmp_value(value_str: str) -> Tuple[str, Any]:
    """Parse SNMP value and return (type, value) tuple."""
    value_str = value_str.strip()

    # STRING: "value"
    match = re.match(r'STRING:\s*"?([^"]*)"?', value_str)
    if match:
        return ('STRING', match.group(1).strip())

    # INTEGER: 42
    match = re.match(r'INTEGER:\s*(\d+)', value_str)
    if match:
        return ('INTEGER', int(match.group(1)))

    # Gauge32: 12345
    match = re.match(r'Gauge32:\s*(\d+)', value_str)
    if match:
        return ('Gauge32', int(match.group(1)))

    # Counter32: 12345
    match = re.match(r'Counter32:\s*(\d+)', value_str)
    if match:
        return ('Counter32', int(match.group(1)))

    # Counter64: 12345
    match = re.match(r'Counter64:\s*(\d+)', value_str)
    if match:
        return ('Counter64', int(match.group(1)))

    # Timeticks: (12345) 0:02:03.45
    match = re.match(r'Timeticks:\s*\((\d+)\)\s*(.*)', value_str)
    if match:
        return ('Timeticks', {'raw': int(match.group(1)), 'formatted': match.group(2).strip()})

    # OID: .1.3.6.1.x.x.x
    match = re.match(r'OID:\s*\.?(.+)', value_str)
    if match:
        return ('OID', match.group(1).strip())

    # IpAddress: 192.168.1.1
    match = re.match(r'IpAddress:\s*(\d+\.\d+\.\d+\.\d+)', value_str)
    if match:
        return ('IpAddress', match.group(1))

    # Hex-STRING: XX XX XX XX
    match = re.match(r'Hex-STRING:\s*(.+)', value_str)
    if match:
        hex_val = match.group(1).strip()
        # Try to convert to MAC address if it looks like one
        hex_bytes = hex_val.split()
        if len(hex_bytes) == 6:
            return ('Hex-STRING', ':'.join(hex_bytes))
        return ('Hex-STRING', hex_val)

    # Network Address
    match = re.match(r'Network Address:\s*(.+)', value_str)
    if match:
        return ('Network Address', match.group(1).strip())

    # NULL or empty
    if value_str == '' or 'No Such' in value_str or 'NULL' in value_str:
        return ('NULL', None)

    # Default: treat as string
    return ('STRING', value_str)


def parse_snmp_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single SNMP output line."""
    line = line.strip()

    if not line or line.startswith('#'):
        return None

    # Format 1: .1.3.6.1.2.1.1.1.0 = STRING: "Linux host 5.4.0"
    # Format 2: iso.3.6.1.2.1.1.1.0 = STRING: "Linux host 5.4.0"
    # Format 3: SNMPv2-MIB::sysDescr.0 = STRING: "Linux host 5.4.0"

    # Try numeric OID format first
    match = re.match(r'\.?([\d.]+)\s*=\s*(.+)', line)
    if match:
        oid = match.group(1)
        value_type, value = parse_snmp_value(match.group(2))
        return {
            'oid': oid,
            'oid_name': get_oid_name(oid),
            'type': value_type,
            'value': value
        }

    # Try iso. format (convert to numeric)
    match = re.match(r'iso\.([\d.]+)\s*=\s*(.+)', line)
    if match:
        oid = '1.' + match.group(1)
        value_type, value = parse_snmp_value(match.group(2))
        return {
            'oid': oid,
            'oid_name': get_oid_name(oid),
            'type': value_type,
            'value': value
        }

    # Try MIB name format
    match = re.match(r'(\S+)::(\S+)\s*=\s*(.+)', line)
    if match:
        mib_name = match.group(1)
        oid_suffix = match.group(2)
        value_type, value = parse_snmp_value(match.group(3))
        return {
            'oid': f"{mib_name}::{oid_suffix}",
            'oid_name': oid_suffix.split('.')[0],
            'type': value_type,
            'value': value
        }

    return None


def extract_system_info(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract system information from parsed entries."""
    system_info = {
        'description': None,
        'contact': None,
        'name': None,
        'location': None,
        'uptime': None,
        'object_id': None,
        'services': None,
        'num_users': None,
        'num_processes': None,
        'memory_size': None
    }

    for entry in entries:
        oid_name = entry.get('oid_name', '')
        value = entry.get('value')

        if value is None:
            continue

        if oid_name == 'sysDescr':
            system_info['description'] = str(value)
        elif oid_name == 'sysContact':
            system_info['contact'] = str(value)
        elif oid_name == 'sysName':
            system_info['name'] = str(value)
        elif oid_name == 'sysLocation':
            system_info['location'] = str(value)
        elif oid_name == 'sysUpTime':
            if isinstance(value, dict):
                system_info['uptime'] = value.get('formatted', str(value.get('raw')))
            else:
                system_info['uptime'] = str(value)
        elif oid_name == 'sysObjectID':
            system_info['object_id'] = str(value)
        elif oid_name == 'sysServices':
            system_info['services'] = value
        elif oid_name == 'hrSystemNumUsers':
            system_info['num_users'] = value
        elif oid_name == 'hrSystemProcesses':
            system_info['num_processes'] = value
        elif oid_name == 'hrMemorySize':
            system_info['memory_size'] = value

    return system_info


def extract_interfaces(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract network interface information."""
    interfaces = {}

    for entry in entries:
        oid = entry.get('oid', '')
        oid_name = entry.get('oid_name', '')
        value = entry.get('value')

        if value is None:
            continue

        # Extract interface index from OID
        if oid_name in ['ifIndex', 'ifDescr', 'ifType', 'ifMtu', 'ifSpeed',
                        'ifPhysAddress', 'ifAdminStatus', 'ifOperStatus']:
            parts = oid.split('.')
            if parts:
                idx = parts[-1]
                if idx not in interfaces:
                    interfaces[idx] = {'index': idx}

                if oid_name == 'ifDescr':
                    interfaces[idx]['description'] = str(value)
                elif oid_name == 'ifPhysAddress':
                    interfaces[idx]['mac_address'] = str(value)
                elif oid_name == 'ifType':
                    interfaces[idx]['type'] = value
                elif oid_name == 'ifMtu':
                    interfaces[idx]['mtu'] = value
                elif oid_name == 'ifSpeed':
                    interfaces[idx]['speed'] = value
                elif oid_name == 'ifAdminStatus':
                    interfaces[idx]['admin_status'] = 'up' if value == 1 else 'down'
                elif oid_name == 'ifOperStatus':
                    interfaces[idx]['oper_status'] = 'up' if value == 1 else 'down'

    return list(interfaces.values())


def extract_ip_addresses(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract IP address information."""
    addresses = {}

    for entry in entries:
        oid = entry.get('oid', '')
        oid_name = entry.get('oid_name', '')
        value = entry.get('value')

        if oid_name == 'ipAdEntAddr' and value:
            # IP is both the index and value
            addresses[str(value)] = {'address': str(value)}
        elif oid_name == 'ipAdEntNetMask' and value:
            # Extract IP from OID suffix
            parts = oid.split('.')
            if len(parts) >= 4:
                ip = '.'.join(parts[-4:])
                if ip in addresses:
                    addresses[ip]['netmask'] = str(value)

    return list(addresses.values())


def extract_processes(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract running process information."""
    processes = {}

    for entry in entries:
        oid = entry.get('oid', '')
        oid_name = entry.get('oid_name', '')
        value = entry.get('value')

        if value is None:
            continue

        # Extract process index from OID
        if oid_name in ['hrSWRunName', 'hrSWRunPath', 'hrSWRunParameters',
                        'hrSWRunType', 'hrSWRunStatus']:
            parts = oid.split('.')
            if parts:
                idx = parts[-1]
                if idx not in processes:
                    processes[idx] = {'pid': idx}

                if oid_name == 'hrSWRunName':
                    processes[idx]['name'] = str(value)
                elif oid_name == 'hrSWRunPath':
                    processes[idx]['path'] = str(value)
                elif oid_name == 'hrSWRunParameters':
                    processes[idx]['parameters'] = str(value)
                elif oid_name == 'hrSWRunType':
                    type_map = {1: 'unknown', 2: 'operatingSystem', 3: 'deviceDriver', 4: 'application'}
                    processes[idx]['type'] = type_map.get(value, str(value))
                elif oid_name == 'hrSWRunStatus':
                    status_map = {1: 'running', 2: 'runnable', 3: 'notRunnable', 4: 'invalid'}
                    processes[idx]['status'] = status_map.get(value, str(value))

    return list(processes.values())


def extract_storage(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract storage/disk information."""
    storage = {}

    for entry in entries:
        oid = entry.get('oid', '')
        oid_name = entry.get('oid_name', '')
        value = entry.get('value')

        if value is None:
            continue

        if oid_name in ['hrStorageIndex', 'hrStorageDescr', 'hrStorageType',
                        'hrStorageAllocationUnits', 'hrStorageSize', 'hrStorageUsed']:
            parts = oid.split('.')
            if parts:
                idx = parts[-1]
                if idx not in storage:
                    storage[idx] = {'index': idx}

                if oid_name == 'hrStorageDescr':
                    storage[idx]['description'] = str(value)
                elif oid_name == 'hrStorageAllocationUnits':
                    storage[idx]['allocation_units'] = value
                elif oid_name == 'hrStorageSize':
                    storage[idx]['size'] = value
                elif oid_name == 'hrStorageUsed':
                    storage[idx]['used'] = value

    # Calculate actual sizes in bytes
    result = []
    for item in storage.values():
        if 'allocation_units' in item and 'size' in item:
            item['size_bytes'] = item['allocation_units'] * item['size']
            if 'used' in item:
                item['used_bytes'] = item['allocation_units'] * item['used']
                item['percent_used'] = round((item['used'] / item['size']) * 100, 2) if item['size'] > 0 else 0
        result.append(item)

    return result


def extract_installed_software(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract installed software information."""
    software = {}

    for entry in entries:
        oid = entry.get('oid', '')
        oid_name = entry.get('oid_name', '')
        value = entry.get('value')

        if value is None:
            continue

        if oid_name in ['hrSWInstalledName', 'hrSWInstalledDate', 'hrSWInstalledType']:
            parts = oid.split('.')
            if parts:
                idx = parts[-1]
                if idx not in software:
                    software[idx] = {'index': idx}

                if oid_name == 'hrSWInstalledName':
                    software[idx]['name'] = str(value)
                elif oid_name == 'hrSWInstalledDate':
                    software[idx]['install_date'] = str(value)
                elif oid_name == 'hrSWInstalledType':
                    type_map = {1: 'unknown', 2: 'operatingSystem', 3: 'deviceDriver', 4: 'application'}
                    software[idx]['type'] = type_map.get(value, str(value))

    return list(software.values())


def extract_users_from_processes(processes: List[Dict[str, Any]]) -> List[str]:
    """Extract potential usernames from running processes."""
    users = set()

    # Look for user-related processes
    user_process_patterns = [
        r'/home/(\w+)/',
        r'user[=:](\w+)',
        r'--user[=\s](\w+)',
    ]

    for proc in processes:
        path = proc.get('path', '')
        params = proc.get('parameters', '')
        combined = f"{path} {params}"

        for pattern in user_process_patterns:
            match = re.search(pattern, combined)
            if match:
                users.add(match.group(1))

    return list(users)


def identify_interesting_entries(entries: List[Dict[str, Any]]) -> List[str]:
    """Identify security-interesting entries."""
    interesting = []

    for entry in entries:
        oid_name = entry.get('oid_name', '')
        value = entry.get('value')

        if value is None or value == '':
            continue

        # NET-SNMP extend commands (potential RCE vectors)
        if oid_name in ['nsExtendCommand', 'nsExtendArgs']:
            interesting.append(f"NET-SNMP Extend: {oid_name} = {value}")

        # System description (OS fingerprinting)
        if oid_name == 'sysDescr' and value:
            interesting.append(f"System: {value}")

        # Look for sensitive keywords in values
        value_str = str(value).lower()
        if any(keyword in value_str for keyword in ['password', 'secret', 'key', 'token', 'credential']):
            interesting.append(f"Sensitive keyword in {oid_name}: {value[:100]}...")

    return interesting


def parse_snmpwalk(file_path: Path) -> Dict[str, Any]:
    """Parse snmpwalk output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.strip().split('\n')

    # Try to extract target from file content or filename
    target = None
    community = None

    # Check first few lines for target/community info
    for line in lines[:10]:
        # snmpwalk -v2c -c public 10.10.10.1
        match = re.search(r'-c\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            community = match.group(1)
            target = match.group(2)
            break

        # Just IP address
        match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            target = match.group(1)

    # Try to get target from filename
    if not target:
        filename = file_path.name
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', filename)
        if match:
            target = match.group(1)

    result = {
        'type': 'snmpwalk',
        'target': target,
        'community': community,
        'entries': [],
        'system_info': {},
        'interfaces': [],
        'ip_addresses': [],
        'processes': [],
        'storage': [],
        'installed_software': [],
        'users': [],
        'stats': {
            'total_entries': 0,
            'interesting': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Parse all entries
    entries = []
    for line in lines:
        entry = parse_snmp_line(line)
        if entry:
            entries.append(entry)

    result['entries'] = entries
    result['stats']['total_entries'] = len(entries)

    # Extract structured data
    result['system_info'] = extract_system_info(entries)
    result['interfaces'] = extract_interfaces(entries)
    result['ip_addresses'] = extract_ip_addresses(entries)
    result['processes'] = extract_processes(entries)
    result['storage'] = extract_storage(entries)
    result['installed_software'] = extract_installed_software(entries)

    # Try to extract users from process data
    result['users'] = extract_users_from_processes(result['processes'])

    # Identify interesting findings
    interesting = identify_interesting_entries(entries)

    # Add summary interesting items
    if result['system_info'].get('description'):
        interesting.insert(0, f"System: {result['system_info']['description'][:100]}")

    if result['processes']:
        interesting.append(f"Found {len(result['processes'])} running processes")

    if result['users']:
        interesting.append(f"Potential users: {', '.join(result['users'])}")

    # Look for interesting services in processes
    interesting_services = ['apache', 'nginx', 'mysql', 'postgres', 'ssh', 'smb',
                           'docker', 'python', 'perl', 'ruby', 'java', 'tomcat']
    found_services = set()
    for proc in result['processes']:
        proc_name = proc.get('name', '').lower()
        for svc in interesting_services:
            if svc in proc_name:
                found_services.add(proc_name)

    if found_services:
        interesting.append(f"Services running: {', '.join(list(found_services)[:10])}")

    result['stats']['interesting'] = interesting

    return result


def main():
    parser = argparse.ArgumentParser(
        description='Parse snmpwalk output into structured JSON'
    )
    parser.add_argument('file', type=Path, help='SNMPWalk output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    parser.add_argument('--entries', action='store_true',
                       help='Include all raw entries (default: excluded for brevity)')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_snmpwalk(args.file)

        # Optionally exclude raw entries to reduce output size
        if not args.entries:
            result['entries'] = f"[{result['stats']['total_entries']} entries - use --entries to include]"

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
