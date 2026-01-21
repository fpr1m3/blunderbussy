#!/usr/bin/env python3
"""
Agent Opulence - Nmap XML Parser
================================
Parses nmap XML output into structured JSON for enrichment pipeline.

Uses python-libnmap for robust XML parsing, with custom transformation
layer for CAS (Context-Aware Summary) format.

Usage: parse-nmap.py <nmap_xml_file>
Output: JSON to stdout

Extracts:
- Hosts (IP, hostname, status)
- Ports (number, protocol, state, service, version)
- OS detection
- Scripts output
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

# Try to use python-libnmap for robust parsing
# Falls back to manual XML parsing if unavailable
try:
    from libnmap.parser import NmapParser
    from libnmap.objects import NmapHost, NmapService
    HAS_LIBNMAP = True
except ImportError:
    HAS_LIBNMAP = False
    try:
        from defusedxml import ElementTree as ET
    except ImportError:
        import xml.etree.ElementTree as ET


def parse_ssh_scripts(scripts: List[Dict]) -> Dict[str, Any]:
    """
    Parse SSH-specific nmap script outputs into structured data.

    Handles:
    - ssh-auth-methods: Authentication methods supported
    - ssh-hostkey: Host key fingerprints
    - ssh2-enum-algos: Supported algorithms
    - banner: SSH version banner
    """
    ssh_data = {
        'auth_methods': [],
        'host_keys': [],
        'algorithms': {
            'kex': [],
            'host_key': [],
            'encryption': [],
            'mac': [],
            'compression': []
        },
        'banner': None
    }

    for script in scripts:
        script_id = script.get('id', '')
        output = script.get('output', '')

        if script_id == 'ssh-auth-methods':
            # Parse: "Supported authentication methods: publickey password"
            if 'Supported authentication methods' in output:
                methods_line = output.split('Supported authentication methods:')[-1]
                methods = [m.strip() for m in methods_line.replace('\n', ' ').split() if m.strip()]
                ssh_data['auth_methods'] = methods

        elif script_id == 'banner':
            ssh_data['banner'] = output.strip()

        elif script_id == 'ssh-hostkey':
            # Parse host key fingerprints
            # Format: "256 01:74:26:... (ECDSA)" or "256 SHA256:... (ED25519)"
            import re
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                # Match: bits fingerprint (type)
                match = re.match(r'(\d+)\s+([^\s]+)\s+\((\w+)\)', line)
                if match:
                    ssh_data['host_keys'].append({
                        'bits': int(match.group(1)),
                        'fingerprint': match.group(2),
                        'type': match.group(3)
                    })
                # Also match base64 key format
                match2 = re.match(r'(\w+[-\w]*)\s+(\S+)$', line)
                if match2 and not match:
                    ssh_data['host_keys'].append({
                        'type': match2.group(1),
                        'key': match2.group(2)[:40] + '...' if len(match2.group(2)) > 40 else match2.group(2)
                    })

        elif script_id == 'ssh2-enum-algos':
            # Parse algorithm categories
            import re
            current_category = None
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue

                # Check for category headers
                if 'kex_algorithms' in line:
                    current_category = 'kex'
                elif 'server_host_key_algorithms' in line:
                    current_category = 'host_key'
                elif 'encryption_algorithms' in line:
                    current_category = 'encryption'
                elif 'mac_algorithms' in line:
                    current_category = 'mac'
                elif 'compression_algorithms' in line:
                    current_category = 'compression'
                elif current_category and not line.startswith('|'):
                    # This is an algorithm name
                    algo = line.strip()
                    if algo and not algo.startswith('(') and current_category in ssh_data['algorithms']:
                        ssh_data['algorithms'][current_category].append(algo)

    return ssh_data


def transform_service(service: 'NmapService') -> Dict[str, Any]:
    """Transform libnmap service to our CAS format."""
    port_data = {
        'port': service.port,
        'protocol': service.protocol,
        'state': service.state,
        'service': service.service,
        'version': None,
        'product': None,
        'extra_info': None,
        'scripts': [],
        'reason': service.reason if hasattr(service, 'reason') else ''
    }

    # Parse service details from banner
    if service.banner:
        port_data['product'] = service.banner
        port_data['version_string'] = service.banner

    # Extract product/version from service dict if available
    if hasattr(service, 'service_dict'):
        svc = service.service_dict
        port_data['product'] = svc.get('product')
        port_data['version'] = svc.get('version')
        port_data['extra_info'] = svc.get('extrainfo')
        # Extract hostname from service (e.g., vhost detection)
        port_data['service_hostname'] = svc.get('hostname')

        # Build version string
        version_parts = []
        if port_data['product']:
            version_parts.append(port_data['product'])
        if port_data['version']:
            version_parts.append(port_data['version'])
        if version_parts:
            port_data['version_string'] = ' '.join(version_parts)

    # Parse NSE scripts
    if service.scripts_results:
        for script in service.scripts_results:
            script_data = {
                'id': script.get('id'),
                'output': script.get('output')
            }
            # Parse script elements if present
            if 'elements' in script:
                script_data['elements'] = script['elements']
            port_data['scripts'].append(script_data)

        # Parse SSH-specific scripts into structured data
        if port_data['service'] == 'ssh':
            port_data['ssh'] = parse_ssh_scripts(port_data['scripts'])

    return port_data


def transform_os(host: 'NmapHost') -> Optional[Dict[str, Any]]:
    """Transform libnmap OS detection to our CAS format."""
    if not host.os_fingerprinted:
        return None

    os_data = {
        'matches': [],
        'fingerprint': host.os_fingerprint if hasattr(host, 'os_fingerprint') else None
    }

    # Get OS matches
    if hasattr(host, 'os_match_probabilities') and host.os_match_probabilities:
        for osmatch in host.os_match_probabilities():
            match = {
                'name': osmatch.name,
                'accuracy': osmatch.accuracy,
                'classes': []
            }

            if hasattr(osmatch, 'osclasses'):
                for osclass in osmatch.osclasses:
                    os_class = {
                        'type': osclass.type if hasattr(osclass, 'type') else None,
                        'vendor': osclass.vendor,
                        'osfamily': osclass.osfamily,
                        'osgen': osclass.osgen,
                        'accuracy': osclass.accuracy
                    }
                    match['classes'].append(os_class)

            os_data['matches'].append(match)

    # Alternative: use os_class_probabilities if available
    elif hasattr(host, 'os_class_probabilities') and host.os_class_probabilities():
        for osclass in host.os_class_probabilities():
            os_data['matches'].append({
                'name': f"{osclass.vendor} {osclass.osfamily} {osclass.osgen or ''}".strip(),
                'accuracy': osclass.accuracy,
                'classes': [{
                    'vendor': osclass.vendor,
                    'osfamily': osclass.osfamily,
                    'osgen': osclass.osgen,
                    'accuracy': osclass.accuracy
                }]
            })

    return os_data if os_data['matches'] else None


def transform_host(host: 'NmapHost') -> Dict[str, Any]:
    """Transform libnmap host to our CAS format."""
    host_data = {
        'status': host.status,
        'addresses': [],
        'hostnames': [],
        'ports': [],
        'os': None,
        'scripts': [],
        'uptime': None,
        'distance': None
    }

    # Set primary IP
    host_data['ip'] = host.address
    host_data['addresses'].append({
        'addr': host.address,
        'type': 'ipv4' if '.' in host.address else 'ipv6',
        'vendor': None
    })

    # MAC address if available
    if hasattr(host, 'mac') and host.mac:
        host_data['mac'] = host.mac
        host_data['addresses'].append({
            'addr': host.mac,
            'type': 'mac',
            'vendor': host.vendor if hasattr(host, 'vendor') else None
        })

    # Hostnames
    if host.hostnames:
        for hostname in host.hostnames:
            host_data['hostnames'].append({
                'name': hostname,
                'type': 'PTR'
            })
        host_data['hostname'] = host.hostnames[0]

    # Ports - only open/filtered
    for service in host.services:
        if service.state in ['open', 'open|filtered']:
            port_data = transform_service(service)
            host_data['ports'].append(port_data)
            # Extract hostname from service if host doesn't have one
            if not host_data.get('hostname') and port_data.get('service_hostname'):
                host_data['hostname'] = port_data['service_hostname']
                host_data['hostnames'].append({
                    'name': port_data['service_hostname'],
                    'type': 'service'
                })

    # OS detection
    host_data['os'] = transform_os(host)

    # Host scripts
    if hasattr(host, 'scripts_results') and host.scripts_results:
        for script in host.scripts_results:
            script_data = {
                'id': script.get('id'),
                'output': script.get('output')
            }
            host_data['scripts'].append(script_data)

    # Uptime
    if hasattr(host, 'uptime') and host.uptime:
        host_data['uptime'] = {
            'seconds': host.uptime,
            'lastboot': host.lastboot if hasattr(host, 'lastboot') else None
        }

    # Distance (hops)
    if hasattr(host, 'distance') and host.distance:
        host_data['distance'] = host.distance

    return host_data


def parse_nmap_libnmap(file_path: Path) -> Dict[str, Any]:
    """Parse nmap XML using python-libnmap library."""
    report = NmapParser.parse_fromfile(str(file_path))

    result = {
        'type': 'nmap',
        'version': 'nmap',
        'scan_info': {
            'args': report.commandline,
            'start': str(report.started),
            'startstr': report.startedstr if hasattr(report, 'startedstr') else None,
            'version': report.version,
            'end_time': str(report.endtime) if hasattr(report, 'endtime') else None,
            'elapsed': str(report.elapsed) if hasattr(report, 'elapsed') else None,
        },
        'hosts': [],
        'stats': {
            'total_hosts': 0,
            'hosts_up': 0,
            'hosts_down': 0,
            'total_ports': 0,
            'open_ports': 0
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Get scan type info
    if hasattr(report, 'scan_type'):
        result['scan_info']['scan_type'] = report.scan_type

    # Transform hosts
    for host in report.hosts:
        host_data = transform_host(host)
        result['hosts'].append(host_data)

        # Update stats
        result['stats']['total_hosts'] += 1
        if host_data['status'] == 'up':
            result['stats']['hosts_up'] += 1
        else:
            result['stats']['hosts_down'] += 1

        result['stats']['total_ports'] += len(host_data['ports'])
        result['stats']['open_ports'] += len([p for p in host_data['ports'] if p['state'] == 'open'])

    # Summary from report
    if hasattr(report, 'summary'):
        result['scan_info']['summary'] = report.summary

    return result


# ============================================================================
# Fallback: Manual XML parsing (if libnmap not installed)
# ============================================================================

def parse_port_xml(port_elem) -> Dict[str, Any]:
    """Parse a single port element (fallback)."""
    port_data = {
        'port': int(port_elem.get('portid', 0)),
        'protocol': port_elem.get('protocol', 'tcp'),
        'state': 'unknown',
        'service': None,
        'version': None,
        'product': None,
        'extra_info': None,
        'scripts': []
    }

    state_elem = port_elem.find('state')
    if state_elem is not None:
        port_data['state'] = state_elem.get('state', 'unknown')
        port_data['reason'] = state_elem.get('reason', '')

    service_elem = port_elem.find('service')
    if service_elem is not None:
        port_data['service'] = service_elem.get('name')
        port_data['product'] = service_elem.get('product')
        port_data['version'] = service_elem.get('version')
        port_data['extra_info'] = service_elem.get('extrainfo')
        # Extract hostname from service element (e.g., vhost detection)
        port_data['service_hostname'] = service_elem.get('hostname')

        version_parts = []
        if port_data['product']:
            version_parts.append(port_data['product'])
        if port_data['version']:
            version_parts.append(port_data['version'])
        if version_parts:
            port_data['version_string'] = ' '.join(version_parts)

    for script_elem in port_elem.findall('script'):
        script_data = {
            'id': script_elem.get('id'),
            'output': script_elem.get('output')
        }
        port_data['scripts'].append(script_data)

    # Parse SSH-specific scripts into structured data
    if port_data['service'] == 'ssh' and port_data['scripts']:
        port_data['ssh'] = parse_ssh_scripts(port_data['scripts'])

    return port_data


def parse_os_xml(host_elem) -> Optional[Dict[str, Any]]:
    """Parse OS detection (fallback)."""
    os_elem = host_elem.find('os')
    if os_elem is None:
        return None

    os_data = {'matches': [], 'fingerprint': None}

    for osmatch in os_elem.findall('osmatch'):
        match = {
            'name': osmatch.get('name'),
            'accuracy': int(osmatch.get('accuracy', 0)),
            'classes': []
        }
        for osclass in osmatch.findall('osclass'):
            match['classes'].append({
                'type': osclass.get('type'),
                'vendor': osclass.get('vendor'),
                'osfamily': osclass.get('osfamily'),
                'osgen': osclass.get('osgen'),
                'accuracy': int(osclass.get('accuracy', 0))
            })
        os_data['matches'].append(match)

    fp_elem = os_elem.find('osfingerprint')
    if fp_elem is not None:
        os_data['fingerprint'] = fp_elem.get('fingerprint')

    return os_data if os_data['matches'] else None


def parse_host_xml(host_elem) -> Dict[str, Any]:
    """Parse a single host element (fallback)."""
    host_data = {
        'status': 'unknown',
        'addresses': [],
        'hostnames': [],
        'ports': [],
        'os': None,
        'scripts': [],
        'uptime': None,
        'distance': None
    }

    status_elem = host_elem.find('status')
    if status_elem is not None:
        host_data['status'] = status_elem.get('state', 'unknown')

    for addr_elem in host_elem.findall('address'):
        addr_data = {
            'addr': addr_elem.get('addr'),
            'type': addr_elem.get('addrtype'),
            'vendor': addr_elem.get('vendor')
        }
        host_data['addresses'].append(addr_data)
        if addr_data['type'] == 'ipv4' and 'ip' not in host_data:
            host_data['ip'] = addr_data['addr']
        elif addr_data['type'] == 'mac':
            host_data['mac'] = addr_data['addr']

    hostnames_elem = host_elem.find('hostnames')
    if hostnames_elem is not None:
        for hostname_elem in hostnames_elem.findall('hostname'):
            host_data['hostnames'].append({
                'name': hostname_elem.get('name'),
                'type': hostname_elem.get('type')
            })
        if host_data['hostnames']:
            host_data['hostname'] = host_data['hostnames'][0]['name']

    ports_elem = host_elem.find('ports')
    if ports_elem is not None:
        for port_elem in ports_elem.findall('port'):
            port_data = parse_port_xml(port_elem)
            if port_data['state'] in ['open', 'open|filtered']:
                host_data['ports'].append(port_data)
                # Extract hostname from service if host doesn't have one
                if not host_data.get('hostname') and port_data.get('service_hostname'):
                    host_data['hostname'] = port_data['service_hostname']
                    host_data['hostnames'].append({
                        'name': port_data['service_hostname'],
                        'type': 'service'
                    })

    host_data['os'] = parse_os_xml(host_elem)

    uptime_elem = host_elem.find('uptime')
    if uptime_elem is not None:
        host_data['uptime'] = {
            'seconds': int(uptime_elem.get('seconds', 0)),
            'lastboot': uptime_elem.get('lastboot')
        }

    distance_elem = host_elem.find('distance')
    if distance_elem is not None:
        host_data['distance'] = int(distance_elem.get('value', 0))

    return host_data


def parse_nmap_xml_fallback(file_path: Path) -> Dict[str, Any]:
    """Parse nmap XML manually (fallback if libnmap unavailable)."""
    tree = ET.parse(str(file_path))
    root = tree.getroot()

    result = {
        'type': 'nmap',
        'version': root.get('scanner', 'nmap'),
        'scan_info': {
            'args': root.get('args', ''),
            'start': root.get('start'),
            'startstr': root.get('startstr'),
            'version': root.get('version'),
        },
        'hosts': [],
        'stats': {
            'total_hosts': 0,
            'hosts_up': 0,
            'hosts_down': 0,
            'total_ports': 0,
            'open_ports': 0
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    for host_elem in root.findall('host'):
        host_data = parse_host_xml(host_elem)
        result['hosts'].append(host_data)

        result['stats']['total_hosts'] += 1
        if host_data['status'] == 'up':
            result['stats']['hosts_up'] += 1
        else:
            result['stats']['hosts_down'] += 1
        result['stats']['total_ports'] += len(host_data['ports'])
        result['stats']['open_ports'] += len([p for p in host_data['ports'] if p['state'] == 'open'])

    runstats = root.find('runstats')
    if runstats is not None:
        finished = runstats.find('finished')
        if finished is not None:
            result['scan_info']['end_time'] = finished.get('time')
            result['scan_info']['elapsed'] = finished.get('elapsed')

    return result


# ============================================================================
# Main entry point
# ============================================================================

def parse_nmap(file_path: Path) -> Dict[str, Any]:
    """
    Parse nmap XML file into structured data.

    Uses python-libnmap if available, falls back to manual XML parsing.
    """
    if HAS_LIBNMAP:
        return parse_nmap_libnmap(file_path)
    else:
        return parse_nmap_xml_fallback(file_path)


def main():
    parser = argparse.ArgumentParser(
        description='Parse nmap XML output',
        epilog=f'Parser backend: {"python-libnmap" if HAS_LIBNMAP else "xml.etree (fallback)"}'
    )
    parser.add_argument('file', type=Path, help='Nmap XML file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    parser.add_argument('--backend', action='store_true', help='Show which parser backend is being used')
    args = parser.parse_args()

    if args.backend:
        print(f"Backend: {'python-libnmap' if HAS_LIBNMAP else 'xml.etree (fallback)'}")
        sys.exit(0)

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_nmap(args.file)
        # Add metadata about parser used
        result['_parser_backend'] = 'libnmap' if HAS_LIBNMAP else 'xml.etree'

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
