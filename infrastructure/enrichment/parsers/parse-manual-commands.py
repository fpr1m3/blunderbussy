#!/usr/bin/env python3
"""
Agent Opulence - Manual Commands Parser
========================================
Parses AutoRecon _manual_commands.txt into structured attack recommendations.

Usage: parse-manual-commands.py <manual_commands_file>
Output: JSON to stdout

The _manual_commands.txt file contains suggested follow-up commands
organized by service, which the Dame can use for next attack steps.
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def parse_manual_commands(file_path: Path) -> Dict[str, Any]:
    """
    Parse AutoRecon manual commands file into structured recommendations.

    Format:
        [*] ssh on tcp/22
            [-] Bruteforce logins:
                hydra -L ... ssh://target
                medusa -U ... -M ssh -h target

        [*] http on tcp/80
            [-] (feroxbuster) Description:
                feroxbuster -u http://target ...
    """
    result = {
        'type': 'manual_commands',
        'services': [],
        'recommendations': [],
        'stats': {
            'total_services': 0,
            'total_commands': 0,
            'by_category': {}
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    # Split by service sections
    service_blocks = re.split(r'\[\*\]\s+', content)

    for block in service_blocks:
        block = block.strip()
        if not block:
            continue

        # Parse service header: "ssh on tcp/22"
        header_match = re.match(r'^(\w+)\s+on\s+(\w+)/(\d+)', block)
        if not header_match:
            continue

        service_name = header_match.group(1)
        protocol = header_match.group(2)
        port = int(header_match.group(3))

        service_data = {
            'service': service_name,
            'protocol': protocol,
            'port': port,
            'categories': []
        }

        # Parse command categories within the service block
        # Format: [-] (tool) Description: or [-] Description:
        category_blocks = re.split(r'\[-\]\s+', block)

        for cat_block in category_blocks[1:]:  # Skip first (header)
            cat_block = cat_block.strip()
            if not cat_block:
                continue

            # Parse category header
            # Formats: "(tool) Description:" or "Description:"
            cat_match = re.match(r'^(?:\((\w+)\)\s+)?([^:]+):', cat_block)
            if not cat_match:
                continue

            tool = cat_match.group(1)  # May be None
            description = cat_match.group(2).strip()

            # Extract commands (lines starting with tool names or containing common patterns)
            commands = []
            lines = cat_block.split('\n')
            for line in lines[1:]:  # Skip category header line
                line = line.strip()
                if not line:
                    continue

                # Skip if it's another category marker
                if line.startswith('[-]') or line.startswith('[*]'):
                    break

                # Check if line looks like a command
                # Common command starts: hydra, medusa, feroxbuster, wpscan, nmap, nikto, etc.
                command_patterns = [
                    r'^(hydra|medusa|feroxbuster|gobuster|wpscan|nikto|nmap|sqlmap|'
                    r'enum4linux|smbclient|smbmap|rpcclient|curl|wget|nc|netcat)\s',
                    r'^[a-z]+\s+-[A-Za-z]',  # tool -flag pattern
                ]

                is_command = any(re.match(p, line, re.IGNORECASE) for p in command_patterns)
                if is_command:
                    commands.append(line)

            if commands:
                category_data = {
                    'tool': tool,
                    'description': description,
                    'commands': commands
                }
                service_data['categories'].append(category_data)

                # Create recommendations
                for cmd in commands:
                    rec = {
                        'service': service_name,
                        'port': port,
                        'category': description,
                        'tool': tool or _extract_tool_from_command(cmd),
                        'command': cmd,
                        'priority': _calculate_priority(service_name, description)
                    }
                    result['recommendations'].append(rec)
                    result['stats']['total_commands'] += 1

                    # Track by category
                    cat_key = description.lower().split()[0] if description else 'other'
                    result['stats']['by_category'].setdefault(cat_key, 0)
                    result['stats']['by_category'][cat_key] += 1

        if service_data['categories']:
            result['services'].append(service_data)
            result['stats']['total_services'] += 1

    # Sort recommendations by priority
    result['recommendations'].sort(key=lambda x: x.get('priority', 5))

    return result


def _extract_tool_from_command(cmd: str) -> Optional[str]:
    """Extract tool name from command string."""
    match = re.match(r'^(\w+)', cmd)
    return match.group(1) if match else None


def _calculate_priority(service: str, description: str) -> int:
    """
    Calculate attack priority based on service and description.

    Lower number = higher priority.
    """
    desc_lower = description.lower()

    # High priority attacks
    if 'bruteforce' in desc_lower or 'brute' in desc_lower:
        if service in ('ssh', 'ftp', 'smb'):
            return 2  # Credential attacks on critical services
        return 3

    if 'credential' in desc_lower or 'password' in desc_lower:
        return 2

    # Medium priority
    if 'enumerat' in desc_lower:
        return 4

    if 'directory' in desc_lower or 'wordlist' in desc_lower:
        return 4

    if 'vulnerability' in desc_lower or 'vuln' in desc_lower:
        return 3

    # WordPress/CMS specific
    if 'wpscan' in desc_lower or 'wordpress' in desc_lower:
        return 3

    return 5  # Default


def main():
    parser = argparse.ArgumentParser(description='Parse AutoRecon manual commands')
    parser.add_argument('file', type=Path, help='Manual commands file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_manual_commands(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
