#!/usr/bin/env python3
"""
Agent Opulence - Enum4linux Output Parser
==========================================
Parses enum4linux SMB enumeration output into structured JSON.

Usage: parse-enum4linux.py <enum4linux_output_file>
Output: JSON to stdout

Enum4linux is a tool for enumerating information from Windows/Samba hosts:
- User enumeration via RID cycling
- Share enumeration
- Group enumeration
- Password policy
- OS information
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def is_enum4linux_ng(lines: List[str]) -> bool:
    """Detect if output is from enum4linux-ng vs classic enum4linux."""
    for line in lines[:5]:
        if 'ENUM4LINUX - next generation' in line or 'enum4linux-ng' in line.lower():
            return True
    return False


def parse_target(lines: List[str]) -> Optional[str]:
    """Extract target from enum4linux output."""
    for line in lines[:30]:
        # Target Information (format: "Target ........... 10.10.10.3")
        match = re.search(r'Target\s*[.:]+\s*(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            return match.group(1)

        # Starting enum4linux (classic)
        match = re.search(r'Starting enum4linux.*?(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            return match.group(1)

    return None


def parse_os_info(lines: List[str]) -> Dict[str, Any]:
    """Extract OS information section."""
    os_info = {
        'native_os': None,
        'native_lanman': None,
        'workgroup': None,
        'domain': None
    }

    is_ng = is_enum4linux_ng(lines)
    in_os_section = False
    in_netbios_section = False

    for line in lines:
        if 'OS information' in line or 'OS Information' in line:
            in_os_section = True
            continue

        if 'NetBIOS Names' in line or 'Nbtstat' in line:
            in_netbios_section = True
            continue

        if in_os_section:
            # Classic format
            match = re.search(r'Native OS:\s*(.+)', line)
            if match:
                os_info['native_os'] = match.group(1).strip()

            match = re.search(r'Native LAN Manager:\s*(.+)', line)
            if match:
                os_info['native_lanman'] = match.group(1).strip()

            # enum4linux-ng format - server_type_string contains Samba version
            match = re.search(r'server_type_string:\s*(.+)', line)
            if match:
                server_type = match.group(1).strip()
                # Extract Samba version from server_type_string
                samba_match = re.search(r'(Samba\s+[\d.]+[^\)]*)', server_type)
                if samba_match:
                    os_info['native_lanman'] = samba_match.group(1)
                # Try to infer OS from server type
                if 'Unx' in server_type and not os_info['native_os']:
                    os_info['native_os'] = 'Unix'

            # End of section (classic)
            if line.startswith('=====') and os_info['native_os']:
                in_os_section = False

        if in_netbios_section:
            # Workgroup from NetBIOS
            match = re.search(r'workgroup[:/]\s*(\S+)', line, re.IGNORECASE)
            if match:
                os_info['workgroup'] = match.group(1)

            # enum4linux-ng format: Workgroup: VALUE
            match = re.search(r'^Workgroup:\s*(\S+)', line)
            if match:
                os_info['workgroup'] = match.group(1)

            # Domain
            match = re.search(r'^Domain:\s*(\S+)', line)
            if match and match.group(1) != "''":
                os_info['domain'] = match.group(1)

            if line.startswith('====='):
                in_netbios_section = False

    return os_info


def parse_shares(lines: List[str]) -> List[Dict[str, Any]]:
    """Extract share enumeration section."""
    shares = []
    in_share_section = False
    is_ng = is_enum4linux_ng(lines)
    current_share = None
    saw_content = False  # Track if we've seen actual content

    for i, line in enumerate(lines):
        if 'Share Enumeration' in line or 'Shares via RPC' in line:
            in_share_section = True
            saw_content = False
            continue

        if in_share_section:
            # enum4linux-ng YAML format: "sharename:" at start of line (not indented)
            if is_ng:
                # Share name line: "sharename:" (not indented, ends with colon)
                match = re.match(r'^([A-Za-z0-9$_]+):$', line)
                if match:
                    saw_content = True
                    if current_share:
                        shares.append(current_share)
                    current_share = {
                        'name': match.group(1),
                        'type': '',
                        'comment': ''
                    }
                    continue

                # Indented properties for current share
                if current_share:
                    match = re.match(r'^\s+comment:\s*(.*)', line)
                    if match:
                        current_share['comment'] = match.group(1).strip("'\"")
                        continue

                    match = re.match(r'^\s+type:\s*(\S+)', line)
                    if match:
                        current_share['type'] = match.group(1)
                        continue

                # Mapping results from ng format
                match = re.search(r'Testing share\s+(\S+)', line)
                if match:
                    tested_share = match.group(1)
                    # Look at next line for result
                    continue

                match = re.search(r'\[.\]\s+Mapping:\s*(\S+)', line)
                if match:
                    mapping_result = match.group(1).upper()
                    # Find the share being tested (from previous Testing share line)
                    for share in shares:
                        if f"Testing share {share['name']}" in lines[i-1] if i > 0 else '':
                            share['accessible'] = mapping_result == 'OK'
                            break

            # Classic format: \\target\sharename type comment
            match = re.match(r'\s*\\\\[^\\]+\\(\S+)\s+(\S+)\s*(.*)', line)
            if match:
                saw_content = True
                shares.append({
                    'name': match.group(1),
                    'type': match.group(2),
                    'comment': match.group(3).strip() if match.group(3) else ''
                })
                continue

            # Classic format: sharename    Disk/IPC/Printer    comment
            match = re.match(r'\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)', line, re.IGNORECASE)
            if match:
                saw_content = True
                shares.append({
                    'name': match.group(1),
                    'type': match.group(2),
                    'comment': match.group(3).strip() if match.group(3) else ''
                })
                continue

            # Classic Mapping share access: //host/share Mapping: OK
            match = re.search(r'//[^/]+/(\S+)\s+Mapping:\s*(OK|DENIED)', line, re.IGNORECASE)
            if match:
                share_name = match.group(1)
                access = match.group(2).upper()
                for share in shares:
                    if share['name'] == share_name:
                        share['accessible'] = access == 'OK'
                        break

            # End of section (only exit if we've seen content)
            if line.strip().startswith('====='):
                if saw_content:
                    if current_share:
                        shares.append(current_share)
                        current_share = None
                    if not is_ng:
                        in_share_section = False
                continue

            if line.startswith('[*]') and 'Testing' not in line and shares:
                if current_share:
                    shares.append(current_share)
                    current_share = None
                if not is_ng:
                    in_share_section = False

    # Don't forget the last share in ng format
    if current_share:
        shares.append(current_share)

    return shares


def parse_users(lines: List[str]) -> List[Dict[str, Any]]:
    """Extract user enumeration section (including RID cycling)."""
    users = []
    seen_users = set()
    in_user_section = False
    is_ng = is_enum4linux_ng(lines)
    current_user = None
    saw_content = False  # Track if we've seen actual content (not just header)

    for i, line in enumerate(lines):
        if 'Users on' in line or 'RID cycling' in line or 'user enumeration' in line.lower() or 'Users via RPC' in line:
            in_user_section = True
            saw_content = False
            continue

        # End of user section (only exit if we've seen content, to skip header box)
        if in_user_section and line.strip().startswith('====='):
            if saw_content:
                if current_user and current_user.get('username') and current_user['username'] not in seen_users:
                    seen_users.add(current_user['username'])
                    users.append(current_user)
                current_user = None
                in_user_section = False
            continue

        if in_user_section:
            # enum4linux-ng YAML format
            if is_ng:
                # RID line: "'1000':" or "'501':"
                match = re.match(r"^'(\d+)':$", line)
                if match:
                    saw_content = True
                    if current_user and current_user.get('username') and current_user['username'] not in seen_users:
                        seen_users.add(current_user['username'])
                        users.append(current_user)
                    current_user = {'rid': match.group(1)}
                    continue

                # Username property
                match = re.match(r'^\s+username:\s*(\S+)', line)
                if match and current_user is not None:
                    current_user['username'] = match.group(1)
                    continue

                # Name property
                match = re.match(r'^\s+name:\s*(.*)', line)
                if match and current_user is not None:
                    name = match.group(1).strip()
                    if name and name != '(null)':
                        current_user['name'] = name
                    continue

                # Description property
                match = re.match(r'^\s+description:\s*(.*)', line)
                if match and current_user is not None:
                    desc = match.group(1).strip()
                    if desc and desc != '(null)':
                        current_user['description'] = desc
                    continue

            # Classic RID cycling format: S-1-5-21-...-500 DOMAIN\username (SidTypeUser)
            match = re.search(r'(S-\d+-\d+-[\d-]+)\s+[^\\]+\\(\S+)\s+\((\w+)\)', line)
            if match:
                saw_content = True
                username = match.group(2)
                if username not in seen_users:
                    seen_users.add(username)
                    users.append({
                        'username': username,
                        'sid': match.group(1),
                        'type': match.group(3)
                    })
                continue

            # Classic user list format: user:[username] rid:[hex]
            match = re.search(r'user:\[([^\]]+)\]\s+rid:\[(0x[0-9a-f]+)\]', line, re.IGNORECASE)
            if match:
                saw_content = True
                username = match.group(1)
                if username not in seen_users:
                    seen_users.add(username)
                    users.append({
                        'username': username,
                        'rid': match.group(2)
                    })
                continue

            # Simple user format
            match = re.search(r'^\s+(\S+)\s+\(Local User\)', line)
            if match:
                username = match.group(1)
                if username not in seen_users:
                    seen_users.add(username)
                    users.append({
                        'username': username,
                        'type': 'Local User'
                    })

    # Don't forget the last user
    if current_user and current_user.get('username') and current_user['username'] not in seen_users:
        users.append(current_user)

    return users


def parse_groups(lines: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Extract group enumeration section."""
    groups = {
        'local': [],
        'domain': [],
        'builtin': []
    }
    in_group_section = False
    current_category = 'local'
    is_ng = is_enum4linux_ng(lines)
    current_group = None
    saw_content = False  # Track if we've seen actual content

    for i, line in enumerate(lines):
        # Detect section type - classic format uses "Groups on X.X.X.X"
        if 'Groups via RPC' in line or 'Groups on' in line or ('Group' in line and ('enum' in line.lower() or 'Mapping' in line)):
            in_group_section = True
            saw_content = False
            continue

        # Category detection for both formats
        if 'domain group' in line.lower():
            current_category = 'domain'
            continue
        elif 'builtin group' in line.lower():
            current_category = 'builtin'
            continue
        elif 'local group' in line.lower():
            current_category = 'local'
            continue

        # End of section (only exit if we've seen content)
        if in_group_section and line.strip().startswith('====='):
            if saw_content:
                if current_group and current_group.get('name'):
                    groups[current_category].append(current_group)
                current_group = None
                in_group_section = False
            continue

        if in_group_section:
            # enum4linux-ng YAML format
            if is_ng:
                # RID line: "'548':" or "'544':"
                match = re.match(r"^'(\d+)':$", line)
                if match:
                    saw_content = True
                    if current_group and current_group.get('name'):
                        groups[current_category].append(current_group)
                    current_group = {'rid': match.group(1)}
                    continue

                # Groupname property
                match = re.match(r'^\s+groupname:\s*(.+)', line)
                if match and current_group is not None:
                    current_group['name'] = match.group(1).strip()
                    continue

                # Type property
                match = re.match(r'^\s+type:\s*(\S+)', line)
                if match and current_group is not None:
                    group_type = match.group(1).lower()
                    current_group['type'] = group_type
                    # Also use type to categorize
                    if group_type == 'domain':
                        current_category = 'domain'
                    elif group_type == 'builtin':
                        current_category = 'builtin'
                    continue

            # Classic format: group:[groupname] rid:[hex]
            match = re.search(r'group:\[([^\]]+)\]\s+rid:\[(0x[0-9a-f]+)\]', line, re.IGNORECASE)
            if match:
                saw_content = True
                groups[current_category].append({
                    'name': match.group(1),
                    'rid': match.group(2)
                })
                continue

            # Group with members format
            match = re.search(r'^\s+(\S+)\s+\((\w+)\)\s*$', line)
            if match:
                groups[current_category].append({
                    'name': match.group(1),
                    'type': match.group(2)
                })

    # Don't forget the last group
    if current_group and current_group.get('name'):
        groups[current_category].append(current_group)

    return groups


def parse_password_policy(lines: List[str]) -> Dict[str, Any]:
    """Extract password policy section."""
    policy = {}
    in_policy_section = False

    for line in lines:
        if 'Password Policy' in line or 'password info' in line.lower():
            in_policy_section = True
            continue

        if in_policy_section:
            # Min password length
            match = re.search(r'Minimum password length:\s*(\d+)', line)
            if match:
                policy['min_length'] = int(match.group(1))

            # Password history
            match = re.search(r'Password history length:\s*(\d+)', line)
            if match:
                policy['history_length'] = int(match.group(1))

            # Max password age
            match = re.search(r'Maximum password age:\s*(.+)', line)
            if match:
                policy['max_age'] = match.group(1).strip()

            # Lockout threshold
            match = re.search(r'Account lockout threshold:\s*(\d+)', line)
            if match:
                policy['lockout_threshold'] = int(match.group(1))

            # Complexity
            match = re.search(r'Password Complexity:\s*(.+)', line)
            if match:
                policy['complexity'] = match.group(1).strip()

            # End of section
            if line.startswith('=====') and policy:
                break

    return policy


def parse_sessions(lines: List[str]) -> List[Dict[str, Any]]:
    """Extract session information."""
    sessions = []

    for line in lines:
        # Session format varies
        match = re.search(r'Session\s+\\\\(\S+)\s+(\S+)', line)
        if match:
            sessions.append({
                'host': match.group(1),
                'user': match.group(2)
            })

    return sessions


def parse_enum4linux(file_path: Path) -> Dict[str, Any]:
    """Parse enum4linux output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.strip().split('\n')

    result = {
        'type': 'enum4linux',
        'target': parse_target(lines),
        'os_info': parse_os_info(lines),
        'shares': parse_shares(lines),
        'users': parse_users(lines),
        'groups': parse_groups(lines),
        'password_policy': parse_password_policy(lines),
        'sessions': parse_sessions(lines),
        'stats': {
            'shares_found': 0,
            'users_found': 0,
            'groups_found': 0,
            'interesting': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Calculate stats
    result['stats']['shares_found'] = len(result['shares'])
    result['stats']['users_found'] = len(result['users'])
    result['stats']['groups_found'] = sum(len(g) for g in result['groups'].values())

    # Identify interesting findings
    interesting = []

    # Accessible shares (especially non-default)
    for share in result['shares']:
        if share.get('accessible'):
            interesting.append(f"Accessible share: {share['name']}")
        if share['name'].lower() not in ['ipc$', 'print$', 'c$', 'admin$']:
            interesting.append(f"Non-default share: {share['name']}")

    # Users found
    if result['users']:
        interesting.append(f"Enumerated {len(result['users'])} users")
        # Look for common admin accounts
        for user in result['users']:
            if user.get('username', '').lower() in ['administrator', 'admin', 'root']:
                interesting.append(f"Admin account found: {user['username']}")

    # Weak password policy
    policy = result['password_policy']
    if policy.get('min_length', 99) < 8:
        interesting.append(f"Weak password policy: min length {policy['min_length']}")
    if policy.get('lockout_threshold', 0) == 0:
        interesting.append("No account lockout threshold")

    result['stats']['interesting'] = interesting

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse enum4linux output')
    parser.add_argument('file', type=Path, help='Enum4linux output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_enum4linux(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
