#!/usr/bin/env python3
"""
Agent Opulence - WhatWeb Output Parser
=======================================
Parses WhatWeb technology fingerprinting output into structured JSON.

Usage: parse-whatweb.py <whatweb_output_file>
Output: JSON to stdout

Supports:
- JSON output (--log-json)
- Brief/verbose text output
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def parse_json_output(file_path: Path) -> Dict[str, Any]:
    """Parse WhatWeb JSON output."""
    result = {
        'type': 'whatweb',
        'format': 'json',
        'targets': [],
        'technologies': [],
        'stats': {
            'total_targets': 0,
            'total_technologies': 0,
            'by_category': {}
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    with open(file_path, 'r', errors='replace') as f:
        content = f.read().strip()

    # Handle multiple JSON arrays, JSONL, or single JSON array
    # WhatWeb may be run multiple times (IP + vhost) appending to same file
    entries = []
    if content.startswith('['):
        # Try single array first
        try:
            entries = json.loads(content)
        except json.JSONDecodeError:
            # Multiple concatenated arrays: split on ]\n[ or ][
            arrays = re.split(r'\]\s*\[', content)
            for i, arr in enumerate(arrays):
                # Restore brackets removed by split
                if i == 0:
                    arr = arr + ']'
                elif i == len(arrays) - 1:
                    arr = '[' + arr
                else:
                    arr = '[' + arr + ']'
                try:
                    entries.extend(json.loads(arr))
                except json.JSONDecodeError:
                    continue
    else:
        # JSONL format
        for line in content.split('\n'):
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    for entry in entries:
        target_url = entry.get('target', '')
        http_status = entry.get('http_status')

        target_data = {
            'url': target_url,
            'status': http_status,
            'technologies': []
        }

        plugins = entry.get('plugins', {})
        for plugin_name, plugin_data in plugins.items():
            tech = {
                'name': plugin_name,
                'version': None,
                'string': None,
                'account': None,
                'module': None
            }

            # Extract version
            if isinstance(plugin_data, dict):
                versions = plugin_data.get('version', [])
                if versions:
                    tech['version'] = versions[0] if isinstance(versions, list) else versions

                strings = plugin_data.get('string', [])
                if strings:
                    tech['string'] = strings[0] if isinstance(strings, list) else strings

                accounts = plugin_data.get('account', [])
                if accounts:
                    tech['account'] = accounts[0] if isinstance(accounts, list) else accounts

                modules = plugin_data.get('module', [])
                if modules:
                    tech['module'] = modules[0] if isinstance(modules, list) else modules

            target_data['technologies'].append(tech)

            # Track global technologies
            tech_key = f"{tech['name']}"
            if tech['version']:
                tech_key += f" {tech['version']}"

            if not any(t.get('name') == tech['name'] for t in result['technologies']):
                result['technologies'].append(tech.copy())

        result['targets'].append(target_data)
        result['stats']['total_targets'] += 1
        result['stats']['total_technologies'] += len(target_data['technologies'])

    # Categorize technologies
    categories = {
        'web_server': ['Apache', 'nginx', 'IIS', 'LiteSpeed', 'Caddy', 'OpenResty'],
        'framework': ['PHP', 'ASP.NET', 'Django', 'Rails', 'Express', 'Flask', 'Laravel'],
        'cms': ['WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'Ghost'],
        'javascript': ['jQuery', 'React', 'Vue', 'Angular', 'Bootstrap', 'Modernizr'],
        'security': ['WAF', 'Cloudflare', 'Sucuri', 'Imperva', 'mod_security'],
        'database': ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'SQLite']
    }

    for tech in result['technologies']:
        for category, keywords in categories.items():
            if any(kw.lower() in tech['name'].lower() for kw in keywords):
                result['stats']['by_category'].setdefault(category, [])
                result['stats']['by_category'][category].append(tech['name'])
                break

    return result


def parse_text_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a WhatWeb text output line.

    Format: http://example.com [200 OK] Country[US][...] Apache[2.4.41] ...
    """
    # Match URL and status
    match = re.match(r'^(\S+)\s+\[(\d+)\s*([^\]]*)\](.*)$', line.strip())
    if not match:
        return None

    url = match.group(1)
    status = int(match.group(2))
    status_text = match.group(3)
    tech_string = match.group(4)

    target_data = {
        'url': url,
        'status': status,
        'status_text': status_text,
        'technologies': []
    }

    # Parse technology strings: Name[value], Name, Name[value1,value2]
    tech_pattern = re.compile(r'(\w[\w\s\-\.]*?)(?:\[([^\]]*)\])?(?=\s+\w|\s*$)')

    for match in tech_pattern.finditer(tech_string):
        name = match.group(1).strip()
        value = match.group(2)

        if not name:
            continue

        tech = {
            'name': name,
            'version': None,
            'string': None
        }

        if value:
            # Check if it looks like a version
            if re.match(r'^[\d\.]+', value):
                tech['version'] = value
            else:
                tech['string'] = value

        target_data['technologies'].append(tech)

    return target_data


def parse_verbose_report(file_path: Path) -> Dict[str, Any]:
    """
    Parse WhatWeb verbose report format (AutoRecon output).

    Format:
        WhatWeb report for http://example.com:80
        Status    : 200 OK
        Title     : Page Title
        IP        : 10.0.0.1
        Summary   : Apache[2.4.52], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)]

        Detected Plugins:
        [ Apache ]
            Version      : 2.4.52 (from HTTP Server Header)
        ...
    """
    result = {
        'type': 'whatweb',
        'format': 'verbose',
        'targets': [],
        'technologies': [],
        'stats': {
            'total_targets': 0,
            'total_technologies': 0,
            'by_category': {}
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    # Split into report blocks (each starts with "WhatWeb report for")
    blocks = re.split(r'(?=WhatWeb report for )', content)

    for block in blocks:
        block = block.strip()
        if not block or not block.startswith('WhatWeb report for'):
            continue

        target_data = {
            'url': '',
            'status': 0,
            'status_text': '',
            'title': '',
            'ip': '',
            'technologies': []
        }

        # Extract URL
        url_match = re.search(r'WhatWeb report for (\S+)', block)
        if url_match:
            target_data['url'] = url_match.group(1)

        # Extract Status
        status_match = re.search(r'Status\s*:\s*(\d+)\s*(.*)', block)
        if status_match:
            target_data['status'] = int(status_match.group(1))
            target_data['status_text'] = status_match.group(2).strip()

        # Extract Title
        title_match = re.search(r'Title\s*:\s*(.+)', block)
        if title_match:
            target_data['title'] = title_match.group(1).strip()

        # Extract IP
        ip_match = re.search(r'IP\s*:\s*(\S+)', block)
        if ip_match:
            target_data['ip'] = ip_match.group(1).strip()

        # Extract technologies from Summary line
        # Format: Summary   : Apache[2.4.52], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], PasswordField[password]
        summary_match = re.search(r'Summary\s*:\s*(.+)', block)
        if summary_match:
            summary = summary_match.group(1)
            # Parse tech entries: Name[value] or Name[value1][value2] or just Name
            # Handle nested brackets and multiple values
            tech_pattern = re.compile(r'(\w[\w\-\.]*?)(?:\[([^\]]*)\])?(?:\[([^\]]*)\])?(?:,|$)')

            for match in tech_pattern.finditer(summary):
                name = match.group(1).strip()
                value1 = match.group(2)
                value2 = match.group(3)

                if not name:
                    continue

                tech = {
                    'name': name,
                    'version': None,
                    'string': None
                }

                # First bracket value
                if value1:
                    if re.match(r'^[\d\.]+', value1):
                        tech['version'] = value1
                    else:
                        tech['string'] = value1

                # Second bracket value (often more detail)
                if value2:
                    if not tech['version'] and re.match(r'^[\d\.]+', value2):
                        tech['version'] = value2
                    elif not tech['string']:
                        tech['string'] = value2

                target_data['technologies'].append(tech)

        # Also extract from Detected Plugins section for more detail
        plugins_section = re.search(r'Detected Plugins:(.*?)(?:HTTP Headers:|$)', block, re.DOTALL)
        if plugins_section:
            plugin_blocks = re.split(r'\n\[ ', plugins_section.group(1))
            for plugin_block in plugin_blocks:
                plugin_block = plugin_block.strip()
                if not plugin_block:
                    continue

                # Get plugin name
                name_match = re.match(r'(\w[\w\s\-\.]*?)\s*\]', plugin_block)
                if name_match:
                    plugin_name = name_match.group(1).strip()

                    # Check if we already have this tech
                    existing = next((t for t in target_data['technologies'] if t['name'] == plugin_name), None)

                    # Extract version from plugin details
                    version_match = re.search(r'Version\s*:\s*([\d\.]+)', plugin_block)
                    if version_match:
                        version = version_match.group(1)
                        if existing:
                            existing['version'] = version
                        else:
                            target_data['technologies'].append({
                                'name': plugin_name,
                                'version': version,
                                'string': None
                            })

                    # Extract String value
                    string_match = re.search(r'String\s*:\s*(.+)', plugin_block)
                    if string_match and existing:
                        existing['string'] = string_match.group(1).strip()

        result['targets'].append(target_data)
        result['stats']['total_targets'] += 1
        result['stats']['total_technologies'] += len(target_data['technologies'])

        for tech in target_data['technologies']:
            if not any(t.get('name') == tech['name'] for t in result['technologies']):
                result['technologies'].append(tech.copy())

    # Categorize technologies
    categories = {
        'web_server': ['Apache', 'nginx', 'IIS', 'LiteSpeed', 'Caddy', 'OpenResty', 'HTTPServer'],
        'framework': ['PHP', 'ASP.NET', 'Django', 'Rails', 'Express', 'Flask', 'Laravel', 'Python'],
        'cms': ['WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'Ghost'],
        'javascript': ['jQuery', 'React', 'Vue', 'Angular', 'Bootstrap', 'Modernizr'],
        'security': ['WAF', 'Cloudflare', 'Sucuri', 'Imperva', 'mod_security'],
        'database': ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'SQLite'],
        'auth': ['PasswordField', 'Login', 'OAuth', 'SSO']
    }

    for tech in result['technologies']:
        for category, keywords in categories.items():
            if any(kw.lower() in tech['name'].lower() for kw in keywords):
                result['stats']['by_category'].setdefault(category, [])
                result['stats']['by_category'][category].append(tech['name'])
                break

    return result


def parse_text_output(file_path: Path) -> Dict[str, Any]:
    """Parse WhatWeb text output (brief format)."""
    result = {
        'type': 'whatweb',
        'format': 'txt',
        'targets': [],
        'technologies': [],
        'stats': {
            'total_targets': 0,
            'total_technologies': 0,
            'by_category': {}
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    with open(file_path, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            target_data = parse_text_line(line)
            if target_data:
                result['targets'].append(target_data)
                result['stats']['total_targets'] += 1
                result['stats']['total_technologies'] += len(target_data['technologies'])

                for tech in target_data['technologies']:
                    if not any(t.get('name') == tech['name'] for t in result['technologies']):
                        result['technologies'].append(tech.copy())

    return result


def detect_format(file_path: Path) -> str:
    """Detect WhatWeb output format."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read(500)

    first_char = content[0] if content else ''

    if first_char in '[{':
        return 'json'

    # Check for verbose report format (AutoRecon output)
    if 'WhatWeb report for' in content:
        return 'verbose'

    return 'txt'


def parse_whatweb(file_path: Path) -> Dict[str, Any]:
    """Parse WhatWeb output file, auto-detecting format."""
    fmt = detect_format(file_path)

    if fmt == 'json':
        return parse_json_output(file_path)
    elif fmt == 'verbose':
        return parse_verbose_report(file_path)
    else:
        return parse_text_output(file_path)


def main():
    parser = argparse.ArgumentParser(description='Parse WhatWeb output')
    parser.add_argument('file', type=Path, help='WhatWeb output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_whatweb(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
