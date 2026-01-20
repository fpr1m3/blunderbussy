#!/usr/bin/env python3
"""
Agent Opulence - WPScan Output Parser
======================================
Parses WPScan WordPress vulnerability scanner output into structured JSON.

Usage: parse-wpscan.py <wpscan_output_file>
Output: JSON to stdout

Supports both JSON and text output formats from WPScan.
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def extract_cve_info(text: str) -> List[Dict[str, Any]]:
    """Extract CVE identifiers and related info from text."""
    cves = []
    # Match CVE-YYYY-NNNNN pattern
    for match in re.finditer(r'CVE-(\d{4})-(\d+)', text, re.IGNORECASE):
        cves.append({
            'id': f'CVE-{match.group(1)}-{match.group(2)}',
            'year': int(match.group(1)),
            'number': int(match.group(2))
        })
    return cves


def extract_cvss_score(text: str) -> Optional[float]:
    """Extract CVSS score from text."""
    # Match patterns like "CVSS: 7.5" or "cvss_score: 9.8"
    match = re.search(r'cvss[_\s]*(?:score)?[:\s]*(\d+\.?\d*)', text, re.IGNORECASE)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            pass
    return None


def parse_wpscan_json(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse WPScan JSON output format."""
    result = {
        'type': 'wpscan',
        'target': data.get('target_url'),
        'wordpress': {
            'version': None,
            'version_status': None,
            'theme': None,
            'theme_version': None,
            'plugins': []
        },
        'vulnerabilities': [],
        'users': [],
        'stats': {
            'total_vulnerabilities': 0,
            'plugins_found': 0,
            'users_found': 0,
            'interesting_findings': 0
        }
    }

    # WordPress version info
    if 'version' in data:
        version_data = data['version']
        if isinstance(version_data, dict):
            result['wordpress']['version'] = version_data.get('number')
            result['wordpress']['version_status'] = version_data.get('status', 'unknown')
            # Version vulnerabilities
            if 'vulnerabilities' in version_data:
                for vuln in version_data['vulnerabilities']:
                    vuln_entry = {
                        'title': vuln.get('title', 'Unknown'),
                        'type': 'wordpress_core',
                        'fixed_in': vuln.get('fixed_in'),
                        'references': vuln.get('references', {}),
                        'cves': [],
                        'cvss': None
                    }
                    # Extract CVEs from references
                    if 'cve' in vuln.get('references', {}):
                        for cve in vuln['references']['cve']:
                            vuln_entry['cves'].append(f'CVE-{cve}')
                    result['vulnerabilities'].append(vuln_entry)

    # Main theme
    if 'main_theme' in data:
        theme_data = data['main_theme']
        if isinstance(theme_data, dict):
            result['wordpress']['theme'] = theme_data.get('slug')
            result['wordpress']['theme_version'] = theme_data.get('version', {}).get('number') if isinstance(theme_data.get('version'), dict) else theme_data.get('version')
            # Theme vulnerabilities
            if 'vulnerabilities' in theme_data:
                for vuln in theme_data['vulnerabilities']:
                    vuln_entry = {
                        'title': vuln.get('title', 'Unknown'),
                        'type': 'theme',
                        'component': theme_data.get('slug'),
                        'fixed_in': vuln.get('fixed_in'),
                        'references': vuln.get('references', {}),
                        'cves': [],
                        'cvss': None
                    }
                    if 'cve' in vuln.get('references', {}):
                        for cve in vuln['references']['cve']:
                            vuln_entry['cves'].append(f'CVE-{cve}')
                    result['vulnerabilities'].append(vuln_entry)

    # Plugins
    if 'plugins' in data:
        for plugin_name, plugin_data in data['plugins'].items():
            if isinstance(plugin_data, dict):
                plugin_entry = {
                    'name': plugin_name,
                    'slug': plugin_data.get('slug', plugin_name),
                    'version': plugin_data.get('version', {}).get('number') if isinstance(plugin_data.get('version'), dict) else plugin_data.get('version'),
                    'outdated': plugin_data.get('outdated', False),
                    'vulnerabilities': []
                }
                # Plugin vulnerabilities
                if 'vulnerabilities' in plugin_data:
                    for vuln in plugin_data['vulnerabilities']:
                        vuln_entry = {
                            'title': vuln.get('title', 'Unknown'),
                            'type': 'plugin',
                            'component': plugin_name,
                            'fixed_in': vuln.get('fixed_in'),
                            'references': vuln.get('references', {}),
                            'cves': [],
                            'cvss': None
                        }
                        if 'cve' in vuln.get('references', {}):
                            for cve in vuln['references']['cve']:
                                vuln_entry['cves'].append(f'CVE-{cve}')
                        plugin_entry['vulnerabilities'].append(vuln_entry)
                        result['vulnerabilities'].append(vuln_entry)
                result['wordpress']['plugins'].append(plugin_entry)

    # Users
    if 'users' in data:
        for username, user_data in data['users'].items():
            if isinstance(user_data, dict):
                result['users'].append({
                    'username': username,
                    'id': user_data.get('id'),
                    'slug': user_data.get('slug', username),
                    'confidence': user_data.get('confidence', 100)
                })
            else:
                result['users'].append({'username': username})

    # Interesting findings
    if 'interesting_findings' in data:
        result['stats']['interesting_findings'] = len(data['interesting_findings'])

    # Update stats
    result['stats']['total_vulnerabilities'] = len(result['vulnerabilities'])
    result['stats']['plugins_found'] = len(result['wordpress']['plugins'])
    result['stats']['users_found'] = len(result['users'])

    return result


def parse_wpscan_text(content: str) -> Dict[str, Any]:
    """Parse WPScan text output format."""
    result = {
        'type': 'wpscan',
        'target': None,
        'wordpress': {
            'version': None,
            'version_status': None,
            'theme': None,
            'theme_version': None,
            'plugins': []
        },
        'vulnerabilities': [],
        'users': [],
        'stats': {
            'total_vulnerabilities': 0,
            'plugins_found': 0,
            'users_found': 0,
            'interesting_findings': 0
        }
    }

    lines = content.split('\n')

    # Extract target URL
    for line in lines[:30]:
        match = re.search(r'URL:\s*(https?://\S+)', line, re.IGNORECASE)
        if match:
            result['target'] = match.group(1).rstrip('/')
            break
        match = re.search(r'Scan(?:ning)?\s+(https?://\S+)', line, re.IGNORECASE)
        if match:
            result['target'] = match.group(1).rstrip('/')
            break

    # Extract WordPress version
    for line in lines:
        # Pattern: WordPress version X.X.X identified
        match = re.search(r'WordPress version[:\s]+(\d+\.\d+(?:\.\d+)?)', line, re.IGNORECASE)
        if match:
            result['wordpress']['version'] = match.group(1)
            if 'insecure' in line.lower() or 'outdated' in line.lower():
                result['wordpress']['version_status'] = 'insecure'
            elif 'latest' in line.lower():
                result['wordpress']['version_status'] = 'latest'
            break

    # Extract theme info
    theme_section = False
    current_theme = None
    for i, line in enumerate(lines):
        if re.search(r'WordPress theme in use:', line, re.IGNORECASE):
            theme_section = True
            match = re.search(r'theme in use:\s*(\S+)', line, re.IGNORECASE)
            if match:
                current_theme = match.group(1)
                result['wordpress']['theme'] = current_theme
        elif theme_section:
            match = re.search(r'Version:\s*(\S+)', line, re.IGNORECASE)
            if match:
                result['wordpress']['theme_version'] = match.group(1)
                theme_section = False

    # Extract plugins - look for plugin detection patterns
    plugin_pattern = re.compile(r'\[!\]\s*(?:Name|Title):\s*(.+)', re.IGNORECASE)
    plugin_section = False
    current_plugin = None

    for i, line in enumerate(lines):
        # Detect plugin enumeration section
        if re.search(r'Enumerating.*plugin', line, re.IGNORECASE):
            plugin_section = True
            continue

        if plugin_section:
            # Plugin name patterns
            match = re.search(r'\|\s*Name:\s*(.+)', line)
            if match:
                plugin_name = match.group(1).strip()
                current_plugin = {
                    'name': plugin_name,
                    'slug': plugin_name.lower().replace(' ', '-'),
                    'version': None,
                    'outdated': False,
                    'vulnerabilities': []
                }
                result['wordpress']['plugins'].append(current_plugin)
                continue

            # Also match [+] Plugin Name format
            match = re.search(r'\[\+\]\s*(.+?)(?:\s*$|\s+-)', line)
            if match and 'http' not in line:
                plugin_name = match.group(1).strip()
                if plugin_name and not plugin_name.startswith('Location'):
                    current_plugin = {
                        'name': plugin_name,
                        'slug': plugin_name.lower().replace(' ', '-'),
                        'version': None,
                        'outdated': False,
                        'vulnerabilities': []
                    }
                    result['wordpress']['plugins'].append(current_plugin)
                    continue

            # Version info
            if current_plugin:
                match = re.search(r'Version:\s*(\S+)', line, re.IGNORECASE)
                if match:
                    current_plugin['version'] = match.group(1)
                if 'outdated' in line.lower():
                    current_plugin['outdated'] = True

    # Extract vulnerabilities
    vuln_section = False
    current_vuln = None

    for i, line in enumerate(lines):
        # Vulnerability markers
        if re.search(r'\[!\].*(?:vulnerabilit|CVE-|security)', line, re.IGNORECASE):
            vuln_section = True
            vuln_title = re.sub(r'\[!\]\s*', '', line).strip()
            current_vuln = {
                'title': vuln_title,
                'type': 'unknown',
                'component': None,
                'fixed_in': None,
                'references': {},
                'cves': extract_cve_info(line),
                'cvss': extract_cvss_score(line)
            }
            # Determine type from context
            if 'plugin' in line.lower():
                current_vuln['type'] = 'plugin'
            elif 'theme' in line.lower():
                current_vuln['type'] = 'theme'
            elif 'wordpress' in line.lower() or 'core' in line.lower():
                current_vuln['type'] = 'wordpress_core'
            result['vulnerabilities'].append(current_vuln)

        elif vuln_section and current_vuln:
            # Fixed in version
            match = re.search(r'Fixed in:\s*(\S+)', line, re.IGNORECASE)
            if match:
                current_vuln['fixed_in'] = match.group(1)

            # Additional CVEs
            cves = extract_cve_info(line)
            for cve in cves:
                if cve['id'] not in [c['id'] if isinstance(c, dict) else c for c in current_vuln['cves']]:
                    current_vuln['cves'].append(cve['id'])

            # CVSS score
            if not current_vuln['cvss']:
                current_vuln['cvss'] = extract_cvss_score(line)

            # Reference URLs
            match = re.search(r'Reference:\s*(https?://\S+)', line, re.IGNORECASE)
            if match:
                current_vuln['references']['url'] = current_vuln['references'].get('url', [])
                current_vuln['references']['url'].append(match.group(1))

    # Extract users
    user_section = False
    for i, line in enumerate(lines):
        if re.search(r'User\(?s?\)?.*(?:found|identified|enumerat)', line, re.IGNORECASE):
            user_section = True
            continue

        if user_section:
            # Pattern: | ID | Login | Name |
            match = re.search(r'\|\s*(\d+)\s*\|\s*(\S+)\s*\|', line)
            if match:
                result['users'].append({
                    'id': int(match.group(1)),
                    'username': match.group(2),
                    'slug': match.group(2)
                })
                continue

            # Pattern: [+] username
            match = re.search(r'\[\+\]\s*(\S+)', line)
            if match and 'http' not in line:
                username = match.group(1)
                if username and username not in ['Identified', 'Found']:
                    result['users'].append({
                        'username': username,
                        'slug': username
                    })
                continue

            # Pattern: - username (id: N)
            match = re.search(r'-\s*(\S+)\s*(?:\(id:\s*(\d+)\))?', line)
            if match:
                user_entry = {'username': match.group(1), 'slug': match.group(1)}
                if match.group(2):
                    user_entry['id'] = int(match.group(2))
                result['users'].append(user_entry)

    # Count interesting findings
    interesting_count = 0
    for line in lines:
        if re.search(r'\[\+\].*(?:interesting|found|identified)', line, re.IGNORECASE):
            interesting_count += 1
    result['stats']['interesting_findings'] = interesting_count

    # Update stats
    result['stats']['total_vulnerabilities'] = len(result['vulnerabilities'])
    result['stats']['plugins_found'] = len(result['wordpress']['plugins'])
    result['stats']['users_found'] = len(result['users'])

    return result


def parse_wpscan(file_path: Path) -> Dict[str, Any]:
    """Parse WPScan output file into structured data."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    # Try JSON format first
    try:
        data = json.loads(content)
        result = parse_wpscan_json(data)
    except json.JSONDecodeError:
        # Fall back to text format
        result = parse_wpscan_text(content)

    result['raw_file'] = str(file_path)
    result['parsed_at'] = datetime.now(timezone.utc).isoformat()

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse WPScan output')
    parser.add_argument('file', type=Path, help='WPScan output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_wpscan(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
