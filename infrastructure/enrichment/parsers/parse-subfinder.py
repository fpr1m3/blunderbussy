#!/usr/bin/env python3
"""
Agent Opulence - Subfinder Parser
=================================
Parses subfinder output (JSON/JSONL or plain text) into structured format.

Usage: parse-subfinder.py <subfinder_file>
Output: JSON to stdout

Extracts:
- Subdomains
- Sources
- Domain hierarchy
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Set
from datetime import datetime, timezone
from collections import defaultdict


def extract_domain_parts(subdomain: str) -> Dict[str, Any]:
    """Extract domain hierarchy from subdomain."""
    parts = subdomain.lower().strip().split('.')

    result = {
        'full': subdomain.lower().strip(),
        'parts': parts,
        'depth': len(parts),
        'tld': parts[-1] if parts else '',
        'root_domain': '.'.join(parts[-2:]) if len(parts) >= 2 else subdomain,
        'subdomain_prefix': '.'.join(parts[:-2]) if len(parts) > 2 else ''
    }

    # Detect interesting patterns
    result['patterns'] = []

    # Common interesting subdomains
    interesting_prefixes = [
        'admin', 'api', 'dev', 'staging', 'test', 'uat', 'beta', 'alpha',
        'internal', 'vpn', 'mail', 'webmail', 'remote', 'secure', 'portal',
        'jenkins', 'gitlab', 'github', 'jira', 'confluence', 'kibana',
        'grafana', 'prometheus', 'elastic', 'mongo', 'mysql', 'postgres',
        'redis', 'memcached', 'rabbitmq', 'kafka', 'zookeeper',
        'ftp', 'sftp', 'backup', 'bak', 'old', 'new', 'v1', 'v2',
        'cms', 'blog', 'shop', 'store', 'app', 'mobile', 'm',
        'cdn', 'static', 'assets', 'media', 'images', 'img',
        'login', 'sso', 'auth', 'oauth', 'cas', 'ldap', 'ad',
        'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap',
        'git', 'svn', 'hg', 'repo', 'registry', 'docker', 'k8s', 'kubernetes',
        'aws', 'azure', 'gcp', 'cloud', 's3', 'bucket'
    ]

    prefix = parts[0] if parts else ''
    for interesting in interesting_prefixes:
        if interesting in prefix.lower():
            result['patterns'].append(interesting)

    # Detect environment indicators
    env_indicators = ['dev', 'staging', 'stage', 'stg', 'test', 'uat', 'qa',
                      'prod', 'production', 'demo', 'sandbox', 'preview']
    for env in env_indicators:
        if env in subdomain.lower():
            result['environment'] = env
            break

    return result


def parse_json_format(content: str) -> List[Dict[str, Any]]:
    """Parse JSON/JSONL format."""
    subdomains = []

    if content.strip().startswith('['):
        # JSON array format
        data = json.loads(content)
        for item in data:
            if isinstance(item, str):
                subdomains.append({'host': item, 'sources': []})
            elif isinstance(item, dict):
                subdomains.append({
                    'host': item.get('host', item.get('subdomain', '')),
                    'sources': item.get('sources', item.get('source', [])),
                    'input': item.get('input', '')
                })
    else:
        # JSONL format
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, str):
                    subdomains.append({'host': item, 'sources': []})
                elif isinstance(item, dict):
                    subdomains.append({
                        'host': item.get('host', item.get('subdomain', '')),
                        'sources': item.get('sources', item.get('source', [])),
                        'input': item.get('input', '')
                    })
            except json.JSONDecodeError:
                # Might be plain text
                if '.' in line and not line.startswith('#'):
                    subdomains.append({'host': line, 'sources': []})

    return subdomains


def parse_text_format(content: str) -> List[Dict[str, Any]]:
    """Parse plain text format (one subdomain per line)."""
    subdomains = []

    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#') and '.' in line:
            # Basic validation - should look like a domain
            if all(c.isalnum() or c in '.-_' for c in line):
                subdomains.append({'host': line, 'sources': []})

    return subdomains


def parse_subfinder_output(file_path: Path) -> Dict[str, Any]:
    """Parse subfinder output file."""
    with open(file_path, 'r') as f:
        content = f.read().strip()

    # Detect format and parse
    if content.startswith('[') or content.startswith('{'):
        raw_subdomains = parse_json_format(content)
    else:
        raw_subdomains = parse_text_format(content)

    # Process and deduplicate
    seen_hosts: Set[str] = set()
    subdomains = []
    sources_by_host: Dict[str, Set[str]] = defaultdict(set)

    for item in raw_subdomains:
        host = item.get('host', '').lower().strip()
        if not host or host in seen_hosts:
            continue

        seen_hosts.add(host)

        # Collect sources
        sources = item.get('sources', [])
        if isinstance(sources, str):
            sources = [sources]
        for source in sources:
            sources_by_host[host].add(source)

        # Parse domain structure
        domain_info = extract_domain_parts(host)

        subdomain_entry = {
            'host': host,
            'sources': list(sources_by_host[host]),
            'domain_info': domain_info
        }

        subdomains.append(subdomain_entry)

    # Build result structure
    result = {
        'type': 'subfinder',
        'version': 'subfinder',
        'subdomains': subdomains,
        'stats': {
            'total': len(subdomains),
            'unique_root_domains': set(),
            'by_source': defaultdict(int),
            'by_depth': defaultdict(int),
            'interesting_count': 0,
            'with_patterns': defaultdict(int),
            'by_environment': defaultdict(int)
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Calculate stats
    for subdomain in subdomains:
        domain_info = subdomain['domain_info']

        result['stats']['unique_root_domains'].add(domain_info['root_domain'])
        result['stats']['by_depth'][str(domain_info['depth'])] += 1

        for source in subdomain['sources']:
            result['stats']['by_source'][source] += 1

        if domain_info['patterns']:
            result['stats']['interesting_count'] += 1
            for pattern in domain_info['patterns']:
                result['stats']['with_patterns'][pattern] += 1

        if 'environment' in domain_info:
            result['stats']['by_environment'][domain_info['environment']] += 1

    # Convert sets to lists for JSON serialization
    result['stats']['unique_root_domains'] = list(result['stats']['unique_root_domains'])
    result['stats']['by_source'] = dict(result['stats']['by_source'])
    result['stats']['by_depth'] = dict(result['stats']['by_depth'])
    result['stats']['with_patterns'] = dict(result['stats']['with_patterns'])
    result['stats']['by_environment'] = dict(result['stats']['by_environment'])

    # Organize by root domain
    result['by_root_domain'] = defaultdict(list)
    for subdomain in subdomains:
        root = subdomain['domain_info']['root_domain']
        result['by_root_domain'][root].append(subdomain['host'])
    result['by_root_domain'] = dict(result['by_root_domain'])

    # Extract interesting findings for agents
    result['interesting'] = {
        'development_environments': [],
        'admin_panels': [],
        'api_endpoints': [],
        'internal_services': [],
        'devops_tools': [],
        'databases': []
    }

    # Categorize interesting subdomains
    category_patterns = {
        'development_environments': ['dev', 'staging', 'stage', 'test', 'uat', 'qa', 'sandbox'],
        'admin_panels': ['admin', 'portal', 'console', 'dashboard', 'manage'],
        'api_endpoints': ['api', 'rest', 'graphql', 'ws', 'websocket'],
        'internal_services': ['internal', 'intranet', 'vpn', 'corp', 'private'],
        'devops_tools': ['jenkins', 'gitlab', 'github', 'jira', 'confluence', 'kibana',
                         'grafana', 'prometheus', 'docker', 'k8s', 'kubernetes', 'ci', 'cd'],
        'databases': ['mongo', 'mysql', 'postgres', 'redis', 'elastic', 'db', 'database']
    }

    for subdomain in subdomains:
        host = subdomain['host']
        for category, patterns in category_patterns.items():
            for pattern in patterns:
                if pattern in host.lower():
                    if host not in result['interesting'][category]:
                        result['interesting'][category].append(host)
                    break

    return result


def main():
    parser = argparse.ArgumentParser(description='Parse subfinder output')
    parser.add_argument('file', type=Path, help='Subfinder output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_subfinder_output(args.file)
        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}'}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
