#!/usr/bin/env python3
"""
Redis-CLI output parser for Agent Opulence framework.

Parses various Redis CLI command outputs including:
- INFO command (server information, keyspace stats)
- KEYS listing
- CONFIG GET output

Example usage:
    python parse-redis-cli.py /path/to/redis-output.txt
    python parse-redis-cli.py /path/to/redis-output.txt --pretty
"""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def extract_target(content: str) -> str:
    """Extract target host:port from output header or default."""
    # Look for target in first line comment
    first_line = content.split('\n')[0] if content else ''
    target_match = re.search(r'(\d+\.\d+\.\d+\.\d+:\d+)', first_line)
    if target_match:
        return target_match.group(1)
    return "unknown:6379"


def parse_info_section(content: str) -> Dict[str, Any]:
    """Parse Redis INFO command output sections."""
    info_data = {}
    current_section = None

    for line in content.split('\n'):
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Section header (e.g., "# Server", "# Clients")
        if line.startswith('#'):
            # Extract section name
            section_text = line[1:].strip()

            # Skip special sections that aren't INFO sections
            # Use more precise matching to avoid false positives (e.g., "Keyspace" vs "KEYS")
            skip_keywords = ['REDIS CLI OUTPUT', 'CONFIG GET']
            # For KEYS, match exactly or at start of string
            if section_text.upper() in ['KEYS', 'KEYS *', 'KEYS * OUTPUT']:
                current_section = None
                continue
            if any(keyword in section_text.upper() for keyword in skip_keywords):
                current_section = None
                continue

            # Valid section header - convert to snake_case
            section_name = section_text.lower().replace(' ', '_')
            current_section = section_name
            if current_section not in info_data:
                info_data[current_section] = {}
            continue

        # Key:value pair
        if ':' in line and not line.startswith('#') and not line.startswith(')'):
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            # Store in current section or root
            if current_section:
                info_data[current_section][key] = value
            else:
                if 'other' not in info_data:
                    info_data['other'] = {}
                info_data['other'][key] = value

    return info_data


def parse_keyspace_section(info_data: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    """Parse keyspace section from INFO output."""
    databases = {}

    if 'keyspace' not in info_data:
        return databases

    for db_name, db_info in info_data['keyspace'].items():
        if db_name.startswith('db'):
            # Parse "keys=42,expires=10,avg_ttl=86400000"
            db_stats = {}
            for pair in db_info.split(','):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    try:
                        db_stats[key.strip()] = int(value.strip())
                    except ValueError:
                        db_stats[key.strip()] = value.strip()
            databases[db_name] = db_stats

    return databases


def parse_keys_listing(content: str) -> List[str]:
    """Parse KEYS command output (numbered list)."""
    keys = []

    # Look for numbered key listings like: 1) "key_name"
    key_pattern = re.compile(r'^\d+\)\s+"?([^"]+)"?$')

    in_keys_section = False
    for line in content.split('\n'):
        line = line.strip()

        # Detect KEYS section
        if '# KEYS' in line.upper():
            in_keys_section = True
            continue

        # Exit on next section
        if line.startswith('# ') and in_keys_section and 'KEYS' not in line.upper():
            break

        # Parse key entry
        match = key_pattern.match(line)
        if match:
            key = match.group(1).strip('"')
            keys.append(key)

    return keys


def parse_config_output(content: str) -> Dict[str, str]:
    """Parse CONFIG GET command output (alternating key-value pairs)."""
    config = {}

    # Look for CONFIG GET section
    lines = content.split('\n')
    in_config_section = False
    config_lines = []

    for line in lines:
        line = line.strip()

        # Detect CONFIG section
        if '# CONFIG GET' in line.upper():
            in_config_section = True
            continue

        # Exit on next section
        if line.startswith('# ') and in_config_section and 'CONFIG' not in line.upper():
            break

        # Collect numbered lines in config section
        if in_config_section and re.match(r'^\d+\)', line):
            # Extract value after number
            value = re.sub(r'^\d+\)\s+"?', '', line).strip('"')
            config_lines.append(value)

    # Pair up alternating key-value entries
    for i in range(0, len(config_lines) - 1, 2):
        key = config_lines[i]
        value = config_lines[i + 1]
        config[key] = value

    return config


def identify_interesting_findings(
    keys: List[str],
    databases: Dict[str, Dict[str, int]],
    config: Dict[str, str],
    server_info: Dict[str, Any]
) -> List[str]:
    """Identify interesting security findings."""
    findings = []

    # Sensitive keywords in keys
    sensitive_patterns = [
        'admin', 'password', 'secret', 'token', 'key',
        'credential', 'config', 'session', 'auth', 'jwt',
        'api', 'encryption', 'aws', 'private'
    ]

    sensitive_keys = []
    for key in keys:
        key_lower = key.lower()
        for pattern in sensitive_patterns:
            if pattern in key_lower:
                sensitive_keys.append(key)
                break

    if sensitive_keys:
        findings.append(f"Found {len(sensitive_keys)} potentially sensitive keys")
        for key in sensitive_keys[:5]:  # Show first 5
            findings.append(f"  - {key}")
        if len(sensitive_keys) > 5:
            findings.append(f"  ... and {len(sensitive_keys) - 5} more")

    # Large databases
    for db_name, db_stats in databases.items():
        key_count = db_stats.get('keys', 0)
        if key_count > 100:
            findings.append(f"Large database: {db_name} has {key_count} keys")

    # Security-relevant config
    if config.get('requirepass') == '' or not config.get('requirepass'):
        findings.append("WARNING: No password protection (requirepass is empty)")

    if config.get('protected-mode') == 'no':
        findings.append("WARNING: Protected mode is disabled")

    if config.get('bind') in ['0.0.0.0', '*']:
        findings.append("WARNING: Redis is bound to all interfaces")

    # Check server info
    if 'server' in server_info:
        version = server_info['server'].get('redis_version', '')
        if version:
            findings.append(f"Redis version: {version}")

    return findings


def parse_redis_cli(file_path: Path) -> Dict[str, Any]:
    """
    Parse Redis CLI output file.

    Args:
        file_path: Path to the redis-cli output file

    Returns:
        Dictionary containing parsed data with keys:
        - type: "redis-cli"
        - target: host:port
        - server_info: Server information sections
        - keys: List of key names
        - databases: Database statistics
        - config: Configuration key-value pairs
        - stats: Summary statistics
        - raw_file: Original file path
        - parsed_at: Timestamp
    """
    content = file_path.read_text()

    # Extract target
    target = extract_target(content)

    # Parse INFO sections
    info_data = parse_info_section(content)

    # Parse keyspace (databases)
    databases = parse_keyspace_section(info_data)

    # Parse KEYS listing
    keys = parse_keys_listing(content)

    # Parse CONFIG GET output
    config = parse_config_output(content)

    # Calculate total keys across all databases
    total_keys = sum(db.get('keys', 0) for db in databases.values())
    if keys:  # If we have explicit keys list, use that count
        total_keys = max(total_keys, len(keys))

    # Identify interesting findings
    interesting = identify_interesting_findings(keys, databases, config, info_data)

    # Build output structure
    result = {
        "type": "redis-cli",
        "target": target,
        "server_info": info_data.get('server', {}),
        "clients_info": info_data.get('clients', {}),
        "memory_info": info_data.get('memory', {}),
        "persistence_info": info_data.get('persistence', {}),
        "stats_info": info_data.get('stats', {}),
        "replication_info": info_data.get('replication', {}),
        "cpu_info": info_data.get('cpu', {}),
        "keys": keys,
        "databases": databases,
        "config": config,
        "stats": {
            "total_keys": total_keys,
            "total_databases": len(databases),
            "keys_found": len(keys),
            "config_entries": len(config),
            "interesting": interesting
        },
        "raw_file": str(file_path.absolute()),
        "parsed_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    }

    return result


def main():
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description="Parse Redis CLI output and convert to JSON"
    )
    parser.add_argument(
        "file",
        type=Path,
        help="Path to redis-cli output file"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty print JSON output"
    )

    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({"error": f"File not found: {args.file}"}))
        return 1

    try:
        result = parse_redis_cli(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))

        return 0
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1


if __name__ == "__main__":
    exit(main())
