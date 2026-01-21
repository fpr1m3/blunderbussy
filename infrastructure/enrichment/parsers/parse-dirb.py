#!/usr/bin/env python3
"""
DIRB output parser for Agent Opulence enrichment pipeline.

Parses DIRB directory brute-forcing output into structured JSON format.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def parse_dirb(file_path: Path) -> Dict[str, Any]:
    """
    Parse DIRB output file into structured JSON.

    Args:
        file_path: Path to DIRB output file

    Returns:
        Dictionary containing parsed DIRB data with findings, stats, and metadata
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Initialize result structure
    result = {
        "type": "dirb",
        "target": None,
        "config": {},
        "findings": [],
        "stats": {
            "total_found": 0,
            "status_codes": {},
            "directories": [],
            "files": [],
            "interesting": []
        },
        "raw_file": content,
        "parsed_at": datetime.now(timezone.utc).isoformat()
    }

    # Parse configuration
    if match := re.search(r'URL_BASE:\s+(.+)', content):
        result["target"] = match.group(1).strip()

    if match := re.search(r'WORDLIST_FILES:\s+(.+)', content):
        result["config"]["wordlist"] = match.group(1).strip()

    if match := re.search(r'START_TIME:\s+(.+)', content):
        result["config"]["start_time"] = match.group(1).strip()

    # Parse findings
    # Pattern: + http://... (CODE:xxx|SIZE:xxx)
    finding_pattern = re.compile(r'\+\s+(http[^\s]+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)')
    for match in finding_pattern.finditer(content):
        url = match.group(1)
        status = int(match.group(2))
        size = int(match.group(3))

        parsed_url = urlparse(url)
        path = parsed_url.path
        if parsed_url.query:
            path += f"?{parsed_url.query}"

        # 301 redirects typically indicate directories
        is_directory = (status == 301)

        finding = {
            "status": status,
            "size": size,
            "url": url,
            "path": path,
            "is_directory": is_directory
        }

        result["findings"].append(finding)

    # Parse directory markers
    # Pattern: ==> DIRECTORY: http://...
    directory_pattern = re.compile(r'==> DIRECTORY:\s+(http[^\s]+)')
    for match in directory_pattern.finditer(content):
        url = match.group(1)
        parsed_url = urlparse(url)
        path = parsed_url.path

        # Mark existing findings as directories or add new directory entry
        found_existing = False
        for finding in result["findings"]:
            if finding["url"].rstrip('/') == url.rstrip('/'):
                finding["is_directory"] = True
                found_existing = True
                break

        if not found_existing:
            # Add directory entry (no status code available from marker)
            finding = {
                "status": None,
                "size": None,
                "url": url,
                "path": path,
                "is_directory": True
            }
            result["findings"].append(finding)

    # Build statistics
    result["stats"]["total_found"] = len(result["findings"])

    for finding in result["findings"]:
        # Count status codes
        if finding["status"]:
            status_str = str(finding["status"])
            result["stats"]["status_codes"][status_str] = \
                result["stats"]["status_codes"].get(status_str, 0) + 1

        # Categorize paths
        path = finding["path"]
        if finding["is_directory"]:
            if path not in result["stats"]["directories"]:
                result["stats"]["directories"].append(path)
        else:
            if path not in result["stats"]["files"]:
                result["stats"]["files"].append(path)

        # Identify interesting findings
        if is_interesting(path):
            if path not in result["stats"]["interesting"]:
                result["stats"]["interesting"].append(path)

    return result


def is_interesting(path: str) -> bool:
    """
    Determine if a path contains interesting keywords.

    Args:
        path: URL path to check

    Returns:
        True if path contains interesting patterns
    """
    interesting_keywords = [
        'admin', 'backup', 'config', 'upload', 'api', 'dev', 'test',
        '.git', '.env', '.svn', 'phpinfo', 'credentials', 'password',
        'secret', 'private', 'keys', 'token', 'auth', 'login',
        'dashboard', 'panel', 'console', 'debug', 'sql', 'database',
        'db', 'phpmyadmin', 'mysql', 'postgres', 'oracle',
        'jenkins', 'gitlab', 'bitbucket', 'jira', 'confluence'
    ]

    path_lower = path.lower()
    return any(keyword in path_lower for keyword in interesting_keywords)


def main():
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description='Parse DIRB output into structured JSON'
    )
    parser.add_argument(
        'file',
        type=Path,
        help='Path to DIRB output file'
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Pretty-print JSON output'
    )

    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_dirb(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))

    except Exception as e:
        print(f"Error parsing file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
