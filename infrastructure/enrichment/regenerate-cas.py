#!/usr/bin/env python3
"""
Regenerate CAS from existing Faraday workspace data.

Usage:
    # Inside enrichment container:
    python3 regenerate-cas.py <workspace> <target_ip>

    # From host:
    podman exec enrichment python3 /app/regenerate-cas.py <workspace> <target_ip>

Examples:
    python3 regenerate-cas.py gavel 10.129.242.203
    python3 regenerate-cas.py ws_10_129_3_245 10.129.3.245
"""

import os
import sys

from faraday_client import FaradayClient, FaradayConfig
from faraday_watcher import generate_cas_from_workspace


def list_workspaces(client: FaradayClient) -> None:
    """List all workspaces with their stats."""
    resp = client.session.get(f'{client.config.url}/_api/v3/ws', timeout=30)
    data = resp.json()
    rows = data.get('rows', data) if isinstance(data, dict) else data

    print('Available workspaces:')
    for ws in rows:
        name = ws.get('name')
        stats = ws.get('stats', {})
        hosts = stats.get('hosts', 0)
        services = stats.get('services', 0)
        vulns = stats.get('opened_vulns', 0) + stats.get('closed_vulns', 0)
        print(f'  {name}: {hosts} hosts, {services} services, {vulns} vulns')


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print('Error: workspace name required')
        print('Use --list to see available workspaces')
        sys.exit(1)

    # Initialize client
    config = FaradayConfig(
        url=os.getenv('FARADAY_URL', 'http://faraday-server:5985'),
        username=os.getenv('FARADAY_USER', 'faraday'),
        password=os.getenv('FARADAY_PASSWORD', 'changeme')
    )
    client = FaradayClient(config)
    client.authenticate()

    # Handle --list flag
    if sys.argv[1] == '--list':
        list_workspaces(client)
        sys.exit(0)

    workspace = sys.argv[1]

    # Target IP - derive from workspace name if not provided
    if len(sys.argv) >= 3:
        target = sys.argv[2]
    else:
        # Try to extract IP from workspace name (ws_10_129_3_245 -> 10.129.3.245)
        if workspace.startswith('ws_'):
            target = workspace[3:].replace('_', '.')
        else:
            target = workspace
        print(f'Target IP not provided, using: {target}')

    # Optional: skip PTT generation (useful if PTT has bugs)
    generate_ptt = '--no-ptt' not in sys.argv

    print(f'Regenerating CAS for workspace "{workspace}" -> target "{target}"')
    print(f'PTT generation: {"enabled" if generate_ptt else "disabled"}')

    result = generate_cas_from_workspace(
        client=client,
        workspace=workspace,
        target=target,
        scan_type='faraday',
        generate_ptt=generate_ptt
    )

    if result:
        print(f'\nSuccess: {result}')
    else:
        print('\nFailed to generate CAS')
        sys.exit(1)


if __name__ == '__main__':
    main()
