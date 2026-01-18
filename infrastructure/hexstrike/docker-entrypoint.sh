#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# HexStrike Container Entrypoint
# ═══════════════════════════════════════════════════════════════════════════════
# Handles HTB target hostname resolution before starting services.
#
# Environment Variables:
#   HTB_TARGET   - IP address of the HTB target (e.g., 10.129.2.163)
#   HTB_HOSTNAME - Hostname to resolve (e.g., conversor.htb)
#
# Multiple hostnames can be space-separated in HTB_HOSTNAME:
#   HTB_HOSTNAME="conversor.htb api.conversor.htb admin.conversor.htb"
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# Configure /etc/hosts if HTB target is specified
if [ -n "$HTB_TARGET" ] && [ -n "$HTB_HOSTNAME" ]; then
    echo "[hexstrike-entrypoint] Adding hosts entry: $HTB_TARGET → $HTB_HOSTNAME"

    # Handle space-separated hostnames
    echo "$HTB_TARGET $HTB_HOSTNAME" >> /etc/hosts

    echo "[hexstrike-entrypoint] /etc/hosts updated:"
    grep "$HTB_TARGET" /etc/hosts
fi

# Execute the main command
exec "$@"
