#!/bin/bash
set -e

# ═══════════════════════════════════════════════════════════════════════════
# Split Tunnel Setup - Route HTB subnets through gluetun VPN
# ═══════════════════════════════════════════════════════════════════════════
setup_split_tunnel() {
    if [ -z "$HTB_SUBNETS" ]; then
        echo "[split-tunnel] HTB_SUBNETS not set, skipping VPN routing"
        return 0
    fi

    echo "[split-tunnel] Configuring routes for HTB subnets: $HTB_SUBNETS"

    # Resolve gluetun IP (wait for DNS to be ready)
    local retries=10
    local gluetun_ip=""
    while [ $retries -gt 0 ]; do
        gluetun_ip=$(getent hosts gluetun 2>/dev/null | awk '{print $1}' | head -1)
        if [ -n "$gluetun_ip" ]; then
            break
        fi
        echo "[split-tunnel] Waiting for gluetun DNS resolution..."
        sleep 2
        retries=$((retries - 1))
    done

    if [ -z "$gluetun_ip" ]; then
        echo "[split-tunnel] ERROR: Could not resolve gluetun IP"
        return 1
    fi

    echo "[split-tunnel] Gluetun IP: $gluetun_ip"

    # Add routes for each HTB subnet via gluetun
    IFS=',' read -ra SUBNETS <<< "$HTB_SUBNETS"
    for subnet in "${SUBNETS[@]}"; do
        subnet=$(echo "$subnet" | xargs)  # trim whitespace
        if ip route add "$subnet" via "$gluetun_ip" 2>/dev/null; then
            echo "[split-tunnel] Route added: $subnet via $gluetun_ip"
        else
            echo "[split-tunnel] Route exists or failed: $subnet"
        fi
    done

    echo "[split-tunnel] Setup complete. HTB traffic → VPN, other traffic → direct"
}

# Run split tunnel setup (non-fatal if it fails)
setup_split_tunnel || echo "[split-tunnel] Warning: Setup failed, continuing without VPN routing"

# ═══════════════════════════════════════════════════════════════════════════
# Gemini CLI Setup
# ═══════════════════════════════════════════════════════════════════════════

# Bootstrap gemini config - start fresh, only essentials
mkdir -p /root/.gemini/extensions

# Only copy settings (container-specific config)
cp /etc/gemini/settings.json /root/.gemini/settings.json

# Link opulence extension (mounted at /ext/opulence)
rm -rf /root/.gemini/extensions/opulence
ln -s /ext/opulence /root/.gemini/extensions/opulence

# Note: OAuth tokens stored in mcp-oauth-tokens-v2.json
# Persists in dame-gemini volume after first auth
# GEMINI_FORCE_FILE_STORAGE=true bypasses keychain

# Start tmux session with gemini-cli in yolo mode (auto-approve all actions)
if ! tmux has-session -t dame 2>/dev/null; then
    tmux new-session -d -s dame 'gemini --yolo'
fi

# Keep container alive
exec tail -f /dev/null
