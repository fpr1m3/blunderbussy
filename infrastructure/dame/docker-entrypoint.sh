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
  IFS=',' read -ra SUBNETS <<<"$HTB_SUBNETS"
  for subnet in "${SUBNETS[@]}"; do
    subnet=$(echo "$subnet" | xargs) # trim whitespace
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
# Target Resolution
# ═══════════════════════════════════════════════════════════════════════════
# TARGET may be passed at container start: podman run -e TARGET=10.0.0.1
# Or written mid-session by /attack command to /artifacts/.current_target
# Export it so gemini-cli hooks (spawned as child processes) can read it.

if [ -n "$TARGET" ]; then
  echo "[target] TARGET set from environment: $TARGET"
elif [ -f /artifacts/.current_target ]; then
  TARGET=$(cat /artifacts/.current_target | tr -d '[:space:]')
  if [ -n "$TARGET" ]; then
    echo "[target] TARGET loaded from /artifacts/.current_target: $TARGET"
  fi
fi

if [ -n "$TARGET" ]; then
  export TARGET
else
  echo "[target] TARGET not set (will be set when /attack is used)"
fi

# ═══════════════════════════════════════════════════════════════════════════
# Gemini CLI Setup
# ═══════════════════════════════════════════════════════════════════════════

# Bootstrap gemini config (force overwrite to ensure image config is used)
mkdir -p /root/.gemini/extensions
cp -f /etc/gemini/settings.json /root/.gemini/settings.json

# If GEMINI_API_KEY is set, switch auth from OAuth to API key mode
if [ -n "$GEMINI_API_KEY" ]; then
  echo "[auth] GEMINI_API_KEY detected, switching to gemini-api-key auth"
  sed -i 's/"selectedType": "oauth-personal"/"selectedType": "gemini-api-key"/' /root/.gemini/settings.json
fi

# ═══════════════════════════════════════════════════════════════════════════
# Extension Linking
# ═══════════════════════════════════════════════════════════════════════════
if [ -d /ext/opulence ]; then
  rm -rf /root/.gemini/extensions/opulence 2>/dev/null || true
  gemini extensions link /ext/opulence --consent >/dev/null 2>&1 || echo "[gemini] Extension link failed"
else
  echo "[gemini] Extension directory /ext/opulence not found"
fi

# Note: OAuth tokens stored in mcp-oauth-tokens-v2.json
# Persists in dame-gemini volume after first auth
# GEMINI_FORCE_FILE_STORAGE=true bypasses keychain

# ═══════════════════════════════════════════════════════════════════════════
# Launch Mode
# ═══════════════════════════════════════════════════════════════════════════
# If CMD args are passed (e.g. from eval harness), run gemini directly
# in headless mode. Otherwise, start interactive tmux session.

if [ $# -gt 0 ]; then
  # Headless mode: exec the provided command (e.g. gemini --yolo ...)
  echo "[dame] Headless mode: $*"
  export GEMINI_SYSTEM_MD=/ext/opulence/GEMINI.md
  # Run from /artifacts so gemini-cli's file sandbox allows reading CAS/PTT
  cd /artifacts 2>/dev/null || true
  exec "$@"
else
  # Interactive mode: tmux session with gemini-cli
  # GEMINI_SYSTEM_MD enables dynamic context injection via custom system prompt
  # TARGET is passed explicitly so hooks spawned by gemini-cli can read it
  if ! tmux has-session -t dame 2>/dev/null; then
    tmux new-session -d -s dame "TARGET=${TARGET:-} GEMINI_SYSTEM_MD=/ext/opulence/GEMINI.md gemini --yolo"
  fi

  # Keep container alive
  exec tail -f /dev/null
fi
