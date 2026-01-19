#!/bin/bash
set -e

# Bootstrap gemini config from host mount
mkdir -p /root/.gemini/extensions

# Copy auth files from host (mounted at /root/.gemini-host)
# Using cp instead of symlink because gemini-cli may need write access
cp /root/.gemini-host/oauth_creds.json /root/.gemini/
cp /root/.gemini-host/google_accounts.json /root/.gemini/
cp /root/.gemini-host/installation_id /root/.gemini/

# Copy container settings (baked in at build time)
cp /etc/gemini/settings.json /root/.gemini/settings.json

# Link opulence extension (mounted at /ext/opulence)
ln -sf /ext/opulence /root/.gemini/extensions/opulence

# Start tmux session with gemini-cli
if ! tmux has-session -t dame 2>/dev/null; then
    tmux new-session -d -s dame 'gemini'
fi

# Keep container alive
exec tail -f /dev/null
