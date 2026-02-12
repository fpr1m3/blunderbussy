# Security Model

> Back to [README](../README.md)

## Four-Layer Protection

1. **Network Isolation (Primary/Hard Boundary)**
   - Recon, C2, and MCP containers locked to gluetun VPN (`network_mode: "service:gluetun"`)
   - Killswitch blocks all traffic if VPN drops
   - Dame uses split tunnel: HTB subnets via VPN, direct internet for OAuth/APIs only

2. **Volume Isolation (Primary/Hard Boundary)**
   - Dame can only access `/artifacts` (shared data) and `/ext/opulence` (read-only extension code)
   - No host filesystem access beyond mounted volumes
   - Extension code is read-only — Dame cannot modify its own instructions

3. **Scope Definition (Secondary/Soft)**
   - `/artifacts/scope.yaml` defines allowed targets
   - Dame instructed to respect scope in system prompt
   - Parsers filter out-of-scope results

4. **AI Guardrails (Tertiary)**
   - Dame's system prompt: "Only operate on targets in CAS"
   - "No reconnaissance beyond provided CAS"
   - "Document all attempts and findings"
