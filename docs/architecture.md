# Architecture

> Back to [README](../README.md)

```
┌─────────────────────────────────────────────────────────────┐
│                     DAME CONTAINER                           │
│  Kali Linux + gemini-cli + pwncat-cs                        │
│  Dame (AI): Reads CAS, exploits, privesc                    │
├─────────────────────────────────────────────────────────────┤
│                   ENRICHMENT PIPELINE                        │
│  faraday_watcher.py → Faraday → Enrichers → CAS Formatter   │
├─────────────────────────────────────────────────────────────┤
│                  HEXSTRIKE (Recon Tools)                     │
│  AutoRecon, nmap, nuclei, feroxbuster, 150+ tools           │
├─────────────────────────────────────────────────────────────┤
│                   C2 FRAMEWORKS (MSF + Sliver)               │
│  msf (msfrpcd) + msf-bridge + sliver daemon                  │
├─────────────────────────────────────────────────────────────┤
│                 NETWORK ISOLATION (GLUETUN)                  │
│  VPN tunnel + killswitch, all traffic through HTB VPN       │
└─────────────────────────────────────────────────────────────┘
```

## Main Components

| Component | Container | Purpose |
|-----------|-----------|---------|
| `gluetun` | VPN gateway | Mandatory VPN with killswitch, network isolation |
| `enrichment` | Python 3.11 | Watches raw scans, parses, enriches, outputs CAS |
| `hexstrike-recon` | 150+ tools | Automated recon (nmap, nuclei, feroxbuster, etc.) |
| `dame` | Kali + gemini-cli | AI exploitation agent with full offensive toolkit |
| `qdrant` | Vector DB | Technique library for exploitation knowledge |
| `pwncat-mcp` | Python | Post-exploitation framework MCP server |
| `msf` | Metasploit | Metasploit Framework with msfrpcd for exploitation* |
| `msf-bridge` | Go HTTP API | HTTP bridge for MSFRPC communication* |
| `sliver` | Sliver C2 | Sliver implant server for C2 operations* |

> **\*** The MSF and Sliver integrations are architecturally complete but have not yet been end-to-end tested against live HTB targets. They may require additional configuration or debugging during first real engagement.

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DAME CONTAINER                            │
│  Split tunnel: HTB subnets via VPN, else direct internet    │
│  - 10.10.0.0/16 → gluetun VPN                               │
│  - 10.129.0.0/16 → gluetun VPN                              │
│  - Everything else → direct (OAuth, APIs, web)              │
├─────────────────────────────────────────────────────────────┤
│              HEXSTRIKE / C2 / MCP CONTAINERS                │
│  network_mode: "service:gluetun" (full VPN lockdown)        │
│  - ALL traffic forced through VPN tunnel                    │
│  - Can ONLY reach HTB targets, no direct internet           │
├─────────────────────────────────────────────────────────────┤
│                     GLUETUN CONTAINER                        │
│  VPN tunnel (HTB) + killswitch + DNS leak protection        │
│  - Only HTB network accessible when VPN connected           │
│  - Killswitch blocks all traffic if VPN drops               │
└─────────────────────────────────────────────────────────────┘
```
