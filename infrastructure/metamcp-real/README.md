# MetaMCP Integration for Agent Opulence

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OpenCode / AI Agent                                │
│                                    │                                         │
│                          MCP Protocol (SSE/HTTP)                            │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    MetaMCP Aggregator (:12008)                       │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │                      Namespaces                              │   │   │
│  │  │  opulence-recon   │ opulence-exploit │ opulence-c2 │ htb    │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│              ┌──────────────────┼──────────────────┐                       │
│              ▼                  ▼                  ▼                        │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │   MSF MCP     │  │  Sliver MCP   │  │  HTB MCP      │  │  HexStrike  │ │
│  │   (Python)    │  │   (Python)    │  │    (Go)       │  │   (Flask)   │ │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘  └──────┬──────┘ │
│          │                  │                  │                  │        │
│          ▼                  ▼                  ▼                  ▼        │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │  Metasploit   │  │    Sliver     │  │   HTB API     │  │  nmap, etc  │ │
│  │   Framework   │  │      C2       │  │   (Cloud)     │  │  (150+ tools)│ │
│  └───────────────┘  └───────────────┘  └───────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. MetaMCP (metatool-ai/metamcp)
- **What**: MCP aggregator/gateway with web UI
- **Role**: Routes tool calls to appropriate backends based on namespaces
- **Port**: 12008
- **Repo**: https://github.com/metatool-ai/metamcp

### 2. MSF MCP (`infrastructure/msf/`)
- **What**: Python wrapper for Metasploit RPC
- **Tools**: `msf__search`, `msf__exploit`, `msf__auxiliary`, `msf__sessions_list`, etc.
- **Transport**: stdio (JSON-RPC 2.0)

### 3. Sliver MCP (`infrastructure/sliver/`)
- **What**: Python wrapper for Sliver C2 gRPC
- **Tools**: `sliver__implant_generate`, `sliver__listener_start`, `sliver__execute`, etc.
- **Transport**: stdio (JSON-RPC 2.0)

### 4. HTB MCP (external)
- **What**: Go-based HackTheBox MCP server
- **Tools**: `list_machines`, `start_machine`, `submit_user_flag`, etc.
- **Repo**: https://github.com/noaslr/htb-mcp-server
- **Note**: Fork needed to add `terminate_machine`, `reset_machine`

### 5. HexStrike (`infrastructure/hexstrike/`)
- **What**: 150+ offensive security tools via MCP
- **Tools**: `nmap_scan`, `nuclei_scan`, `gobuster_scan`, `sqlmap_scan`, etc.
- **Repo**: https://github.com/0x4m4/HexStrike-AI
- **Note**: Runs privileged (needs raw sockets for nmap, etc.)

## Setup Instructions

### Prerequisites

```bash
# Environment variables (add to .env)
HTB_TOKEN=your.jwt.token.here
MSF_TOKEN=msfrpc_password
METAMCP_DB_PASSWORD=secure_password_here
METAMCP_AUTH_SECRET=$(openssl rand -hex 32)
```

### Step 1: Start Core Services

```bash
cd ~/Projects/blunderbussy

# Start VPN, enrichment, MCP wrappers, and HexStrike
podman-compose up -d gluetun enrichment msf-mcp sliver-mcp hexstrike
```

### Step 2: Start MetaMCP

```bash
# Start MetaMCP aggregator with PostgreSQL
podman-compose -f infrastructure/metamcp-real/docker-compose.metamcp.yml up -d
```

### Step 3: Configure MetaMCP

1. Open http://localhost:12008
2. Create account / login
3. Go to **MCP Servers** → **Import JSON**
4. Paste contents of `mcp-servers.json`
5. Create namespace "opulence" and add all servers
6. Create endpoint and generate API key

### Step 4: Connect OpenCode

Add to your OpenCode MCP config (`~/.config/opencode/mcp.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "opulence": {
      "url": "http://localhost:12008/metamcp/opulence/sse"
    }
  }
}
```

Or for stdio transport via mcp-proxy:

```json
{
  "mcpServers": {
    "opulence": {
      "command": "uvx",
      "args": [
        "mcp-proxy",
        "--transport", "streamablehttp",
        "http://localhost:12008/metamcp/opulence/mcp"
      ],
      "env": {
        "API_ACCESS_TOKEN": "sk_mt_your_api_key_here"
      }
    }
  }
}
```

## Namespaces

| Namespace | Servers | Tool Prefixes |
|-----------|---------|---------------|
| `opulence-recon` | HexStrike | `nmap_*`, `masscan_*`, `subfinder_*`, `nuclei_*` |
| `opulence-enum` | HexStrike | `gobuster_*`, `ffuf_*`, `nikto_*`, `wpscan_*` |
| `opulence-exploit` | MSF, HexStrike | `msf__*`, `sqlmap_*`, `hydra_*` |
| `opulence-c2` | Sliver | `sliver__*` |
| `opulence-htb` | HTB | `list_machines`, `start_machine`, etc. |

## Tool Naming Convention

MetaMCP prefixes all tools with their server name:

```
{ServerName}__{originalToolName}

Examples:
- opulence-msf__exploit
- opulence-sliver__implant_generate
- opulence-hexstrike__nmap_scan
- opulence-htb__list_machines
```

## Troubleshooting

### MetaMCP can't reach backends

```bash
# Check if backends are running
podman ps | grep -E "(msf|sliver|hexstrike)"

# Test MSF MCP directly
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
  podman exec -i msf-mcp python3 /app/server.py
```

### HexStrike tools fail

```bash
# Check if tool is installed in container
podman exec hexstrike which nmap
podman exec hexstrike nmap --version

# Check Flask backend health
podman exec hexstrike curl localhost:8888/health
```

### HTB MCP issues

```bash
# Verify HTB token is valid
curl -H "Authorization: Bearer $HTB_TOKEN" \
  https://labs.hackthebox.com/api/v4/user/info
```

## Known Gaps

1. **HTB MCP missing tools**: Need to fork and add:
   - `terminate_machine` - Stop active machine
   - `reset_machine` - Reset machine state

2. **HexStrike tool coverage**: Not all tools may be installed in container. Check Dockerfile and add as needed.

3. **Real backend connections**: MSF and Sliver MCP wrappers return simulated data until real backends (Metasploit/Sliver servers) are deployed and configured.

## Files

```
infrastructure/
├── metamcp-real/
│   ├── docker-compose.metamcp.yml   # MetaMCP + PostgreSQL
│   ├── mcp-servers.json             # Server configuration for import
│   └── README.md                    # This file
├── msf/
│   ├── Dockerfile
│   ├── server.py                    # MSF MCP wrapper
│   └── requirements.txt
├── sliver/
│   ├── Dockerfile
│   ├── server.py                    # Sliver MCP wrapper
│   └── requirements.txt
└── hexstrike/
    └── Dockerfile                   # Kali + security tools + HexStrike
```

## References

- [MetaMCP Documentation](https://github.com/metatool-ai/metamcp)
- [HexStrike-AI](https://github.com/0x4m4/HexStrike-AI)
- [HTB MCP Server](https://github.com/noaslr/htb-mcp-server)
- [MCP Protocol Spec](https://modelcontextprotocol.io/)
