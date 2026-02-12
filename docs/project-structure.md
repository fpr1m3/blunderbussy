# Project Structure

> Back to [README](../README.md)

```
blunderbussy/
├── infrastructure/
│   ├── enrichment/           # Enrichment pipeline
│   │   ├── faraday_watcher.py    # File watcher + Faraday uploader
│   │   ├── faraday_client.py     # Faraday REST API client
│   │   ├── format-cas.py         # CAS YAML formatter
│   │   ├── init-ptt.py           # PTT initializer (CAS → PTT)
│   │   └── enrichers/            # Service analysis, web detection
│   ├── dame/                  # Kali + gemini-cli container
│   │   ├── Dockerfile        # Multi-platform build (linux/windows)
│   │   └── docker-entrypoint.sh  # Split tunnel setup
│   ├── PrEP/                  # Gemini-CLI extension + MCP servers
│   │   ├── servers/
│   │   │   ├── pwncat-server.py  # In-container via gemini-extension.json
│   │   │   ├── msf-server.py     # Separate container (msf-mcp), via MetaMCP
│   │   │   ├── sliver-server.py  # Separate container (sliver-mcp), via MetaMCP
│   │   │   └── msf-bridge/       # Go HTTP-to-MSFRPC bridge
│   │   ├── agents/           # Sub-agents (code-analysis-*, archivist)
│   │   ├── skills/           # Skills (code-vuln-analysis, etc.)
│   │   ├── gemini-extension.json
│   │   ├── GEMINI.md         # Dame's system prompt
│   │   ├── ptt.py            # Pentesting Task Tree module
│   │   └── commands/         # /attack command
│   ├── hexstrike-recon/      # AutoRecon + 150+ security tools
│   ├── gluetun/              # VPN configuration
│   └── faraday/              # Faraday vulnerability management
├── artifacts/                # Runtime (mounted volume)
│   ├── raw/                  # Raw scan output
│   └── {target}/             # Per-target directories
│       ├── context.yaml      # CAS document
│       ├── ptt.yaml          # Task tree
│       └── loot/             # Flags, creds
├── tests/                    # Test suite
│   ├── fixtures/             # Test data (autorecon, nmap, nuclei, etc.)
│   ├── hooks/                # Hook unit tests (loop detector, file gate, etc.)
│   ├── integration/          # Integration tests
│   ├── mcp/                  # MCP server input validation tests
│   └── test_protocol/        # Protocol action/response tests
├── docker-compose.yml        # Stack definition
├── CLAUDE.md                 # Development instructions
├── GEMINI.md                 # Implementation guide
└── AGENTS.md                 # Agent work instructions
```
