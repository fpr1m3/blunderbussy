# Agent Opulence / Blunderbussy framework

## Use of `bd` for task management

Use `bd` to manage all tasks. Make sure to create issues
to keep track of everything.

## Python tooling

Use `uv` for Python package management and running tests:
- `uv pip install <package>` - Install packages
- `uv run pytest` - Run tests
- `uv run python script.py` - Run scripts

## Container tooling

Use `podman` and `podman-compose` (not docker):
- `podman-compose up -d` - Start services
- `podman-compose ps` - List running containers
- `podman exec -it <container> <command>` - Execute in container

**IMPORTANT: Fully qualified image names required**

Podman does not have unqualified-search registries configured. Always use full image paths:

```yaml
# WRONG - will fail
image: postgres:15
image: redis:alpine

# CORRECT - always prefix with registry
image: docker.io/library/postgres:15
image: docker.io/library/redis:alpine
image: docker.io/faradaysec/faraday:latest
```

Official images use `docker.io/library/`, third-party use `docker.io/<org>/`.

## Dame container builds

The Dame Dockerfile supports platform-specific tool groups via build arg:

```bash
# Linux target (default) - includes searchsploit
podman build --build-arg TARGET_PLATFORM=linux -t dame:linux -f infrastructure/dame/Dockerfile infrastructure/dame/

# Windows/AD target - includes evil-winrm, responder, ldap-utils, bloodhound
podman build --build-arg TARGET_PLATFORM=windows -t dame:windows -f infrastructure/dame/Dockerfile infrastructure/dame/
```

Core tools (always installed): nc, ping, traceroute, wget, socat, rlwrap, git, jq, dig, proxychains4, nbtscan, onesixtyone, snmpwalk, nmap, dnsrecon, gobuster, feroxbuster, ffuf, whatweb, sqlmap, nikto, enum4linux, smbmap, smbclient, impacket-scripts, crackmapexec, hydra, tmux, ripgrep

## Gemini CLI Extension System (Dame)

Dame runs on gemini-cli with the `opulence` extension. **This is an undocumented experimental feature** - not in official docs, extracted from source code at `~/Code/gemini-cli/`. See `docs/gemini-cli-agents.md` for reference.

### Extension Structure

The extension is installed during Dame container entrypoint from `infrastructure/PrEP/`:

```
infrastructure/PrEP/
├── gemini-extension.json    # Extension manifest (MCP servers, metadata)
├── GEMINI.md                # Dame's system prompt
├── session_state.py         # Session state management
├── session_memory.py        # Memory persistence
├── agents/                  # Subagents (delegate_to_agent)
│   ├── archivist.md         # Multi-step research (saves context window)
│   ├── code-analysis-recon.md
│   ├── code-analysis-triage.md
│   ├── code-analysis-analysis.md
│   └── code-analysis-validation.md
├── skills/                  # Skills (activate_skill)
│   ├── SCHEMA.md            # Skill schema documentation
│   ├── code-vuln-analysis/  # Multi-agent vulnerability analysis
│   │   ├── SKILL.md
│   │   ├── prompts/         # Agent prompts
│   │   ├── resources/       # Patterns and anti-patterns
│   │   └── scripts/         # Helper scripts (tokens, taint, etc.)
│   ├── initial-access/
│   ├── pentest-checklist/
│   ├── pentest-commands/
│   ├── red-team-tactics/
│   ├── scanning-tools/
│   ├── sql-injection-testing/
│   ├── api-fuzzing-bug-bounty/
│   └── vulnerability-scanner/
├── hooks/                   # Tool execution hooks
│   ├── hooks.json
│   ├── session_start.py       # SessionStart: load state + inject memory
│   ├── before_tool.py         # BeforeTool: query cache dedup
│   ├── after_tool.py          # AfterTool: output processing + cred extraction
│   ├── file_size_gate.py      # BeforeTool: block oversized file reads
│   ├── autorecon_dedup.py     # BeforeTool: block redundant scans
│   ├── shellcheck_validator.py # BeforeTool: validate shell syntax
│   ├── command_utils.py       # Shared command parsing utilities
│   └── loop_detector.py       # AfterTool: MinHash similarity loop detection
├── servers/                 # MCP servers
│   ├── pwncat-server.py
│   ├── msf-server.py
│   └── sliver-server.py
├── commands/
│   └── attack.toml          # /attack {target} command
├── protocol/                # IPC protocol definitions
├── schemas/                 # Data schemas
├── tests/                   # PrEP-specific tests (pipeline gate, etc.)
└── ERROR_HANDLING.md        # Error classification reference
```

### Skills vs Agents

| Type | Location | Tool | Purpose |
|------|----------|------|---------|
| Skills | `${ext}/skills/` | `activate_skill("name")` | Load instructions into Dame's context |
| Agents | `${ext}/agents/` | `delegate_to_agent(agent_name, query)` | Spawn independent subagent |

### Enabling (settings.json)

```json
{
  "general": {
    "previewFeatures": true
  },
  "context": {
    "includeDirectories": ["/artifacts"]
  },
  "experimental": {
    "introspectionAgentSettings": { "enabled": true },
    "plan": true,
    "skills": true,
    "enableAgents": true,
    "useOSC52Paste": true
  },
  "model": {
    "name": "gemini-3-flash-preview"
  },
  "tools": {
    "enableHooks": true,
    "enableToolOutputTruncation": true,
    "truncateToolOutputThreshold": 15000,
    "truncateToolOutputLines": 100
  },
  "hooksConfig": {
    "enabled": true
  }
}
```

### Code Vulnerability Analysis Flow

1. Dame finds source code (git dump, LFI, etc.)
2. Dame calls `activate_skill("code-vuln-analysis")`
3. Skill instructions load, telling Dame to orchestrate 4 sub-agents
4. Dame uses `delegate_to_agent` to call recon → triage → analysis → validation
5. Dame receives Vulnerability Brief and executes PoCs
