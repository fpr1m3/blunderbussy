# Gemini CLI Agent & Skill System

Reference documentation for configuring agents and skills in gemini-cli (Dame).

> **Note:** This is an undocumented, experimental feature in gemini-cli. Not in official docs - extracted from source code at `~/Code/gemini-cli/`.

## Skills vs Agents

| Type | Tool | Location | Behavior |
|------|------|----------|----------|
| Skills | `activate_skill("name")` | `${ext}/skills/{name}/SKILL.md` | Loads instructions into agent's context |
| Agents | `delegate_to_agent(agent, query)` | `${ext}/agents/{name}.md` | Spawns independent subagent |

**Skills** = Instructions the main agent follows (orchestration)
**Agents** = Independent workers that return results (delegation)

## Skill File Structure

Skills use YAML frontmatter similar to agents:

```markdown
---
name: skill-name              # REQUIRED: lowercase
description: What this skill does
---

# Skill instructions here...
```

## Enabling Agents

In `settings.json`:
```json
{
  "experimental": {
    "enableAgents": true
  }
}
```

## Agent File Structure

**Location:** `.gemini/agents/` (project-level) or `~/.gemini/agents/` (user-level)

**Format:** Markdown files with YAML frontmatter

**Files starting with `_` are ignored** (allows disabling without deletion)

### Schema

```markdown
---
name: agent-name              # REQUIRED: lowercase /^[a-z0-9-_]+$/
description: What this does   # REQUIRED: minimum 1 character
display_name: Agent Name      # optional: user-friendly name
tools:                        # optional: defaults to all tools
  - read_file
  - search_file_content
  - glob
model: gemini-3-flash-preview # optional: specify full model name
temperature: 1.0              # optional: 0-2, default 1
max_turns: 25                 # optional: max conversation turns
timeout_mins: 5               # optional: default 5
---

Your system prompt goes here.

The agent receives: ${query}
```

### Available Tools

File ops: `glob`, `list_directory`, `read_file`, `read_many_files`, `search_file_content`, `write_file`, `replace`

Execution: `run_shell_command`

Web: `google_web_search`, `web_fetch`

System: `save_memory`, `write_todos`, `activate_skill`

MCP: `server__tool` format (e.g., `pwncat__listen`)

**Cannot use:** `delegate_to_agent` (prevents circular delegation)

## Invoking Agents

Agents are invoked via the `delegate_to_agent` tool:

```
delegate_to_agent(
  agent="code-analysis-recon",
  query="Analyze /var/www/html for vulnerabilities"
)
```

The main agent (Dame) calls this tool, the subagent executes with its own context, and returns results as markdown.

## Agent Overrides

Override agent settings in `settings.json`:

```json
{
  "agents": {
    "overrides": {
      "agent-name": {
        "enabled": false,
        "runConfig": {
          "maxTimeMinutes": 15,
          "maxTurns": 50
        },
        "modelConfig": {
          "model": "gemini-2.0-pro"
        }
      }
    }
  }
}
```

## CLI Commands

- `/agents list` - List all available agents
- `/agents enable <name>` - Enable a disabled agent
- `/agents disable <name>` - Disable an enabled agent
- `/agents refresh` - Reload agent registry

## Extension Manifest

The extension manifest (`gemini-extension.json`) declares the extension:

```json
{
  "name": "opulence",
  "version": "1.2.1",
  "description": "Extension description",
  "mcpServers": {
    "server-name": {
      "command": "command-to-run",
      "args": ["arg1", "arg2"],
      "env": { "VAR": "value" }
    }
  }
}
```

## For Blunderbussy (Dame)

The opulence extension structure:

```
infrastructure/PrEP/
├── skills/
│   ├── code-vuln-analysis/SKILL.md    # Activated via activate_skill()
│   ├── pentest-commands/SKILL.md
│   ├── pentest-checklist/SKILL.md
│   ├── red-team-tactics/SKILL.md
│   ├── scanning-tools/SKILL.md
│   ├── sql-injection-testing/SKILL.md
│   ├── api-fuzzing-bug-bounty/SKILL.md
│   └── vulnerability-scanner/SKILL.md
├── agents/
│   ├── archivist.md                   # Research subagent for context-saving lookups
│   ├── code-analysis-recon.md         # Called by skill via delegate_to_agent()
│   ├── code-analysis-triage.md
│   ├── code-analysis-analysis.md
│   └── code-analysis-validation.md
└── gemini-extension.json
```

**Flow:**
1. Dame calls `activate_skill("code-vuln-analysis")`
2. SKILL.md loads into context with orchestration instructions
3. Dame follows instructions to call the 4 sub-agents via `delegate_to_agent()`
4. Dame receives Vulnerability Brief and executes PoCs
