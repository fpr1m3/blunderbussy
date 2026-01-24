# Gemini CLI Agent File Schema (v0.25.0)

This document describes the file format for defining custom agents in Gemini CLI when `experimental.enableAgents` is enabled.

## Overview

Agents are defined as Markdown files (`.md`) with YAML frontmatter. They are loaded from:

| Location | Path | Notes |
|----------|------|-------|
| User-level | `~/.gemini/agents/` | Always loaded |
| Project-level | `.gemini/agents/` | Only loaded if folder is trusted |
| Extensions | Via extension definitions | Depends on extension |

Files starting with `_` (underscore) are ignored, allowing you to disable agents without deleting them.

## Agent Types

Gemini CLI supports two types of agents:

1. **Local Agents** - Run locally using Gemini models with a custom system prompt
2. **Remote Agents** - Connect to external A2A (Agent-to-Agent) protocol endpoints

---

## Local Agent Schema

Local agents execute using Gemini models with customizable tools and prompts.

### File Structure

```markdown
---
name: <slug>
description: <string>
display_name: <string>          # optional
tools:                          # optional
  - <tool_name>
  - <tool_name>
model: <string>                 # optional
temperature: <number>           # optional
max_turns: <number>             # optional
timeout_mins: <number>          # optional
---

<system-prompt-body>
```

### Field Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **Yes** | - | Unique identifier. Must match `/^[a-z0-9-_]+$/` (lowercase letters, numbers, hyphens, underscores only) |
| `description` | string | **Yes** | - | Human-readable description of the agent's purpose (min 1 character) |
| `display_name` | string | No | - | Optional display name shown in UI (can include spaces/capitals) |
| `kind` | `'local'` | No | `'local'` | Agent type discriminator (inferred if omitted) |
| `tools` | string[] | No | All tools | Array of tool names the agent can use |
| `model` | string | No | `'inherit'` | Model to use (e.g., `'gemini-2.0-flash'`). Use `'inherit'` to use current session model |
| `temperature` | number | No | `1` | Sampling temperature (0-2 range). Lower = more deterministic |
| `max_turns` | integer | No | - | Maximum conversation turns before termination |
| `timeout_mins` | integer | No | `5` | Maximum execution time in minutes |

### System Prompt Body

The content after the frontmatter `---` delimiter becomes the agent's system prompt. Use `${query}` to inject the user's task:

```markdown
---
name: code-reviewer
description: Reviews code for best practices and potential issues.
---

You are an expert code reviewer. Analyze the code provided and identify:
- Security vulnerabilities
- Performance issues
- Code style violations

User request: ${query}
```

### Available Tools

Built-in tools that can be specified in the `tools` array:

| Tool Name | Description |
|-----------|-------------|
| `glob` | Pattern-based file search |
| `list_directory` | List directory contents |
| `read_file` | Read file contents |
| `read_many_files` | Read multiple files at once |
| `search_file_content` | Search file contents (grep) |
| `write_file` | Write/create files |
| `replace` | Edit/replace file content |
| `run_shell_command` | Execute shell commands |
| `google_web_search` | Web search |
| `web_fetch` | Fetch URL content |
| `save_memory` | Save to memory/context |
| `write_todos` | Write todo items |
| `activate_skill` | Activate a skill |

**MCP Tools**: Use format `server__tool` (e.g., `github__create_issue`)

**Restriction**: The `delegate_to_agent` tool cannot be used in agent definitions (prevents circular delegation).

---

## Remote Agent Schema

Remote agents connect to external A2A protocol endpoints.

### Single Remote Agent

```markdown
---
name: <slug>
kind: remote
agent_card_url: <url>
description: <string>           # optional
display_name: <string>          # optional
---
```

### Multiple Remote Agents

A single file can define multiple remote agents using YAML array syntax:

```markdown
---
- name: remote-agent-1
  agent_card_url: https://example.com/agent1/.well-known/agent.json

- name: remote-agent-2
  agent_card_url: https://example.com/agent2/.well-known/agent.json
  description: Optional description
---
```

### Field Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **Yes** | - | Unique identifier. Must match `/^[a-z0-9-_]+$/` |
| `kind` | `'remote'` | **Yes** | - | Must be `'remote'` (or inferred from `agent_card_url`) |
| `agent_card_url` | URL | **Yes** | - | Valid URL to the agent's A2A card |
| `description` | string | No | `'(Loading description...)'` | Human-readable description |
| `display_name` | string | No | - | Optional display name for UI |

---

## Complete Examples

### Example: Unit Test Expert

```markdown
---
name: unit-test-expert
description: A specialized agent for writing and debugging unit tests.
tools:
  - list_directory
  - read_file
  - run_shell_command
---

You are an expert software engineer specializing in unit testing.
Your goal is to help the user write, debug, and improve their unit tests.

The user has provided the following request:
${query}

Follow these rules:
1. Analyze the existing codebase and tests before proposing changes.
2. Ensure new tests follow the project's established testing patterns.
3. Verify your tests by running them using the project's test runner.
```

### Example: Security Analyst

```markdown
---
name: security-analyst
description: Analyzes code for security vulnerabilities and suggests fixes.
display_name: Security Analyst
tools:
  - read_file
  - read_many_files
  - search_file_content
  - glob
model: gemini-2.0-flash
temperature: 0.3
timeout_mins: 10
---

You are a security-focused code analyst. Your task is to:

1. Identify potential security vulnerabilities (OWASP Top 10, etc.)
2. Analyze authentication and authorization patterns
3. Check for sensitive data exposure
4. Review input validation and sanitization

Task: ${query}

Provide findings in order of severity with recommended fixes.
```

### Example: Remote Agent

```markdown
---
name: external-research
kind: remote
agent_card_url: https://api.example.com/.well-known/agent.json
description: External research agent for deep web analysis
display_name: Research Agent
---
```

---

## Agent Overrides (Settings)

Agents can be overridden in your settings file (`~/.gemini/settings.json`):

```json
{
  "agents": {
    "overrides": {
      "unit-test-expert": {
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

---

## Validation Rules

1. **Name format**: Must be lowercase with only letters, numbers, hyphens, and underscores (`/^[a-z0-9-_]+$/`)
2. **Required fields**: Local agents require `name` and `description`; Remote agents require `name` and `agent_card_url`
3. **Frontmatter required**: Files must start with YAML frontmatter enclosed in `---` delimiters
4. **No delegation**: Local agents cannot include `delegate_to_agent` in their tools list
5. **Tool validation**: All tool names must be valid built-in tools or MCP tool format (`server__tool`)
6. **Type constraints**: `temperature` must be a number; `max_turns` and `timeout_mins` must be positive integers
7. **URL validation**: `agent_card_url` must be a valid URL

---

## Enabling Agents

To enable the experimental agents feature:

```bash
gemini settings set experimental.enableAgents true
```

Or add to `~/.gemini/settings.json`:

```json
{
  "experimental": {
    "enableAgents": true
  }
}
```

**Warning**: This is an experimental feature that uses YOLO mode for subagents.
