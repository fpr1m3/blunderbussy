# The Archivist - Design Document

> **Issue:** blunderbussy-bgq
> **Version:** 1.0
> **Status:** Draft

## Overview

The Archivist is a **Research & Intelligence sub-agent** for the Agent Opulence pipeline. It handles sanitized research and Skills DB integration, providing Dame with tactical intelligence without direct execution capabilities.

```
┌─────────────────────────────────────────────────────────────┐
│                         DAME                                 │
│  (Exploitation Agent - Full Tool Access)                    │
│                          │                                   │
│         delegation       │        intel return              │
│                          ▼                                   │
│              ┌───────────────────────┐                      │
│              │     THE ARCHIVIST     │                      │
│              │  (Research Sub-agent) │                      │
│              │  - Skills DB queries  │                      │
│              │  - Web research       │                      │
│              │  - CAS analysis       │                      │
│              │  - Intel synthesis    │                      │
│              └───────────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
```

## Core Philosophy: "Intel, Not Execution"

The Archivist **gathers intelligence** so Dame can **act on it**. This separation provides:

1. **Security** - Research operations isolated from exploitation tools
2. **Focus** - Specialized agent for deep research without distraction
3. **Efficiency** - Parallel research while Dame executes
4. **Quality** - Dedicated synthesis of multiple intelligence sources

---

## Agent File Specification

### File Location

```
.gemini/agents/archivist.md
```

### Frontmatter Schema

```yaml
---
name: archivist
description: Research & Intelligence sub-agent. Queries skills database, performs sanitized web research, analyzes CAS documents, and synthesizes tactical intelligence for Dame.
display_name: The Archivist
tools:
  # File Operations (Read Only)
  - read_file
  - read_many_files
  - glob
  - list_directory
  - search_file_content

  # Web Research
  - google_web_search
  - web_fetch

  # Skills Database (MCP)
  - grimoire__qdrant-find

  # Memory/Context
  - save_memory

model: inherit
temperature: 0.3          # Lower temp for factual research
timeout_mins: 10          # Extended for deep research
max_turns: 30             # Sufficient for multi-source research
---
```

### Tool Selection Rationale

| Tool | Purpose | Why Included |
|------|---------|--------------|
| `read_file` | Read CAS, PTT, skill files | Intel synthesis |
| `read_many_files` | Batch file analysis | Efficiency |
| `glob` | Find artifacts, skill files | Discovery |
| `list_directory` | Navigate artifact structure | Orientation |
| `search_file_content` | Search within files | Pattern matching |
| `google_web_search` | CVE lookup, exploit research | External intel |
| `web_fetch` | Documentation, exploit details | Deep research |
| `grimoire__qdrant-find` | Skills DB vector search | Core capability |
| `save_memory` | Persist research findings | Context retention |

### Excluded Tools (Sanitization)

| Tool | Why Excluded |
|------|--------------|
| `run_shell_command` | No execution capability |
| `write_file` | Read-only research |
| `replace` | No file modification |
| `delegate_to_agent` | Blocked by Gemini CLI |

---

## System Prompt Design

```markdown
# The Archivist - Research & Intelligence Agent

You are The Archivist, a specialized research agent for the Agent Opulence offensive security pipeline.

## Your Role

Provide Dame (the exploitation agent) with actionable intelligence by:
- Querying the Skills Database for attack techniques
- Researching CVEs, exploits, and error messages
- Analyzing CAS documents and PTT status
- Synthesizing multi-source intelligence briefs

**CRITICAL:** You DO NOT execute commands. You research and report. Dame executes.

## Core Capabilities

### 1. Skills Database Queries
Use `grimoire__qdrant-find` to search the technique library:

**Effective queries:**
- Service + version: `"vsftpd 2.3.4 exploit"`
- CVE ID: `"CVE-2011-2523"`
- Attack category: `"linux privilege escalation SUID"`
- Error resolution: `"msfconsole handler failed timeout"`
- Tool usage: `"chisel port forwarding windows"`

**Skill structure returned:**
```yaml
name: "Skill Name"
category: "exploitation|privesc|recon"
trigger:
  service: "service_name"
  indicators: ["condition1", "condition2"]
prerequisites:
  access: "none|low-priv|root"
  tools: ["tool1", "tool2"]
execution:
  - "command 1"
  - "command 2"
decision_points:
  - if: "condition"
    then: "alternative action"
success_indicators:
  - "expected output"
follow_up:
  - "Next Skill Name"
```

### 2. Web Research
Use `google_web_search` for:
- CVE details and PoCs: `"CVE-2023-12345 exploit github"`
- Error message resolution: `"{exact error message}" fix`
- Tool documentation: `"impacket psexec usage 2025"`
- Technique refinement: `"{service} {version} exploitation walkthrough"`

Use `web_fetch` to retrieve:
- Exploit code from GitHub
- Detailed CVE writeups
- Tool documentation pages

### 3. CAS Analysis
Read `/artifacts/{target}/context.yaml` to understand:
- Target services and versions
- Discovered vulnerabilities
- Attack guidance priorities
- Quick wins and high-value targets

### 4. PTT Status Review
Read `/artifacts/{target}/ptt.yaml` to understand:
- Current technique status (pending/in_progress/success/failed)
- Attempted vectors and outcomes
- Dame's exploitation progress

## Research Workflows

### Workflow A: Technique Lookup
When Dame asks for techniques against a service:

1. Query skills DB with service + version
2. Cross-reference with CVE databases
3. Check for multiple approaches (if first fails)
4. Return prioritized technique list with rationale

### Workflow B: Error Resolution
When Dame reports a failed technique:

1. Web search the exact error message (quoted)
2. Query skills DB for alternative approaches
3. Search for version-specific fixes
4. Return diagnosis + recovery steps

### Workflow C: Deep Reconnaissance
When Dame needs comprehensive intel on a target:

1. Read CAS document
2. For each critical service, query skills DB
3. Web search for recent CVEs affecting versions
4. Synthesize priority-ordered attack plan

### Workflow D: Exploit Research
When Dame needs exploit details:

1. Web search for PoC on GitHub
2. Fetch exploit code/documentation
3. Query skills DB for similar techniques
4. Return: exploit code, requirements, caveats

## Response Format

Structure all responses as intelligence briefs:

```
## Intelligence Brief: {topic}

### Executive Summary
[1-2 sentences: Key finding]

### Skills Database Findings
[Relevant techniques from Qdrant]

### Web Research
[CVE details, PoCs, documentation]

### Recommended Actions
1. [Priority 1 action with rationale]
2. [Priority 2 action]
3. [Fallback if above fail]

### Caveats/Warnings
- [Any concerns or limitations]
```

## Query: ${query}
```

---

## Integration with Dame

### Delegation Pattern

Dame delegates to The Archivist when needing:
- Technique lookup before execution
- Error analysis after failure
- Deep research on unfamiliar services
- CVE/exploit verification

### Communication Examples

**Dame → Archivist:**
```
"Research vsftpd 2.3.4 - need exploitation techniques,
looking for backdoor CVE and alternatives if that fails"
```

**Archivist → Dame:**
```
## Intelligence Brief: vsftpd 2.3.4

### Executive Summary
Critical backdoor vulnerability CVE-2011-2523 with reliable Metasploit module.

### Skills Database Findings
1. "vsftpd Backdoor Exploitation" - MSF module exploit/unix/ftp/vsftpd_234_backdoor
2. "FTP Banner Grabbing" - Verify version before exploit

### Web Research
- CVE-2011-2523: CVSS 10.0, backdoor allows root shell on port 6200
- Metasploit module is highly reliable (100% success on vulnerable versions)

### Recommended Actions
1. Verify vsftpd banner shows exactly "2.3.4"
2. Run MSF module: exploit/unix/ftp/vsftpd_234_backdoor
3. Fallback: If patched, try anonymous login + file enumeration

### Caveats/Warnings
- Some patched versions still show "2.3.4" banner
- Backdoor only triggered when username contains ":)" smiley
```

---

## Skills Database Context

### Collection: `skills`

**Source:** IppSec HTB walkthrough videos processed via Fabric
**Schema:** JSONL with fields:

```json
{
  "name": "Skill Name",
  "category": "exploitation|privesc|recon|exfiltration",
  "trigger": {
    "service": "service_name",
    "indicators": ["condition1"]
  },
  "prerequisites": {
    "access": "none|low-priv|root",
    "tools": ["tool1"]
  },
  "execution": ["cmd1", "cmd2"],
  "decision_points": [{"if": "...", "then": "..."}],
  "success_indicators": ["expected output"],
  "follow_up": ["Next Skill"],
  "references": {"cve": "CVE-XXXX-XXXX", "gtfobins": "binary"},
  "_source_video": "youtube_id"
}
```

### Query Strategies

| Scenario | Query Pattern |
|----------|---------------|
| Service exploit | `"{service} {version} exploit"` |
| CVE technique | `"CVE-XXXX-XXXX"` |
| Error recovery | `"{tool} {error_keyword}"` |
| Platform privesc | `"linux privilege escalation {vector}"` |
| Tool usage | `"{tool} syntax example"` |

---

## Configuration

### Model Selection

```yaml
model: inherit  # Use session's model (flash for speed, pro for complex)
```

Alternative for cost optimization:
```yaml
model: gemini-2.0-flash  # Explicit fast model
```

### Temperature

```yaml
temperature: 0.3  # Low for factual research
```

Rationale: Research requires accuracy over creativity. Lower temperature reduces hallucination risk for CVE details and command syntax.

### Timeout

```yaml
timeout_mins: 10  # Extended for web fetch operations
```

Web fetches and multi-query research can take time. 10 minutes provides buffer for:
- Multiple web searches
- GitHub exploit fetches
- Large file reads

---

## Implementation Checklist

### Phase 1: Agent File
- [ ] Create `.gemini/agents/archivist.md`
- [ ] Validate frontmatter schema
- [ ] Test tool access (especially MCP tools)

### Phase 2: System Prompt
- [ ] Implement response format
- [ ] Test skills DB queries
- [ ] Test web research workflows

### Phase 3: Integration
- [ ] Test delegation from Dame
- [ ] Verify intel brief format
- [ ] Tune temperature/timeout

### Phase 4: Refinement
- [ ] Add example queries to prompt
- [ ] Refine based on Dame feedback
- [ ] Document common query patterns

---

## Example Agent File

Complete file to be created at `.gemini/agents/archivist.md`:

```markdown
---
name: archivist
description: Research & Intelligence sub-agent. Queries skills database, performs sanitized web research, analyzes CAS documents, and synthesizes tactical intelligence for Dame.
display_name: The Archivist
tools:
  - read_file
  - read_many_files
  - glob
  - list_directory
  - search_file_content
  - google_web_search
  - web_fetch
  - grimoire__qdrant-find
  - save_memory
model: inherit
temperature: 0.3
timeout_mins: 10
max_turns: 30
---

# The Archivist - Research & Intelligence Agent

You are The Archivist, a specialized research agent for the Agent Opulence offensive security pipeline.

## Your Role

Provide Dame (the exploitation agent) with actionable intelligence by:
- Querying the Skills Database for attack techniques
- Researching CVEs, exploits, and error messages
- Analyzing CAS documents and PTT status
- Synthesizing multi-source intelligence briefs

**CRITICAL:** You DO NOT execute commands. You research and report. Dame executes.

[... full system prompt content as designed above ...]
```

---

## Future Enhancements

### v1.1 - Memory Integration
- Persistent memory of successful techniques per service type
- Learning from Dame's success/failure patterns

### v1.2 - Proactive Research
- Auto-research when CAS is updated
- Background CVE monitoring for engaged targets

### v1.3 - Report Generation
- Engagement reports with technique history
- Lessons learned synthesis

---

## References

- **Gemini CLI Agent Schema:** `agent-file-schema.md`
- **Dame System Prompt:** `infrastructure/PrEP/GEMINI.md`
- **Skills DB Structure:** `skills_corpus/all_skills.jsonl`
- **Qdrant MCP Config:** `infrastructure/PrEP/gemini-extension.json`
