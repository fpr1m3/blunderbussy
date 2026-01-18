# Real Backend Implementation Plan

**Created:** 2026-01-16
**Updated:** 2026-01-16
**Status:** Ready for Implementation
**Scope:** MSF MCP + Sliver MCP - Rewrite as Go-based MCP servers

---

## Overview

Both `msf/server.py` and `sliver/server.py` will be rewritten as Go-based MCP servers. This aligns with:
- Architecture diagram showing `go-msf-rpc` for MSF integration
- Sliver's native Go ecosystem (Sliver is written in Go)
- Better performance characteristics for security tooling

---

## 1. Metasploit MCP Server (Go)

### 1.1 Library Selection

**MCP Server:** Go MCP SDK (github.com/mark3labs/mcp-go or similar)
**MSF Client:** `github.com/fpr1m3/go-msf-rpc` - Go RPC client for Metasploit

```bash
go get -u github.com/fpr1m3/go-msf-rpc/...
```

### 1.2 Backend Requirements

1. **MSF Container** must run `msfrpcd`:
   ```bash
   msfrpcd -P ${MSF_TOKEN} -S -a 0.0.0.0 -p 55553
   ```

2. **Environment Variables:**
   - `MSF_HOST` - Hostname (default: `msf`)
   - `MSF_PORT` - RPC port (default: `55553`)
   - `MSF_TOKEN` - RPC password

### 1.3 Implementation Tasks

- [ ] **1.3.1** Create Go module: `infrastructure/msf-mcp/`
- [ ] **1.3.2** Add MCP server scaffolding (stdio JSON-RPC)
- [ ] **1.3.3** Implement MSF RPC client (msgpack-rpc over SSL)
- [ ] **1.3.4** Implement tools:
  - [ ] `msf__search` - Module search
  - [ ] `msf__module_info` - Module details
  - [ ] `msf__exploit` - Run exploit module
  - [ ] `msf__auxiliary` - Run auxiliary module
  - [ ] `msf__sessions_list` - List active sessions
  - [ ] `msf__session_interact` - Execute command in session
- [ ] **1.3.5** Create Dockerfile for Go build
- [ ] **1.3.6** Test with vsftpd backdoor on Metasploitable2

### 1.4 Directory Structure

```
infrastructure/msf-mcp/
├── go.mod
├── go.sum
├── main.go              # MCP server entry point
├── internal/
│   ├── msfrpc/
│   │   ├── client.go    # MSF RPC client
│   │   └── types.go     # MSF data types
│   └── tools/
│       ├── search.go
│       ├── exploit.go
│       ├── auxiliary.go
│       └── sessions.go
├── Dockerfile
└── README.md
```

---

## 2. Sliver MCP Server (Go)

### 2.1 Library Selection

**MCP Server:** Go MCP SDK
**Sliver Client:** Official Sliver Go client (`github.com/BishopFox/sliver/client`)

### 2.2 Backend Requirements

1. **Sliver Server** must be running with multiplayer mode
2. **Operator Config** - Generate via `sliver > new-operator --name opulence --lhost <host>`
3. **Environment Variables:**
   - `SLIVER_CONFIG` - Path to operator config file

### 2.3 Implementation Tasks

- [ ] **2.3.1** Create Go module: `infrastructure/sliver-mcp/`
- [ ] **2.3.2** Add MCP server scaffolding (stdio JSON-RPC)
- [ ] **2.3.3** Implement Sliver gRPC client using official library
- [ ] **2.3.4** Implement tools:
  - [ ] `sliver__implant_generate` - Generate implant
  - [ ] `sliver__listeners_list` - List listeners
  - [ ] `sliver__listener_start` - Start listener
  - [ ] `sliver__listener_stop` - Stop listener
  - [ ] `sliver__sessions_list` - List sessions
  - [ ] `sliver__session_info` - Session details
  - [ ] `sliver__execute` - Execute command
  - [ ] `sliver__download` - Download file
  - [ ] `sliver__upload` - Upload file
- [ ] **2.3.5** Create Dockerfile for Go build
- [ ] **2.3.6** Test beacon deployment on test VM

### 2.4 Directory Structure

```
infrastructure/sliver-mcp/
├── go.mod
├── go.sum
├── main.go              # MCP server entry point
├── internal/
│   ├── sliver/
│   │   ├── client.go    # Sliver gRPC client wrapper
│   │   └── config.go    # Operator config parsing
│   └── tools/
│       ├── implants.go
│       ├── listeners.go
│       ├── sessions.go
│       └── execute.go
├── Dockerfile
└── README.md
```

---

## 3. Go MCP SDK Research

### 3.1 Available Options

1. **mark3labs/mcp-go** - Community Go SDK for MCP
   - GitHub: https://github.com/mark3labs/mcp-go
   - Supports stdio transport
   - Well-documented

2. **Custom implementation** - Raw JSON-RPC 2.0 over stdio
   - More control
   - Less dependency

### 3.2 MCP Server Pattern (Go)

```go
package main

import (
    "encoding/json"
    "os"
    "bufio"
)

type MCPServer struct {
    tools map[string]ToolHandler
}

type ToolHandler func(args map[string]interface{}) (interface{}, error)

func (s *MCPServer) handleRequest(req Request) Response {
    switch req.Method {
    case "initialize":
        return s.initialize()
    case "tools/list":
        return s.listTools()
    case "tools/call":
        return s.callTool(req.Params)
    default:
        return errorResponse(req.ID, -32601, "Method not found")
    }
}

func main() {
    server := NewMCPServer()
    scanner := bufio.NewScanner(os.Stdin)

    for scanner.Scan() {
        var req Request
        json.Unmarshal(scanner.Bytes(), &req)
        resp := server.handleRequest(req)
        json.NewEncoder(os.Stdout).Encode(resp)
    }
}
```

---

## 4. Container Updates

### 4.1 MSF MCP Container

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o msf-mcp .

# Runtime stage
FROM alpine:latest
COPY --from=builder /app/msf-mcp /usr/local/bin/
ENTRYPOINT ["msf-mcp"]
```

### 4.2 Sliver MCP Container

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o sliver-mcp .

# Runtime stage
FROM alpine:latest
COPY --from=builder /app/sliver-mcp /usr/local/bin/
ENTRYPOINT ["sliver-mcp"]
```

### 4.3 MetaMCP Configuration Update

Update `mcp-servers.json` to use Go binaries:

```json
{
  "mcpServers": {
    "opulence-msf": {
      "type": "stdio",
      "command": "/opt/mcp-servers/msf/msf-mcp",
      "args": [],
      "env": {
        "MSF_HOST": "host.docker.internal",
        "MSF_PORT": "55553",
        "MSF_TOKEN": "${MSF_TOKEN}"
      }
    },
    "opulence-sliver": {
      "type": "stdio",
      "command": "/opt/mcp-servers/sliver/sliver-mcp",
      "args": [],
      "env": {
        "SLIVER_CONFIG": "/configs/opulence.cfg"
      }
    }
  }
}
```

---

## 5. Migration Plan

### Phase 1: MSF MCP (Go)
1. Create `infrastructure/msf-mcp/` Go module
2. Implement MSF RPC client
3. Implement MCP tools
4. Build and test Docker image
5. Update MetaMCP config
6. Deprecate Python wrapper

### Phase 2: Sliver MCP (Go)
1. Create `infrastructure/sliver-mcp/` Go module
2. Integrate official Sliver Go client
3. Implement MCP tools
4. Build and test Docker image
5. Update MetaMCP config
6. Deprecate Python wrapper

### Phase 3: Cleanup
1. Remove `infrastructure/msf/server.py`
2. Remove `infrastructure/sliver/server.py`
3. Update docker-compose.yml
4. Update documentation

---

## 6. Rollback Strategy

Keep Python wrappers in place during migration. MetaMCP can be configured to use either:
- Go binary: `/opt/mcp-servers/msf/msf-mcp`
- Python script: `python3 /opt/mcp-servers/msf/server.py`

Switch by updating `mcp-servers.json` command.

---

## 7. Related Documentation

- **Obsidian:** `~/Notes/Obsidian/10 - PROJECTS/Agent Opulence/TASK_LIST.md` § 2.2, § 2.3
- **Architecture:** `Agents.md` (go-msf-rpc reference)
- **MetaMCP:** `infrastructure/metamcp-real/mcp-servers.json`
