---
name: red-team-tactics
description: Red team tactics based on MITRE ATT&CK. Attack lifecycle phases, defense evasion, lateral movement, and privilege escalation principles.
---

# Red Team Tactics

Adversary simulation principles based on MITRE ATT&CK framework.

---

## MITRE ATT&CK Lifecycle

```
RECONNAISSANCE → INITIAL ACCESS → EXECUTION → PERSISTENCE
       ↓              ↓              ↓            ↓
   PRIVILEGE ESC → DEFENSE EVASION → CRED ACCESS → DISCOVERY
       ↓              ↓              ↓            ↓
LATERAL MOVEMENT → COLLECTION → C2 → EXFILTRATION → IMPACT
```

### Phase Objectives

| Phase | Objective |
|-------|-----------|
| **Recon** | Map attack surface |
| **Initial Access** | Get first foothold |
| **Execution** | Run code on target |
| **Persistence** | Survive reboots |
| **Privilege Escalation** | Get admin/root |
| **Defense Evasion** | Avoid detection |
| **Credential Access** | Harvest credentials |
| **Discovery** | Map internal network |
| **Lateral Movement** | Spread to other systems |
| **Collection** | Gather target data |
| **C2** | Maintain command channel |
| **Exfiltration** | Extract data |

---

## Initial Access Vectors

| Vector | When to Use |
|--------|-------------|
| **Phishing** | Human target, email access |
| **Public exploits** | Vulnerable services exposed |
| **Valid credentials** | Leaked or cracked |
| **Supply chain** | Third-party access |

---

## Privilege Escalation Principles

### Linux Targets

| Check | Opportunity |
|-------|-------------|
| SUID binaries | Execute as owner (GTFOBins) |
| Sudo misconfiguration | Command execution |
| Kernel vulnerabilities | Kernel exploits (DirtyPipe, etc.) |
| Cron jobs | Writable scripts |
| Capabilities | CAP_SETUID, CAP_NET_BIND |
| Docker group | Container escape |
| NFS no_root_squash | Mount and create SUID |

### Windows Targets

| Check | Opportunity |
|-------|-------------|
| Unquoted service paths | Write to path |
| Weak service permissions | Modify service binary |
| Token privileges | SeImpersonate, SeDebug |
| Stored credentials | cmdkey, DPAPI |
| AlwaysInstallElevated | MSI privilege escalation |
| UAC bypass | Various techniques |
| PrintNightmare | Print spooler exploit |

---

## Defense Evasion Principles

### Key Techniques

| Technique | Purpose |
|-----------|---------|
| LOLBins | Use legitimate tools (certutil, powershell) |
| Obfuscation | Hide malicious code |
| Timestomping | Hide file modifications |
| Log clearing | Remove evidence |
| Process injection | Hide in legitimate processes |

### Operational Security

- Work during business hours
- Mimic legitimate traffic patterns
- Use encrypted channels
- Blend with normal behavior
- Avoid triggering rate limits

---

## Lateral Movement

### Credential Types

| Type | Use |
|------|-----|
| Password | Standard auth |
| Hash | Pass-the-hash (NTLM) |
| Ticket | Pass-the-ticket (Kerberos) |
| Certificate | Certificate auth |

### Movement Paths

- Admin shares (C$, ADMIN$)
- Remote services (RDP, SSH, WinRM, PSExec)
- Exploitation of internal services
- Credential reuse across systems

---

## Active Directory Attacks

| Attack | Target |
|--------|--------|
| Kerberoasting | Service account passwords |
| AS-REP Roasting | Accounts without pre-auth |
| DCSync | Domain credentials (mimikatz) |
| Golden Ticket | Persistent domain access |
| Silver Ticket | Service-specific access |
| Pass-the-Hash | NTLM authentication |
| Pass-the-Ticket | Kerberos authentication |

---

## Post-Exploitation Priorities

1. **Stabilize access** - Persistent shell, multiple channels
2. **Credential harvesting** - Memory, files, registry
3. **Local enumeration** - Users, groups, permissions
4. **Network discovery** - Adjacent hosts, services
5. **Privilege escalation** - Root/SYSTEM access
6. **Lateral movement** - Spread to other systems
7. **Data collection** - Target objectives (flags, data)

---

## Ethical Boundaries

### Always
- Stay within scope
- Minimize impact
- Report immediately if real threat found
- Document all actions

### Never
- Destroy production data
- Cause denial of service (unless scoped)
- Access beyond proof of concept
- Retain sensitive data

---

## Anti-Patterns

| Don't | Do |
|-------|-----|
| Rush to exploitation | Follow methodology |
| Cause damage | Minimize impact |
| Skip documentation | Record in PTT |
| Ignore scope | Stay within boundaries |
| Use loud tools first | Start with quiet techniques |
