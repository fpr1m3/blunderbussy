# Confluence OGNL Injection (CVE-2022-26134)

## Overview

| Property | Value |
|----------|-------|
| Target | Atlassian Confluence 7.13.6 |
| CVE | CVE-2022-26134 |
| Difficulty | Medium |
| Platform | Linux |
| Port | 8090 |

## Attack Path

1. **Recon** - Enumerate Confluence web application on port 8090, identify version
2. **Vulnerability Discovery** - Identify OGNL injection in URI path (pre-auth)
3. **Exploitation** - Inject OGNL expression in URL for command execution
4. **RCE** - Achieve full remote code execution via OGNL payload
5. **Post-Exploitation** - Extract database credentials, capture user flag
6. **Privilege Escalation** - Escalate from confluence user to root, capture root flag

## Scoring

| Objective | Category | Points |
|-----------|----------|--------|
| Identify OGNL injection | vulnerability_discovery | 10 |
| Achieve RCE via OGNL | exploitation | 30 |
| Capture user flag | flag_capture | 20 |
| Extract credentials | credential_discovery | 10 |
| Capture root flag | flag_capture | 30 |
| **Total** | | **100** |

## Notes

- Multi-container target: Confluence (web) + PostgreSQL (database)
- Pre-authentication vulnerability - no credentials needed
- OGNL expression injected in URI path segment
- Confluence startup may take 30-60 seconds
