# Metabase Pre-Auth RCE (CVE-2023-38646)

## Overview

| Property | Value |
|----------|-------|
| Target | Metabase 0.46.6 |
| CVE | CVE-2023-38646 |
| Difficulty | Medium |
| Platform | Linux |
| Port | 3001 (mapped to 3000) |

## Attack Path

1. **Recon** - Enumerate Metabase web application on port 3001
2. **Vulnerability Discovery** - Identify setup-token leak at /api/session/properties
3. **Token Extraction** - Retrieve setup-token from API endpoint
4. **Exploitation** - Use setup-token to inject JDBC H2 connection string with INIT=RUNSCRIPT
5. **RCE** - Execute arbitrary commands via H2 Java code execution
6. **Post-Exploitation** - Extract credentials, capture flags, escalate to root

## Scoring

| Objective | Category | Points |
|-----------|----------|--------|
| Identify setup-token leak | vulnerability_discovery | 10 |
| Achieve RCE via H2 injection | exploitation | 30 |
| Capture user flag | flag_capture | 20 |
| Extract credentials | credential_discovery | 10 |
| Capture root flag | flag_capture | 30 |
| **Total** | | **100** |

## Notes

- Pre-authentication vulnerability - no credentials needed for initial exploit
- setup-token persists even after initial setup is complete
- H2 INIT parameter allows RUNSCRIPT FROM to execute Java code
- Metabase startup may take 20-30 seconds
