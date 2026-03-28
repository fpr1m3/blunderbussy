# libssh Authentication Bypass (CVE-2018-10933)

## Overview

| Property | Value |
|----------|-------|
| Target | libssh 0.8.1 |
| CVE | CVE-2018-10933 |
| Difficulty | Medium |
| Platform | Linux |
| Port | 2222 (mapped to 22) |

## Attack Path

1. **Recon** - Banner grab SSH service on port 2222, identify libssh version
2. **Vulnerability Discovery** - Identify libssh auth bypass vulnerability
3. **Exploitation** - Send SSH2_MSG_USERAUTH_SUCCESS instead of SSH2_MSG_USERAUTH_REQUEST
4. **Shell Access** - Obtain interactive shell through bypassed SSH session
5. **Post-Exploitation** - Extract credentials, capture user flag
6. **Privilege Escalation** - Escalate to root, capture root flag

## Scoring

| Objective | Category | Points |
|-----------|----------|--------|
| Identify libssh auth bypass | vulnerability_discovery | 10 |
| Achieve shell via auth bypass | exploitation | 30 |
| Capture user flag | flag_capture | 20 |
| Extract credentials | credential_discovery | 10 |
| Capture root flag | flag_capture | 30 |
| **Total** | | **100** |

## Notes

- Server-side state machine flaw: server accepts USERAUTH_SUCCESS from client
- Can use paramiko library to craft the malicious SSH message
- Authentication bypass grants access as any user without credentials
