# Redis Lua Sandbox Escape (CVE-2022-0543)

## Overview

| Property | Value |
|----------|-------|
| Target | Redis 5.0.7 (Debian-patched) |
| CVE | CVE-2022-0543 |
| Difficulty | Medium |
| Platform | Linux |
| Port | 6380 (mapped to 6379) |

## Attack Path

1. **Recon** - Connect to Redis on port 6380, enumerate version and configuration
2. **Vulnerability Discovery** - Identify Debian-patched Lua sandbox escape vector
3. **Exploitation** - Use EVAL with Lua script exploiting package.loadlib to load liblua5.1.so.0
4. **RCE** - Call luaopen_os to access os.execute for arbitrary command execution
5. **Post-Exploitation** - Extract credentials, capture user flag
6. **Privilege Escalation** - Escalate to root, capture root flag

## Scoring

| Objective | Category | Points |
|-----------|----------|--------|
| Identify Lua sandbox escape | vulnerability_discovery | 10 |
| Achieve RCE via sandbox escape | exploitation | 30 |
| Capture user flag | flag_capture | 20 |
| Extract credentials | credential_discovery | 10 |
| Capture root flag | flag_capture | 30 |
| **Total** | | **100** |

## Notes

- Redis is unauthenticated by default - no credentials needed for initial access
- Vulnerability is specific to Debian/Ubuntu packaged Redis (patched Lua library path)
- Exploit uses package.loadlib to load liblua shared object and escape sandbox
- Key Lua payload: `package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_os")()`
