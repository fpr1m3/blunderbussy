# Redis 4.0.14 - Unauthenticated Access

## Overview
Redis 4.0.14 running without authentication. An attacker can connect and use
CONFIG SET to write arbitrary files (SSH keys, crontab, webshell) to achieve
remote code execution.

## Target Details
- **Image:** docker.io/vulhub/redis:4.0.14
- **Port:** 6379
- **Vulnerability:** Misconfiguration (no requirepass)
- **Difficulty:** Easy

## Attack Path
1. Connect to Redis without credentials
2. Use CONFIG SET dir / CONFIG SET dbfilename to write to disk
3. Write SSH authorized_keys, crontab entry, or webshell
4. Gain shell access via written payload

## Flags
- User flag: `/home/user/user.txt` or `/tmp/user.txt`
- Root flag: `/root/root.txt`
