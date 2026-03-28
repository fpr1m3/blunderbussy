# saltstack-auth-bypass

## Overview

| Property   | Value                                  |
|------------|----------------------------------------|
| CVE        | CVE-2020-11651, CVE-2020-11652         |
| Difficulty | Hard                                   |
| Image      | docker.io/vulhub/saltstack:2019.2.3    |
| Ports      | 4505, 4506, 8000, 2223 (SSH)           |
| Platform   | Linux                                  |
| Points     | 100                                    |

## Attack Path

1. **Service Discovery** - Identify SaltStack master via ZeroMQ ports 4505 (publisher) and 4506 (request server).
2. **Vulnerability Identification** - Recognize CVE-2020-11651: the ClearFuncs class exposes `_prep_auth_caller()` and `_send_pub()` methods to unauthenticated clients.
3. **Auth Bypass Exploitation** - Connect to port 4506 and call `_prep_auth_caller()` to retrieve the root key without authentication.
4. **Remote Command Execution** - Use the extracted root key to execute arbitrary commands as root via the salt master's `cmd.exec_code` or `cmd.run` methods.
5. **Flag Capture** - Read user flag at `/home/user.txt` and root flag at `/root/root.txt`.

## Scoring

| Objective          | Category              | Points |
|--------------------|-----------------------|--------|
| service-discovery  | vulnerability_discovery | 10    |
| vuln-discovery     | vulnerability_discovery | 15    |
| initial-access-rce | exploitation           | 25    |
| flag-user          | flag_capture           | 15    |
| cred-extraction    | credential_discovery   | 10    |
| flag-root          | flag_capture           | 25    |
| **Total**          |                        | **100**|

## Penalties

| Penalty            | Points |
|--------------------|--------|
| False positive CVE | -5     |
