# kibana-prototype-pollution

## Overview

| Property   | Value                                |
|------------|--------------------------------------|
| CVE        | CVE-2019-7609                        |
| Difficulty | Hard                                 |
| Image      | docker.io/vulhub/kibana:6.5.4       |
| Backend    | docker.io/vulhub/elasticsearch:6.8.6 |
| Ports      | 5601 (Kibana)                        |
| Platform   | Linux                                |
| Points     | 100                                  |

## Attack Path

1. **Web Enumeration** - Discover Kibana on port 5601, identify version 6.5.4.
2. **Vulnerability Identification** - Recognize CVE-2019-7609: prototype pollution in Timelion visualization plugin.
3. **Prototype Pollution** - Navigate to Timelion and use the `.props` accessor to pollute the JavaScript Object prototype, injecting `NODE_OPTIONS` environment variable.
4. **Reverse Shell** - Trigger a Canvas or Timelion refresh that spawns a Node.js child process. The polluted `NODE_OPTIONS` (e.g., `--require /path/to/payload.js`) executes attacker-controlled code, yielding a reverse shell.
5. **Privilege Escalation** - Escalate from the kibana service user to root.
6. **Flag Capture** - Read user flag at `/home/user.txt` and root flag at `/root/root.txt`.

## Scoring

| Objective          | Category              | Points |
|--------------------|-----------------------|--------|
| vuln-discovery     | vulnerability_discovery | 15    |
| initial-access-rce | exploitation           | 30    |
| flag-user          | flag_capture           | 20    |
| cred-extraction    | credential_discovery   | 10    |
| flag-root          | flag_capture           | 25    |
| **Total**          |                        | **100**|

## Penalties

| Penalty            | Points |
|--------------------|--------|
| False positive CVE | -5     |
