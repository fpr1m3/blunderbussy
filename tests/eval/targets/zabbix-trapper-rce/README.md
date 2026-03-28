# zabbix-trapper-rce

## Overview

| Property   | Value                                      |
|------------|--------------------------------------------|
| CVE        | CVE-2017-2824                              |
| Difficulty | Hard                                       |
| Images     | docker.io/vulhub/zabbix:3.0.3-server      |
|            | docker.io/vulhub/zabbix:3.0.3-web         |
|            | docker.io/library/mysql:5                  |
| Ports      | 10051 (trapper), 8089 (web)                |
| Platform   | Linux                                      |
| Points     | 100                                        |
| Containers | 4 (server, agent, mysql, web)              |

## Attack Path

1. **Service Discovery** - Identify Zabbix server trapper port on 10051 and web frontend on port 8089.
2. **Vulnerability Identification** - Recognize CVE-2017-2824: the Zabbix server trapper processing does not properly sanitize input data, allowing SQL injection.
3. **SQL Injection** - Send crafted trapper item data to port 10051. The malicious payload is processed and written into the MySQL database via SQL injection in the trapper data handler.
4. **Remote Command Execution** - The injected SQL inserts a malicious command into the Zabbix items table. The Zabbix agent periodically polls the database for active checks and executes the injected command, achieving RCE.
5. **Credential Extraction** - Extract database credentials from environment variables or Zabbix configuration, and attempt Zabbix web login with default credentials (Admin/zabbix).
6. **Flag Capture** - Read user flag at `/home/user.txt` and root flag at `/root/root.txt`.

## Scoring

| Objective          | Category              | Points |
|--------------------|-----------------------|--------|
| service-discovery  | vulnerability_discovery | 10    |
| vuln-discovery     | vulnerability_discovery | 15    |
| sqli-exploitation  | exploitation           | 15    |
| initial-access-rce | exploitation           | 20    |
| flag-user          | flag_capture           | 15    |
| cred-extraction    | credential_discovery   | 10    |
| flag-root          | flag_capture           | 15    |
| **Total**          |                        | **100**|

## Penalties

| Penalty            | Points |
|--------------------|--------|
| False positive CVE | -5     |

## Notes

This is a multi-container target with a complex dependency chain:
- MySQL must start first (database initialization takes ~30s)
- Server depends on MySQL
- Agent and Web depend on Server
- The trapper exploit requires the full chain: server processes data -> MySQL stores it -> agent executes it
