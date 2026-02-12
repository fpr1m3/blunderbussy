# Data Schemas

> Back to [README](../README.md)

## CAS (Context-Aware Summary)

```yaml
# /artifacts/{target}/context.yaml
meta:
  target: 10.10.10.3
  scan_time: 2026-01-20T12:00:00Z
  tools_run: [nmap, httpx, nuclei, feroxbuster]

summary:
  open_ports: 5
  services: [ftp, ssh, http, smb]
  critical_findings: 2

services:
  - port: 21
    service: ftp
    version: vsftpd 2.3.4
    vulns:
      - cve: CVE-2011-2523
        severity: critical
        epss: 9.8
        exploit_available: true

attack_guidance:
  quick_wins: []        # Default creds, anon access
  priority_targets: []  # High-value services
```

## PTT (Pentesting Task Tree)

```yaml
# /artifacts/{target}/ptt.yaml
engagement:
  target: 10.10.10.3
  hosts:
    - ip: 10.10.10.3
      services:
        - port: 21
          service: ftp
          techniques:
            - name: anonymous_ftp_login
              status: pending|in_progress|success|failed
              attempts: 0
```
