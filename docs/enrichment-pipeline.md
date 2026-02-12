# Enrichment Pipeline

> Back to [README](../README.md)

## Faraday Integration (80+ Parsers)

Parsing is handled by Faraday's built-in plugins, supporting 80+ security tool formats including:

| Category | Example Tools |
|----------|---------------|
| **Network** | nmap, masscan, dnsrecon, snmpwalk |
| **Web** | burp, nikto, nuclei, feroxbuster, gobuster, ffuf, whatweb, wpscan |
| **Vulnerability** | nessus, openvas, qualys, nexpose |
| **SMB/Enum** | enum4linux, smbmap, crackmapexec |

## Pipeline Flow

```
Raw scan file detected (inotify)
    ↓
faraday_watcher.py uploads to Faraday API
    ↓
Faraday parses with 80+ built-in plugins
    ↓
Enrichers add context:
  - Service priority scoring
  - Web technology detection
    ↓
CAS Formatter outputs YAML (with Gemini attack guidance)
    ↓
PTT Initializer transforms CAS → PTT (deterministic)
    ↓
Result: /artifacts/{target}/context.yaml + ptt.yaml
```
