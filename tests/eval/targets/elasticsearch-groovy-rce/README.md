# Elasticsearch Groovy Sandbox Bypass RCE (CVE-2015-1427)

## Overview

| Property | Value |
|----------|-------|
| Target | Elasticsearch 1.4.2 |
| CVE | CVE-2015-1427 |
| Difficulty | Medium |
| Platform | Linux |
| Port | 9200 |

## Attack Path

1. **Recon** - Enumerate Elasticsearch REST API on port 9200, check version and cluster info
2. **Vulnerability Discovery** - Identify Groovy scripting sandbox bypass
3. **Preparation** - Create test index and document (required for script execution)
4. **Exploitation** - Send _search request with Groovy script_fields bypassing sandbox
5. **RCE** - Use java.lang.Runtime to run system commands
6. **Post-Exploitation** - Extract credentials, capture flags, escalate to root

## Scoring

| Objective | Category | Points |
|-----------|----------|--------|
| Identify Groovy sandbox bypass | vulnerability_discovery | 10 |
| Achieve RCE via Groovy scripts | exploitation | 30 |
| Capture user flag | flag_capture | 20 |
| Extract credentials | credential_discovery | 10 |
| Capture root flag | flag_capture | 30 |
| **Total** | | **100** |

## Notes

- Elasticsearch REST API is unauthenticated by default
- Must create at least one document before _search with scripts works
- Groovy sandbox bypass uses java.lang.Runtime reflection
- No authentication required for exploitation
