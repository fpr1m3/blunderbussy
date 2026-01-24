# Enrichment Pipeline Migration: watcher.py -> Faraday

## Overview

This document describes the migration from the custom watcher.py enrichment
pipeline to Faraday vulnerability management platform.

## Timeline

- Migration Date: 2026-01-23
- Epic: blunderbussy-fj1

## What Changed

### Removed Components
- `watcher.py` (archived to `archive/watcher.py.bak`)
- `parsers/` directory (24 custom parsers)
- `enrichers/enrich-cves.py`

### New Components
- `faraday_client.py` - Faraday API client with retry logic
- `faraday_watcher.py` - File watcher that uploads to Faraday
- `infrastructure/faraday/` - Faraday deployment configs
- `prompts/attack_guidance.md` - Gemini prompt for attack guidance

### Modified Components
- `format-cas.py` - Added Faraday data mappers and attack guidance generation
- `init-ptt.py` - Handle Faraday-sourced CAS documents
- `update-manifest.py` - Support `scan_type: faraday`
- `Dockerfile` - New entry point and dependencies
- `requirements.txt` - Streamlined (removed 11 unused dependencies)

## Architecture Comparison

### Before (Custom Pipeline)
```
scan file -> watcher.py -> parser -> enricher -> format-cas.py -> CAS
                              |
                              v
                         25 custom
                         parsers
```

### After (Faraday)
```
scan file -> faraday_watcher.py -> Faraday API -> format-cas.py -> CAS
                                        |
                                   (80+ built-in parsers)
                                        |
                                        v
                                   Faraday UI
```

## Key Design Decisions

1. **Faraday handles all parsing** - Removed custom parsers in favor of Faraday's 80+ built-in plugins
2. **CVE enrichment via Faraday** - Removed custom CVE API calls; Faraday has built-in CVE database
3. **Attack guidance via Gemini CLI** - Non-interactive subprocess calls with heuristic fallback
4. **CAS format v1.2** - Breaking change: facts only, attack_guidance separate with source flag

## Retained Enrichers

- `enrich-services.py` - Service priority scoring
- `enrich-web.py` - WAF detection and web technology identification

## Files Preserved

The original `watcher.py` is archived at `archive/watcher.py.bak` for reference.

## Dependencies Removed

```
python-libnmap>=0.7.3    # Nmap XML parsing
lxml>=4.9.0              # XML parsing
defusedxml>=0.7.1        # Safe XML parsing
httpx>=0.25.0            # Async HTTP
aiohttp>=3.9.0           # Async HTTP
aiofiles>=23.0.0         # Async file I/O
python-dateutil>=2.8.2   # Date parsing
netaddr>=0.9.0           # IP/CIDR handling
jsonschema>=4.20.0       # JSON validation
ipaddress                # Built-in since Python 3.3
```
