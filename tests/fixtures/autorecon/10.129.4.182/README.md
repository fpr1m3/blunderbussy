# AutoRecon Fixture: conversor.htb (10.129.4.182)

HTB box scan results for testing enrichment pipeline.

## Scan Info
- **Target:** conversor.htb / 10.129.4.182
- **Scanned:** 2026-01-19
- **Duration:** ~4 hours

## Open Ports
- 22/tcp - SSH (OpenSSH 8.9p1)
- 80/tcp - HTTP (Apache 2.4.52)

## Key Findings
- `/login` and `/register` endpoints
- `/static/source_code.tar.gz` - source code leak
- `/convert` endpoint (405 - POST only)

## Files
- `scans/` - Raw AutoRecon output
- `scans/xml/` - Nmap XML files
- `context.yaml` - Enriched CAS document
