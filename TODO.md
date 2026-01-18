# Blunderbussy TODO

## Completed

- [x] **Vhost auto-detection in run-recon.sh** (Option 2)
  - After nmap runs, parses output for redirect hints
  - Auto-detects hostnames from `Did not follow redirect to https://hostname/`
  - Adds to `/etc/hosts` and passes vhost to web tools

- [x] **Pre-download nuclei templates in hexstrike Dockerfile**
  - Templates baked into image at build time
  - 6039 templates loaded, no first-run delay

## Backlog

- [ ] Refactor SERVICE_DATABASE to be minimal (defer recommendations to Dame agent)
- [ ] Clear processed_hashes.json when enricher logic changes
