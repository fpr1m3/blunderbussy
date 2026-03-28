# PHP-FPM RCE (CVE-2019-11043)

## Overview

| Property | Value |
|----------|-------|
| Target | nginx + PHP-FPM 7.2.10 |
| CVE | CVE-2019-11043 |
| Difficulty | Medium |
| Platform | Linux |
| Port | 8087 (mapped to 80) |

## Attack Path

1. **Recon** - Enumerate web server on port 8087, identify nginx + PHP backend
2. **Vulnerability Discovery** - Test path info manipulation with newline injection in URLs
3. **Exploitation** - Exploit PHP-FPM buffer underflow via fastcgi_split_path_info regex bypass
4. **RCE** - Inject PHP_VALUE via corrupted FastCGI parameters for code execution
5. **Post-Exploitation** - Extract credentials from config.php, capture user flag
6. **Privilege Escalation** - Escalate from www-data to root, capture root flag

## Scoring

| Objective | Category | Points |
|-----------|----------|--------|
| Identify PHP-FPM buffer underflow | vulnerability_discovery | 10 |
| Achieve RCE via FPM exploit | exploitation | 30 |
| Capture user flag | flag_capture | 20 |
| Extract credentials | credential_discovery | 10 |
| Capture root flag | flag_capture | 30 |
| **Total** | | **100** |

## Notes

- Multi-container target: nginx (frontend) + PHP-FPM (backend)
- Vulnerable nginx config: `fastcgi_split_path_info` regex can be bypassed with newline
- Tools: phuip-fpizdam is the standard exploit tool for this vulnerability
- Support files: www/index.php (phpinfo page), default.conf (nginx config)
