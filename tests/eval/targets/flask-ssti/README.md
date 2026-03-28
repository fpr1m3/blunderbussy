# Flask 1.1.1 - Jinja2 Server-Side Template Injection

## Overview
Flask application with an SSTI vulnerability in the `name` query parameter.
User input is passed directly to `render_template_string` without sanitization,
allowing Jinja2 template injection that escalates to RCE.

## Target Details
- **Image:** docker.io/vulhub/flask:1.1.1
- **Port:** 8000, mapped to 8084
- **Vulnerability:** SSTI (no CVE, vulnerability class)
- **Difficulty:** Easy

## Attack Path
1. Discover web application on port 8000
2. Test SSTI: `curl 'http://target:8000/?name={{7*7}}'` returns "Hello 49!"
3. Escalate to RCE via Python MRO chain
4. Escalate privileges to root

## Flags
- User flag: `/home/user/user.txt` or `/tmp/user.txt`
- Root flag: `/root/root.txt`

## Support Files
- `src/app.py` - Vulnerable Flask application
