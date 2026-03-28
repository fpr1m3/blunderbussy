# Bash 4.3 - Shellshock (CVE-2014-6271)

## Overview
Apache HTTP server with CGI scripts running under vulnerable GNU Bash 4.3.
The Shellshock vulnerability allows remote code execution by injecting commands
through HTTP headers that become environment variables for CGI processes.

## Target Details
- **Image:** docker.io/vulhub/bash:4.3.0-with-httpd
- **Port:** 80, mapped to 8083
- **CVE:** CVE-2014-6271
- **Difficulty:** Easy

## Attack Path
1. Discover HTTP service and CGI endpoints
2. Test for Shellshock: `curl -A '() { :; }; echo; /usr/bin/id' http://target/cgi-bin/victim.cgi`
3. Exploit for reverse shell or command execution
4. Escalate privileges to root

## Flags
- User flag: `/home/user/user.txt` or `/tmp/user.txt`
- Root flag: `/root/root.txt`

## Support Files
- `victim.cgi` - Vulnerable CGI script (uses bash)
- `safe.cgi` - Non-vulnerable CGI script (uses dash)
