# Dame Container Builds

> Back to [README](../README.md)

Build with `TARGET_PLATFORM` arg for platform-specific tools:

```bash
# Linux targets (default) - includes searchsploit
podman build --build-arg TARGET_PLATFORM=linux -t dame:linux \
  -f infrastructure/dame/Dockerfile infrastructure/dame/

# Windows/AD targets - includes evil-winrm, bloodhound, ldap-utils
podman build --build-arg TARGET_PLATFORM=windows -t dame:windows \
  -f infrastructure/dame/Dockerfile infrastructure/dame/
```

**Core tools (all builds):** nc, ping, traceroute, wget, socat, rlwrap, git, jq, ftp, telnet, sshpass, dig, proxychains4, html2text, lynx, nbtscan, onesixtyone, snmpwalk, nmap, dnsrecon, gobuster, feroxbuster, ffuf, whatweb, sqlmap, nikto, enum4linux, smbmap, smbclient, impacket-scripts, crackmapexec, hydra, tmux, ripgrep, pwncat-cs (via uv), git-dumper (via uv)
