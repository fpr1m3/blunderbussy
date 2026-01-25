---
name: scanning-tools
description: Security scanning tools reference. Nmap, Masscan, Nikto, Burp Suite, ZAP, and vulnerability assessment tools. Note - recon is handled by HexStrike pipeline, Dame uses this for targeted follow-up scans.
---

# Security Scanning Tools

Comprehensive scanning tool reference. Dame primarily uses these for targeted follow-up scans after initial recon.

**Note:** Initial reconnaissance is handled by HexStrike/AutoRecon. Dame reads results from CAS.

---

## Nmap (Network Mapper)

### Host Discovery
```bash
nmap -sn $TARGET/24              # Ping scan (no port scan)
nmap -Pn $TARGET                 # Skip host discovery
```

### Port Scanning
```bash
nmap -sS $TARGET                 # TCP SYN scan (stealth)
nmap -sT $TARGET                 # TCP connect scan
nmap -sU $TARGET                 # UDP scan
nmap -p- $TARGET                 # All 65535 ports
nmap --top-ports 100 $TARGET     # Top 100 common ports
```

### Service and OS Detection
```bash
nmap -sV $TARGET                 # Service version detection
nmap -O $TARGET                  # OS detection
nmap -A $TARGET                  # Aggressive (OS, version, scripts)
```

### NSE Scripts
```bash
nmap --script=vuln $TARGET               # Vulnerability scripts
nmap --script=http-enum $TARGET          # Web enumeration
nmap --script=smb-vuln* $TARGET          # SMB vulnerabilities
nmap --script=default $TARGET            # Default script set
```

### Timing (for Dame - avoid hangs)
```bash
nmap -T4 $TARGET                 # Aggressive (faster)
nmap --host-timeout 60s $TARGET  # Timeout per host
```

### Output
```bash
nmap -oN scan.txt $TARGET        # Normal output
nmap -oX scan.xml $TARGET        # XML (for Faraday import)
nmap -oG scan.gnmap $TARGET      # Grepable output
```

---

## Masscan (High-Speed)

For large-scale scanning (usually pre-Dame):

```bash
masscan -p80 $TARGET/24 --rate=1000
masscan -p80,443,8080 $TARGET/24 --rate=10000
masscan -p0-65535 $TARGET --rate=5000
masscan -p80 $TARGET --banners           # Banner grabbing
```

---

## Web Application Scanning

### Nikto
```bash
nikto -h http://$TARGET
nikto -h http://$TARGET -C all           # Comprehensive
nikto -h http://$TARGET -Plugins robots
nikto -h http://$TARGET -Plugins shellshock
nikto -h http://$TARGET -o report.html -Format html
```

### OWASP ZAP
```bash
# Automated scan
zap-cli quick-scan http://$TARGET

# Full scan
zap-cli spider http://$TARGET
zap-cli active-scan http://$TARGET

# Generate report
zap-cli report -o report.html -f html
```

### Feroxbuster / Gobuster
```bash
# Directory brute forcing
feroxbuster -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://$TARGET -w wordlist.txt -x php,txt,html
```

---

## Vulnerability Scanning

### OpenVAS (Greenbone)
```bash
sudo gvm-start                   # Start services
# Access https://localhost:9392
```

### Nessus
```bash
sudo systemctl start nessusd
# Access https://localhost:8834
```

---

## SMB Enumeration

```bash
smbclient -L //$TARGET -N                # List shares (anonymous)
smbmap -H $TARGET                        # Map shares
enum4linux -a $TARGET                    # Comprehensive enum
crackmapexec smb $TARGET -u '' -p ''     # Null session
```

---

## DNS Enumeration

```bash
dnsrecon -d $DOMAIN -t std               # Standard recon
dig axfr @$TARGET $DOMAIN                # Zone transfer
fierce --domain $DOMAIN                  # Brute force subdomains
```

---

## Tool Selection Guide

| Scenario | Recommended Tools |
|----------|-------------------|
| Network Discovery | Nmap, Masscan |
| Vulnerability Assessment | Nessus, OpenVAS |
| Web App Testing | Burp Suite, ZAP, Nikto |
| SMB Enumeration | smbmap, enum4linux, crackmapexec |
| Directory Brute | Feroxbuster, Gobuster |
| Protocol Analysis | Wireshark, tcpdump |

---

## Common Ports Reference

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 139/445 | SMB |
| 443 | HTTPS |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Scan not detecting hosts | Try `nmap -Pn` or `-PS22,80,443` |
| Slow scan performance | Increase timing `-T4`, reduce port range |
| Web scanner missing vulns | Authenticate, increase crawl depth |
| Filtered ports | Try different scan types (ACK, Window) |
