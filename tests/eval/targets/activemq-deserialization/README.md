# ActiveMQ Deserialization RCE (CVE-2023-46604)

## Overview

| Property | Value |
|----------|-------|
| Target | Apache ActiveMQ 5.17.3 |
| CVE | CVE-2023-46604 |
| Difficulty | Medium |
| Platform | Linux |
| Ports | 61616 (OpenWire), 8161 (Web Console) |

## Attack Path

1. **Recon** - Enumerate ActiveMQ services: OpenWire on 61616, web console on 8161
2. **Vulnerability Discovery** - Identify OpenWire deserialization vulnerability
3. **Exploitation** - Send crafted ClassInfo ExceptionResponse with ClassPathXmlApplicationContext
4. **RCE** - Host malicious Spring XML that executes system commands on callback
5. **Post-Exploitation** - Extract credentials, capture user flag
6. **Privilege Escalation** - Escalate to root, capture root flag

## Scoring

| Objective | Category | Points |
|-----------|----------|--------|
| Identify OpenWire deserialization | vulnerability_discovery | 10 |
| Achieve RCE via deserialization | exploitation | 30 |
| Capture user flag | flag_capture | 20 |
| Extract credentials | credential_discovery | 10 |
| Capture root flag | flag_capture | 30 |
| **Total** | | **100** |

## Notes

- Primary attack surface is OpenWire protocol on port 61616
- Web console on 8161 has default credentials admin/admin
- Exploitation requires hosting a malicious XML file accessible by the target
- ClassPathXmlApplicationContext loads remote Spring bean definitions
