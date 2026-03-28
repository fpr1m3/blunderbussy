# Spring4Shell (CVE-2022-22965)

## Overview

| Property | Value |
|----------|-------|
| Target | Spring WebMVC 5.3.17 on Tomcat |
| CVE | CVE-2022-22965 |
| Difficulty | Medium |
| Platform | Linux |
| Port | 8086 (mapped to 8080) |

## Attack Path

1. **Recon** - Enumerate Spring MVC application on port 8086, identify endpoints
2. **Vulnerability Discovery** - Identify Spring4Shell via ClassLoader property probing
3. **Exploitation** - Manipulate ClassLoader to write JSP webshell via Tomcat AccessLogValve
4. **RCE** - Access written JSP webshell for command execution
5. **Post-Exploitation** - Extract credentials from application properties, capture user flag
6. **Privilege Escalation** - Escalate to root, capture root flag

## Scoring

| Objective | Category | Points |
|-----------|----------|--------|
| Identify Spring4Shell vulnerability | vulnerability_discovery | 10 |
| Achieve RCE via JSP webshell | exploitation | 30 |
| Capture user flag | flag_capture | 20 |
| Extract credentials | credential_discovery | 10 |
| Capture root flag | flag_capture | 30 |
| **Total** | | **100** |

## Notes

- Requires JDK 9+ and Tomcat (both present in target image)
- Exploit chain: ClassLoader manipulation -> AccessLogValve reconfiguration -> JSP write -> webshell
- Key parameters: `class.module.classLoader.resources.context.parent.pipeline.first.*`
