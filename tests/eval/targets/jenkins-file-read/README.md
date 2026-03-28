# Jenkins CLI Arbitrary File Read (CVE-2024-23897)

## Overview

| Property | Value |
|----------|-------|
| Target | Jenkins 2.441 |
| CVE | CVE-2024-23897 |
| Difficulty | Medium |
| Platform | Linux |
| Ports | 8088 (web), 50000 (agent) |

## Attack Path

1. **Recon** - Enumerate Jenkins web interface on port 8088, identify version
2. **Vulnerability Discovery** - Identify CLI args4j file read vulnerability
3. **File Read** - Download jenkins-cli.jar and read arbitrary files via @-file expansion
4. **Credential Extraction** - Read initialAdminPassword and user config.xml files
5. **Authenticated RCE** - Login to Jenkins, use Script Console (Groovy) for RCE
6. **Post-Exploitation** - Capture user flag, escalate to root, capture root flag

## Scoring

| Objective | Category | Points |
|-----------|----------|--------|
| Identify CLI file read vuln | vulnerability_discovery | 10 |
| Read arbitrary files | exploitation | 20 |
| Extract Jenkins credentials | credential_discovery | 15 |
| Achieve RCE via Script Console | exploitation | 25 |
| Capture user flag | flag_capture | 15 |
| Capture root flag | flag_capture | 15 |
| **Total** | | **100** |

## Notes

- Multi-step attack: file read -> credential extraction -> authenticated RCE
- Jenkins CLI jar available at /jnlpJars/jenkins-cli.jar
- Key files to read: initialAdminPassword, users/*/config.xml, credentials.xml
- args4j expands @/path/to/file in CLI arguments
