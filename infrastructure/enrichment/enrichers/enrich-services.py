#!/usr/bin/env python3
"""
Agent Opulence - Service Enrichment Script
==========================================
Enriches host/service data with additional context for exploitation.

Input: JSON with hosts/ports data (stdin)
Output: Enriched JSON (stdout)

Enriches with:
- Default credentials database
- Known vulnerabilities by service/version
- Common misconfigurations
- Exploitation techniques
- Priority scoring for attack planning
"""

import sys
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict, field


# Service database with exploitation context
SERVICE_DATABASE = {
    # SSH - Note: brute force rarely works on HTB, focus on key leaks and version exploits
    'ssh': {
        'default_ports': [22, 2222],
        'default_creds': [],  # Rarely useful on HTB
        'known_vulns': {
            'OpenSSH 7.': ['CVE-2018-15473'],  # Username enumeration
            'OpenSSH 8.': [],
            'dropbear': ['CVE-2018-15599']
        },
        'attack_vectors': ['private_key_disclosure', 'username_enum', 'version_specific_exploits'],
        'priority_boost': 1,  # Usually need creds from elsewhere first
        'notes': 'Look for leaked private keys, id_rsa in web dirs, .git exposure, LFI to read keys'
    },
    # FTP
    'ftp': {
        'default_ports': [21],
        'default_creds': [
            ('anonymous', ''), ('anonymous', 'anonymous'), ('ftp', 'ftp'),
            ('admin', 'admin'), ('root', 'root')
        ],
        'known_vulns': {
            'vsftpd 2.3.4': ['CVE-2011-2523'],  # Backdoor
            'ProFTPD 1.3.3': ['CVE-2010-4221'],  # Heap overflow
            'ProFTPD 1.3.5': ['CVE-2015-3306'],  # mod_copy
        },
        'attack_vectors': ['anonymous_access', 'brute_force', 'version_exploits'],
        'priority_boost': 1,
        'notes': 'Check anonymous access, writeable dirs, PASV mode'
    },
    # SMB
    'microsoft-ds': {
        'default_ports': [445],
        'default_creds': [
            ('administrator', ''), ('administrator', 'administrator'),
            ('guest', ''), ('admin', 'admin')
        ],
        'known_vulns': {
            'Samba 3.': ['CVE-2017-7494'],  # SambaCry
            'Windows 6.1': ['MS17-010'],  # EternalBlue
            'Windows 10': ['CVE-2020-0796'],  # SMBGhost
        },
        'attack_vectors': ['null_session', 'eternal_blue', 'relay_attacks', 'share_enum'],
        'priority_boost': 3,  # Very high value
        'notes': 'Check null sessions, guest access, writeable shares, SMB signing'
    },
    'netbios-ssn': {
        'default_ports': [139],
        'default_creds': [],
        'known_vulns': {},
        'attack_vectors': ['nbtscan', 'session_enum'],
        'priority_boost': 1,
        'notes': 'Legacy protocol, enumerate for SMB'
    },
    # Web servers
    'http': {
        'default_ports': [80, 8080, 8000, 8888],
        'default_creds': [
            ('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
            ('tomcat', 'tomcat'), ('manager', 'manager')
        ],
        'known_vulns': {
            'Apache/2.4.49': ['CVE-2021-41773'],  # Path traversal
            'Apache/2.4.50': ['CVE-2021-42013'],  # Path traversal
            'nginx/1.': [],
            'IIS/': ['CVE-2017-7269'],  # WebDAV
        },
        'attack_vectors': ['directory_traversal', 'misconfig', 'cgi_vuln', 'default_creds'],
        'priority_boost': 1,
        'notes': 'Check for default pages, admin panels, exposed APIs'
    },
    'https': {
        'default_ports': [443, 8443],
        'default_creds': [],
        'known_vulns': {},
        'attack_vectors': ['ssl_vulns', 'certificate_issues'],
        'priority_boost': 1,
        'notes': 'Check SSL/TLS config, cert validity, HSTS'
    },
    # Databases
    'mysql': {
        'default_ports': [3306],
        'default_creds': [
            ('root', ''), ('root', 'root'), ('root', 'mysql'),
            ('admin', 'admin'), ('mysql', 'mysql')
        ],
        'known_vulns': {
            'MySQL 5.5': ['CVE-2012-2122'],  # Auth bypass
            'MySQL 5.7': [],
            'MariaDB': []
        },
        'attack_vectors': ['default_creds', 'udf_exploitation', 'file_read'],
        'priority_boost': 2,
        'notes': 'Check remote root access, UDF loading, file privileges'
    },
    'postgresql': {
        'default_ports': [5432],
        'default_creds': [
            ('postgres', 'postgres'), ('postgres', ''), ('admin', 'admin')
        ],
        'known_vulns': {
            'PostgreSQL 9.': ['CVE-2019-9193'],  # RCE via COPY
        },
        'attack_vectors': ['default_creds', 'copy_rce', 'extension_abuse'],
        'priority_boost': 2,
        'notes': 'Check trust authentication, COPY TO PROGRAM'
    },
    'ms-sql-s': {
        'default_ports': [1433],
        'default_creds': [
            ('sa', ''), ('sa', 'sa'), ('sa', 'password'),
            ('admin', 'admin')
        ],
        'known_vulns': {},
        'attack_vectors': ['xp_cmdshell', 'default_creds', 'linked_servers'],
        'priority_boost': 3,
        'notes': 'Check xp_cmdshell, linked servers, NTLM relay'
    },
    'mongodb': {
        'default_ports': [27017],
        'default_creds': [],  # Often no auth
        'known_vulns': {},
        'attack_vectors': ['no_auth', 'injection'],
        'priority_boost': 2,
        'notes': 'Often exposed without authentication'
    },
    'redis': {
        'default_ports': [6379],
        'default_creds': [],  # Often no auth
        'known_vulns': {
            'Redis 5.': ['CVE-2022-0543'],  # Lua sandbox escape
        },
        'attack_vectors': ['no_auth', 'config_rce', 'lua_exploit'],
        'priority_boost': 2,
        'notes': 'Check no auth, CONFIG SET for RCE'
    },
    # Remote access
    'rdp': {
        'default_ports': [3389],
        'default_creds': [
            ('administrator', ''), ('admin', 'admin')
        ],
        'known_vulns': {
            'Windows': ['CVE-2019-0708'],  # BlueKeep
        },
        'attack_vectors': ['bluekeep', 'brute_force', 'nla_bypass'],
        'priority_boost': 3,
        'notes': 'Check NLA, BlueKeep, session hijacking'
    },
    'ms-wbt-server': {
        'default_ports': [3389],
        'default_creds': [],
        'known_vulns': {
            'Windows': ['CVE-2019-0708'],
        },
        'attack_vectors': ['bluekeep', 'brute_force'],
        'priority_boost': 3,
        'notes': 'Same as RDP'
    },
    'vnc': {
        'default_ports': [5900, 5901],
        'default_creds': [],
        'known_vulns': {
            'RealVNC': ['CVE-2006-2369'],  # Auth bypass
        },
        'attack_vectors': ['weak_password', 'no_auth', 'version_exploits'],
        'priority_boost': 2,
        'notes': 'Often weak/no password'
    },
    'telnet': {
        'default_ports': [23],
        'default_creds': [
            ('root', 'root'), ('admin', 'admin'), ('user', 'user'),
            ('admin', 'password'), ('admin', '1234')
        ],
        'known_vulns': {},
        'attack_vectors': ['brute_force', 'clear_text_sniffing'],
        'priority_boost': 2,
        'notes': 'Clear text, often on IoT/network devices'
    },
    # Misc services
    'ldap': {
        'default_ports': [389, 636],
        'default_creds': [],
        'known_vulns': {},
        'attack_vectors': ['anonymous_bind', 'injection', 'enum'],
        'priority_boost': 2,
        'notes': 'Check anonymous bind, LDAP injection'
    },
    'snmp': {
        'default_ports': [161],
        'default_creds': [
            ('public', ''), ('private', ''), ('community', '')
        ],
        'known_vulns': {},
        'attack_vectors': ['default_community', 'info_disclosure'],
        'priority_boost': 1,
        'notes': 'Check default community strings'
    },
    'nfs': {
        'default_ports': [2049],
        'default_creds': [],
        'known_vulns': {},
        'attack_vectors': ['showmount', 'uid_spoofing'],
        'priority_boost': 2,
        'notes': 'Check exports, no_root_squash'
    },
    'rpcbind': {
        'default_ports': [111],
        'default_creds': [],
        'known_vulns': {},
        'attack_vectors': ['service_enum'],
        'priority_boost': 0,
        'notes': 'Enumerate RPC services'
    },
    'ajp13': {
        'default_ports': [8009],
        'default_creds': [],
        'known_vulns': {
            'Apache Tomcat': ['CVE-2020-1938'],  # Ghostcat
        },
        'attack_vectors': ['ghostcat_lfi'],
        'priority_boost': 2,
        'notes': 'Ghostcat vulnerability for LFI/RCE'
    },
    'java-rmi': {
        'default_ports': [1099],
        'default_creds': [],
        'known_vulns': {},
        'attack_vectors': ['deserialization', 'rmi_registry_abuse'],
        'priority_boost': 2,
        'notes': 'Check for deserialization vulns'
    },
    'docker': {
        'default_ports': [2375, 2376],
        'default_creds': [],
        'known_vulns': {},
        'attack_vectors': ['unauthenticated_api', 'container_escape'],
        'priority_boost': 3,
        'notes': 'Unauthenticated Docker API = instant root'
    },
    'kubernetes': {
        'default_ports': [6443, 10250],
        'default_creds': [],
        'known_vulns': {},
        'attack_vectors': ['api_abuse', 'kubelet_exec'],
        'priority_boost': 3,
        'notes': 'Check kubelet API, anonymous auth'
    }
}


@dataclass
class ServiceEnrichment:
    """Enriched service data."""
    service: str
    port: int
    protocol: str = 'tcp'
    version_detected: str = ''
    default_creds: List[Tuple[str, str]] = field(default_factory=list)
    known_vulns: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    priority_score: int = 0
    notes: str = ''
    recommendations: List[str] = field(default_factory=list)


class ServiceEnricher:
    """Enriches service data with exploitation context."""

    def __init__(self):
        self.service_db = SERVICE_DATABASE

    def _normalize_service_name(self, service: str) -> str:
        """Normalize service name for lookup."""
        if not service:
            return ''

        service_lower = service.lower()

        # Direct match
        if service_lower in self.service_db:
            return service_lower

        # Alias mapping
        aliases = {
            'ssh': ['openssh', 'dropbear'],
            'http': ['http-proxy', 'apache', 'nginx', 'httpd', 'lighttpd'],
            'https': ['ssl/http', 'http-ssl'],
            'microsoft-ds': ['smb', 'cifs'],
            'ms-sql-s': ['mssql', 'sqlserver'],
            'mysql': ['mariadb'],
            'rdp': ['ms-wbt-server', 'terminal-services'],
            'ldap': ['ldaps'],
            'vnc': ['vnc-http', 'realvnc']
        }

        for canonical, alias_list in aliases.items():
            if service_lower in alias_list or any(a in service_lower for a in alias_list):
                return canonical

        return service_lower

    def _match_version_vulns(self, service: str, version: str) -> List[str]:
        """Match service version against known vulnerabilities."""
        if not version or service not in self.service_db:
            return []

        vulns = []
        known_vulns = self.service_db[service].get('known_vulns', {})

        for version_pattern, cve_list in known_vulns.items():
            if version_pattern.lower() in version.lower():
                vulns.extend(cve_list)

        return list(set(vulns))

    def _calculate_priority(self, service: str, port: int, state: str, vulns: List[str]) -> int:
        """Calculate attack priority score (0-10)."""
        score = 5  # Base score

        # Service-specific boost
        if service in self.service_db:
            score += self.service_db[service].get('priority_boost', 0)

        # Known vulnerabilities boost
        score += min(len(vulns) * 2, 4)

        # High-value port boost
        high_value_ports = [22, 23, 445, 3389, 1433, 3306, 5432, 6379]
        if port in high_value_ports:
            score += 1

        # State adjustment
        if state != 'open':
            score -= 2

        return min(max(score, 0), 10)

    def _generate_recommendations(self, service: str, enrichment: ServiceEnrichment) -> List[str]:
        """Generate attack recommendations."""
        recommendations = []

        if enrichment.default_creds:
            recommendations.append(f"Try default credentials ({len(enrichment.default_creds)} known pairs)")

        if enrichment.known_vulns:
            recommendations.append(f"Check for {', '.join(enrichment.known_vulns[:3])}")

        if service in self.service_db:
            db_entry = self.service_db[service]
            vectors = db_entry.get('attack_vectors', [])

            if 'anonymous_access' in vectors or 'no_auth' in vectors:
                recommendations.append("Check for anonymous/unauthenticated access")

            if 'private_key_disclosure' in vectors:
                recommendations.append("Search for leaked SSH keys via LFI, backup files, .git")

            if 'version_exploits' in vectors or 'version_specific_exploits' in vectors:
                recommendations.append("Search for version-specific exploits")

        return recommendations

    def enrich_port(self, port_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single port with service context."""
        service_name = port_data.get('service', '')
        port_num = port_data.get('port', 0)
        protocol = port_data.get('protocol', 'tcp')
        state = port_data.get('state', 'unknown')
        version = port_data.get('version_string', port_data.get('version', ''))
        product = port_data.get('product', '')

        # Combine version info
        full_version = f"{product} {version}".strip() if product else version

        # Normalize service name
        normalized_service = self._normalize_service_name(service_name)

        # Build enrichment
        enrichment = ServiceEnrichment(
            service=normalized_service or service_name,
            port=port_num,
            protocol=protocol,
            version_detected=full_version
        )

        # Add service-specific data
        if normalized_service in self.service_db:
            db_entry = self.service_db[normalized_service]
            enrichment.default_creds = db_entry.get('default_creds', [])
            enrichment.attack_vectors = db_entry.get('attack_vectors', [])
            enrichment.notes = db_entry.get('notes', '')

        # Match version vulnerabilities
        enrichment.known_vulns = self._match_version_vulns(normalized_service, full_version)

        # Calculate priority
        enrichment.priority_score = self._calculate_priority(
            normalized_service, port_num, state, enrichment.known_vulns
        )

        # Generate recommendations
        enrichment.recommendations = self._generate_recommendations(normalized_service, enrichment)

        # Merge back into port data
        enriched_port = port_data.copy()
        enriched_port['enrichment'] = {
            'normalized_service': enrichment.service,
            'default_creds_count': len(enrichment.default_creds),
            'default_creds': enrichment.default_creds[:5],  # Limit for output
            'known_vulns': enrichment.known_vulns,
            'attack_vectors': enrichment.attack_vectors,
            'priority_score': enrichment.priority_score,
            'notes': enrichment.notes,
            'recommendations': enrichment.recommendations
        }

        return enriched_port

    def enrich_hosts(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich all hosts/services in the data."""
        enriched = data.copy()

        # Track global stats
        high_priority_targets = []
        services_found = {}
        total_default_creds = 0
        total_known_vulns = 0

        # Process hosts
        if 'hosts' in data:
            for host in enriched['hosts']:
                host_priority = 0
                host_vulns = []

                if 'ports' in host:
                    for i, port in enumerate(host['ports']):
                        enriched_port = self.enrich_port(port)
                        host['ports'][i] = enriched_port

                        # Aggregate stats
                        port_enrichment = enriched_port.get('enrichment', {})
                        priority = port_enrichment.get('priority_score', 0)
                        host_priority = max(host_priority, priority)
                        host_vulns.extend(port_enrichment.get('known_vulns', []))

                        service = port_enrichment.get('normalized_service', '')
                        if service:
                            services_found[service] = services_found.get(service, 0) + 1

                        total_default_creds += port_enrichment.get('default_creds_count', 0)
                        total_known_vulns += len(port_enrichment.get('known_vulns', []))

                # Add host-level enrichment summary
                host['enrichment_summary'] = {
                    'max_priority': host_priority,
                    'vulns_found': list(set(host_vulns)),
                    'open_ports': len(host.get('ports', []))
                }

                # Track high priority targets
                if host_priority >= 7:
                    high_priority_targets.append({
                        'ip': host.get('ip', ''),
                        'hostname': host.get('hostname', ''),
                        'priority': host_priority,
                        'vulns': host_vulns[:5]
                    })

        # Sort high priority targets
        high_priority_targets.sort(key=lambda x: x['priority'], reverse=True)

        # Add enrichment metadata
        enriched['enrichment'] = enriched.get('enrichment', {})
        enriched['enrichment']['services'] = {
            'enriched_at': datetime.utcnow().isoformat(),
            'services_found': services_found,
            'high_priority_targets': high_priority_targets[:10],
            'total_services_with_default_creds': total_default_creds,
            'total_known_vulns': total_known_vulns
        }

        # Add attack plan summary
        enriched['attack_plan'] = {
            'priority_targets': [
                {
                    'target': t['ip'] or t['hostname'],
                    'priority': t['priority'],
                    'reason': f"Known vulns: {t['vulns'][:3]}" if t['vulns'] else "High-value service"
                }
                for t in high_priority_targets[:5]
            ],
            'recommended_first_steps': self._generate_attack_plan(enriched)
        }

        return enriched

    def _generate_attack_plan(self, data: Dict[str, Any]) -> List[str]:
        """Generate recommended attack steps."""
        steps = []

        # Check for quick wins
        services_found = data.get('enrichment', {}).get('services', {}).get('services_found', {})

        if 'microsoft-ds' in services_found or 'smb' in services_found:
            steps.append("Run SMB enumeration (enum4linux, smbclient null session)")

        if 'ftp' in services_found:
            steps.append("Check FTP anonymous access")

        if 'ssh' in services_found:
            steps.append("SSH found - look for key leaks via LFI, .git, backups")

        if 'mysql' in services_found or 'postgresql' in services_found:
            steps.append("Test database services for default/no credentials")

        if 'redis' in services_found or 'mongodb' in services_found:
            steps.append("Check NoSQL services for unauthenticated access")

        if 'http' in services_found or 'https' in services_found:
            steps.append("Run web vulnerability scan (nuclei, nikto)")

        if 'rdp' in services_found:
            steps.append("Check RDP for BlueKeep (CVE-2019-0708)")

        if not steps:
            steps.append("Enumerate all open services for version info")
            steps.append("Run credential spray against authentication services")

        return steps[:5]


def main():
    # Read input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({'error': f'Invalid JSON input: {e}'}), file=sys.stderr)
        sys.exit(1)

    # Enrich
    enricher = ServiceEnricher()
    enriched = enricher.enrich_hosts(input_data)

    # Output
    print(json.dumps(enriched))


if __name__ == '__main__':
    main()
