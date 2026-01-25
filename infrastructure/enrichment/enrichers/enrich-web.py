#!/usr/bin/env python3
"""
Agent Opulence - Web Service Enrichment Script
==============================================
Enriches web service data with security context and attack surface analysis.

Input: JSON with web services data from httpx (stdin)
Output: Enriched JSON (stdout)

Enriches with:
- Technology vulnerability mapping
- Security header analysis
- Attack surface scoring
- Common vulnerability patterns
- Recommended tests
"""

import sys
import json
import re
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timezone
from dataclasses import dataclass, field
from urllib.parse import urlparse


# Technology vulnerability database
TECH_VULNS = {
    # CMS
    'WordPress': {
        'vulns': ['SQLi in plugins', 'XSS', 'Authentication bypass'],
        'paths': ['/wp-admin/', '/wp-login.php', '/wp-content/', '/xmlrpc.php'],
        'tools': ['wpscan', 'nuclei -t wordpress'],
        'priority': 3
    },
    'Drupal': {
        'vulns': ['Drupalgeddon (CVE-2018-7600)', 'CVE-2019-6340'],
        'paths': ['/user/login', '/admin/', '/node/'],
        'tools': ['droopescan', 'nuclei -t drupal'],
        'priority': 3
    },
    'Joomla': {
        'vulns': ['CVE-2023-23752', 'SQLi', 'XSS'],
        'paths': ['/administrator/', '/api/'],
        'tools': ['joomscan', 'nuclei -t joomla'],
        'priority': 2
    },
    # Frameworks
    'Laravel': {
        'vulns': ['Debug mode info disclosure', 'CVE-2021-3129'],
        'paths': ['/_ignition/execute-solution', '/.env'],
        'tools': ['nuclei -t laravel'],
        'priority': 2
    },
    'Django': {
        'vulns': ['Debug mode', 'SSTI'],
        'paths': ['/admin/', '/__debug__/'],
        'tools': ['nuclei -t django'],
        'priority': 2
    },
    'Spring': {
        'vulns': ['Spring4Shell (CVE-2022-22965)', 'Actuator exposure'],
        'paths': ['/actuator/', '/actuator/env', '/actuator/heapdump'],
        'tools': ['nuclei -t spring'],
        'priority': 3
    },
    'Express': {
        'vulns': ['Prototype pollution', 'Path traversal'],
        'paths': [],
        'tools': ['nuclei -t express'],
        'priority': 1
    },
    # Servers
    'Apache Tomcat': {
        'vulns': ['CVE-2020-1938 (Ghostcat)', 'Manager default creds'],
        'paths': ['/manager/', '/host-manager/', '/manager/html'],
        'tools': ['nuclei -t tomcat'],
        'priority': 3
    },
    'Apache': {
        'vulns': ['CVE-2021-41773', 'CVE-2021-42013'],
        'paths': ['/server-status', '/server-info'],
        'tools': ['nuclei -t apache'],
        'priority': 2
    },
    'nginx': {
        'vulns': ['Alias traversal', 'Off-by-slash'],
        'paths': ['/nginx_status'],
        'tools': ['nuclei -t nginx'],
        'priority': 1
    },
    'IIS': {
        'vulns': ['CVE-2017-7269 (WebDAV)', 'Short filename'],
        'paths': [],
        'tools': ['nuclei -t iis'],
        'priority': 2
    },
    # Applications
    'Jenkins': {
        'vulns': ['Unauthenticated access', 'Script console RCE'],
        'paths': ['/script', '/manage', '/asynchPeople/'],
        'tools': ['nuclei -t jenkins'],
        'priority': 3
    },
    'GitLab': {
        'vulns': ['CVE-2021-22205', 'SSRF', 'RCE'],
        'paths': ['/users/sign_in', '/api/v4/'],
        'tools': ['nuclei -t gitlab'],
        'priority': 3
    },
    'Grafana': {
        'vulns': ['CVE-2021-43798 (Path traversal)', 'Auth bypass'],
        'paths': ['/public/plugins/', '/api/'],
        'tools': ['nuclei -t grafana'],
        'priority': 3
    },
    'Kibana': {
        'vulns': ['CVE-2019-7609 (Prototype pollution RCE)'],
        'paths': ['/app/kibana', '/api/'],
        'tools': ['nuclei -t kibana'],
        'priority': 3
    },
    'Elasticsearch': {
        'vulns': ['Unauthenticated access', 'CVE-2015-1427'],
        'paths': ['/_search', '/_cat/indices'],
        'tools': ['nuclei -t elasticsearch'],
        'priority': 3
    },
    'Prometheus': {
        'vulns': ['Unauthenticated metrics', 'SSRF via targets'],
        'paths': ['/metrics', '/api/v1/targets', '/graph'],
        'tools': ['nuclei -t prometheus'],
        'priority': 2
    },
    'Kubernetes': {
        'vulns': ['Dashboard access', 'API exposure'],
        'paths': ['/api', '/apis', '/healthz'],
        'tools': ['nuclei -t kubernetes'],
        'priority': 3
    },
    # Languages/Runtimes
    'PHP': {
        'vulns': ['Type juggling', 'Object injection', 'LFI/RFI'],
        'paths': ['/info.php', '/phpinfo.php'],
        'tools': ['nuclei -t php'],
        'priority': 2
    },
    'ASP.NET': {
        'vulns': ['ViewState deserialization', 'Padding oracle'],
        'paths': ['/elmah.axd', '/trace.axd'],
        'tools': ['nuclei -t aspnet'],
        'priority': 2
    },
    'Node.js': {
        'vulns': ['Prototype pollution', 'SSRF'],
        'paths': [],
        'tools': ['nuclei -t nodejs'],
        'priority': 1
    }
}

# Security header requirements
SECURITY_HEADERS = {
    'content-security-policy': {
        'required': True,
        'impact': 'XSS mitigation',
        'severity': 'medium'
    },
    'x-frame-options': {
        'required': True,
        'impact': 'Clickjacking protection',
        'severity': 'medium'
    },
    'x-content-type-options': {
        'required': True,
        'impact': 'MIME sniffing protection',
        'severity': 'low'
    },
    'strict-transport-security': {
        'required': True,
        'impact': 'HTTPS enforcement',
        'severity': 'high'
    },
    'x-xss-protection': {
        'required': False,
        'impact': 'Legacy XSS filter',
        'severity': 'info'
    },
    'referrer-policy': {
        'required': False,
        'impact': 'Information leakage',
        'severity': 'low'
    },
    'permissions-policy': {
        'required': False,
        'impact': 'Feature restrictions',
        'severity': 'low'
    }
}


@dataclass
class WebEnrichment:
    """Enriched web service data."""
    url: str
    attack_surface_score: int = 0
    tech_vulns: List[Dict] = field(default_factory=list)
    security_issues: List[Dict] = field(default_factory=list)
    interesting_paths: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)


class WebEnricher:
    """Enriches web service data with security context."""

    def __init__(self):
        self.tech_db = TECH_VULNS
        self.header_requirements = SECURITY_HEADERS

    def _analyze_technologies(self, technologies: List[str]) -> List[Dict]:
        """Analyze detected technologies for vulnerabilities."""
        results = []

        for tech in technologies:
            # Direct match
            if tech in self.tech_db:
                db_entry = self.tech_db[tech]
                results.append({
                    'technology': tech,
                    'vulns': db_entry['vulns'],
                    'paths_to_check': db_entry['paths'],
                    'tools': db_entry['tools'],
                    'priority': db_entry['priority']
                })
                continue

            # Partial match
            for db_tech, db_entry in self.tech_db.items():
                if db_tech.lower() in tech.lower() or tech.lower() in db_tech.lower():
                    results.append({
                        'technology': tech,
                        'matched_as': db_tech,
                        'vulns': db_entry['vulns'],
                        'paths_to_check': db_entry['paths'],
                        'tools': db_entry['tools'],
                        'priority': db_entry['priority']
                    })
                    break

        return results

    def _analyze_security_headers(self, headers: Dict[str, str], scheme: str) -> List[Dict]:
        """Analyze security headers for issues."""
        issues = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, config in self.header_requirements.items():
            present = header in headers_lower

            # HSTS only required for HTTPS
            if header == 'strict-transport-security' and scheme != 'https':
                continue

            if config['required'] and not present:
                issues.append({
                    'header': header,
                    'issue': 'missing',
                    'impact': config['impact'],
                    'severity': config['severity']
                })
            elif present:
                # Check for weak configurations
                value = headers_lower[header]

                if header == 'content-security-policy':
                    if 'unsafe-inline' in value or 'unsafe-eval' in value:
                        issues.append({
                            'header': header,
                            'issue': 'weak_config',
                            'value': value[:100],
                            'impact': 'CSP allows unsafe directives',
                            'severity': 'medium'
                        })

                if header == 'x-frame-options':
                    if value.upper() not in ['DENY', 'SAMEORIGIN']:
                        issues.append({
                            'header': header,
                            'issue': 'weak_config',
                            'value': value,
                            'impact': 'Potentially weak X-Frame-Options',
                            'severity': 'low'
                        })

        return issues

    def _analyze_tls(self, tls_info: Optional[Dict]) -> List[Dict]:
        """Analyze TLS configuration for issues."""
        issues = []

        if not tls_info:
            return issues

        if tls_info.get('expired'):
            issues.append({
                'type': 'tls',
                'issue': 'expired_certificate',
                'severity': 'high',
                'details': f"Certificate expired: {tls_info.get('not_after', 'unknown')}"
            })

        if tls_info.get('self_signed'):
            issues.append({
                'type': 'tls',
                'issue': 'self_signed_certificate',
                'severity': 'medium',
                'details': f"Self-signed certificate from: {tls_info.get('issuer', 'unknown')}"
            })

        if tls_info.get('mismatched'):
            issues.append({
                'type': 'tls',
                'issue': 'certificate_mismatch',
                'severity': 'medium',
                'details': 'Certificate does not match hostname'
            })

        # Check TLS version
        version = tls_info.get('version', '')
        if 'TLS 1.0' in version or 'TLS 1.1' in version or 'SSL' in version:
            issues.append({
                'type': 'tls',
                'issue': 'weak_tls_version',
                'severity': 'medium',
                'details': f"Weak TLS version: {version}"
            })

        return issues

    def _calculate_attack_surface(self, service: Dict, tech_vulns: List, security_issues: List) -> int:
        """Calculate attack surface score (0-100)."""
        score = 20  # Base score

        # Technology vulnerabilities
        for tech in tech_vulns:
            score += tech.get('priority', 1) * 10

        # Security header issues
        for issue in security_issues:
            if issue.get('severity') == 'high':
                score += 15
            elif issue.get('severity') == 'medium':
                score += 10
            elif issue.get('severity') == 'low':
                score += 5

        # Status code analysis
        status = service.get('status_code', 0)
        if 200 <= status < 300:
            score += 5  # Active service
        if status in [401, 403]:
            score += 10  # Protected resource worth exploring

        # WAF/CDN (reduces score slightly - harder target)
        if service.get('waf', {}).get('detected'):
            score -= 10
        if service.get('cdn', {}).get('detected'):
            score -= 5

        # Interesting headers
        if service.get('interesting_headers'):
            score += len(service['interesting_headers']) * 2

        return min(max(score, 0), 100)

    def _generate_recommendations(self, tech_vulns: List, security_issues: List) -> List[str]:
        """Generate recommended tools and tests."""
        recommendations = set()

        # From technology analysis
        for tech in tech_vulns:
            for tool in tech.get('tools', []):
                recommendations.add(tool)

        # Default recommendations
        recommendations.add("nuclei -t cves/")
        recommendations.add("nuclei -t exposures/")

        if security_issues:
            recommendations.add("nuclei -t misconfiguration/")

        # Specific checks
        header_issues = [i for i in security_issues if i.get('header')]
        if header_issues:
            recommendations.add("Check for clickjacking, XSS")

        return list(recommendations)[:10]

    def _get_attack_vectors(self, service: Dict, tech_vulns: List) -> List[str]:
        """Determine applicable attack vectors."""
        vectors = []

        # From technologies
        for tech in tech_vulns:
            tech_name = tech.get('technology', '').lower()
            if 'php' in tech_name:
                vectors.extend(['LFI/RFI', 'Type juggling', 'Object injection'])
            if 'java' in tech_name or 'tomcat' in tech_name or 'spring' in tech_name:
                vectors.extend(['Deserialization', 'JNDI injection'])
            if 'wordpress' in tech_name or 'drupal' in tech_name or 'joomla' in tech_name:
                vectors.extend(['Plugin vulnerabilities', 'SQLi', 'Auth bypass'])
            if 'api' in tech_name or 'rest' in tech_name:
                vectors.extend(['IDOR', 'Mass assignment', 'Auth bypass'])

        # From service characteristics
        if service.get('title', '').lower().count('admin') or service.get('title', '').lower().count('login'):
            vectors.append('Brute force authentication')

        if service.get('status_code') in [401, 403]:
            vectors.append('Access control bypass')

        # Default vectors
        vectors.extend(['XSS', 'SQLi', 'Path traversal'])

        return list(set(vectors))[:10]

    def enrich_service(self, service: Dict) -> Dict:
        """Enrich a single web service."""
        enriched = service.copy()

        # Analyze technologies
        technologies = service.get('technologies', [])
        tech_analysis = self._analyze_technologies(technologies)

        # Analyze security headers
        security_headers = service.get('security_headers', {})
        headers = service.get('headers', {})
        scheme = service.get('scheme', 'http')
        header_issues = self._analyze_security_headers(headers, scheme)

        # Analyze TLS
        tls_issues = self._analyze_tls(service.get('tls'))

        # Combine security issues
        all_issues = header_issues + tls_issues

        # Calculate attack surface score
        attack_surface = self._calculate_attack_surface(service, tech_analysis, all_issues)

        # Get interesting paths to check
        interesting_paths = []
        for tech in tech_analysis:
            interesting_paths.extend(tech.get('paths_to_check', []))
        interesting_paths = list(set(interesting_paths))

        # Generate recommendations
        recommendations = self._generate_recommendations(tech_analysis, all_issues)

        # Get attack vectors
        attack_vectors = self._get_attack_vectors(service, tech_analysis)

        # Build enrichment
        enriched['enrichment'] = {
            'attack_surface_score': attack_surface,
            'tech_analysis': tech_analysis,
            'security_issues': all_issues,
            'interesting_paths': interesting_paths[:20],
            'recommended_tools': recommendations,
            'attack_vectors': attack_vectors
        }

        return enriched

    def enrich_web_services(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich all web services."""
        enriched = data.copy()

        # Track global stats
        high_value_targets = []
        all_tech_vulns = []
        all_security_issues = []
        paths_to_scan = set()
        tools_recommended = set()

        # Process web services
        if 'web_services' in data:
            for i, service in enumerate(enriched['web_services']):
                enriched_service = self.enrich_service(service)
                enriched['web_services'][i] = enriched_service

                # Aggregate stats
                service_enrichment = enriched_service.get('enrichment', {})
                attack_surface = service_enrichment.get('attack_surface_score', 0)

                if attack_surface >= 50:
                    high_value_targets.append({
                        'url': enriched_service.get('url', ''),
                        'score': attack_surface,
                        'technologies': [t['technology'] for t in service_enrichment.get('tech_analysis', [])],
                        'issues_count': len(service_enrichment.get('security_issues', []))
                    })

                all_tech_vulns.extend(service_enrichment.get('tech_analysis', []))
                all_security_issues.extend(service_enrichment.get('security_issues', []))

                for path in service_enrichment.get('interesting_paths', []):
                    base_url = enriched_service.get('url', '').rstrip('/')
                    paths_to_scan.add(f"{base_url}{path}")

                for tool in service_enrichment.get('recommended_tools', []):
                    tools_recommended.add(tool)

        # Sort high value targets
        high_value_targets.sort(key=lambda x: x['score'], reverse=True)

        # Add enrichment summary
        enriched['enrichment'] = enriched.get('enrichment', {})
        enriched['enrichment']['web'] = {
            'enriched_at': datetime.now(timezone.utc).isoformat(),
            'high_value_targets': high_value_targets[:10],
            'total_tech_vulns': len(all_tech_vulns),
            'total_security_issues': len(all_security_issues),
            'unique_technologies': list(set(t['technology'] for t in all_tech_vulns)),
            'paths_to_scan': list(paths_to_scan)[:50],
            'recommended_tools': list(tools_recommended)
        }

        # Generate web attack plan
        enriched['web_attack_plan'] = self._generate_attack_plan(enriched, high_value_targets)

        return enriched

    def _generate_attack_plan(self, data: Dict, targets: List) -> Dict:
        """Generate web-specific attack plan."""
        plan = {
            'priority_targets': [],
            'vulnerability_scan_commands': [],
            'manual_checks': []
        }

        # Priority targets
        for target in targets[:5]:
            plan['priority_targets'].append({
                'url': target['url'],
                'reason': f"Attack surface score: {target['score']}, Technologies: {', '.join(target['technologies'][:3])}"
            })

        # Generate scan commands
        tools = data.get('enrichment', {}).get('web', {}).get('recommended_tools', [])
        for tool in tools[:5]:
            plan['vulnerability_scan_commands'].append(tool)

        # Manual checks
        plan['manual_checks'] = [
            "Check robots.txt and sitemap.xml",
            "Test for directory traversal",
            "Check for exposed admin panels",
            "Test authentication mechanisms",
            "Look for API documentation or Swagger UI"
        ]

        return plan


def main():
    # Read input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({'error': f'Invalid JSON input: {e}'}), file=sys.stderr)
        sys.exit(1)

    # Enrich
    enricher = WebEnricher()
    enriched = enricher.enrich_web_services(input_data)

    # Output
    print(json.dumps(enriched))


if __name__ == '__main__':
    main()
