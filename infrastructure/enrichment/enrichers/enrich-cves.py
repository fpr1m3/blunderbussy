#!/usr/bin/env python3
"""
Agent Opulence - CVE Enrichment Script
======================================
Enriches vulnerability data with CVE details from NVD/NIST.

Input: JSON with vulnerabilities (stdin)
Output: Enriched JSON (stdout)

Enriches with:
- CVSS v3.1 scores and vectors
- Exploit availability (from CISA KEV, Exploit-DB)
- Vendor advisories
- Remediation guidance
- Attack complexity/vector analysis
"""

import sys
import json
import os
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import requests
from tenacity import retry, stop_after_attempt, wait_exponential


# Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR = Path("/artifacts/cache/cves")
CACHE_TTL_HOURS = 24
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
REQUEST_DELAY = 0.6 if not NVD_API_KEY else 0.1  # Rate limiting


@dataclass
class CVEInfo:
    """Structured CVE information."""
    cve_id: str
    description: str = ""
    cvss_v3_score: float = 0.0
    cvss_v3_vector: str = ""
    cvss_v3_severity: str = "UNKNOWN"
    cvss_v2_score: float = 0.0
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality_impact: str = ""
    integrity_impact: str = ""
    availability_impact: str = ""
    exploit_available: bool = False
    exploit_sources: List[str] = None
    in_cisa_kev: bool = False
    kev_due_date: str = ""
    references: List[Dict[str, str]] = None
    vendor_advisory: str = ""
    cpe_matches: List[str] = None
    published_date: str = ""
    last_modified: str = ""
    weaknesses: List[str] = None
    enriched_at: str = ""

    def __post_init__(self):
        if self.exploit_sources is None:
            self.exploit_sources = []
        if self.references is None:
            self.references = []
        if self.cpe_matches is None:
            self.cpe_matches = []
        if self.weaknesses is None:
            self.weaknesses = []


class CVEEnricher:
    """Enriches CVE data from multiple sources."""

    def __init__(self):
        self.cache_dir = CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.kev_cache: Optional[Dict[str, Dict]] = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Agent-Opulence-Enrichment/1.0'
        })
        if NVD_API_KEY:
            self.session.headers['apiKey'] = NVD_API_KEY

    def _get_cache_path(self, cve_id: str) -> Path:
        """Get cache file path for a CVE."""
        return self.cache_dir / f"{cve_id}.json"

    def _load_cache(self, cve_id: str) -> Optional[Dict]:
        """Load cached CVE data if valid."""
        cache_path = self._get_cache_path(cve_id)
        if not cache_path.exists():
            return None

        try:
            with open(cache_path) as f:
                cached = json.load(f)

            # Check TTL
            cached_at = datetime.fromisoformat(cached.get('cached_at', ''))
            if datetime.utcnow() - cached_at < timedelta(hours=CACHE_TTL_HOURS):
                return cached.get('data')
        except Exception:
            pass

        return None

    def _save_cache(self, cve_id: str, data: Dict):
        """Save CVE data to cache."""
        cache_path = self._get_cache_path(cve_id)
        try:
            with open(cache_path, 'w') as f:
                json.dump({
                    'cached_at': datetime.utcnow().isoformat(),
                    'data': data
                }, f)
        except Exception:
            pass

    def _load_cisa_kev(self) -> Dict[str, Dict]:
        """Load CISA Known Exploited Vulnerabilities catalog."""
        if self.kev_cache is not None:
            return self.kev_cache

        kev_cache_path = self.cache_dir / "cisa_kev.json"

        # Check cache
        if kev_cache_path.exists():
            try:
                with open(kev_cache_path) as f:
                    cached = json.load(f)
                cached_at = datetime.fromisoformat(cached.get('cached_at', ''))
                if datetime.utcnow() - cached_at < timedelta(hours=24):
                    self.kev_cache = cached.get('data', {})
                    return self.kev_cache
            except Exception:
                pass

        # Fetch fresh data
        try:
            response = self.session.get(CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            kev_data = response.json()

            # Index by CVE ID
            self.kev_cache = {}
            for vuln in kev_data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                if cve_id:
                    self.kev_cache[cve_id] = {
                        'vendor': vuln.get('vendorProject'),
                        'product': vuln.get('product'),
                        'name': vuln.get('vulnerabilityName'),
                        'description': vuln.get('shortDescription'),
                        'due_date': vuln.get('dueDate'),
                        'required_action': vuln.get('requiredAction'),
                        'notes': vuln.get('notes')
                    }

            # Cache it
            with open(kev_cache_path, 'w') as f:
                json.dump({
                    'cached_at': datetime.utcnow().isoformat(),
                    'data': self.kev_cache
                }, f)

        except Exception as e:
            self.kev_cache = {}

        return self.kev_cache

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _fetch_nvd(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE data from NVD API."""
        try:
            time.sleep(REQUEST_DELAY)  # Rate limiting

            response = self.session.get(
                NVD_API_URL,
                params={'cveId': cve_id},
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            if vulnerabilities:
                return vulnerabilities[0].get('cve', {})

        except requests.exceptions.RequestException:
            pass

        return None

    def _parse_cvss_v3(self, metrics: Dict) -> Dict[str, Any]:
        """Parse CVSS v3.x metrics."""
        result = {
            'score': 0.0,
            'vector': '',
            'severity': 'UNKNOWN',
            'attack_vector': '',
            'attack_complexity': '',
            'privileges_required': '',
            'user_interaction': '',
            'scope': '',
            'confidentiality_impact': '',
            'integrity_impact': '',
            'availability_impact': ''
        }

        # Try v3.1 first, then v3.0
        for version in ['cvssMetricV31', 'cvssMetricV30']:
            if version in metrics:
                metric_list = metrics[version]
                if metric_list:
                    metric = metric_list[0]
                    cvss_data = metric.get('cvssData', {})

                    result['score'] = cvss_data.get('baseScore', 0.0)
                    result['vector'] = cvss_data.get('vectorString', '')
                    result['severity'] = cvss_data.get('baseSeverity', 'UNKNOWN')
                    result['attack_vector'] = cvss_data.get('attackVector', '')
                    result['attack_complexity'] = cvss_data.get('attackComplexity', '')
                    result['privileges_required'] = cvss_data.get('privilegesRequired', '')
                    result['user_interaction'] = cvss_data.get('userInteraction', '')
                    result['scope'] = cvss_data.get('scope', '')
                    result['confidentiality_impact'] = cvss_data.get('confidentialityImpact', '')
                    result['integrity_impact'] = cvss_data.get('integrityImpact', '')
                    result['availability_impact'] = cvss_data.get('availabilityImpact', '')
                    break

        return result

    def _check_exploit_sources(self, references: List[Dict]) -> List[str]:
        """Check references for exploit sources."""
        exploit_sources = []
        exploit_indicators = [
            ('exploit-db.com', 'Exploit-DB'),
            ('packetstormsecurity', 'PacketStorm'),
            ('github.com', 'GitHub PoC'),
            ('metasploit', 'Metasploit'),
            ('rapid7', 'Rapid7'),
            ('nuclei-templates', 'Nuclei Template')
        ]

        for ref in references:
            url = ref.get('url', '').lower()
            tags = ref.get('tags', [])

            # Check URL patterns
            for pattern, source_name in exploit_indicators:
                if pattern in url:
                    if source_name not in exploit_sources:
                        exploit_sources.append(source_name)
                    break

            # Check tags
            if 'Exploit' in tags or 'Third Party Advisory' in tags:
                for pattern, source_name in exploit_indicators:
                    if pattern in url and source_name not in exploit_sources:
                        exploit_sources.append(source_name)

        return exploit_sources

    def enrich_cve(self, cve_id: str) -> CVEInfo:
        """Enrich a single CVE with full details."""
        # Check cache first
        cached = self._load_cache(cve_id)
        if cached:
            return CVEInfo(**cached)

        info = CVEInfo(cve_id=cve_id, enriched_at=datetime.utcnow().isoformat())

        # Fetch from NVD
        nvd_data = self._fetch_nvd(cve_id)

        if nvd_data:
            # Parse descriptions
            descriptions = nvd_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    info.description = desc.get('value', '')
                    break

            # Parse metrics
            metrics = nvd_data.get('metrics', {})
            cvss_info = self._parse_cvss_v3(metrics)
            info.cvss_v3_score = cvss_info['score']
            info.cvss_v3_vector = cvss_info['vector']
            info.cvss_v3_severity = cvss_info['severity']
            info.attack_vector = cvss_info['attack_vector']
            info.attack_complexity = cvss_info['attack_complexity']
            info.privileges_required = cvss_info['privileges_required']
            info.user_interaction = cvss_info['user_interaction']
            info.scope = cvss_info['scope']
            info.confidentiality_impact = cvss_info['confidentiality_impact']
            info.integrity_impact = cvss_info['integrity_impact']
            info.availability_impact = cvss_info['availability_impact']

            # CVSS v2 fallback
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_v2 = metrics['cvssMetricV2'][0].get('cvssData', {})
                info.cvss_v2_score = cvss_v2.get('baseScore', 0.0)

            # Parse references
            references = nvd_data.get('references', [])
            info.references = [
                {'url': ref.get('url'), 'source': ref.get('source'), 'tags': ref.get('tags', [])}
                for ref in references
            ]

            # Check for exploits
            info.exploit_sources = self._check_exploit_sources(references)
            info.exploit_available = len(info.exploit_sources) > 0

            # Parse weaknesses (CWE)
            weaknesses = nvd_data.get('weaknesses', [])
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        info.weaknesses.append(desc.get('value', ''))

            # Parse CPE matches
            configurations = nvd_data.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for match in node.get('cpeMatch', []):
                        if match.get('vulnerable'):
                            info.cpe_matches.append(match.get('criteria', ''))

            # Dates
            info.published_date = nvd_data.get('published', '')
            info.last_modified = nvd_data.get('lastModified', '')

        # Check CISA KEV
        kev_catalog = self._load_cisa_kev()
        if cve_id in kev_catalog:
            kev_info = kev_catalog[cve_id]
            info.in_cisa_kev = True
            info.kev_due_date = kev_info.get('due_date', '')
            info.exploit_available = True
            if 'CISA KEV' not in info.exploit_sources:
                info.exploit_sources.append('CISA KEV')

        # Cache the result
        self._save_cache(cve_id, asdict(info))

        return info

    def enrich_vulnerabilities(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich all CVEs in vulnerability data."""
        enriched = data.copy()

        # Find CVEs to enrich
        cves_to_enrich = set()

        # From nuclei findings
        if 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                for cve in vuln.get('cves', []):
                    cves_to_enrich.add(cve)

        if 'stats' in data and 'cves_found' in data['stats']:
            for cve in data['stats']['cves_found']:
                cves_to_enrich.add(cve)

        # Enrich each CVE
        enriched['cve_details'] = {}
        enriched['exploit_available'] = []
        enriched['critical_cves'] = []
        enriched['cisa_kev_cves'] = []

        for cve_id in cves_to_enrich:
            info = self.enrich_cve(cve_id)
            enriched['cve_details'][cve_id] = asdict(info)

            if info.exploit_available:
                enriched['exploit_available'].append(cve_id)

            if info.cvss_v3_severity == 'CRITICAL' or info.cvss_v3_score >= 9.0:
                enriched['critical_cves'].append(cve_id)

            if info.in_cisa_kev:
                enriched['cisa_kev_cves'].append(cve_id)

        # Update vulnerabilities with enriched data
        if 'vulnerabilities' in enriched:
            for vuln in enriched['vulnerabilities']:
                for cve in vuln.get('cves', []):
                    if cve in enriched['cve_details']:
                        cve_info = enriched['cve_details'][cve]
                        vuln['cve_enriched'] = vuln.get('cve_enriched', {})
                        vuln['cve_enriched'][cve] = {
                            'cvss_v3_score': cve_info['cvss_v3_score'],
                            'cvss_v3_severity': cve_info['cvss_v3_severity'],
                            'exploit_available': cve_info['exploit_available'],
                            'in_cisa_kev': cve_info['in_cisa_kev'],
                            'attack_vector': cve_info['attack_vector']
                        }

        # Add enrichment metadata
        enriched['enrichment'] = enriched.get('enrichment', {})
        enriched['enrichment']['cve'] = {
            'enriched_at': datetime.utcnow().isoformat(),
            'total_cves': len(cves_to_enrich),
            'exploitable': len(enriched['exploit_available']),
            'critical': len(enriched['critical_cves']),
            'in_kev': len(enriched['cisa_kev_cves'])
        }

        return enriched


def main():
    # Read input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({'error': f'Invalid JSON input: {e}'}), file=sys.stderr)
        sys.exit(1)

    # Enrich
    enricher = CVEEnricher()
    enriched = enricher.enrich_vulnerabilities(input_data)

    # Output
    print(json.dumps(enriched))


if __name__ == '__main__':
    main()
