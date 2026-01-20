#!/usr/bin/env python3
"""
Agent Opulence - SSLScan Output Parser
======================================
Parses sslscan output (XML or text) into structured JSON for enrichment pipeline.

Usage: parse-sslscan.py <sslscan_output_file>
Output: JSON to stdout

SSLScan checks SSL/TLS configurations:
- Protocol support (SSLv2, SSLv3, TLSv1.0-1.3)
- Cipher suites with strength ratings
- Certificate information
- Known vulnerabilities (Heartbleed, POODLE, etc.)
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

# Try to use defusedxml for safer XML parsing
try:
    from defusedxml import ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


# Cipher strength classifications
WEAK_CIPHERS = {
    'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'ADH', 'AECDH',
    'DES-CBC', 'RC2', 'IDEA'
}

MEDIUM_CIPHERS = {
    'SHA1', 'CBC'
}


def classify_cipher_strength(cipher_name: str, bits: int) -> str:
    """Classify cipher strength based on name and bit length."""
    cipher_upper = cipher_name.upper()

    # Weak ciphers
    for weak in WEAK_CIPHERS:
        if weak.upper() in cipher_upper:
            return 'weak'

    # Check key length
    if bits < 128:
        return 'weak'
    elif bits < 256:
        # Medium strength - check for other indicators
        for medium in MEDIUM_CIPHERS:
            if medium in cipher_upper:
                return 'medium'
        return 'medium' if bits == 128 else 'strong'

    # Strong ciphers (256+ bits, modern algorithms)
    if 'GCM' in cipher_upper or 'CHACHA' in cipher_upper:
        return 'strong'

    return 'strong' if bits >= 256 else 'medium'


def parse_sslscan_xml(file_path: Path) -> Dict[str, Any]:
    """Parse sslscan XML output format."""
    tree = ET.parse(str(file_path))
    root = tree.getroot()

    result = {
        'type': 'sslscan',
        'target': None,
        'protocols': {
            'sslv2': False,
            'sslv3': False,
            'tlsv1_0': False,
            'tlsv1_1': False,
            'tlsv1_2': False,
            'tlsv1_3': False
        },
        'ciphers': [],
        'certificate': None,
        'vulnerabilities': {
            'heartbleed': False,
            'ccs_injection': False,
            'beast': False,
            'poodle': False,
            'sweet32': False,
            'ticketbleed': False,
            'robot': False,
            'drown': False,
            'crime': False,
            'breach': False,
            'logjam': False,
            'freak': False
        },
        'stats': {
            'weak_ciphers': [],
            'issues': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    # Find ssltest element (may be root or child)
    ssltest = root.find('.//ssltest')
    if ssltest is None:
        ssltest = root if root.tag == 'ssltest' else root

    # Extract target
    if ssltest.get('host'):
        port = ssltest.get('port', '443')
        result['target'] = f"{ssltest.get('host')}:{port}"

    # Parse protocols
    for protocol in ssltest.findall('.//protocol'):
        proto_type = protocol.get('type', '').lower()
        proto_version = protocol.get('version', '')
        enabled = protocol.get('enabled', '0') == '1'

        proto_key = None
        if proto_type == 'ssl' and proto_version == '2':
            proto_key = 'sslv2'
        elif proto_type == 'ssl' and proto_version == '3':
            proto_key = 'sslv3'
        elif proto_type == 'tls' and proto_version == '1.0':
            proto_key = 'tlsv1_0'
        elif proto_type == 'tls' and proto_version == '1.1':
            proto_key = 'tlsv1_1'
        elif proto_type == 'tls' and proto_version == '1.2':
            proto_key = 'tlsv1_2'
        elif proto_type == 'tls' and proto_version == '1.3':
            proto_key = 'tlsv1_3'

        if proto_key:
            result['protocols'][proto_key] = enabled

    # Parse ciphers
    for cipher in ssltest.findall('.//cipher'):
        if cipher.get('status') == 'accepted':
            cipher_name = cipher.get('cipher', '')
            bits = int(cipher.get('bits', 0))
            protocol = cipher.get('sslversion', '')

            # Normalize protocol name
            if protocol.startswith('TLS'):
                protocol = protocol.replace('TLS', 'TLSv')

            strength = classify_cipher_strength(cipher_name, bits)

            cipher_data = {
                'name': cipher_name,
                'bits': bits,
                'protocol': protocol,
                'strength': strength
            }

            # Check for key exchange info
            if cipher.get('kx'):
                cipher_data['key_exchange'] = cipher.get('kx')
            if cipher.get('au'):
                cipher_data['authentication'] = cipher.get('au')

            result['ciphers'].append(cipher_data)

            # Track weak ciphers
            if strength == 'weak':
                result['stats']['weak_ciphers'].append(cipher_name)

    # Parse certificate
    cert_elem = ssltest.find('.//certificate')
    if cert_elem is not None:
        cert_data = {
            'subject': None,
            'issuer': None,
            'valid_from': None,
            'valid_to': None,
            'expired': False,
            'self_signed': False,
            'signature_algorithm': None,
            'key_bits': None,
            'san': []
        }

        # Subject
        subject = cert_elem.find('.//subject')
        if subject is not None:
            cert_data['subject'] = subject.text

        # Issuer
        issuer = cert_elem.find('.//issuer')
        if issuer is not None:
            cert_data['issuer'] = issuer.text

        # Validity
        not_before = cert_elem.find('.//not-valid-before')
        if not_before is not None:
            cert_data['valid_from'] = not_before.text

        not_after = cert_elem.find('.//not-valid-after')
        if not_after is not None:
            cert_data['valid_to'] = not_after.text

        # Check expiration
        expired = cert_elem.find('.//expired')
        if expired is not None:
            cert_data['expired'] = expired.text.lower() == 'true'

        # Self-signed check
        self_signed = cert_elem.find('.//self-signed')
        if self_signed is not None:
            cert_data['self_signed'] = self_signed.text.lower() == 'true'

        # Signature algorithm
        sig_algo = cert_elem.find('.//signature-algorithm')
        if sig_algo is not None:
            cert_data['signature_algorithm'] = sig_algo.text

        # Key strength
        pk_elem = cert_elem.find('.//pk')
        if pk_elem is not None:
            cert_data['key_bits'] = int(pk_elem.get('bits', 0))

        # Subject Alternative Names
        for san in cert_elem.findall('.//altname'):
            if san.text:
                cert_data['san'].append(san.text)

        result['certificate'] = cert_data

    # Parse vulnerabilities
    heartbleed = ssltest.find('.//heartbleed')
    if heartbleed is not None:
        result['vulnerabilities']['heartbleed'] = heartbleed.get('vulnerable', '0') == '1'

    # Parse other vulnerability checks
    vuln_mapping = {
        'heartbleed': ['heartbleed'],
        'ccs_injection': ['openssl-ccs', 'ccs'],
        'poodle': ['fallback'],
        'robot': ['robot'],
        'ticketbleed': ['ticketbleed'],
        'crime': ['compression']
    }

    for vuln_name, search_terms in vuln_mapping.items():
        for term in search_terms:
            elem = ssltest.find(f'.//{term}')
            if elem is not None:
                vulnerable = elem.get('vulnerable', elem.get('supported', '0'))
                result['vulnerabilities'][vuln_name] = vulnerable == '1'

    return result


def parse_sslscan_text(file_path: Path) -> Dict[str, Any]:
    """Parse sslscan text output format."""
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    lines = content.strip().split('\n')

    result = {
        'type': 'sslscan',
        'target': None,
        'protocols': {
            'sslv2': False,
            'sslv3': False,
            'tlsv1_0': False,
            'tlsv1_1': False,
            'tlsv1_2': False,
            'tlsv1_3': False
        },
        'ciphers': [],
        'certificate': None,
        'vulnerabilities': {
            'heartbleed': False,
            'ccs_injection': False,
            'beast': False,
            'poodle': False,
            'sweet32': False,
            'ticketbleed': False,
            'robot': False,
            'drown': False,
            'crime': False,
            'breach': False,
            'logjam': False,
            'freak': False
        },
        'stats': {
            'weak_ciphers': [],
            'issues': []
        },
        'raw_file': str(file_path),
        'parsed_at': datetime.now(timezone.utc).isoformat()
    }

    in_cipher_section = False
    in_cert_section = False
    cert_data = {
        'subject': None,
        'issuer': None,
        'valid_from': None,
        'valid_to': None,
        'expired': False,
        'self_signed': False,
        'signature_algorithm': None,
        'key_bits': None,
        'san': []
    }

    for line in lines:
        line_stripped = line.strip()

        # Extract target
        # Testing SSL server X.X.X.X on port 443
        match = re.search(r'Testing SSL server\s+(\S+)\s+on port\s+(\d+)', line)
        if match:
            result['target'] = f"{match.group(1)}:{match.group(2)}"
            continue

        # Connected to format
        match = re.search(r'Connected to\s+(\S+)', line)
        if match and not result['target']:
            result['target'] = match.group(1)
            continue

        # Protocol support - various formats
        # SSLv2     disabled
        # TLSv1.2   enabled
        # SSLv2       not supported
        proto_patterns = [
            (r'SSLv2\s+(enabled|disabled|not supported)', 'sslv2'),
            (r'SSLv3\s+(enabled|disabled|not supported)', 'sslv3'),
            (r'TLSv1\.0\s+(enabled|disabled|not supported)', 'tlsv1_0'),
            (r'TLSv1\.1\s+(enabled|disabled|not supported)', 'tlsv1_1'),
            (r'TLSv1\.2\s+(enabled|disabled|not supported)', 'tlsv1_2'),
            (r'TLSv1\.3\s+(enabled|disabled|not supported)', 'tlsv1_3'),
        ]

        for pattern, proto_key in proto_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                result['protocols'][proto_key] = match.group(1).lower() == 'enabled'

        # Cipher detection section
        if 'Supported Server Cipher' in line:
            in_cipher_section = True
            continue

        # Parse cipher lines - check on every line since Accepted/Preferred
        # lines may appear without explicit section header
        # Cipher line formats:
        # Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384
        # Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384
        # Or: TLSv1.2    256 bits   ECDHE-RSA-AES256-GCM-SHA384   Curve P-256 DHE 256
        match = re.search(
            r'(Accepted|Preferred)\s+(SSLv[23]|TLSv1\.[0-3])\s+(\d+)\s+bits\s+(\S+)',
            line
        )
        if match:
            in_cipher_section = True
            cipher_name = match.group(4)
            bits = int(match.group(3))
            protocol = match.group(2)
            strength = classify_cipher_strength(cipher_name, bits)

            cipher_data = {
                'name': cipher_name,
                'bits': bits,
                'protocol': protocol,
                'strength': strength,
                'preferred': match.group(1) == 'Preferred'
            }

            result['ciphers'].append(cipher_data)

            if strength == 'weak':
                result['stats']['weak_ciphers'].append(cipher_name)
            continue

        if in_cipher_section:
            # End of cipher section
            if line_stripped.startswith('SSL Certificate') or (not line_stripped and result['ciphers']):
                in_cipher_section = False

        # Certificate section
        if 'SSL Certificate' in line or 'Certificate:' in line:
            in_cert_section = True
            continue

        if in_cert_section:
            # Subject: CN=example.com
            match = re.search(r'Subject:\s*(.+)', line)
            if match:
                cert_data['subject'] = match.group(1).strip()

            # Issuer: CN=Let's Encrypt Authority X3
            match = re.search(r'Issuer:\s*(.+)', line)
            if match:
                cert_data['issuer'] = match.group(1).strip()

            # Not valid before: Jan  1 00:00:00 2024 GMT
            match = re.search(r'Not valid before:\s*(.+)', line)
            if match:
                cert_data['valid_from'] = match.group(1).strip()

            # Not valid after:  Dec 31 23:59:59 2024 GMT
            match = re.search(r'Not valid after:\s*(.+)', line)
            if match:
                cert_data['valid_to'] = match.group(1).strip()

            # Signature Algorithm: sha256WithRSAEncryption
            match = re.search(r'Signature Algorithm:\s*(\S+)', line)
            if match:
                cert_data['signature_algorithm'] = match.group(1)

            # RSA Key Strength: 2048
            match = re.search(r'(?:RSA|EC)\s+Key\s+Strength:\s*(\d+)', line)
            if match:
                cert_data['key_bits'] = int(match.group(1))

            # Subject Alternative Names
            # Format: "Altnames: DNS:example.com, DNS:www.example.com"
            # or just "DNS:example.com"
            for san_match in re.finditer(r'DNS:\s*([^\s,]+)', line):
                san_value = san_match.group(1).rstrip(',')
                if san_value and san_value not in cert_data['san']:
                    cert_data['san'].append(san_value)

            # Expired check
            if 'Certificate has expired' in line or 'EXPIRED' in line.upper():
                cert_data['expired'] = True

            # Self-signed check
            if 'self-signed' in line.lower() or 'self signed' in line.lower():
                cert_data['self_signed'] = True

        # Vulnerability detection
        # Formats:
        #   Heartbleed: NOT vulnerable
        #   Heartbleed:         vulnerable (CVE-2014-0160)
        #   TLSv1.2 vulnerable (CVE-2014-0160)
        #   TLSv1.2 not vulnerable to heartbleed
        vuln_checks = [
            (r'Heartbleed[:\s]+(NOT\s+)?vulnerable', 'heartbleed'),
            (r'(not\s+)?vulnerable.*heartbleed', 'heartbleed'),
            (r'(not\s+)?vulnerable.*CVE-2014-0160', 'heartbleed'),
            (r'OpenSSL CCS[:\s]+(NOT\s+)?vulnerable', 'ccs_injection'),
            (r'CCS[:\s]+(NOT\s+)?vulnerable', 'ccs_injection'),
            (r'(not\s+)?vulnerable.*CVE-2014-0224', 'ccs_injection'),
            (r'POODLE[:\s]+(NOT\s+)?vulnerable', 'poodle'),
            (r'(not\s+)?vulnerable.*CVE-2014-3566', 'poodle'),
            (r'BEAST[:\s]+(NOT\s+)?vulnerable', 'beast'),
            (r'(not\s+)?vulnerable.*CVE-2011-3389', 'beast'),
            (r'Sweet32[:\s]+(NOT\s+)?vulnerable', 'sweet32'),
            (r'(not\s+)?vulnerable.*CVE-2016-2183', 'sweet32'),
            (r'Ticketbleed[:\s]+(NOT\s+)?vulnerable', 'ticketbleed'),
            (r'(not\s+)?vulnerable.*CVE-2016-9244', 'ticketbleed'),
            (r'ROBOT[:\s]+(NOT\s+)?vulnerable', 'robot'),
            (r'(not\s+)?vulnerable.*CVE-2017-13099', 'robot'),
            (r'DROWN[:\s]+(NOT\s+)?vulnerable', 'drown'),
            (r'(not\s+)?vulnerable.*CVE-2016-0800', 'drown'),
            (r'CRIME[:\s]+(NOT\s+)?vulnerable', 'crime'),
            (r'(not\s+)?vulnerable.*CVE-2012-4929', 'crime'),
            (r'BREACH[:\s]+(NOT\s+)?vulnerable', 'breach'),
            (r'(not\s+)?vulnerable.*CVE-2013-3587', 'breach'),
            (r'Logjam[:\s]+(NOT\s+)?vulnerable', 'logjam'),
            (r'(not\s+)?vulnerable.*CVE-2015-4000', 'logjam'),
            (r'FREAK[:\s]+(NOT\s+)?vulnerable', 'freak'),
            (r'(not\s+)?vulnerable.*CVE-2015-0204', 'freak'),
        ]

        for pattern, vuln_key in vuln_checks:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                # If "NOT" or "not" is captured in group 1, it's not vulnerable
                result['vulnerabilities'][vuln_key] = match.group(1) is None

        # TLS compression (CRIME)
        if 'Compression' in line:
            if 'enabled' in line.lower() or 'DEFLATE' in line:
                result['vulnerabilities']['crime'] = True

    # Set certificate if we found any data
    if cert_data['subject'] or cert_data['issuer']:
        result['certificate'] = cert_data

    return result


def is_xml_file(file_path: Path) -> bool:
    """Check if file is XML format."""
    with open(file_path, 'r', errors='replace') as f:
        first_line = f.readline().strip()
        # Check for XML declaration or root element
        return first_line.startswith('<?xml') or first_line.startswith('<')


def identify_issues(result: Dict[str, Any]) -> List[str]:
    """Identify security issues from parsed results."""
    issues = []

    # Deprecated protocols
    if result['protocols'].get('sslv2'):
        issues.append('SSLv2 enabled - critically insecure')
    if result['protocols'].get('sslv3'):
        issues.append('SSLv3 enabled - vulnerable to POODLE')
    if result['protocols'].get('tlsv1_0'):
        issues.append('TLSv1.0 enabled - deprecated')
    if result['protocols'].get('tlsv1_1'):
        issues.append('TLSv1.1 enabled - deprecated')

    # No modern protocols
    if not result['protocols'].get('tlsv1_2') and not result['protocols'].get('tlsv1_3'):
        issues.append('No modern TLS protocols (1.2/1.3) enabled')

    # Weak ciphers
    if result['stats']['weak_ciphers']:
        issues.append(f"Weak ciphers enabled: {', '.join(result['stats']['weak_ciphers'][:5])}")

    # Certificate issues
    cert = result.get('certificate')
    if cert:
        if cert.get('expired'):
            issues.append('Certificate has expired')
        if cert.get('self_signed'):
            issues.append('Certificate is self-signed')
        if cert.get('key_bits') and cert['key_bits'] < 2048:
            issues.append(f"Weak key size: {cert['key_bits']} bits")
        if cert.get('signature_algorithm'):
            if 'md5' in cert['signature_algorithm'].lower():
                issues.append('Certificate uses MD5 signature (weak)')
            if 'sha1' in cert['signature_algorithm'].lower():
                issues.append('Certificate uses SHA1 signature (deprecated)')

    # Vulnerabilities
    vuln_names = {
        'heartbleed': 'Heartbleed (CVE-2014-0160)',
        'ccs_injection': 'CCS Injection (CVE-2014-0224)',
        'beast': 'BEAST (CVE-2011-3389)',
        'poodle': 'POODLE (CVE-2014-3566)',
        'sweet32': 'Sweet32 (CVE-2016-2183)',
        'ticketbleed': 'Ticketbleed (CVE-2016-9244)',
        'robot': 'ROBOT (CVE-2017-13099)',
        'drown': 'DROWN (CVE-2016-0800)',
        'crime': 'CRIME (CVE-2012-4929)',
        'breach': 'BREACH (CVE-2013-3587)',
        'logjam': 'Logjam (CVE-2015-4000)',
        'freak': 'FREAK (CVE-2015-0204)'
    }

    for vuln_key, vuln_name in vuln_names.items():
        if result['vulnerabilities'].get(vuln_key):
            issues.append(f'Vulnerable to {vuln_name}')

    return issues


def parse_sslscan(file_path: Path) -> Dict[str, Any]:
    """Parse sslscan output file into structured data."""
    if is_xml_file(file_path):
        result = parse_sslscan_xml(file_path)
    else:
        result = parse_sslscan_text(file_path)

    # Identify security issues
    result['stats']['issues'] = identify_issues(result)

    return result


def main():
    parser = argparse.ArgumentParser(
        description='Parse sslscan output (XML or text format)'
    )
    parser.add_argument('file', type=Path, help='SSLScan output file to parse')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({'error': f'File not found: {args.file}'}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_sslscan(args.file)

        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': f'Parse error: {e}', 'type': type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
